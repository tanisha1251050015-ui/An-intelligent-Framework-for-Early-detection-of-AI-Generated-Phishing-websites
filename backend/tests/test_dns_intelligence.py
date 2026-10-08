"""Tests for the Phase 2B DNS intelligence module.

``socket.getaddrinfo`` is always mocked — no test touches real DNS or network.
"""

import json
import socket
import time

import pytest

from app.core.dns_intelligence import (
    DNS_TIMEOUT_SECONDS,
    classify_ip,
    extract_hostname,
    inspect_hostname,
    is_private_or_local,
)

PUBLIC_V4 = "93.184.216.34"
PUBLIC_V6 = "2606:2800:220:1:248:1893:25c8:1946"
PRIVATE_V4 = "192.168.1.99"
PRIVATE_V6 = "fd00::1"


def make_addrinfo(host, *ips):
    """Build a getaddrinfo-style result list from IP strings."""
    result = []
    for ip in ips:
        if ":" in ip:
            result.append((socket.AF_INET6, socket.SOCK_STREAM, 6, "", (ip, 0, 0, 0)))
        else:
            result.append((socket.AF_INET, socket.SOCK_STREAM, 6, "", (ip, 0)))
    return result


# ---------------------------------------------------------------- extraction


def test_extract_hostname_from_url():
    url = "https://user@example.com:8443/path?q=1"
    assert extract_hostname(url) == "example.com"


def test_extract_hostname_strips_trailing_dot_and_case():
    assert extract_hostname("https://EXAMPLE.COM./") == "example.com"


def test_extract_hostname_ipv6():
    assert extract_hostname("https://[2001:db8::1]/") == "2001:db8::1"


# ------------------------------------------------------------ classification


@pytest.mark.parametrize(
    ("ip", "expected"),
    [
        ("10.0.0.1", "private"),
        ("192.168.1.1", "private"),
        ("172.16.0.1", "private"),
        ("127.0.0.1", "loopback"),
        ("169.254.1.1", "link-local"),
        ("0.0.0.0", "unspecified"),
        ("224.0.0.1", "multicast"),
        ("240.0.0.1", "reserved"),
        ("100.64.0.1", "private"),  # CGNAT
        ("192.0.2.1", "private"),  # TEST-NET-1
        ("2001:db8::1", "private"),  # documentation
        ("::1", "loopback"),
        ("::", "unspecified"),
        ("fe80::1", "link-local"),
        ("fd00::1", "private"),
        ("8.8.8.8", "public"),
        ("2606:2800:220:1:248:1893:25c8:1946", "public"),
        ("not-an-ip", "invalid"),
    ],
)
def test_classify_ip_categories(ip, expected):
    assert classify_ip(ip) == expected


def test_ipv4_mapped_ipv6_private():
    assert classify_ip("::ffff:192.168.1.1") == "private"
    assert is_private_or_local("::ffff:192.168.1.1") is True


def test_public_ip_not_private():
    assert is_private_or_local(PUBLIC_V4) is False


# --------------------------------------------------------------- resolution


def test_ipv4_resolution(monkeypatch):
    monkeypatch.setattr(
        socket, "getaddrinfo", lambda host, port, *a, **k: make_addrinfo(host, PUBLIC_V4)
    )
    result = inspect_hostname("example.com")

    assert result["status"] == "resolved"
    assert result["hostname"] == "example.com"
    assert result["ipv4"] == [PUBLIC_V4]
    assert result["ipv6"] == []
    assert result["address_count"] == 1
    assert result["has_private"] is False
    assert result["all_private"] is False
    assert result["error"] is None
    assert result["categories"][PUBLIC_V4] == "public"


def test_ipv6_resolution(monkeypatch):
    monkeypatch.setattr(
        socket, "getaddrinfo", lambda host, port, *a, **k: make_addrinfo(host, PUBLIC_V6)
    )
    result = inspect_hostname("example.com")

    assert result["status"] == "resolved"
    assert result["ipv6"] == [PUBLIC_V6]
    assert result["ipv4"] == []


def test_multiple_addresses_and_deduplication(monkeypatch):
    monkeypatch.setattr(
        socket,
        "getaddrinfo",
        lambda host, port, *a, **k: make_addrinfo(
            host, PUBLIC_V4, PUBLIC_V4, PUBLIC_V6, "10.0.0.1"
        ),
    )
    result = inspect_hostname("example.com")

    assert result["addresses"] == [PUBLIC_V4, PUBLIC_V6, "10.0.0.1"]
    assert result["address_count"] == 3
    assert result["ipv4"] == [PUBLIC_V4, "10.0.0.1"]
    assert result["ipv6"] == [PUBLIC_V6]


def test_all_public_resolution(monkeypatch):
    monkeypatch.setattr(
        socket,
        "getaddrinfo",
        lambda host, port, *a, **k: make_addrinfo(host, PUBLIC_V4, PUBLIC_V6),
    )
    result = inspect_hostname("example.com")
    assert result["has_private"] is False
    assert result["all_private"] is False


def test_dns_rebinding_style_private_resolution(monkeypatch):
    monkeypatch.setattr(
        socket, "getaddrinfo", lambda host, port, *a, **k: make_addrinfo(host, PRIVATE_V4)
    )
    result = inspect_hostname("evil.example.com")

    assert result["status"] == "resolved"
    assert result["has_private"] is True
    assert result["all_private"] is True
    assert result["categories"][PRIVATE_V4] == "private"


def test_mixed_private_public_resolution(monkeypatch):
    monkeypatch.setattr(
        socket,
        "getaddrinfo",
        lambda host, port, *a, **k: make_addrinfo(host, PUBLIC_V4, PRIVATE_V4),
    )
    result = inspect_hostname("mixed.example.com")

    assert result["has_private"] is True
    assert result["all_private"] is False  # not every address is private


def test_resolution_failure_is_structured_error(monkeypatch):
    def fail(host, port, *a, **k):
        raise socket.gaierror("Name or service not known")

    monkeypatch.setattr(socket, "getaddrinfo", fail)

    result = inspect_hostname("no-such-host.invalid")
    assert result["status"] == "error"
    assert result["error"]["type"] == "resolution_failed"
    assert result["address_count"] == 0


def test_socket_timeout_is_error(monkeypatch):
    def fail(host, port, *a, **k):
        raise socket.timeout("DNS timed out")

    monkeypatch.setattr(socket, "getaddrinfo", fail)

    result = inspect_hostname("slow.example.com")
    assert result["status"] == "error"
    assert result["error"]["type"] == "timeout"


def test_malformed_hostname_is_error(monkeypatch):
    def fail(host, port, *a, **k):
        raise socket.gaierror("nodename nor servname provided")

    monkeypatch.setattr(socket, "getaddrinfo", fail)

    result = inspect_hostname("not a valid hostname")
    assert result["status"] == "error"
    assert result["error"]["type"] == "resolution_failed"


def test_unexpected_exception_never_crashes(monkeypatch):
    def boom(host, port, *a, **k):
        raise RuntimeError("unexpected")

    monkeypatch.setattr(socket, "getaddrinfo", boom)

    result = inspect_hostname("weird.example.com")
    assert result["status"] == "error"
    assert result["error"]["type"] == "internal_error"


def test_resolution_timeout_bounded(monkeypatch):
    def slow(host, port, *a, **k):
        time.sleep(0.5)
        return make_addrinfo(host, PUBLIC_V4)

    monkeypatch.setattr(socket, "getaddrinfo", slow)

    result = inspect_hostname("slow.example.com", timeout=0.05)
    assert result["status"] == "timeout"
    assert result["address_count"] == 0
    assert result["resolution_ms"] < 1000


def test_resolution_ms_reported(monkeypatch):
    monkeypatch.setattr(
        socket, "getaddrinfo", lambda host, port, *a, **k: make_addrinfo(host, PUBLIC_V4)
    )
    result = inspect_hostname("example.com")
    assert result["resolution_ms"] >= 0


def test_default_timeout_is_about_five_seconds():
    assert 4.0 <= DNS_TIMEOUT_SECONDS <= 6.0


def test_missing_hostname_is_structured_error():
    result = inspect_hostname("")
    assert result["status"] == "error"
    assert result["error"]["type"] == "missing_hostname"


# ------------------------------------------------------------------- literals


def test_literal_ipv4_no_lookup(monkeypatch):
    def boom(host, port, *a, **k):
        raise AssertionError("literal IPs must not trigger a DNS lookup")

    monkeypatch.setattr(socket, "getaddrinfo", boom)

    result = inspect_hostname("192.168.1.1")
    assert result["status"] == "literal"
    assert result["addresses"] == ["192.168.1.1"]
    assert result["has_private"] is True
    assert result["all_private"] is True
    assert result["categories"]["192.168.1.1"] == "private"


def test_literal_ipv6_no_lookup(monkeypatch):
    def boom(host, port, *a, **k):
        raise AssertionError("literal IPs must not trigger a DNS lookup")

    monkeypatch.setattr(socket, "getaddrinfo", boom)

    result = inspect_hostname("::1")
    assert result["status"] == "literal"
    assert result["ipv6"] == ["::1"]
    assert result["categories"]["::1"] == "loopback"
    assert result["has_private"] is True


def test_literal_public_ip(monkeypatch):
    def boom(host, port, *a, **k):
        raise AssertionError("literal IPs must not trigger a DNS lookup")

    monkeypatch.setattr(socket, "getaddrinfo", boom)

    result = inspect_hostname("8.8.8.8")
    assert result["status"] == "literal"
    assert result["has_private"] is False
    assert result["all_private"] is False
    assert result["categories"]["8.8.8.8"] == "public"


# ----------------------------------------------------------------- API tests


def test_api_returns_dns_for_hostname(client):
    body = client.post(
        "/api/v1/inspect", json={"url": "https://example.com/"}
    ).json()

    assert body["dns"]["hostname"] == "example.com"
    assert body["dns"]["status"] == "resolved"
    assert "93.184.216.34" in body["dns"]["addresses"]
    assert body["dns"]["has_private"] is False
    assert body["score"] == 0  # Phase 1 scoring unchanged
    assert body["classification"] == "safe"


def test_api_returns_dns_for_literal_private(client):
    body = client.post(
        "/api/v1/inspect", json={"url": "http://192.168.1.1/login"}
    ).json()

    assert body["dns"]["status"] == "literal"
    assert body["dns"]["has_private"] is True
    assert body["dns"]["all_private"] is True
    assert body["score"] == 65  # Phase 1 score unchanged (http+ip+keyword)
    assert body["classification"] == "suspicious"


def test_dns_persisted(client, db_session):
    from sqlalchemy import select

    from app.models import Inspection

    client.post("/api/v1/inspect", json={"url": "https://example.com/"})

    row = db_session.scalar(select(Inspection))
    assert row.dns_data is not None
    assert json.loads(row.dns_data)["status"] == "resolved"


def test_dns_retrieved_by_id(client):
    created = client.post(
        "/api/v1/inspect", json={"url": "https://example.com/"}
    ).json()

    got = client.get(f"/api/v1/inspections/{created['id']}").json()
    assert got["dns"] == created["dns"]
    assert got["dns"]["hostname"] == "example.com"


def test_dns_error_persisted_and_does_not_crash(client, db_session, monkeypatch):
    from sqlalchemy import select

    from app.models import Inspection

    def fail(host, port, *a, **k):
        raise socket.gaierror("Name or service not known")

    monkeypatch.setattr(socket, "getaddrinfo", fail)

    body = client.post(
        "/api/v1/inspect", json={"url": "https://nosuchhost.invalid/"}
    ).json()

    assert body["status"] == "completed"
    assert body["dns"]["status"] == "error"
    assert body["dns"]["error"]["type"] == "resolution_failed"
    assert body["score"] == 0  # scoring unaffected by DNS failure

    row = db_session.scalar(select(Inspection))
    assert json.loads(row.dns_data)["status"] == "error"


def test_existing_records_have_null_dns(client, db_session):
    """Pre-Phase 2B records show dns as null (SQL NULL), not text 'null'."""
    from sqlalchemy import select

    from app.models import Inspection

    # Simulate a legacy record by inserting with dns_data left NULL.
    db_session.add(
        Inspection(url="https://legacy.example.com/", status="completed")
    )
    db_session.commit()

    legacy = db_session.scalar(select(Inspection).where(Inspection.url == "https://legacy.example.com/"))
    assert legacy.dns_data is None

    response = client.get(f"/api/v1/inspections/{legacy.id}").json()
    assert response["dns"] is None
