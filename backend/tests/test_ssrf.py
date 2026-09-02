"""Tests for SSRF protection (Phase 2A).

These tests must never perform real DNS or network I/O.
"""

import socket

import pytest

from app.collection import ssrf
from app.collection.ssrf import check_target, is_blocked_ip

PRIVATE_OR_LOCAL = [
    "10.0.0.1",  # RFC 1918
    "172.16.0.1",  # RFC 1918
    "172.31.255.254",  # RFC 1918
    "192.168.1.1",  # RFC 1918
    "127.0.0.1",  # loopback
    "0.0.0.0",  # unspecified
    "169.254.1.1",  # link-local
    "100.64.0.1",  # CGNAT
    "192.0.2.1",  # TEST-NET-1
    "198.18.0.1",  # benchmarking
    "203.0.113.1",  # TEST-NET-3
    "224.0.0.1",  # multicast
    "240.0.0.1",  # reserved
    "255.255.255.255",  # broadcast
    "::1",  # IPv6 loopback
    "::",  # IPv6 unspecified
    "fe80::1",  # IPv6 link-local
    "fc00::1",  # IPv6 ULA
    "2001:db8::1",  # documentation
]

PUBLIC = [
    "8.8.8.8",
    "1.1.1.1",
    "93.184.216.34",
    "2606:2800:220:1:248:1893:25c8:1946",
]


@pytest.mark.parametrize("ip", PRIVATE_OR_LOCAL)
def test_private_and_local_ips_blocked(ip):
    assert is_blocked_ip(ip) is True


@pytest.mark.parametrize("ip", PUBLIC)
def test_public_ips_allowed(ip):
    assert is_blocked_ip(ip) is False


@pytest.mark.parametrize(
    "ip",
    [
        "::ffff:192.168.1.1",
        "::ffff:127.0.0.1",
        "::ffff:10.0.0.1",
    ]
)
def test_ipv4_mapped_ipv6_private_blocked(ip):
    assert is_blocked_ip(ip) is True


def test_ipv4_mapped_ipv6_public_allowed():
    assert is_blocked_ip("::ffff:93.184.216.34") is False


def test_literal_private_ip_target_blocked_before_connect():
    result = check_target("http://192.168.1.1/login")
    assert result.allowed is False
    assert result.status == "blocked"
    assert result.reason == "private_or_local_target"


def test_literal_public_ip_target_allowed():
    assert check_target("http://8.8.8.8/").allowed is True


def test_private_ip_with_port_blocked():
    result = check_target("https://10.0.0.5:8443/admin")
    assert result.allowed is False
    assert result.reason == "private_or_local_target"


@pytest.mark.parametrize(
    "url",
    [
        "http://localhost/",
        "http://localhost:8080/x",
        "http://sub.localhost/",
        "http://LOCALHOST/",
    ],
)
def test_localhost_names_blocked(url):
    result = check_target(url)
    assert result.allowed is False
    assert result.status == "blocked"
    assert result.reason == "private_or_local_target"


def test_hostname_resolving_to_private_ip_blocked(monkeypatch):
    def fake_getaddrinfo(host, port, *args, **kwargs):
        return [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("192.168.1.99", 0))
        ]

    monkeypatch.setattr(ssrf.socket, "getaddrinfo", fake_getaddrinfo)

    result = check_target("https://evil.example.com/")
    assert result.allowed is False
    assert result.reason == "private_or_local_target"


def test_hostname_resolving_to_any_private_ip_blocked(monkeypatch):
    """If ANY resolved address is blocked, the target is blocked."""

    def fake_getaddrinfo(host, port, *args, **kwargs):
        return [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 0)),
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", 0)),
        ]

    monkeypatch.setattr(ssrf.socket, "getaddrinfo", fake_getaddrinfo)

    assert check_target("https://mixed.example.com/").allowed is False


def test_hostname_resolving_to_public_ip_allowed(monkeypatch):
    def fake_getaddrinfo(host, port, *args, **kwargs):
        return [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 0))
        ]

    monkeypatch.setattr(ssrf.socket, "getaddrinfo", fake_getaddrinfo)

    assert check_target("https://example.com/").allowed is True


def test_dns_failure_is_error_not_blocked(monkeypatch):
    def fake_getaddrinfo(host, port, *args, **kwargs):
        raise socket.gaierror("name or service not known")

    monkeypatch.setattr(ssrf.socket, "getaddrinfo", fake_getaddrinfo)

    result = check_target("https://no-such-host.invalid/")
    assert result.allowed is False
    assert result.status == "error"
    assert result.reason == "dns_resolution_failed"


def test_unsupported_scheme_blocked():
    result = check_target("ftp://example.com/file")
    assert result.allowed is False
    assert result.status == "blocked"
    assert result.reason == "unsupported_scheme"


def test_missing_hostname_blocked():
    result = check_target("https:///path")
    assert result.allowed is False
    assert result.reason == "missing_hostname"
