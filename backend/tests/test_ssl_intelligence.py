"""Tests for Phase 2C SSL intelligence.

All network-dependent tests use mocks — no real connections are made.
"""

import datetime
import socket
import ssl
from unittest.mock import MagicMock, patch

import pytest

from app.core.ssl_intelligence import (
    SSL_PORT,
    _check_hostname_match,
    _extract_san,
    _format_name,
    _parse_asn1_date,
    collect_ssl,
    not_applicable,
)


# ---------------------------------------------------------- Helpers


def _make_cert(
    *,
    issuer: tuple = (("countryName", "US"), ("organizationName", "Let's Encrypt")),
    subject: tuple = (("commonName", "example.com"),),
    not_before: str = "Jan  1 00:00:00 2024 GMT",
    not_after: str = "Jan  1 00:00:00 2027 GMT",
    serial: str = "ABC123",
    san: tuple = (("DNS", "example.com"),),
    sig_alg: str = "sha256WithRSAEncryption",
) -> dict:
    """Build a fake peer certificate dict."""
    return {
        "issuer": issuer,
        "subject": subject,
        "notBefore": not_before,
        "notAfter": not_after,
        "serialNumber": serial,
        "subjectAltName": san,
        "signatureAlgorithm": sig_alg,
        "version": 3,
    }


def _mock_ssl_context(cert=None, connect_error=None, close_error=None):
    """Create a mock SSL context and socket chain for testing."""
    mock_ctx = MagicMock()
    mock_raw_sock = MagicMock()
    mock_wrapped_sock = MagicMock()

    # ssl.create_default_context returns our mock context
    # ctx.wrap_socket(raw_sock, ...) returns the wrapped sock
    mock_ctx.wrap_socket.return_value = mock_wrapped_sock

    if cert is not None:
        mock_wrapped_sock.getpeercert.return_value = cert
    if connect_error is not None:
        mock_wrapped_sock.connect.side_effect = connect_error

    return mock_ctx, mock_raw_sock, mock_wrapped_sock


# ---------------------------------------------------------- HTTPS certificate parsing


def test_collect_ssl_returns_collected(monkeypatch):
    """Valid HTTPS certificate is parsed correctly."""
    cert = _make_cert()
    mock_ctx, mock_raw_sock, mock_wrapped_sock = _mock_ssl_context(cert=cert)

    monkeypatch.setattr("app.core.ssl_intelligence.ssl.create_default_context", lambda: mock_ctx)
    monkeypatch.setattr("app.core.ssl_intelligence.socket.socket", lambda *a, **k: mock_raw_sock)

    result = collect_ssl("example.com")

    assert result["status"] == "collected"
    assert result["hostname"] == "example.com"
    assert result["issuer"] == "countryName=US, organizationName=Let's Encrypt"
    assert result["subject"] == "commonName=example.com"
    assert result["serial_number"] == "ABC123"
    assert result["is_expired"] is False
    assert result["is_self_signed"] is False
    assert result["hostname_match"] is True
    assert result["cert_age_days"] is not None
    assert result["cert_age_days"] >= 0


def test_collect_ssl_self_signed():
    """Self-signed certificate is detected."""
    cert = _make_cert(
        issuer=(("commonName", "example.com"),),
        subject=(("commonName", "example.com"),),
    )
    mock_ctx, mock_raw_sock, mock_wrapped_sock = _mock_ssl_context(cert=cert)

    with patch("app.core.ssl_intelligence.ssl.create_default_context", return_value=mock_ctx), \
         patch("app.core.ssl_intelligence.socket.socket", return_value=mock_raw_sock):
        result = collect_ssl("example.com")

    assert result["is_self_signed"] is True


def test_collect_ssl_expired():
    """Expired certificate is detected."""
    cert = _make_cert(not_after="Jan  1 00:00:00 2020 GMT")
    mock_ctx, mock_raw_sock, mock_wrapped_sock = _mock_ssl_context(cert=cert)

    with patch("app.core.ssl_intelligence.ssl.create_default_context", return_value=mock_ctx), \
         patch("app.core.ssl_intelligence.socket.socket", return_value=mock_raw_sock):
        result = collect_ssl("example.com")

    assert result["is_expired"] is True


def test_collect_ssl_hostname_mismatch():
    """Hostname mismatch is detected."""
    cert = _make_cert(
        san=(("DNS", "other.com"),),
        subject=(("commonName", "other.com"),),
    )
    mock_ctx, mock_raw_sock, mock_wrapped_sock = _mock_ssl_context(cert=cert)

    with patch("app.core.ssl_intelligence.ssl.create_default_context", return_value=mock_ctx), \
         patch("app.core.ssl_intelligence.socket.socket", return_value=mock_raw_sock):
        result = collect_ssl("example.com")

    assert result["hostname_match"] is False


def test_collect_ssl_timeout():
    """Connection timeout returns structured error."""
    mock_ctx, mock_raw_sock, mock_wrapped_sock = _mock_ssl_context(
        connect_error=socket.timeout("timed out")
    )

    with patch("app.core.ssl_intelligence.ssl.create_default_context", return_value=mock_ctx), \
         patch("app.core.ssl_intelligence.socket.socket", return_value=mock_raw_sock):
        result = collect_ssl("example.com")

    assert result["status"] == "timeout"
    assert result["hostname"] == "example.com"


def test_collect_ssl_connection_refused():
    """Connection refused returns structured error."""
    mock_ctx, mock_raw_sock, mock_wrapped_sock = _mock_ssl_context(
        connect_error=OSError("Connection refused")
    )

    with patch("app.core.ssl_intelligence.ssl.create_default_context", return_value=mock_ctx), \
         patch("app.core.ssl_intelligence.socket.socket", return_value=mock_raw_sock):
        result = collect_ssl("example.com")

    assert result["status"] == "error"
    assert result["hostname"] == "example.com"


def test_collect_ssl_ssl_error():
    """SSL error returns structured error."""
    mock_ctx, mock_raw_sock, mock_wrapped_sock = _mock_ssl_context(
        connect_error=ssl.SSLError("certificate verify failed")
    )

    with patch("app.core.ssl_intelligence.ssl.create_default_context", return_value=mock_ctx), \
         patch("app.core.ssl_intelligence.socket.socket", return_value=mock_raw_sock):
        result = collect_ssl("example.com")

    assert result["status"] == "error"


def test_collect_ssl_empty_certificate():
    """Empty certificate dict returns error."""
    mock_ctx, mock_raw_sock, mock_wrapped_sock = _mock_ssl_context(cert={})

    with patch("app.core.ssl_intelligence.ssl.create_default_context", return_value=mock_ctx), \
         patch("app.core.ssl_intelligence.socket.socket", return_value=mock_raw_sock):
        result = collect_ssl("example.com")

    assert result["status"] == "error"
    assert result["reason"] == "no_certificate"


def test_collect_ssl_missing_hostname():
    """Missing hostname returns error."""
    result = collect_ssl("")
    assert result["status"] == "error"
    assert result["reason"] == "missing_hostname"


def test_collect_ssl_strips_trailing_dot():
    """Trailing dot is stripped from hostname."""
    cert = _make_cert()
    mock_ctx, mock_raw_sock, mock_wrapped_sock = _mock_ssl_context(cert=cert)

    with patch("app.core.ssl_intelligence.ssl.create_default_context", return_value=mock_ctx), \
         patch("app.core.ssl_intelligence.socket.socket", return_value=mock_raw_sock):
        result = collect_ssl("example.com.")

    assert result["hostname"] == "example.com"


def test_collect_ssl_wildcard_cert():
    """Wildcard certificate matches subdomain."""
    cert = _make_cert(san=(("DNS", "*.example.com"),))
    mock_ctx, mock_raw_sock, mock_wrapped_sock = _mock_ssl_context(cert=cert)

    with patch("app.core.ssl_intelligence.ssl.create_default_context", return_value=mock_ctx), \
         patch("app.core.ssl_intelligence.socket.socket", return_value=mock_raw_sock):
        result = collect_ssl("sub.example.com")

    assert result["hostname_match"] is True


def test_collect_ssl_sans_listed():
    """Multiple SANs are extracted."""
    cert = _make_cert(san=(("DNS", "example.com"), ("DNS", "www.example.com")))
    mock_ctx, mock_raw_sock, mock_wrapped_sock = _mock_ssl_context(cert=cert)

    with patch("app.core.ssl_intelligence.ssl.create_default_context", return_value=mock_ctx), \
         patch("app.core.ssl_intelligence.socket.socket", return_value=mock_raw_sock):
        result = collect_ssl("example.com")

    assert result["subject_alt_names"] == ["example.com", "www.example.com"]


# ------------------------------------------------------------------- helper tests


def test_parse_asn1_date():
    """ASN.1 date strings are parsed."""
    dt = _parse_asn1_date("Jan  1 00:00:00 2024 GMT")
    assert dt is not None
    assert dt.year == 2024


def test_parse_asn1_date_compact():
    """Compact ASN.1 date format is parsed."""
    dt = _parse_asn1_date("20240101000000Z")
    assert dt is not None
    assert dt.year == 2024


def test_parse_asn1_date_invalid():
    """Invalid date returns None."""
    assert _parse_asn1_date("not-a-date") is None


def test_format_name():
    """Name tuple is formatted as readable string."""
    # X.509 names are tuples of RDNs, each RDN is a tuple of (type, value) pairs
    name = (
        (("commonName", "example.com"),),
        (("organizationName", "ACME"),),
    )
    result = _format_name(name)
    assert result == "commonName=example.com, organizationName=ACME"


def test_format_name_flat():
    """Flat name tuple is formatted correctly."""
    name = (("commonName", "example.com"), ("organizationName", "ACME"))
    result = _format_name(name)
    assert result == "commonName=example.com, organizationName=ACME"


def test_format_name_empty():
    """Empty name returns empty string."""
    assert _format_name(()) == ""


def test_extract_san():
    """SANs are extracted from certificate."""
    cert = {"subjectAltName": (("DNS", "a.com"), ("DNS", "b.com"))}
    assert _extract_san(cert) == ["a.com", "b.com"]


def test_extract_san_missing():
    """Missing SANs return empty list."""
    assert _extract_san({}) == []


def test_check_hostname_match_exact():
    """Exact hostname match returns True."""
    assert _check_hostname_match("example.com", ["example.com"], {}) is True


def test_check_hostname_match_wildcard():
    """Wildcard match returns True."""
    assert _check_hostname_match("sub.example.com", ["*.example.com"], {}) is True


def test_check_hostname_match_mismatch():
    """Mismatch returns False when SANs are present."""
    assert _check_hostname_match("other.com", ["example.com"], {}) is False


def test_check_hostname_match_cn_fallback():
    """CN fallback when no SANs."""
    cert = {"subject": ((("commonName", "example.com"),),)}
    assert _check_hostname_match("example.com", [], cert) is True


def test_check_hostname_match_cn_wildcard():
    """CN wildcard match."""
    cert = {"subject": ((("commonName", "*.example.com"),),)}
    assert _check_hostname_match("sub.example.com", [], cert) is True


def test_check_hostname_match_no_san_no_cn():
    """No SANs and no CN returns None."""
    assert _check_hostname_match("example.com", [], {}) is None


# ------------------------------------------------------------------- HTTP


def test_not_applicable():
    """HTTP URLs return not_applicable."""
    result = not_applicable("example.com")
    assert result["status"] == "not_applicable"
    assert result["reason"] == "https_required"
    assert result["hostname"] == "example.com"
