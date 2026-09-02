"""SSL certificate intelligence (Phase 2C).

Collects certificate information from HTTPS targets using only the Python
standard library (``ssl`` and ``socket``). For HTTP URLs returns a structured
``not_applicable`` result. SSL intelligence runs ONLY after the target has
passed Phase 2A SSRF validation and connects ONLY to the inspected hostname
on port 443 with a bounded timeout.

This module never bypasses SSRF protection, never scans ports, never
enumerates hosts, and never crashes the API.
"""

from __future__ import annotations

import datetime
import socket
import ssl
from typing import Any

SSL_TIMEOUT_SECONDS: float = 5.0
SSL_PORT: int = 443


def _format_dt(dt: datetime.datetime | None) -> str | None:
    """Format a datetime to ISO 8601 string, or None."""
    if dt is None:
        return None
    return dt.isoformat()


def collect_ssl(hostname: str, *, timeout: float = SSL_TIMEOUT_SECONDS) -> dict[str, Any]:
    """Collect SSL certificate intelligence for a hostname.

    Must be called ONLY after the target has passed SSRF validation.

    Returns a structured dict with ``status`` one of:

    - ``"collected"`` — certificate information gathered
    - ``"error"``     — connection or parsing failure
    - ``"timeout"``   — connection timed out

    Never raises. Never crashes the API.
    """
    hostname = (hostname or "").strip().lower().rstrip(".")
    if not hostname:
        return {"status": "error", "reason": "missing_hostname"}

    try:
        ctx = ssl.create_default_context()
    except Exception as exc:
        return _ssl_error(hostname, exc)

    raw_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    raw_sock.settimeout(timeout)

    try:
        sock = ctx.wrap_socket(raw_sock, server_hostname=hostname)
    except Exception as exc:
        raw_sock.close()
        return _ssl_error(hostname, exc)

    try:
        sock.connect((hostname, SSL_PORT))
        cert = sock.getpeercert()
    except socket.timeout:
        return {"status": "timeout", "hostname": hostname}
    except ssl.SSLError as exc:
        return _ssl_error(hostname, exc)
    except OSError as exc:
        return _ssl_error(hostname, exc)
    except Exception as exc:
        return _ssl_error(hostname, exc)
    finally:
        try:
            sock.close()
        except Exception:
            pass

    return _parse_cert(hostname, cert)


def _ssl_error(hostname: str, exc: Exception) -> dict[str, Any]:
    """Build a structured error result from an exception."""
    return {
        "status": "error",
        "hostname": hostname,
        "reason": type(exc).__name__,
        "message": str(exc),
    }


def _parse_cert(
    hostname: str, cert: dict[str, Any]
) -> dict[str, Any]:
    """Parse a peer certificate dict into a structured intelligence result."""
    if not cert:
        return {
            "status": "error",
            "hostname": hostname,
            "reason": "no_certificate",
            "message": "Server returned no certificate",
        }

    issuer = _format_name(cert.get("issuer", ()))
    subject = _format_name(cert.get("subject", ()))

    not_before = cert.get("notBefore", "")
    not_after = cert.get("notAfter", "")
    serial = cert.get("serialNumber", "")
    version = cert.get("version", "")
    san = _extract_san(cert)
    sig_alg = cert.get("signatureAlgorithm", "")

    # Parse validity dates
    parsed_before = _parse_asn1_date(not_before) if not_before else None
    parsed_after = _parse_asn1_date(not_after) if not_after else None

    now = datetime.datetime.now(datetime.timezone.utc)
    is_expired = parsed_after is not None and now > parsed_after
    cert_age_days = _days_between(parsed_before, now) if parsed_before else None

    # Self-signed check: issuer == subject
    is_self_signed = bool(issuer and subject and issuer == subject)

    # Hostname match check
    hostname_match = _check_hostname_match(hostname, san, cert)

    return {
        "status": "collected",
        "hostname": hostname,
        "issuer": issuer,
        "subject": subject,
        "not_before": not_before,
        "not_after": not_after,
        "serial_number": serial,
        "version": version,
        "subject_alt_names": san,
        "signature_algorithm": sig_alg if sig_alg else None,
        "cert_age_days": cert_age_days,
        "is_expired": is_expired,
        "is_self_signed": is_self_signed,
        "hostname_match": hostname_match,
    }


def _format_name(name_tuple: tuple) -> str:
    """Flatten an X.509 name tuple into a readable string.

    X.509 names come as a tuple of RDNs, where each RDN is a tuple of
    (attr_type, attr_value) pairs. Handles both nested and flat formats.
    """
    parts: list[str] = []
    for rdn in name_tuple:
        # RDN may be a tuple of (type, value) pairs or a flat (type, value)
        if isinstance(rdn, tuple) and len(rdn) == 2:
            # Could be a single (type, value) pair or an RDN tuple
            first, second = rdn
            if isinstance(first, str) and isinstance(second, str):
                # Flat (type, value) pair
                parts.append(f"{first}={second}")
            else:
                # Nested RDN: ((type, value), ...)
                for attr_type, attr_value in rdn:
                    parts.append(f"{attr_type}={attr_value}")
        else:
            for attr_type, attr_value in rdn:
                parts.append(f"{attr_type}={attr_value}")
    return ", ".join(parts)


def _extract_san(cert: dict[str, Any]) -> list[str]:
    """Extract Subject Alternative Names from the certificate."""
    san_list: list[str] = []
    san_ext = cert.get("subjectAltName", ())
    for san_type, san_value in san_ext:
        san_list.append(san_value)
    return san_list


def _parse_asn1_date(date_str: str) -> datetime.datetime | None:
    """Parse an ASN.1/generalized time date string."""
    formats = [
        "%b %d %H:%M:%S %Y %Z",    # "Jan  1 00:00:00 2026 GMT"
        "%b  %d %H:%M:%S %Y %Z",   # "Jan  1 00:00:00 2026 GMT"
        "%Y%m%d%H%M%SZ",           # "20260101000000Z"
    ]
    for fmt in formats:
        try:
            return datetime.datetime.strptime(date_str, fmt).replace(
                tzinfo=datetime.timezone.utc
            )
        except ValueError:
            continue
    return None


def _days_between(
    earlier: datetime.datetime, later: datetime.datetime
) -> int | None:
    """Compute the number of days between two datetimes."""
    if earlier is None or later is None:
        return None
    delta = later - earlier
    return abs(delta.days)


def _check_hostname_match(
    hostname: str, san_list: list[str], cert: dict[str, Any]
) -> bool | None:
    """Check if the hostname matches the certificate's SANs or CN.

    Returns True for match, False for mismatch, None if undetermined.
    """
    lowered = hostname.lower()

    # Check SANs first
    for san in san_list:
        san_lower = san.lower()
        if san_lower.startswith("*."):
            # Wildcard match: *.example.com matches sub.example.com
            wildcard = san_lower[2:]
            parts = lowered.split(".")
            if len(parts) > 1 and ".".join(parts[1:]) == wildcard:
                return True
        elif san_lower == lowered:
            return True

    # Fall back to CN from subject
    subject = cert.get("subject", ())
    for rdn in subject:
        if isinstance(rdn, tuple) and len(rdn) == 2:
            first, second = rdn
            if isinstance(first, str) and isinstance(second, str):
                # Flat (type, value) pair
                if first == "commonName":
                    return _match_cn(lowered, second)
            else:
                for attr_type, attr_value in rdn:
                    if attr_type == "commonName":
                        return _match_cn(lowered, attr_value)
        else:
            for attr_type, attr_value in rdn:
                if attr_type == "commonName":
                    return _match_cn(lowered, attr_value)

    # If we have SANs but none matched, it's a mismatch
    if san_list:
        return False

    return None


def _match_cn(hostname: str, cn: str) -> bool:
    """Check if hostname matches a Common Name."""
    cn_lower = cn.lower()
    if cn_lower.startswith("*."):
        wildcard = cn_lower[2:]
        parts = hostname.split(".")
        if len(parts) > 1 and ".".join(parts[1:]) == wildcard:
            return True
    elif cn_lower == hostname:
        return True
    return False


def not_applicable(hostname: str) -> dict[str, Any]:
    """Return a structured result for HTTP URLs (no TLS)."""
    return {
        "status": "not_applicable",
        "hostname": hostname,
        "reason": "https_required",
    }
