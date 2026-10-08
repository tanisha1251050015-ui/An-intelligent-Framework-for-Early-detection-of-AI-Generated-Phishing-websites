"""DNS intelligence foundation (Phase 2B).

Resolves and classifies ONLY the hostname of the URL currently being inspected
using the Python standard library (``socket.getaddrinfo``).

This module is **informational only**. It never weakens or bypasses the Phase
2A SSRF protection — SSRF remains authoritative for whether an HTTP request is
allowed. No hostname/subdomain enumeration, no port/network scanning, no
crawling, and no external threat-intelligence lookups are performed.

Bounded resolution: ``getaddrinfo`` runs on a daemon worker thread and the
caller waits at most ``DNS_TIMEOUT_SECONDS`` (default ~5 s). DNS failures and
timeouts are captured as structured results and never crash the API. Literal
IPv4/IPv6 addresses are classified directly WITHOUT any DNS lookup.
"""

from __future__ import annotations

import ipaddress
import socket
import threading
import time
from urllib.parse import urlsplit

DNS_TIMEOUT_SECONDS: float = 5.0

# Non-public ranges not flagged by the ipaddress convenience attributes
# (CGNAT/shared space, IETF assignments, TEST-NETs, benchmarking, broadcast,
# documentation). Kept in sync with app.collection.ssrf for consistency.
_EXTRA_NON_PUBLIC: tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, ...] = (
    ipaddress.ip_network("100.64.0.0/10"),    # CGNAT / shared address space
    ipaddress.ip_network("192.0.0.0/24"),     # IETF protocol assignments
    ipaddress.ip_network("192.0.2.0/24"),     # TEST-NET-1
    ipaddress.ip_network("198.18.0.0/15"),    # benchmarking
    ipaddress.ip_network("198.51.100.0/24"),  # TEST-NET-2
    ipaddress.ip_network("203.0.113.0/24"),   # TEST-NET-3
    ipaddress.ip_network("255.255.255.255/32"),
    ipaddress.ip_network("2001:db8::/32"),    # documentation
)


def classify_ip(ip: str) -> str:
    """Classify an address into a safe, informational category.

    Categories: ``private``, ``loopback``, ``link-local``, ``unspecified``,
    ``multicast``, ``reserved``, ``public``, or ``invalid``. IPv4-mapped IPv6
    addresses (e.g. ``::ffff:192.168.1.1``) inherit the mapped IPv4 category.
    """
    try:
        address = ipaddress.ip_address(ip)
    except ValueError:
        return "invalid"

    # Unwrap IPv4-mapped IPv6 (e.g. ::ffff:192.168.1.1) so the mapped IPv4
    # address is classified (Python 3.11 does not do this automatically).
    mapped = getattr(address, "ipv4_mapped", None)
    if mapped is not None:
        address = mapped

    if address.is_unspecified:
        return "unspecified"
    if address.is_loopback:
        return "loopback"
    if address.is_link_local:
        return "link-local"
    if address.is_multicast:
        return "multicast"
    if address.is_reserved:
        return "reserved"
    if address.is_private:
        return "private"
    if any(address in network for network in _EXTRA_NON_PUBLIC):
        return "private"
    return "public"


def is_private_or_local(ip: str) -> bool:
    """True when the address is not globally public (informational check)."""
    return classify_ip(ip) != "public"


def extract_hostname(raw_url: str) -> str:
    """Extract the normalized hostname from a URL (no DNS performed)."""
    return (urlsplit(raw_url).hostname or "").lower().rstrip(".")


def _is_ipv6(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip).version == 6
    except ValueError:
        return ":" in ip


def _result(
    hostname: str,
    status: str,
    resolution_ms: int,
    ordered: list[str],
    error: dict | None,
) -> dict:
    """Build the structured DNS result dict."""
    categories = {ip: classify_ip(ip) for ip in ordered}
    return {
        "hostname": hostname,
        "status": status,  # resolved | literal | timeout | error
        "resolution_ms": resolution_ms,
        "ipv4": [ip for ip in ordered if not _is_ipv6(ip)],
        "ipv6": [ip for ip in ordered if _is_ipv6(ip)],
        "addresses": ordered,  # deduplicated, in resolution order
        "address_count": len(ordered),
        "categories": categories,
        "has_private": any(is_private_or_local(ip) for ip in ordered),
        "all_private": bool(ordered) and all(
            is_private_or_local(ip) for ip in ordered
        ),
        "error": error,
    }


def inspect_hostname(hostname: str, timeout: float = DNS_TIMEOUT_SECONDS) -> dict:
    """Resolve and classify a hostname with a bounded worker thread.

    Never raises. Returns a dict with ``status`` of ``resolved``, ``literal``
    (no lookup performed), ``timeout``, or ``error``.
    """
    hostname = (hostname or "").strip().lower().rstrip(".")
    if not hostname:
        return _result(
            hostname,
            "error",
            0,
            [],
            {"type": "missing_hostname", "message": "No hostname to resolve"},
        )

    # Literal IPv4/IPv6 addresses are classified WITHOUT a DNS lookup.
    try:
        address = ipaddress.ip_address(hostname)
    except ValueError:
        pass
    else:
        ip = str(address)
        return _result(hostname, "literal", 0, [ip], None)

    holder: dict = {}

    def worker() -> None:
        try:
            holder["infos"] = socket.getaddrinfo(hostname, None)
        except socket.gaierror:
            holder["error"] = {"type": "resolution_failed", "message": "The hostname could not be resolved."}
        except socket.timeout:
            holder["error"] = {"type": "timeout", "message": "DNS resolution timed out."}
        except OSError:
            holder["error"] = {"type": "resolution_failed", "message": "Network error during resolution."}
        except Exception:  # defensive: DNS must never crash the API
            holder["error"] = {"type": "internal_error", "message": "An unexpected error occurred during DNS resolution."}

    thread = threading.Thread(target=worker, daemon=True)
    started = time.monotonic()
    thread.start()
    thread.join(timeout)
    resolution_ms = int((time.monotonic() - started) * 1000)

    if thread.is_alive():
        return _result(hostname, "timeout", resolution_ms, [], None)

    if "error" in holder:
        return _result(hostname, "error", resolution_ms, [], holder["error"])

    ordered: list[str] = []
    for info in holder["infos"]:
        ip = info[4][0]
        if ip not in ordered:
            ordered.append(ip)
    return _result(hostname, "resolved", resolution_ms, ordered, None)
