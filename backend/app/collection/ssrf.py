"""SSRF protection.

Every collection target is validated BEFORE any connection is attempted.
Private, loopback, link-local, reserved, multicast, unspecified, CGNAT, and
documentation address ranges are always rejected, as are "localhost" hostnames
and any hostname whose DNS resolution yields even a single blocked address.
"""

from __future__ import annotations

import ipaddress
import socket
from dataclasses import dataclass
from urllib.parse import urlsplit

# Ranges not covered by the ipaddress convenience attributes that must never be
# contacted: CGNAT/shared space, IETF assignments, TEST-NETs, benchmarking, and
# documentation ranges.
_EXTRA_BLOCKED_NETWORKS: tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, ...] = (
    ipaddress.ip_network("100.64.0.0/10"),    # CGNAT / shared address space
    ipaddress.ip_network("192.0.0.0/24"),     # IETF protocol assignments
    ipaddress.ip_network("192.0.2.0/24"),     # TEST-NET-1
    ipaddress.ip_network("198.18.0.0/15"),    # benchmarking
    ipaddress.ip_network("198.51.100.0/24"),  # TEST-NET-2
    ipaddress.ip_network("203.0.113.0/24"),   # TEST-NET-3
    ipaddress.ip_network("255.255.255.255/32"),
    ipaddress.ip_network("2001:db8::/32"),    # documentation
)


def is_blocked_ip(ip: str) -> bool:
    """Return True when an IP string is private, local, reserved, or unparseable."""
    try:
        address = ipaddress.ip_address(ip)
    except ValueError:
        return True  # unparseable addresses are treated as unsafe

    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped:
        address = address.ipv4_mapped

    return (
        address.is_private
        or address.is_loopback
        or address.is_link_local
        or address.is_reserved
        or address.is_multicast
        or address.is_unspecified
        or any(address in network for network in _EXTRA_BLOCKED_NETWORKS)
    )


def is_literal_ip(hostname: str) -> bool:
    """Return True when the hostname is a literal IPv4/IPv6 address."""
    try:
        ipaddress.ip_address(hostname)
        return True
    except ValueError:
        return False


@dataclass(frozen=True)
class TargetCheck:
    """Result of validating a collection target before any connection."""

    allowed: bool
    status: str = ""   # "blocked" | "error" | "" (allowed)
    reason: str = ""


def check_target(raw_url: str) -> TargetCheck:
    """Validate a URL for collection.

    Returns ``allowed=True`` only for public http/https targets. Otherwise
    returns ``allowed=False`` with a structured ``status``/``reason`` so the
    caller can report e.g. ``{"status": "blocked", "reason": "private_or_local_target"}``.
    """
    parts = urlsplit(raw_url.strip())

    if parts.scheme.lower() not in ("http", "https"):
        return TargetCheck(allowed=False, status="blocked", reason="unsupported_scheme")

    hostname = (parts.hostname or "").lower().rstrip(".")
    if not hostname:
        return TargetCheck(allowed=False, status="blocked", reason="missing_hostname")

    # IP literals are checked directly, before any connection.
    if is_literal_ip(hostname):
        if is_blocked_ip(hostname):
            return TargetCheck(
                allowed=False, status="blocked", reason="private_or_local_target"
            )
        return TargetCheck(allowed=True)

    # Block obvious local names without DNS.
    if hostname == "localhost" or hostname.endswith(".localhost"):
        return TargetCheck(
            allowed=False, status="blocked", reason="private_or_local_target"
        )

    # Resolve and reject if ANY resolved address is private/local/reserved.
    try:
        infos = socket.getaddrinfo(hostname, None)
    except socket.gaierror:
        return TargetCheck(allowed=False, status="error", reason="dns_resolution_failed")

    for info in infos:
        address = info[4][0]
        if is_blocked_ip(address):
            return TargetCheck(
                allowed=False, status="blocked", reason="private_or_local_target"
            )

    return TargetCheck(allowed=True)
