"""Safe HTTP/HTML collection layer (Phase 2A).

Collects limited, bounded HTTP/HTML metadata for eligible URLs. Never executes
JavaScript, never runs browser automation, never crawls, and never contacts
private/local/reserved targets (SSRF protection runs before any connection).
"""

from app.collection.collector import collect
from app.collection.ssrf import check_target, is_blocked_ip

__all__ = ["check_target", "collect", "is_blocked_ip"]
