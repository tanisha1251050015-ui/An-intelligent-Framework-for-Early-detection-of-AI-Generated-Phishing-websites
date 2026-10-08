"""WHOIS intelligence component (Phase 3 Step 1).

Provides a secure, bounded WHOIS intelligence gathering interface.
Enforces SSRF protections and applies rigorous bounds to all parsed
data to prevent memory exhaustion. Extracts advisory risk signals.
"""

from __future__ import annotations

import os
import threading
from datetime import datetime, timezone
from typing import Any

import whois

from app.collection.ssrf import check_target

WHOIS_TIMEOUT_SECONDS: float = float(os.environ.get("WHOIS_TIMEOUT_SECONDS", "5.0"))
MAX_STRING_LENGTH = 255
MAX_LIST_LENGTH = 10


def query_whois(hostname: str, timeout: float = WHOIS_TIMEOUT_SECONDS) -> dict:
    """Query WHOIS information for a hostname securely.

    Validates the target via SSRF protections, runs the lookup on a bounded
    worker thread, strictly bounds the returned data, and generates advisory
    risk hints without altering Phase 1 scoring.
    """
    hostname = (hostname or "").strip().lower().rstrip(".")
    registrable_domain = _extract_registrable_domain_candidate(hostname)

    if not registrable_domain:
        return {
            "status": "failed",
            "reason": "invalid_domain",
            "hostname": hostname,
            "registrable_domain_candidate": None,
        }

    # SSRF Protection: ensure the derived registrable domain resolves to a safe target
    target = check_target(f"http://{registrable_domain}")
    if not target.allowed:
        return {
            "status": "failed",
            "reason": target.reason,
            "hostname": hostname,
            "registrable_domain_candidate": registrable_domain,
        }

    holder: dict = {}

    def worker() -> None:
        try:
            w = whois.whois(registrable_domain)
            
            # Bound and extract fields securely
            creation_date_obj = _parse_date(getattr(w, "creation_date", None))
            expiration_date_obj = _parse_date(getattr(w, "expiration_date", None))
            
            holder["data"] = {
                "registrar": _bound_str(getattr(w, "registrar", None)),
                "creation_date": creation_date_obj.isoformat() if creation_date_obj else None,
                "expiration_date": expiration_date_obj.isoformat() if expiration_date_obj else None,
                "updated_date": _format_date(getattr(w, "updated_date", None)),
                "nameservers": _bound_list(getattr(w, "name_servers", None)),
                "domain_status": _bound_list(getattr(w, "status", None)),
                "country": _bound_str(getattr(w, "country", None)),
                "org": _bound_str(getattr(w, "org", None)),
            }
            
            # Derived Intelligence
            risk_hints = []
            
            domain_age_days = None
            if creation_date_obj:
                now = datetime.now(timezone.utc)
                # Ensure creation date is naive or aware uniformly for calculation
                # creation_date_obj is forced naive in _parse_date for safe math
                age_delta = datetime.utcnow() - creation_date_obj
                domain_age_days = age_delta.days
                holder["data"]["domain_age_days"] = domain_age_days
                
                if domain_age_days < 30:
                    risk_hints.append({
                        "type": "newly_registered_domain",
                        "confidence": 1.0,
                        "evidence": f"Domain is less than 30 days old (age: {domain_age_days} days)"
                    })
            else:
                risk_hints.append({
                    "type": "missing_creation_date",
                    "confidence": 0.5,
                    "evidence": "WHOIS response missing creation date"
                })

            days_until_expiration = None
            if expiration_date_obj:
                exp_delta = expiration_date_obj - datetime.utcnow()
                days_until_expiration = exp_delta.days
                holder["data"]["days_until_expiration"] = days_until_expiration
                
                if days_until_expiration < 14:
                    risk_hints.append({
                        "type": "expiring_soon",
                        "confidence": 1.0,
                        "evidence": f"Domain expires in {max(0, days_until_expiration)} days"
                    })
            else:
                risk_hints.append({
                    "type": "missing_expiration_date",
                    "confidence": 0.5,
                    "evidence": "WHOIS response missing expiration date"
                })
                
            registrar_val = holder["data"]["registrar"]
            if not registrar_val or str(registrar_val).strip() == "":
                risk_hints.append({
                    "type": "missing_registrar",
                    "confidence": 0.8,
                    "evidence": "WHOIS response is missing registrar information"
                })
                
            ns_val = holder["data"]["nameservers"]
            if not ns_val or len(ns_val) == 0:
                risk_hints.append({
                    "type": "missing_nameservers",
                    "confidence": 0.8,
                    "evidence": "WHOIS response contains no nameserver records"
                })
                
            holder["data"]["risk_hints"] = risk_hints

        except Exception as exc:
            # We don't expose raw exception details
            holder["error"] = "lookup_failed"

    thread = threading.Thread(target=worker, daemon=True)
    thread.start()
    thread.join(timeout)

    if thread.is_alive():
        return {
            "status": "failed",
            "reason": "timeout",
            "hostname": hostname,
            "registrable_domain_candidate": registrable_domain,
        }

    if "error" in holder:
        return {
            "status": "failed",
            "reason": "lookup_failed",
            "hostname": hostname,
            "registrable_domain_candidate": registrable_domain,
        }

    data = holder.get("data", {})
    return {
        "status": "success",
        "hostname": hostname,
        "registrable_domain_candidate": registrable_domain,
        **data,
    }


def _bound_str(val: Any) -> str | None:
    """Safely cast to string and bound the length."""
    if val is None:
        return None
    s = str(val).strip()
    return s[:MAX_STRING_LENGTH]


def _bound_list(val: Any) -> list[str]:
    """Safely extract a bounded list of bounded strings."""
    if not val:
        return []
    if not isinstance(val, list):
        val = [val]
    
    result = []
    for item in val[:MAX_LIST_LENGTH]:
        s = _bound_str(item)
        if s:
            result.append(s)
    return result


def _parse_date(val: Any) -> datetime | None:
    """Parse WHOIS date to a naive datetime safely."""
    if not val:
        return None
    if isinstance(val, list):
        val = val[0]
    try:
        if isinstance(val, datetime):
            # Strip timezone for safe subtraction with utcnow
            return val.replace(tzinfo=None)
        # Attempt to parse common string if needed (python-whois usually returns datetime)
        # We rely on python-whois object types mostly.
        return None
    except Exception:
        return None


def _format_date(val: Any) -> str | None:
    """Format WHOIS date to ISO string safely."""
    dt = _parse_date(val)
    return dt.isoformat() if dt else None


def _extract_registrable_domain_candidate(hostname: str) -> str | None:
    """Best-effort extraction of a registrable domain from a hostname."""
    if not hostname:
        return None

    import ipaddress
    try:
        ipaddress.ip_address(hostname)
        return None
    except ValueError:
        pass

    if hostname.startswith("[") and hostname.endswith("]"):
        return None

    parts = hostname.split(".")
    if len(parts) < 2:
        return None

    return ".".join(parts[-2:])
