"""Rule-based intelligence fusion engine (Phase 2C).

Combines all intelligence sources into a structured summary. Rule-based only —
no ML, no LLM, no SHAP. The fusion result NEVER overwrites or alters the
existing Phase 1 score/classification; Phase 1 remains authoritative.
"""

from __future__ import annotations

from typing import Any


def fuse_intelligence(
    *,
    score: int | None = None,
    classification: str | None = None,
    features: dict[str, Any] | None = None,
    collection: dict[str, Any] | None = None,
    dns: dict[str, Any] | None = None,
    ssl_data: dict[str, Any] | None = None,
    whois_data: dict[str, Any] | None = None,
    screenshot_data: dict[str, Any] | None = None,
    ocr_data: dict[str, Any] | None = None,
    domain_intelligence: dict[str, Any] | None = None,
    llm_data: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Fuse all intelligence sources into a structured summary.

    Returns a dict with:

    - ``status`` — overall intelligence status
    - ``signals`` — aggregated signal list
    - ``risk_hints`` — aggregated risk hints (as structured dicts)
    - ``reasoning`` — combined reasoning
    - ``evidence`` — per-source evidence summary
    - ``available_sources`` — which sources produced data
    - ``missing_sources`` — which sources are unavailable or not configured
    - ``summary`` — advisory summary (e.g. from LLM)

    Phase 1 score and classification are NEVER modified.
    """
    features = features or {}
    collection = collection or {}
    dns = dns or {}
    ssl_data = ssl_data or {}
    whois_data = whois_data or {}
    screenshot_data = screenshot_data or {}
    ocr_data = ocr_data or {}
    domain_intelligence = domain_intelligence or {}
    llm_data = llm_data or {}

    # Aggregate signals, hints, and reasoning from all sources
    all_signals: list[dict[str, str]] = []
    all_risk_hints: list[dict[str, Any]] = []
    all_reasoning: list[str] = []

    # Domain intelligence provides the most signals
    all_signals.extend(domain_intelligence.get("signals", []))
    for hint_str in domain_intelligence.get("risk_hints", []):
        all_risk_hints.append({
            "source": "domain_intelligence",
            "type": "informational",
            "confidence": 1.0,
            "evidence": hint_str
        })
    all_reasoning.extend(domain_intelligence.get("reasoning", []))

    # Add collection status reasoning if blocked
    if collection.get("status") == "blocked":
        all_reasoning.append(
            f"Collection was blocked: {collection.get('reason', 'unknown')}"
        )
    elif collection.get("status") == "error":
        all_reasoning.append(
            f"Collection failed: {collection.get('reason', 'unknown')}"
        )

    # Add DNS status reasoning if present
    if dns.get("status") == "timeout":
        all_reasoning.append(
            f"DNS resolution timed out after {dns.get('resolution_ms', '?')}ms."
        )
    elif dns.get("status") == "error":
        error_info = dns.get("error") or {}
        all_reasoning.append(
            f"DNS resolution failed: {error_info.get('message', 'unknown error')}"
        )

    # Determine available and missing sources
    available_sources: list[str] = []
    missing_sources: list[str] = []

    if features:
        available_sources.append("features")
    else:
        missing_sources.append("features")

    if collection and collection.get("status") == "collected":
        available_sources.append("collection")
    else:
        missing_sources.append("collection")

    if dns and dns.get("status") in ("resolved", "literal"):
        available_sources.append("dns")
    else:
        missing_sources.append("dns")

    if ssl_data and ssl_data.get("status") == "collected":
        available_sources.append("ssl")
    else:
        missing_sources.append("ssl")

    if whois_data and whois_data.get("status") == "collected":
        available_sources.append("whois")
    else:
        missing_sources.append("whois")

    if screenshot_data and screenshot_data.get("status") == "collected":
        available_sources.append("screenshot")
    else:
        missing_sources.append("screenshot")

    if ocr_data and ocr_data.get("status") == "completed":
        available_sources.append("ocr")
    else:
        missing_sources.append("ocr")

    if domain_intelligence.get("signals"):
        available_sources.append("domain_intelligence")

    if whois_data and whois_data.get("risk_hints"):
        import math
        for hint in whois_data.get("risk_hints", []):
            if not isinstance(hint, dict):
                continue
            conf = hint.get("confidence")
            if not isinstance(conf, (int, float)) or isinstance(conf, bool) or not math.isfinite(conf) or conf < 0.0 or conf > 1.0:
                conf = 1.0
            all_risk_hints.append({
                "source": "whois",
                "type": str(hint.get("type", "unknown"))[:100],
                "confidence": float(conf),
                "evidence": str(hint.get("evidence", ""))[:1000]
            })

    if llm_data and llm_data.get("status") == "completed":
        available_sources.append("llm")
        import math
        for hint in llm_data.get("risk_hints", []):
            if not isinstance(hint, dict):
                continue
            conf = hint.get("confidence")
            if not isinstance(conf, (int, float)) or isinstance(conf, bool) or not math.isfinite(conf) or conf < 0.0 or conf > 1.0:
                continue
            all_risk_hints.append({
                "source": "llm",
                "type": str(hint.get("type", "unknown"))[:100],
                "confidence": float(conf),
                "evidence": str(hint.get("evidence", ""))[:1000]
            })
    elif llm_data:
        missing_sources.append("llm")

    # Determine overall intelligence status
    high_severity = any(s.get("severity") == "high" for s in all_signals)
    medium_severity = any(s.get("severity") == "medium" for s in all_signals)

    if high_severity:
        status = "elevated_risk"
    elif medium_severity:
        status = "moderate_risk"
    elif all_signals:
        status = "low_risk"
    else:
        status = "informational"

    # Build evidence summary
    evidence: dict[str, Any] = {}
    if ssl_data:
        evidence["ssl"] = {
            "status": ssl_data.get("status"),
            "issuer": ssl_data.get("issuer"),
            "is_expired": ssl_data.get("is_expired"),
            "is_self_signed": ssl_data.get("is_self_signed"),
            "hostname_match": ssl_data.get("hostname_match"),
            "cert_age_days": ssl_data.get("cert_age_days"),
        }
    if dns:
        evidence["dns"] = {
            "status": dns.get("status"),
            "has_private": dns.get("has_private"),
            "address_count": dns.get("address_count"),
        }
    if collection and collection.get("status") == "collected":
        html = collection.get("html") or {}
        evidence["collection"] = {
            "http_status": collection.get("http_status"),
            "password_input_count": html.get("password_input_count", 0),
            "form_count": html.get("form_count", 0),
        }
    if whois_data:
        evidence["whois"] = {
            "status": whois_data.get("status"),
            "registrar": whois_data.get("registrar"),
            "domain_age_days": whois_data.get("domain_age_days"),
            "days_until_expiration": whois_data.get("days_until_expiration"),
        }
    if screenshot_data:
        evidence["screenshot"] = {"status": screenshot_data.get("status")}
    if ocr_data:
        evidence["ocr"] = {"status": ocr_data.get("status")}
    if llm_data:
        evidence["llm"] = {"status": llm_data.get("status")}

    summary = ""
    if llm_data and llm_data.get("summary"):
        summary = str(llm_data.get("summary"))[:2000]

    return {
        "status": status,
        "signals": all_signals,
        "risk_hints": all_risk_hints,
        "reasoning": all_reasoning,
        "evidence": evidence,
        "available_sources": available_sources,
        "missing_sources": missing_sources,
        "summary": summary,
    }
