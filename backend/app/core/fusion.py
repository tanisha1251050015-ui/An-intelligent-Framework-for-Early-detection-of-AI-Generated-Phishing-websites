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

    if whois_data and whois_data.get("status") == "failed":
        if whois_data.get("reason") == "invalid_domain":
            all_reasoning.append("The domain is invalid.")
        else:
            all_reasoning.append("WHOIS data was unavailable for this domain.")

    if features.get("scheme") == "http":
        all_reasoning.append("The URL uses HTTP instead of HTTPS.")
        all_signals.append({
            "type": "insecure_protocol",
            "severity": "medium",
            "source": "features"
        })
        
    suspicious_keywords = features.get("suspicious_keywords") or []
    if suspicious_keywords:
        location_map = dict(features.get("suspicious_keyword_locations", ()))
        labels = {"hostname": "hostname", "path": "URL path", "query": "URL query", "fragment": "URL fragment"}
        
        AUTH_KWS = {"login", "log in", "signin", "sign in", "account", "verify", "verification", "authenticate", "password", "credential"}
        auth_kws = [kw for kw in suspicious_keywords if kw.lower() in AUTH_KWS]
        gen_kws = [kw for kw in suspicious_keywords if kw.lower() not in AUTH_KWS]
        
        if auth_kws:
            html = collection.get("html") or {}
            has_password = html.get("password_input_count", 0) > 0
            has_external_form = bool(html.get("external_form_actions", []))
            
            risk_score = 0
            if has_password:
                risk_score += 1
            if has_external_form:
                risk_score += 1
                
            if risk_score >= 2:
                severity = "high"
                sig_type = "suspicious_authentication_keywords"
            elif risk_score == 1:
                severity = "medium"
                sig_type = "suspicious_authentication_keywords"
            else:
                severity = "low"
                sig_type = "authentication_keywords"
                
            all_signals.append({
                "type": sig_type,
                "severity": severity,
                "source": "features"
            })
            
            located_auth = []
            for location in ("hostname", "path", "query", "fragment"):
                matched = [kw for kw in auth_kws if location_map.get(kw) == location]
                if matched:
                    located_auth.append(f"The {labels[location]} contains the authentication-related keyword '{', '.join(matched)}'")
                    
            auth_str = " and ".join(located_auth) if located_auth else f"The URL contains the authentication-related keyword '{', '.join(auth_kws)}'"
            
            if has_external_form and has_password:
                all_reasoning.append(f"{auth_str} and the page contains a credential form whose submission target is external to the inspected domain.")
            elif has_password:
                all_reasoning.append(f"{auth_str} and the page contains a password input.")
            else:
                all_reasoning.append(f"{auth_str}.")

        if gen_kws:
            located_gen = []
            for location in ("hostname", "path", "query", "fragment"):
                matched = [kw for kw in gen_kws if location_map.get(kw) == location]
                if matched:
                    located_gen.append(f"The {labels[location]} contains suspicious keyword(s): {', '.join(matched)}")
            
            gen_str = "; ".join(located_gen) if located_gen else f"The URL contains suspicious keyword(s): {', '.join(gen_kws)}."
            all_reasoning.append(gen_str)
            all_signals.append({
                "type": "suspicious_keywords",
                "severity": "low",
                "source": "features"
            })


    # -------------------------------------------------------------------------
    # Priority 5: HTML Semantic Evidence
    # -------------------------------------------------------------------------
    html = collection.get("html") or {}
    login_kw_count = html.get("login_keyword_count", 0)
    payment_kw_count = html.get("payment_keyword_count", 0)
    urgency_kw_count = html.get("urgency_keyword_count", 0)
    verification_kw_count = html.get("verification_keyword_count", 0)
    password_count = html.get("password_input_count", 0)
    credential_count = html.get("credential_input_count", 0)
    ext_form_count = html.get("external_form_action_count", 0)

    if login_kw_count > 0:
        if password_count > 0 and ext_form_count > 0:
            all_signals.append({
                "type": "html_authentication_context",
                "severity": "high",
                "source": "collection"
            })
            all_reasoning.append("The page contains authentication language, a password field, and an external form submission target.")
        elif password_count > 0:
            all_signals.append({
                "type": "html_authentication_context",
                "severity": "medium",
                "source": "collection"
            })
            all_reasoning.append("The page contains authentication-related language accompanied by a password field.")
        else:
            all_signals.append({
                "type": "html_authentication_context",
                "severity": "low",
                "source": "collection"
            })
            all_reasoning.append("The page contains authentication-related language, but no password or credential submission evidence was observed.")

    if payment_kw_count > 0:
        if credential_count > 0 and ext_form_count > 0:
            all_signals.append({
                "type": "html_payment_context",
                "severity": "high",
                "source": "collection"
            })
            all_reasoning.append("The page contains payment language, a credential input, and an external form submission target.")
        else:
            all_signals.append({
                "type": "html_payment_context",
                "severity": "low",
                "source": "collection"
            })
            all_reasoning.append("The page contains payment-related language.")

    if verification_kw_count > 0:
        if login_kw_count > 0 and password_count > 0:
            all_signals.append({
                "type": "html_verification_context",
                "severity": "medium",
                "source": "collection"
            })
            all_reasoning.append("The page contains identity verification language alongside a login and password field.")
        else:
            all_signals.append({
                "type": "html_verification_context",
                "severity": "low",
                "source": "collection"
            })
            all_reasoning.append("The page contains identity verification language.")

    if urgency_kw_count > 0:
        if verification_kw_count > 0 and credential_count > 0:
            all_signals.append({
                "type": "html_urgency_context",
                "severity": "medium",
                "source": "collection"
            })
            all_reasoning.append("The page contains urgency language combined with verification requests and a credential input.")
        else:
            all_signals.append({
                "type": "html_urgency_context",
                "severity": "low",
                "source": "collection"
            })
            all_reasoning.append("The page contains urgency language.")

    # -------------------------------------------------------------------------
    # Priority 5: OCR Semantic Evidence
    # -------------------------------------------------------------------------
    if ocr_data and ocr_data.get("status") == "completed":
        ocr_text = str(ocr_data.get("text", "")).lower()
        if any(kw in ocr_text for kw in ["login", "log in", "signin", "sign in", "username", "password"]):
            all_signals.append({
                "type": "ocr_authentication_context",
                "severity": "low",
                "source": "ocr"
            })
            all_reasoning.append("The screenshot OCR text contains authentication-related language.")

    if dns and dns.get("status") in ("error", "timeout"):
        all_signals.append({
            "type": "dns_resolution_failure",
            "severity": "medium",
            "source": "dns"
        })
        all_reasoning.append("The hostname could not be resolved, preventing webpage collection.")
        all_reasoning.append("Screenshot and OCR analysis were therefore not executed.")
        
    if llm_data and llm_data.get("status") == "unavailable":
        reason = llm_data.get("reason", "unknown error")
        if reason == "llm_not_configured":
            all_reasoning.append("LLM analysis was unavailable because no provider was configured.")
        else:
            all_reasoning.append(f"LLM analysis was unavailable ({reason}).")


    available_sources: list[str] = []
    failed_sources: list[str] = []
    missing_sources: list[str] = []

    if features:
        available_sources.append("features")
    else:
        missing_sources.append("features")

    def _categorize_source(src: dict | None, is_llm: bool = False) -> str:
        if not src:
            return "missing"
            
        st = src.get("status")
        
        if st in ("not_run", "not_configured", "not_applicable"):
            return "missing"
            
        if is_llm and st == "unavailable" and src.get("reason") in ("llm_not_configured", "not_configured"):
            return "missing"
            
        if st in ("error", "timeout", "blocked", "failed"):
            return "failed"
            
        if st == "unavailable":
            return "failed"
            
        return "available"

    for src_name, src_data, is_llm in [
        ("collection", collection, False),
        ("dns", dns, False),
        ("ssl", ssl_data, False),
        ("whois", whois_data, False),
        ("screenshot", screenshot_data, False),
        ("ocr", ocr_data, False),
        ("llm", llm_data, True),
    ]:
        category = _categorize_source(src_data, is_llm)
        if category == "available":
            available_sources.append(src_name)
        elif category == "failed":
            failed_sources.append(src_name)
        else:
            missing_sources.append(src_name)

    if domain_intelligence.get("signals"):
        available_sources.append("domain_intelligence")
    elif not domain_intelligence:
        missing_sources.append("domain_intelligence")

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

    if _categorize_source(llm_data, is_llm=True) == "available":
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
            "title": html.get("title", ""),
            "visible_text": html.get("visible_text", html.get("text", "")),
            "text_length": html.get("text_length", 0),
            "password_input_count": html.get("password_input_count", 0),
            "hidden_input_count": html.get("hidden_input_count", 0),
            "form_count": html.get("form_count", 0),
            "iframe_count": html.get("iframe_count", 0),
            "script_count": html.get("script_count", 0),
            "external_script_count": html.get("external_script_count", 0),
            "external_form_actions": html.get("external_form_actions", []),
            "external_form_domains": html.get("external_form_domains", []),
            "external_script_domains": html.get("external_script_domains", []),
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
    else:
        cls = classification or "unknown"
        sc = score if score is not None else 0
        
        summary_parts = [f"The URL is classified as {cls} with a deterministic Phase 1 score of {sc}/100."]
        
        auth_kws_signal = next((s for s in all_signals if s["type"] in ("suspicious_authentication_keywords", "authentication_keywords")), None)
        html_auth_signal = next((s for s in all_signals if s["type"] == "html_authentication_context"), None)
        
        has_high_auth = any(s["severity"] == "high" for s in all_signals if s["type"] in ("suspicious_authentication_keywords", "html_authentication_context"))
        
        if has_high_auth:
            summary_parts.append("The collected page contains authentication language, credential inputs, and an external form submission target, providing strong evidence of potential credential harvesting.")
        elif auth_kws_signal or html_auth_signal:
            severity = "low"
            if (auth_kws_signal and auth_kws_signal.get("severity") == "medium") or (html_auth_signal and html_auth_signal.get("severity") == "medium"):
                severity = "medium"
                
            html = (collection or {}).get("html", {})
            has_password = html.get("password_input_count", 0) > 0
            has_external_form = bool(html.get("external_form_actions", []))
            
            if auth_kws_signal and not html_auth_signal:
                part = f"The URL components contribute a {severity}-risk authentication keyword signal"
            elif html_auth_signal and not auth_kws_signal:
                part = f"The page content contributes a {severity}-risk authentication keyword signal"
            else:
                part = f"The URL and page content contribute a {severity}-risk authentication keyword signal"

            if not has_password and not has_external_form:
                part += ", but the collected page does not contain a password input or credential form."
            elif has_password and not has_external_form:
                part += ", and the collected page contains a password input."
            elif has_password and has_external_form:
                part += ", and the collected page contains a credential form whose submission target is external."
            else:
                part += "."
            summary_parts.append(part)
            
        if any(s["type"] == "suspicious_keywords" for s in all_signals):
            summary_parts.append("The URL components contain general suspicious keywords.")
            
        if features.get("scheme") == "http":
            summary_parts.append("The URL uses HTTP instead of HTTPS.")
            
        if dns and dns.get("status") in ("error", "timeout"):
            summary_parts.append("DNS resolution failed, preventing webpage, screenshot and OCR analysis.")
        elif collection and collection.get("status") in ("error", "blocked"):
            summary_parts.append(f"Webpage collection was {collection.get('status')} ({collection.get('reason', 'unknown')}).")
            
        summary = " ".join(summary_parts)

    return {
        "status": status,
        "signals": all_signals,
        "risk_hints": all_risk_hints,
        "reasoning": all_reasoning,
        "evidence": evidence,
        "available_sources": available_sources,
        "failed_sources": failed_sources,
        "missing_sources": missing_sources,
        "summary": summary,
    }
