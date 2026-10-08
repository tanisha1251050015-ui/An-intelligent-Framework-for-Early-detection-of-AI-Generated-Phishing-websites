"""Priority 7: Explainability & Analyst Evidence Layer."""

from __future__ import annotations
from typing import Any

def _get_title_and_description(sig_type: str, severity: str) -> tuple[str, str]:
    mapping = {
        "suspicious_authentication_keywords": (
            "Authentication keyword in URL",
            "The URL contains keywords strongly associated with authentication or login flows."
        ),
        "authentication_keywords": (
            "Authentication keyword in URL",
            "The URL contains keywords associated with login flows."
        ),
        "suspicious_keywords": (
            "Suspicious URL keywords",
            "The URL contains general suspicious keywords commonly found in phishing."
        ),
        "insecure_protocol": (
            "Insecure HTTP Protocol",
            "The URL uses unencrypted HTTP rather than HTTPS."
        ),
        "html_authentication_context": (
            "HTML Authentication Context",
            "The page contains authentication-related visible text, and optionally a password field or external form."
        ),
        "html_payment_context": (
            "HTML Payment Context",
            "The page contains payment-related visible text."
        ),
        "html_verification_context": (
            "HTML Verification Context",
            "The page contains identity verification language."
        ),
        "html_urgency_context": (
            "HTML Urgency Context",
            "The page contains urgency language."
        ),
        "ocr_authentication_context": (
            "OCR Authentication Context",
            "The screenshot text contains authentication language."
        ),
        "dns_resolution_failure": (
            "DNS Resolution Failed",
            "The domain could not be resolved to an IP address."
        ),
        "suspicious_tld": (
            "Suspicious TLD",
            "The domain uses a Top-Level Domain frequently associated with abuse."
        ),
        "ip_hostname": (
            "IP Address Hostname",
            "The URL uses a raw IP address instead of a domain name."
        ),
        "excessive_subdomains": (
            "Excessive Subdomains",
            "The URL has an unusually high number of subdomains."
        )
    }
    title, desc = mapping.get(sig_type, (sig_type.replace("_", " ").title(), "Relevant risk indicator detected."))
    return title, desc

def build_evidence(fusion: dict[str, Any], campaign: dict[str, Any] | None) -> tuple[list, list, list]:
    risk_evidence = []
    contextual_evidence = []
    benign_evidence = []
    
    seen_types = set()
    
    # Process fusion signals
    signals = fusion.get("signals", [])
    for sig in signals:
        stype = sig.get("type", "")
        if stype in seen_types:
            continue
        seen_types.add(stype)
        
        severity = sig.get("severity", "low")
        title, desc = _get_title_and_description(stype, severity)
        
        item = {
            "source": sig.get("source", "unknown"),
            "type": stype,
            "severity": severity,
            "title": title,
            "description": desc
        }
        
        if severity in ("high", "medium", "low"):
            risk_evidence.append(item)
        else:
            contextual_evidence.append(item)
            
    # Process risk_hints into contextual_evidence
    for hint in fusion.get("risk_hints", []):
        contextual_evidence.append({
            "source": hint.get("source", "unknown"),
            "type": hint.get("type", "informational"),
            "severity": "informational",
            "title": "Contextual Hint",
            "description": hint.get("evidence", "")
        })
            
    # Process campaign relationships
    if campaign and campaign.get("status") in ("potential_campaign", "strong_campaign_correlation"):
        for rel in campaign.get("relationships", []):
            stype = rel.get("type", "")
            severity = "high" if rel.get("strength") == "strong" else "medium"
            if stype == "SHARED_REGISTRAR":
                severity = "low"
                
            risk_evidence.append({
                "source": "campaign",
                "type": stype,
                "severity": severity,
                "title": f"Campaign Correlation: {stype.replace('_', ' ').title()}",
                "description": rel.get("evidence", "Shared infrastructure detected.")
            })
            
    # Add benign evidence based on missing risk indicators
    # We do NOT fabricate "safe" claims, but note absent elements.
    html_auth = next((s for s in signals if s.get("type") == "html_authentication_context"), None)
    if not html_auth:
        benign_evidence.append({
            "source": "collection",
            "type": "no_authentication_context",
            "severity": "low",
            "title": "No Authentication Context",
            "description": "No visible authentication inputs or language were observed in the HTML."
        })
        
    if campaign and campaign.get("status") == "no_correlation":
        benign_evidence.append({
            "source": "campaign",
            "type": "no_campaign_correlation",
            "severity": "low",
            "title": "No Campaign Relationships",
            "description": "No infrastructure relationship with previously analyzed domains was identified."
        })
        
    return risk_evidence, contextual_evidence, benign_evidence

def build_confidence(risk_level: str, risk_evidence: list, campaign: dict[str, Any] | None) -> str:
    """Calculate categorical confidence based on evidence."""
    # Strong confidence if we have high severity items or multiple medium severity items
    high_count = sum(1 for e in risk_evidence if e["severity"] == "high")
    med_count = sum(1 for e in risk_evidence if e["severity"] == "medium")
    
    if high_count > 0 or med_count >= 2:
        return "high"
    if med_count == 1 or risk_level == "moderate_risk":
        return "medium"
    return "low"

def build_analyst_summary(risk_level: str, risk_evidence: list, campaign: dict[str, Any] | None) -> str:
    """Generate a concise deterministic analyst summary."""
    parts = []
    
    if risk_level == "elevated_risk":
        parts.append("Strong credential-harvesting or phishing indicators were observed.")
    elif risk_level == "moderate_risk":
        parts.append("Multiple phishing indicators were observed, suggesting moderate phishing risk.")
    else:
        parts.append("Limited or contextual phishing indicators were observed, resulting in low intelligence risk.")
        
    has_auth_url = any("authentication_keyword" in e["type"] for e in risk_evidence)
    has_html_auth = any(e["type"] == "html_authentication_context" for e in risk_evidence)
    
    if has_auth_url and has_html_auth:
        parts.append("The URL and page content both contain authentication-related elements.")
    elif has_auth_url:
        parts.append("The URL contains authentication-related keywords.")
    elif has_html_auth:
        parts.append("The page content contains authentication-related elements.")
        
    if campaign and campaign.get("status") in ("potential_campaign", "strong_campaign_correlation"):
        parts.append("The domain shows infrastructure relationships with previously analyzed domains, indicating a potential campaign relationship.")
        
    return " ".join(parts)

def build_explanation(fusion: dict[str, Any], campaign: dict[str, Any] | None) -> dict[str, Any]:
    """Build the final explainable intelligence layer response."""
    risk_evidence, contextual_evidence, benign_evidence = build_evidence(fusion, campaign)
    
    risk_level = fusion.get("status", "informational")
    confidence = build_confidence(risk_level, risk_evidence, campaign)
    analyst_summary = build_analyst_summary(risk_level, risk_evidence, campaign)
    
    return {
        "status": risk_level, # backwards compatibility for anything checking 'status' directly
        "risk_level": risk_level,
        "confidence": confidence,
        "summary": analyst_summary,
        
        "risk_evidence": risk_evidence,
        "contextual_evidence": contextual_evidence,
        "benign_evidence": benign_evidence,
        
        "source_status": {
            "available": fusion.get("available_sources", []),
            "failed": fusion.get("failed_sources", []),
            "missing": fusion.get("missing_sources", [])
        },
        
        "campaign": campaign or {
            "status": "no_correlation",
            "confidence": 0,
            "related_domains": [],
            "relationships": []
        }
    }
