"""Tests for Priority 7: Explainability & Analyst Evidence."""

import pytest
from app.core.fusion import fuse_intelligence
from app.core.explainability import build_explanation

def test_p7_safe_domain():
    """TEST 1: Safe example domain."""
    fusion = fuse_intelligence(
        score=10, classification="Safe",
        features={"scheme": "https", "hostname": "example.com"}
    )
    res = build_explanation(fusion, None)
    
    assert res["status"] in ("informational", "low_risk")
    assert res["summary"]
    # Check no fabricated evidence
    assert not any(e["type"] == "dns_resolution_failure" for e in res["risk_evidence"])
    # Phase 1 properties shouldn't be touched by explainability (fusion handles inputs, res just wraps fusion output)
    
def test_p7_login_only():
    """TEST 2: URL containing login only."""
    fusion = fuse_intelligence(
        features={"scheme": "https", "hostname": "example.com", "suspicious_keywords": ["login"], "suspicious_keyword_locations": [["login", "path"]]}
    )
    res = build_explanation(fusion, None)
    
    auth_ev = [e for e in res["risk_evidence"] if e["type"] in ("authentication_keywords", "suspicious_authentication_keywords")]
    assert len(auth_ev) == 1
    assert auth_ev[0]["severity"] == "low"
    assert "credential-harvesting" not in res["summary"].lower()

def test_p7_login_and_password():
    """TEST 3: Login + password input."""
    fusion = fuse_intelligence(
        features={"scheme": "https", "hostname": "example.com", "suspicious_keywords": ["login"], "suspicious_keyword_locations": [["login", "path"]]},
        collection={"status": "collected", "html": {"password_input_count": 1, "login_keyword_count": 1}}
    )
    res = build_explanation(fusion, None)
    
    assert res["status"] == "moderate_risk"
    assert "moderate phishing risk" in res["summary"].lower()
    
    # URL auth evidence
    url_ev = [e for e in res["risk_evidence"] if "authentication_keyword" in e["type"]]
    assert len(url_ev) == 1
    
    # HTML auth evidence
    html_ev = [e for e in res["risk_evidence"] if e["type"] == "html_authentication_context"]
    assert len(html_ev) == 1
    assert html_ev[0]["severity"] == "medium"

def test_p7_login_password_external():
    """TEST 4: Login + password + external form."""
    fusion = fuse_intelligence(
        features={"scheme": "https", "hostname": "example.com", "suspicious_keywords": ["login"], "suspicious_keyword_locations": [["login", "path"]]},
        collection={"status": "collected", "html": {"password_input_count": 1, "login_keyword_count": 1, "external_form_action_count": 1, "external_form_actions": ["http://evil.com/login"]}}
    )
    res = build_explanation(fusion, None)
    
    assert res["status"] == "elevated_risk"
    assert res["risk_level"] == "elevated_risk"
    assert "credential-harvesting" in res["summary"].lower()
    
    html_ev = [e for e in res["risk_evidence"] if e["type"] == "html_authentication_context"]
    assert html_ev[0]["severity"] == "high"

def test_p7_whois_failure():
    """TEST 5: WHOIS failure."""
    fusion = fuse_intelligence(
        whois_data={"status": "failed"}
    )
    res = build_explanation(fusion, None)
    assert "whois" in res["source_status"]["failed"]
    # Ensure no fabricated WHOIS risk evidence exists
    assert not any("whois" in e["source"] for e in res["risk_evidence"])

def test_p7_llm_unavailable():
    """TEST 6: LLM unavailable."""
    fusion = fuse_intelligence(
        llm_data={"status": "unavailable", "reason": "llm_not_configured"}
    )
    res = build_explanation(fusion, None)
    assert "llm" in res["source_status"]["missing"]
    assert not any("llm" in e["source"] for e in res["risk_evidence"])

def test_p7_dns_failure():
    """TEST 7: DNS failure."""
    fusion = fuse_intelligence(
        dns={"status": "error"}
    )
    res = build_explanation(fusion, None)
    assert "dns" in res["source_status"]["failed"]
    assert any(e["type"] == "dns_resolution_failure" for e in res["risk_evidence"])

def test_p7_campaign_relationship():
    """TEST 8: Campaign relationship."""
    campaign = {
        "status": "potential_campaign",
        "relationships": [
            {"type": "SHARED_IP", "strength": "medium"}
        ]
    }
    fusion = fuse_intelligence()
    res = build_explanation(fusion, campaign)
    
    assert res["campaign"]["status"] == "potential_campaign"
    camp_ev = [e for e in res["risk_evidence"] if e["source"] == "campaign"]
    assert len(camp_ev) == 1
    assert camp_ev[0]["type"] == "SHARED_IP"
    assert "potential campaign relationship" in res["summary"].lower()

def test_p7_no_campaign_relationship():
    """TEST 9: No campaign relationship."""
    campaign = {
        "status": "no_correlation"
    }
    fusion = fuse_intelligence()
    res = build_explanation(fusion, campaign)
    
    assert res["campaign"]["status"] == "no_correlation"
    assert not any(e["source"] == "campaign" for e in res["risk_evidence"])
    assert any(e["type"] == "no_campaign_correlation" for e in res["benign_evidence"])

def test_p7_evidence_deduplication():
    """TEST 10: Evidence deduplication."""
    # Ensure a single signal type produces only 1 output evidence
    fusion = fuse_intelligence(
        features={"scheme": "http", "suspicious_keywords": ["login", "account", "verify"], "suspicious_keyword_locations": [["login", "path"], ["account", "path"], ["verify", "path"]]}
    )
    res = build_explanation(fusion, None)
    
    auth_kws = [e for e in res["risk_evidence"] if e["type"] in ("authentication_keywords", "suspicious_authentication_keywords")]
    assert len(auth_kws) == 1

def test_p7_phase1_isolation():
    """TEST 11: Phase 1 isolation."""
    # Build explanation doesn't take score/classification as mutable references,
    # ensuring it's strictly a presentation layer.
    fusion = fuse_intelligence(score=99, classification="Phishing")
    res = build_explanation(fusion, None)
    # The dictionary doesn't even contain score! It's completely isolated.
    assert "score" not in res
