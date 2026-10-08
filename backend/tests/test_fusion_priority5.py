"""Tests for intelligence fusion semantic weighting (Priority 5)."""

from app.core.fusion import fuse_intelligence

def test_p5_login_keyword_only():
    """Test 1 — Login keyword only -> low."""
    res = fuse_intelligence(
        score=10,
        classification="safe",
        collection={"status": "collected", "html": {"login_keyword_count": 1, "password_input_count": 0, "external_form_action_count": 0}}
    )
    sig = next(s for s in res["signals"] if s["type"] == "html_authentication_context")
    assert sig["severity"] == "low"
    assert "but no password or credential submission evidence was observed" in res["reasoning"][-1]
    assert res["status"] == "low_risk"

def test_p5_login_plus_password():
    """Test 2 — Login + password -> medium."""
    res = fuse_intelligence(
        collection={"status": "collected", "html": {"login_keyword_count": 1, "password_input_count": 1, "external_form_action_count": 0}}
    )
    sig = next(s for s in res["signals"] if s["type"] == "html_authentication_context")
    assert sig["severity"] == "medium"
    assert res["status"] == "moderate_risk"

def test_p5_login_password_external_form():
    """Test 3 — Login + password + external form -> high."""
    res = fuse_intelligence(
        collection={"status": "collected", "html": {"login_keyword_count": 1, "password_input_count": 1, "external_form_action_count": 1}}
    )
    sig = next(s for s in res["signals"] if s["type"] == "html_authentication_context")
    assert sig["severity"] == "high"
    assert res["status"] == "elevated_risk"

def test_p5_payment_language_only():
    """Test 4 — Payment language only -> low."""
    res = fuse_intelligence(
        collection={"status": "collected", "html": {"payment_keyword_count": 1, "credential_input_count": 0, "external_form_action_count": 0}}
    )
    sig = next(s for s in res["signals"] if s["type"] == "html_payment_context")
    assert sig["severity"] == "low"
    assert res["status"] == "low_risk"

def test_p5_verification_only():
    """Test 5 — Verification only -> low."""
    res = fuse_intelligence(
        collection={"status": "collected", "html": {"verification_keyword_count": 1}}
    )
    sig = next(s for s in res["signals"] if s["type"] == "html_verification_context")
    assert sig["severity"] == "low"

def test_p5_urgency_only():
    """Test 6 — Urgency only -> low."""
    res = fuse_intelligence(
        collection={"status": "collected", "html": {"urgency_keyword_count": 1}}
    )
    sig = next(s for s in res["signals"] if s["type"] == "html_urgency_context")
    assert sig["severity"] == "low"

def test_p5_legitimate_login_page():
    """Test 7 — Legitimate login page (login + pass + same domain form) -> medium, not high."""
    res = fuse_intelligence(
        collection={"status": "collected", "html": {"login_keyword_count": 1, "password_input_count": 1, "external_form_action_count": 0}}
    )
    sig = next(s for s in res["signals"] if s["type"] == "html_authentication_context")
    assert sig["severity"] == "medium"
    assert res["status"] == "moderate_risk"  # Not elevated

def test_p5_external_credential_harvesting():
    """Test 8 — External credential harvesting -> high."""
    res = fuse_intelligence(
        collection={"status": "collected", "html": {"login_keyword_count": 1, "password_input_count": 1, "external_form_action_count": 1}}
    )
    assert res["status"] == "elevated_risk"
    assert "strong evidence of potential credential harvesting" in res["summary"]

def test_p5_whois_failure():
    """Test 9 — WHOIS failure."""
    res = fuse_intelligence(whois_data={"status": "failed"})
    assert "whois" in res["failed_sources"]
    # Should not add a risk signal for failing WHOIS
    assert not any(s["type"] == "whois_failure" for s in res["signals"])

def test_p5_llm_unavailable():
    """Test 10 — LLM unavailable."""
    res = fuse_intelligence(llm_data={"status": "unavailable", "reason": "llm_not_configured"})
    assert "llm" in res["missing_sources"]
    assert "llm" not in res["failed_sources"]
    assert not any(s["type"] == "llm_unavailable" for s in res["signals"])

def test_p5_missing_screenshot():
    """Test 11 — Missing screenshot."""
    res = fuse_intelligence(screenshot_data={"status": "failed"})
    assert "screenshot" in res["failed_sources"]
    assert not any(s["type"] == "screenshot_missing" for s in res["signals"])

def test_p5_evidence_deduplication():
    """Test 12 — Evidence deduplication."""
    res = fuse_intelligence(
        features={"suspicious_keywords": ["login"], "suspicious_keyword_locations": [["login", "path"]]},
        collection={"status": "collected", "html": {"login_keyword_count": 1}},
        ocr_data={"status": "completed", "text": "login here"}
    )
    types = [s["type"] for s in res["signals"]]
    assert "authentication_keywords" in types
    assert "html_authentication_context" in types
    assert "ocr_authentication_context" in types
    # Since they are all low, overall status is low_risk
    assert res["status"] == "low_risk"

def test_p5_phase1_isolation():
    """Test 13 — Phase 1 isolation."""
    res = fuse_intelligence(
        score=25,
        classification="safe",
        collection={"status": "collected", "html": {"login_keyword_count": 1, "password_input_count": 1, "external_form_action_count": 1}}
    )
    assert "The URL is classified as safe with a deterministic Phase 1 score of 25/100" in res["summary"]
    # The status of the fusion is elevated_risk, but Phase 1 remains untouched.
    assert res["status"] == "elevated_risk"
