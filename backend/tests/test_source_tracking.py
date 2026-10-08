"""Tests for source tracking logic in fusion engine."""

from app.core.fusion import fuse_intelligence

def test_source_tracking_with_whois_failure():
    """TEST 5 - SOURCE TRACKING"""
    result = fuse_intelligence(
        score=10,
        classification="safe",
        features={"scheme": "https"},
        collection={"status": "collected"},
        dns={"status": "resolved"},
        ssl_data={"status": "collected"},
        whois_data={"status": "failed", "reason": "lookup_failed"},
        screenshot_data={"status": "collected"},
        ocr_data={"status": "collected"},
        llm_data={"status": "not_configured"}
    )
    
    assert "whois" in result["failed_sources"]
    assert "whois" not in result["available_sources"]
    assert "llm" in result["missing_sources"]
    
    successful = ["features", "collection", "dns", "ssl", "screenshot", "ocr"]
    for s in successful:
        assert s in result["available_sources"]
        assert s not in result["failed_sources"]
        assert s not in result["missing_sources"]

def test_source_tracking_with_whois_success():
    """TEST 6 - SUCCESSFUL WHOIS SOURCE TRACKING"""
    result = fuse_intelligence(
        score=10,
        classification="safe",
        features={"scheme": "https"},
        whois_data={"status": "success", "registrar": "Test Registrar"}
    )
    
    assert "whois" in result["available_sources"]
    assert "whois" not in result["failed_sources"]
    assert "whois" not in result["missing_sources"]
