"""End-to-end integration tests for Phase 2D Failure Matrix."""

import pytest
from unittest.mock import patch

@patch("app.api.v1.inspect.query_whois")
@patch("app.api.v1.inspect.collect_ssl")
@patch("app.api.v1.inspect.inspect_hostname")
@patch("app.api.v1.inspect.collect_url")
@patch("app.api.v1.inspect.capture_screenshot")
@patch("app.api.v1.inspect.extract_text")
@patch("app.api.v1.inspect.analyze_webpage")
@patch("app.api.v1.inspect.fuse_intelligence")
def test_e2e_failure_matrix(
    mock_fuse,
    mock_llm,
    mock_ocr,
    mock_screenshot,
    mock_collect,
    mock_dns,
    mock_ssl,
    mock_whois,
    client
):
    """Verify that Phase 2 failures do not crash Phase 1 scoring."""
    
    # Phase 2 failures simulate various conditions:
    mock_ssl.return_value = {"status": "collected"}
    mock_whois.return_value = {"status": "collected"}
    mock_collect.return_value = {"status": "collected"}
    mock_dns.return_value = {"status": "timeout"}
    mock_screenshot.return_value = {"status": "error", "reason": "browser_crash"}
    mock_ocr.return_value = {"status": "error", "reason": "timeout"}
    mock_llm.return_value = {"status": "unavailable", "reason": "timeout"}
    mock_fuse.return_value = {"status": "informational", "signals": [], "risk_hints": []}
    
    # Execute end-to-end API inspection with intelligence=True
    url = "https://example.com/"
    response = client.post("/api/v1/inspect", json={"url": url, "intelligence": True})
    
    assert response.status_code == 200
    body = response.json()
    
    # Phase 1 authority MUST remain unchanged
    assert body["score"] == 0
    assert body["classification"] == "safe"
    assert body["status"] == "completed"
    
    # Verify the intelligence block is safely serialized
    assert "intelligence" in body
    assert body["intelligence"]["status"] == "informational"

@patch("app.api.v1.inspect.analyze_webpage")
def test_llm_malformed_json_degradation(mock_llm, client):
    """Test when LLM returns malformed data inside the API layer."""
    mock_llm.return_value = {"status": "unavailable", "reason": "invalid_schema"}
    
    response = client.post("/api/v1/inspect", json={"url": "https://example.com/", "intelligence": True})
    assert response.status_code == 200
    
    # Score/class untouched
    body = response.json()
    assert body["score"] == 0
    assert body["classification"] == "safe"
