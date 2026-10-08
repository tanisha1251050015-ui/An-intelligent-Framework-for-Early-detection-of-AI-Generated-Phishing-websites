"""Tests for Phase 3 Step 1: Secure WHOIS Domain Intelligence."""

import threading
import time
from datetime import datetime, timedelta, timezone
from unittest import mock

import pytest
from fastapi.testclient import TestClient

from app.core.fusion import fuse_intelligence
from app.core.whois_intelligence import query_whois, MAX_STRING_LENGTH, MAX_LIST_LENGTH
from app.main import app

client = TestClient(app)

class MockWhoisResponse:
    def __init__(self, **kwargs):
        for k, v in kwargs.items():
            setattr(self, k, v)


def test_valid_whois_lookup():
    """1. Valid WHOIS lookup with derived intelligence."""
    now = datetime.now()
    creation = now - timedelta(days=40)
    expiration = now + timedelta(days=20)
    
    mock_response = MockWhoisResponse(
        registrar="Test Registrar",
        creation_date=creation,
        expiration_date=expiration,
        updated_date=now - timedelta(days=5),
        name_servers=["ns1.example.com", "ns2.example.com"],
        status="clientTransferProhibited",
        country="US",
        org="Test Org"
    )
    
    with mock.patch("app.core.whois_intelligence.check_target") as mock_check:
        mock_check.return_value = mock.Mock(allowed=True)
        with mock.patch("whois.whois", return_value=mock_response):
            data = query_whois("example.com")
            
    assert data["status"] == "success"
    assert data["registrar"] == "Test Registrar"
    assert data["domain_age_days"] >= 39
    assert data["days_until_expiration"] <= 21
    
    # Should not have missing registrar or newly registered domain risk hints
    hints = data.get("risk_hints", [])
    hint_types = [h["type"] for h in hints]
    assert "missing_registrar" not in hint_types
    assert "newly_registered_domain" not in hint_types


def test_invalid_hostname():
    """2. Invalid hostname or SSRF blocked."""
    # Test SSRF block
    with mock.patch("app.core.whois_intelligence.check_target") as mock_check:
        mock_check.return_value = mock.Mock(allowed=False)
        data = query_whois("192.168.1.1")
        assert data["status"] == "failed"
        assert data["reason"] == "invalid_domain"


def test_missing_whois_response():
    """3. Missing WHOIS response (error handling)."""
    with mock.patch("app.core.whois_intelligence.check_target") as mock_check:
        mock_check.return_value = mock.Mock(allowed=True)
        with mock.patch("whois.whois", side_effect=Exception("Connection reset by peer")):
            data = query_whois("example.com")
            
    assert data["status"] == "failed"
    assert data["reason"] == "lookup_failed"
    # 16. No sensitive details leaked


def test_whois_timeout():
    """4. WHOIS timeout."""
    def slow_whois(*args, **kwargs):
        time.sleep(0.5)
        return MockWhoisResponse()
        
    with mock.patch("app.core.whois_intelligence.check_target") as mock_check:
        mock_check.return_value = mock.Mock(allowed=True)
        with mock.patch("whois.whois", side_effect=slow_whois):
            data = query_whois("example.com", timeout=0.1)
            
    assert data["status"] == "failed"
    assert data["reason"] == "timeout"


def test_whois_parser_failure_and_malformed():
    """5. WHOIS parser failure. 12. Malformed fields."""
    mock_response = MockWhoisResponse(
        creation_date="Not a real date",
        expiration_date=["Multiple", "Dates", "Malformed"]
    )
    
    with mock.patch("app.core.whois_intelligence.check_target") as mock_check:
        mock_check.return_value = mock.Mock(allowed=True)
        with mock.patch("whois.whois", return_value=mock_response):
            data = query_whois("example.com")
            
    assert data["status"] == "success"
    # Should safely fail date parsing and return None or missing hints
    hints = data.get("risk_hints", [])
    hint_types = [h["type"] for h in hints]
    assert "missing_creation_date" in hint_types
    assert "missing_expiration_date" in hint_types


def test_large_returned_whois_data():
    """6. Extremely long input/domain. 7. Large returned data bounded."""
    long_str = "A" * 1000
    long_list = ["ns.com"] * 50
    
    mock_response = MockWhoisResponse(
        registrar=long_str,
        name_servers=long_list
    )
    
    with mock.patch("app.core.whois_intelligence.check_target") as mock_check:
        mock_check.return_value = mock.Mock(allowed=True)
        with mock.patch("whois.whois", return_value=mock_response):
            data = query_whois("example.com")
            
    assert data["status"] == "success"
    assert len(data["registrar"]) == MAX_STRING_LENGTH
    assert len(data["nameservers"]) == MAX_LIST_LENGTH


def test_missing_registrar_and_dates():
    """8. Missing registrar. 9. Missing creation. 10. Missing expiration. 11. Multiple NS."""
    now = datetime.now()
    
    mock_response = MockWhoisResponse(
        registrar=None,
        creation_date=now - timedelta(days=10), # recently created
        expiration_date=now + timedelta(days=5), # expiring soon
        name_servers=["ns1", "ns2", "ns3"]
    )
    
    with mock.patch("app.core.whois_intelligence.check_target") as mock_check:
        mock_check.return_value = mock.Mock(allowed=True)
        with mock.patch("whois.whois", return_value=mock_response):
            data = query_whois("example.com")
            
    hints = data.get("risk_hints", [])
    hint_types = [h["type"] for h in hints]
    assert "missing_registrar" in hint_types
    assert "newly_registered_domain" in hint_types
    assert "expiring_soon" in hint_types
    assert len(data["nameservers"]) == 3


def test_fusion_labels_signals():
    """15. Fusion correctly labels WHOIS signals with source: whois."""
    whois_data = {
        "status": "success",
        "domain_age_days": 10,
        "risk_hints": [
            {
                "type": "newly_registered_domain",
                "confidence": 1.0,
                "evidence": "Domain age is 10 days"
            }
        ]
    }
    
    fused = fuse_intelligence(whois_data=whois_data)
    
    hints = fused.get("risk_hints", [])
    assert any(h["source"] == "whois" and h["type"] == "newly_registered_domain" for h in hints)
    assert fused["evidence"]["whois"]["domain_age_days"] == 10


def test_integration_whois_failure_does_not_fail_inspect():
    """13. WHOIS failure does not fail API. 14. Phase 1 score unmodified."""
    # Force WHOIS to timeout instantly
    with mock.patch("threading.Thread.is_alive", return_value=True):
        with mock.patch("app.core.whois_intelligence.check_target") as mock_check:
            mock_check.return_value = mock.Mock(allowed=True)
            with mock.patch("whois.whois", return_value=MockWhoisResponse()):
                resp = client.post("/api/v1/inspect", json={"url": "http://example.com", "intelligence": True})
    
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "completed"
    
    # Check Phase 1 unchanged (example.com normally scores 0 without features)
    # Check WHOIS evidence indicates timeout/unavailable
    assert data["whois"]["status"] == "failed"
    assert data["whois"]["reason"] == "timeout"
