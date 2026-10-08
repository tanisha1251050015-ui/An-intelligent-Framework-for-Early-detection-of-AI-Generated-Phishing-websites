"""Tests for intelligence contextual fusion as requested in Priority 1 & 2."""

from app.core.fusion import fuse_intelligence

def test_benign_login_path():
    """TEST 1 — BENIGN LOGIN PATH"""
    result = fuse_intelligence(
        score=10,
        classification="safe",
        features={
            "suspicious_keywords": ["login"],
            "suspicious_keyword_locations": [["login", "path"]]
        },
        collection={
            "status": "collected",
            "html": {
                "password_input_count": 0,
                "form_count": 0,
            }
        },
        ssl_data={
            "status": "collected",
            "cert_age_days": 5 # Should not elevate risk by itself in fusion directly, though domain_intelligence provides it as low severity. We can just test fusion output.
        }
    )
    
    # Phase 1 classification intact
    assert "The URL is classified as safe with a deterministic Phase 1 score of 10/100" in result["summary"]
    
    # Check signal
    types = [s["type"] for s in result["signals"]]
    assert "authentication_keywords" in types
    assert "suspicious_authentication_keywords" not in types
    
    auth_signal = next(s for s in result["signals"] if s["type"] == "authentication_keywords")
    assert auth_signal["severity"] == "low"
    
    assert "but the collected page does not contain a password input or credential form" in result["summary"]
    assert "classified as safe because it contains suspicious keywords" not in result["summary"]
    
    # Should not elevate risk
    assert result["status"] == "informational" or result["status"] == "low_risk"


def test_synthetic_suspicious_url():
    """TEST 2 — SYNTHETIC SUSPICIOUS URL"""
    result = fuse_intelligence(
        score=95,
        classification="phishing",
        features={
            "suspicious_keywords": ["login", "verify", "account"],
            "suspicious_keyword_locations": [["login", "path"], ["verify", "path"], ["account", "hostname"]]
        },
        collection={
            "status": "collected",
            "html": {
                "password_input_count": 1,
                "external_form_actions": ["http://evil.com/post"]
            }
        }
    )
    
    assert "The URL is classified as phishing with a deterministic Phase 1 score of 95/100" in result["summary"]
    
    types = [s["type"] for s in result["signals"]]
    assert "suspicious_authentication_keywords" in types
    
    auth_signal = next(s for s in result["signals"] if s["type"] == "suspicious_authentication_keywords")
    assert auth_signal["severity"] == "high"
    
    assert "The hostname contains the authentication-related keyword 'account'" in result["reasoning"][-1] or "The URL path contains the authentication-related keyword 'login, verify'" in result["reasoning"][-1]
    assert "credential form whose submission target is external" in "".join(result["reasoning"])


def test_url_with_login_and_password_form():
    """TEST 3 — URL WITH LOGIN + PASSWORD FORM"""
    result = fuse_intelligence(
        score=10,
        classification="safe",
        features={
            "suspicious_keywords": ["login"],
            "suspicious_keyword_locations": [["login", "path"]]
        },
        collection={
            "status": "collected",
            "html": {
                "password_input_count": 1,
                "external_form_actions": []
            }
        }
    )
    
    types = [s["type"] for s in result["signals"]]
    assert "suspicious_authentication_keywords" in types
    
    auth_signal = next(s for s in result["signals"] if s["type"] == "suspicious_authentication_keywords")
    assert auth_signal["severity"] == "medium"
    
    assert "and the page contains a password input" in "".join(result["reasoning"])
