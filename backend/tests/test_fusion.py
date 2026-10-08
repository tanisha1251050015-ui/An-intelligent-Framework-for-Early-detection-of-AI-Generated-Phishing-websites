"""Tests for Phase 2C fusion engine."""

import pytest

from app.core.fusion import fuse_intelligence


def test_fusion_with_complete_evidence():
    """Fusion with all sources produces a complete result."""
    result = fuse_intelligence(
        score=45,
        classification="suspicious",
        features={"scheme": "https", "is_suspicious_tld": True},
        collection={"status": "collected", "http_status": 200},
        dns={"status": "resolved", "has_private": False},
        ssl_data={"status": "collected", "issuer": "Let's Encrypt", "is_expired": False},
        whois_data={"status": "not_configured"},
        domain_intelligence={
            "signals": [{"type": "suspicious_tld", "severity": "medium"}],
            "risk_hints": ["Suspicious TLD"],
            "reasoning": ["The TLD is frequently abused."],
        },
    )

    assert result["status"] == "moderate_risk"
    assert len(result["signals"]) >= 1
    assert "features" in result["available_sources"]
    assert "collection" in result["available_sources"]
    assert "dns" in result["available_sources"]
    assert "ssl" in result["available_sources"]
    assert "whois" in result["missing_sources"]
    assert "domain_intelligence" in result["available_sources"]


def test_fusion_with_partial_evidence():
    """Fusion with some sources missing works correctly."""
    result = fuse_intelligence(
        score=0,
        classification="safe",
        features={"scheme": "https"},
    )

    assert result["status"] == "informational"
    assert "features" in result["available_sources"]
    assert "collection" in result["missing_sources"]
    assert "dns" in result["missing_sources"]
    assert "ssl" in result["missing_sources"]


def test_fusion_with_no_evidence():
    """Fusion with no sources works correctly."""
    result = fuse_intelligence()

    assert result["status"] == "informational"
    assert result["signals"] == []
    assert result["risk_hints"] == []
    assert len(result["missing_sources"]) > 0


def test_fusion_deterministic():
    """Same inputs produce the same output."""
    args = {
        "score": 45,
        "classification": "suspicious",
        "features": {"scheme": "https"},
        "ssl_data": {"status": "collected", "is_expired": True},
        "domain_intelligence": {
            "signals": [{"type": "expired_certificate", "severity": "high"}],
            "risk_hints": ["Expired cert"],
            "reasoning": ["Cert is expired."],
        },
    }

    r1 = fuse_intelligence(**args)
    r2 = fuse_intelligence(**args)
    assert r1 == r2


def test_fusion_high_severity():
    """High-severity signal sets status to elevated_risk."""
    result = fuse_intelligence(
        domain_intelligence={
            "signals": [{"type": "expired_certificate", "severity": "high"}],
            "risk_hints": [],
            "reasoning": [],
        },
    )

    assert result["status"] == "elevated_risk"


def test_fusion_medium_severity():
    """Medium-severity signal sets status to moderate_risk."""
    result = fuse_intelligence(
        domain_intelligence={
            "signals": [{"type": "self_signed_certificate", "severity": "medium"}],
            "risk_hints": [],
            "reasoning": [],
        },
    )

    assert result["status"] == "moderate_risk"


def test_fusion_low_severity():
    """Low-severity signal sets status to low_risk."""
    result = fuse_intelligence(
        domain_intelligence={
            "signals": [{"type": "ssl_timeout", "severity": "low"}],
            "risk_hints": [],
            "reasoning": [],
        },
    )

    assert result["status"] == "low_risk"


def test_fusion_no_signals():
    """No signals sets status to informational."""
    result = fuse_intelligence(features={"scheme": "https"})
    assert result["status"] == "informational"


def test_fusion_reasoning_aggregated():
    """Reasoning from multiple sources is aggregated."""
    result = fuse_intelligence(
        domain_intelligence={
            "signals": [],
            "risk_hints": [],
            "reasoning": ["Domain intelligence reasoning."],
        },
        collection={"status": "blocked", "reason": "private_or_local_target"},
    )

    assert any("domain intelligence" in r.lower() for r in result["reasoning"])
    assert any("blocked" in r.lower() for r in result["reasoning"])


def test_fusion_dns_error_reasoning():
    """DNS error adds reasoning."""
    result = fuse_intelligence(
        dns={
            "status": "error",
            "error": {"message": "Name not found"},
            "resolution_ms": 100,
        }
    )

    assert any("could not be resolved" in r for r in result["reasoning"])


def test_fusion_ssl_evidence():
    """SSL evidence is included in the result."""
    ssl_data = {
        "status": "collected",
        "issuer": "Let's Encrypt",
        "is_expired": True,
        "is_self_signed": False,
        "hostname_match": True,
        "cert_age_days": 10,
    }

    result = fuse_intelligence(ssl_data=ssl_data)

    assert "ssl" in result["evidence"]
    assert result["evidence"]["ssl"]["is_expired"] is True
    assert result["evidence"]["ssl"]["issuer"] == "Let's Encrypt"


def test_fusion_dns_evidence():
    """DNS evidence is included in the result."""
    dns = {"status": "resolved", "has_private": True, "address_count": 3}

    result = fuse_intelligence(dns=dns)

    assert "dns" in result["evidence"]
    assert result["evidence"]["dns"]["has_private"] is True
    assert result["evidence"]["dns"]["address_count"] == 3


def test_fusion_collection_evidence():
    """Collection evidence is included in the result."""
    collection = {
        "status": "collected",
        "http_status": 200,
        "html": {"password_input_count": 1, "form_count": 2},
    }

    result = fuse_intelligence(collection=collection)

    assert "collection" in result["evidence"]
    assert result["evidence"]["collection"]["password_input_count"] == 1


def test_fusion_phase1_score_unchanged():
    """Fusion never modifies the Phase 1 score/classification."""
    result = fuse_intelligence(
        score=45,
        classification="suspicious",
        domain_intelligence={
            "signals": [{"type": "expired_certificate", "severity": "high"}],
            "risk_hints": [],
            "reasoning": [],
        },
        llm_data={
            "status": "completed",
            "score": 100, # LLM attempting to alter score
            "classification": "malicious",
            "risk_hints": [],
            "summary": "LLM says malicious"
        }
    )

    # The fusion result contains status, but does NOT override score/classification
    assert "score" not in result
    assert "classification" not in result
    assert result["status"] == "elevated_risk"


def test_fusion_with_llm_data():
    """Fusion incorporates llm_data successfully."""
    result = fuse_intelligence(
        llm_data={
            "status": "completed",
            "risk_hints": [
                {"type": "impersonation", "confidence": 0.95, "evidence": "Looks like fake bank"}
            ],
            "summary": "Suspicious page"
        }
    )
    assert "llm" in result["available_sources"]
    assert "llm" in result["evidence"]
    assert result["summary"] == "Suspicious page"
    assert len(result["risk_hints"]) == 1
    hint = result["risk_hints"][0]
    assert hint["source"] == "llm"
    assert hint["type"] == "impersonation"
    assert hint["confidence"] == 0.95


def test_fusion_with_unavailable_sources():
    """Fusion properly categorizes attempted-but-failed and intentionally-not-executed sources."""
    result = fuse_intelligence(
        score=10,
        classification="safe",
        llm_data={"status": "unavailable", "reason": "timeout"}, # attempted
        ocr_data={"status": "not_run", "reason": "screenshot_unavailable"}, # not executed
        screenshot_data={"status": "error"} # attempted
    )
    # Attempted-but-failed sources go to failed_sources
    assert "llm" in result["failed_sources"]
    assert "screenshot" in result["failed_sources"]
    assert "llm" not in result["available_sources"]
    assert "screenshot" not in result["available_sources"]
    # Intentionally not executed go to missing_sources
    assert "ocr" in result["missing_sources"]
    assert "score" not in result
    assert "classification" not in result


def test_fusion_multiple_advisory_signals():
    """Valid signals from different sources are combined correctly."""
    result = fuse_intelligence(
        domain_intelligence={
            "signals": [{"type": "expired_certificate", "severity": "high"}],
            "risk_hints": ["Expired cert"],
            "reasoning": ["Cert is expired."],
        },
        llm_data={
            "status": "completed",
            "risk_hints": [
                {"type": "impersonation", "confidence": 0.95, "evidence": "Looks like fake bank"}
            ]
        }
    )
    assert len(result["risk_hints"]) == 2
    sources = {h["source"] for h in result["risk_hints"]}
    assert "domain_intelligence" in sources
    assert "llm" in sources


def test_fusion_invalid_llm_hints():
    """Invalid confidence values and malformed hints are rejected by fusion."""
    import math
    result = fuse_intelligence(
        llm_data={
            "status": "completed",
            "risk_hints": [
                {"type": "valid", "confidence": 0.5, "evidence": "valid"},
                {"type": "invalid_conf", "confidence": 1.5, "evidence": "invalid"},
                {"type": "nan_conf", "confidence": float("nan"), "evidence": "invalid"},
                {"type": "inf_conf", "confidence": float("inf"), "evidence": "invalid"},
                {"type": "neg_conf", "confidence": -0.5, "evidence": "invalid"},
                "not a dict"
            ]
        }
    )
    assert len(result["risk_hints"]) == 1
    assert result["risk_hints"][0]["type"] == "valid"


def test_fusion_output_limits():
    """Ensure fusion truncates oversized strings and limits risk hints."""
    result = fuse_intelligence(
        llm_data={
            "status": "completed",
            "risk_hints": [
                {"type": "T" * 5000, "confidence": 0.5, "evidence": "E" * 5000}
            ],
            "summary": "S" * 5000
        }
    )
    assert len(result["risk_hints"]) == 1
    hint = result["risk_hints"][0]
    assert len(hint["type"]) <= 100
    assert len(hint["evidence"]) <= 1000
    assert len(result["summary"]) <= 2000


def test_fusion_summary_score_preservation_safe():
    """Verify fusion properly preserves safe Phase 1 score and classification."""
    result = fuse_intelligence(
        score=10,
        classification="safe",
        features={"scheme": "https"}
    )
    assert "The URL is classified as safe with a deterministic Phase 1 score of 10/100" in result["summary"]


def test_fusion_summary_score_preservation_suspicious():
    """Verify fusion properly preserves suspicious Phase 1 score and classification."""
    result = fuse_intelligence(
        score=55,
        classification="suspicious",
        features={"scheme": "https"}
    )
    assert "The URL is classified as suspicious with a deterministic Phase 1 score of 55/100" in result["summary"]


def test_fusion_summary_score_preservation_phishing():
    """Verify fusion properly preserves phishing Phase 1 score and classification."""
    result = fuse_intelligence(
        score=90,
        classification="phishing",
        features={"scheme": "https"}
    )
    assert "The URL is classified as phishing with a deterministic Phase 1 score of 90/100" in result["summary"]


