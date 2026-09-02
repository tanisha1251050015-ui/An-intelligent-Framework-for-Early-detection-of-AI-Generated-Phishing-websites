"""Tests for Phase 2C domain intelligence hints."""

import pytest

from app.core.domain_intelligence import derive_domain_intelligence


# --------------------------------------------------------- SSL-based signals


def test_expired_certificate_signal():
    """Expired certificate produces a high-severity signal."""
    ssl_data = {"status": "collected", "is_expired": True, "is_self_signed": False}
    result = derive_domain_intelligence(ssl_data=ssl_data)

    types = [s["type"] for s in result["signals"]]
    assert "expired_certificate" in types
    assert any("expired" in h.lower() for h in result["risk_hints"])


def test_self_signed_certificate_signal():
    """Self-signed certificate produces a medium-severity signal."""
    ssl_data = {"status": "collected", "is_expired": False, "is_self_signed": True}
    result = derive_domain_intelligence(ssl_data=ssl_data)

    types = [s["type"] for s in result["signals"]]
    assert "self_signed_certificate" in types


def test_hostname_mismatch_signal():
    """Hostname mismatch produces a high-severity signal."""
    ssl_data = {
        "status": "collected",
        "is_expired": False,
        "is_self_signed": False,
        "hostname_match": False,
    }
    result = derive_domain_intelligence(ssl_data=ssl_data)

    types = [s["type"] for s in result["signals"]]
    assert "hostname_mismatch" in types
    assert any("mismatch" in h.lower() for h in result["risk_hints"])


def test_very_new_certificate_signal():
    """Certificate less than 30 days old produces a signal."""
    ssl_data = {"status": "collected", "cert_age_days": 5}
    result = derive_domain_intelligence(ssl_data=ssl_data)

    types = [s["type"] for s in result["signals"]]
    assert "very_new_certificate" in types


def test_ssl_timeout_signal():
    """SSL timeout produces a low-severity signal."""
    ssl_data = {"status": "timeout"}
    result = derive_domain_intelligence(ssl_data=ssl_data)

    types = [s["type"] for s in result["signals"]]
    assert "ssl_timeout" in types


def test_ssl_error_signal():
    """SSL error produces a low-severity signal."""
    ssl_data = {"status": "error", "reason": "SSLError"}
    result = derive_domain_intelligence(ssl_data=ssl_data)

    types = [s["type"] for s in result["signals"]]
    assert "ssl_error" in types


def test_no_ssl_data():
    """No SSL data produces no SSL signals."""
    result = derive_domain_intelligence()
    types = [s["type"] for s in result["signals"]]
    assert not any(t.startswith("ssl_") or t.endswith("certificate") for t in types)


# --------------------------------------------------------- DNS-based signals


def test_all_private_dns_signal():
    """All-private DNS produces a medium-severity signal."""
    dns = {"status": "resolved", "all_private": True, "has_private": True}
    result = derive_domain_intelligence(dns=dns)

    types = [s["type"] for s in result["signals"]]
    assert "all_private_dns" in types


def test_mixed_private_dns_signal():
    """Mixed private/public DNS produces a low-severity signal."""
    dns = {"status": "resolved", "all_private": False, "has_private": True}
    result = derive_domain_intelligence(dns=dns)

    types = [s["type"] for s in result["signals"]]
    assert "mixed_private_public_dns" in types


def test_dns_error_signal():
    """DNS error produces a medium-severity signal."""
    dns = {"status": "error", "error": {"type": "gaierror", "message": "not found"}}
    result = derive_domain_intelligence(dns=dns)

    types = [s["type"] for s in result["signals"]]
    assert "dns_resolution_error" in types


def test_public_dns_no_signal():
    """All-public DNS produces no DNS signals."""
    dns = {"status": "resolved", "all_private": False, "has_private": False}
    result = derive_domain_intelligence(dns=dns)

    types = [s["type"] for s in result["signals"]]
    assert "all_private_dns" not in types


# -------------------------------------------------------- Collection signals


def test_password_form_signal():
    """Password input form produces a signal."""
    collection = {
        "status": "collected",
        "http_status": 200,
        "html": {"password_input_count": 1, "form_count": 1, "script_count": 0},
    }
    result = derive_domain_intelligence(collection=collection)

    types = [s["type"] for s in result["signals"]]
    assert "password_form_detected" in types


def test_forms_with_heavy_scripts_signal():
    """Forms with >2 scripts produce a signal."""
    collection = {
        "status": "collected",
        "http_status": 200,
        "html": {"password_input_count": 0, "form_count": 1, "script_count": 3},
    }
    result = derive_domain_intelligence(collection=collection)

    types = [s["type"] for s in result["signals"]]
    assert "forms_with_heavy_scripts" in types


def test_error_http_status_signal():
    """HTTP 4xx/5xx status produces a signal."""
    collection = {"status": "collected", "http_status": 404, "html": None}
    result = derive_domain_intelligence(collection=collection)

    types = [s["type"] for s in result["signals"]]
    assert "error_http_status" in types


def test_collection_blocked_reasoning():
    """Blocked collection adds reasoning."""
    collection = {"status": "blocked", "reason": "private_or_local_target"}
    result = derive_domain_intelligence(collection=collection)

    assert any("blocked" in r.lower() for r in result["reasoning"])


# -------------------------------------------------------- Feature signals


def test_ip_hostname_signal():
    """IP-based hostname produces a signal."""
    features = {"is_ip_hostname": True}
    result = derive_domain_intelligence(features=features)

    types = [s["type"] for s in result["signals"]]
    assert "ip_based_hostname" in types


def test_suspicious_tld_signal():
    """Suspicious TLD produces a signal."""
    features = {"is_suspicious_tld": True, "tld": "tk"}
    result = derive_domain_intelligence(features=features)

    types = [s["type"] for s in result["signals"]]
    assert "suspicious_tld" in types


def test_suspicious_keywords_signal():
    """Suspicious keywords produce a signal."""
    features = {"suspicious_keywords": ["login", "verify"]}
    result = derive_domain_intelligence(features=features)

    types = [s["type"] for s in result["signals"]]
    assert "suspicious_keywords" in types


def test_no_features():
    """No features produce no feature signals."""
    result = derive_domain_intelligence()
    types = [s["type"] for s in result["signals"]]
    assert not any(
        t in ("ip_based_hostname", "suspicious_tld", "suspicious_keywords")
        for t in types
    )


# -------------------------------------------------------- Determinism


def test_deterministic_output():
    """Same inputs always produce the same output."""
    ssl_data = {"status": "collected", "is_expired": True, "is_self_signed": True}
    dns = {"status": "resolved", "all_private": True, "has_private": True}
    features = {"is_ip_hostname": True, "is_suspicious_tld": True, "tld": "tk"}

    r1 = derive_domain_intelligence(ssl_data=ssl_data, dns=dns, features=features)
    r2 = derive_domain_intelligence(ssl_data=ssl_data, dns=dns, features=features)

    assert r1 == r2


def test_multiple_sources_combined():
    """Multiple sources produce combined signals."""
    ssl_data = {"status": "collected", "is_expired": True}
    dns = {"status": "resolved", "all_private": True, "has_private": True}
    features = {"is_suspicious_tld": True, "tld": "xyz"}
    collection = {
        "status": "collected",
        "http_status": 200,
        "html": {"password_input_count": 1, "form_count": 1, "script_count": 0},
    }

    result = derive_domain_intelligence(
        ssl_data=ssl_data, dns=dns, features=features, collection=collection
    )

    types = [s["type"] for s in result["signals"]]
    assert "expired_certificate" in types
    assert "all_private_dns" in types
    assert "suspicious_tld" in types
    assert "password_form_detected" in types
    assert len(result["signals"]) >= 4
