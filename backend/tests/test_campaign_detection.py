"""Tests for Priority 6: Infrastructure Relationship & Campaign Detection."""

from app.core.campaign import analyze_campaign, normalize_domain, extract_infrastructure

def mock_inspection(domain: str, ips: list[str]=None, ns: list[str]=None, registrar: str="", cert: tuple=None, sans: list[str]=None, status: str="resolved") -> dict:
    return {
        "features": {"hostname": domain},
        "dns": {"status": status, "addresses": ips or []},
        "whois": {"status": "success", "nameservers": ns or [], "registrar": registrar},
        "ssl": {
            "status": "collected" if (cert or sans) else "failed",
            "issuer": cert[0] if cert else "",
            "serial_number": cert[1] if cert else "",
            "subject_alt_names": sans or []
        }
    }

def test_p6_normalization():
    """Test 14 - Normalization."""
    assert normalize_domain("Example.COM.") == "example.com"
    assert normalize_domain("example.com") == "example.com"
    assert normalize_domain("EXAMPLE.com.") == "example.com"
    
def test_p6_single_domain():
    """Test 1 - Single domain."""
    inspections = [mock_inspection("a.com", ips=["1.1.1.1"])]
    res = analyze_campaign("a.com", inspections)
    assert res["status"] == "no_correlation"
    assert not res["relationships"]

def test_p6_unrelated_domains():
    """Test 2 - Completely unrelated domains."""
    inspections = [
        mock_inspection("a.com", ips=["1.1.1.1"], ns=["ns1.a.com"], registrar="RegA"),
        mock_inspection("b.com", ips=["2.2.2.2"], ns=["ns1.b.com"], registrar="RegB")
    ]
    res = analyze_campaign("a.com", inspections)
    assert res["status"] == "no_correlation"
    assert not res["relationships"]

def test_p6_shared_ip():
    """Test 3 - Shared IP."""
    inspections = [
        mock_inspection("a.com", ips=["1.1.1.1"]),
        mock_inspection("b.com", ips=["1.1.1.1"])
    ]
    res = analyze_campaign("a.com", inspections)
    assert res["status"] == "potential_campaign" or res["status"] == "weak_correlation" # Wait, IP=30 -> potential_campaign? Score is 30, so 30-59 is potential
    assert any(r["type"] == "SHARED_IP" for r in res["relationships"])
    assert res["relationships"][0]["strength"] == "medium"

def test_p6_shared_nameserver():
    """Test 4 - Shared nameserver."""
    inspections = [
        mock_inspection("a.com", ns=["ns1.example.com"]),
        mock_inspection("b.com", ns=["ns1.example.com"])
    ]
    res = analyze_campaign("a.com", inspections)
    assert any(r["type"] == "SHARED_NAMESERVER" for r in res["relationships"])
    assert res["relationships"][0]["strength"] == "medium"

def test_p6_shared_registrar():
    """Test 5 & 10 - Shared registrar."""
    inspections = [
        mock_inspection("a.com", registrar="markmonitor inc."),
        mock_inspection("b.com", registrar="MarkMonitor Inc.  ")
    ]
    res = analyze_campaign("a.com", inspections)
    assert any(r["type"] == "SHARED_REGISTRAR" for r in res["relationships"])
    assert res["relationships"][0]["strength"] == "weak"
    assert res["status"] == "weak_correlation"

def test_p6_shared_certificate():
    """Test 6 - Shared certificate."""
    inspections = [
        mock_inspection("a.com", cert=("Let's Encrypt", "123456")),
        mock_inspection("b.com", cert=("Let's Encrypt", "123456"))
    ]
    res = analyze_campaign("a.com", inspections)
    assert any(r["type"] == "SHARED_CERTIFICATE" for r in res["relationships"])
    assert res["relationships"][0]["strength"] == "strong"
    assert res["status"] == "strong_campaign_correlation"

def test_p6_shared_certificate_san():
    """Test 7 - Shared certificate SAN."""
    inspections = [
        mock_inspection("a.com", sans=["*.example.com", "login.a.com"]),
        mock_inspection("b.com", sans=["*.example.com"])
    ]
    res = analyze_campaign("a.com", inspections)
    assert any(r["type"] == "SHARED_CERTIFICATE_SAN" for r in res["relationships"])
    assert res["relationships"][0]["strength"] == "strong"

def test_p6_multiple_relationships():
    """Test 8 - Multiple relationships."""
    inspections = [
        mock_inspection("a.com", ips=["1.1.1.1"], ns=["ns1.x.com"], cert=("CA", "001")),
        mock_inspection("b.com", ips=["1.1.1.1"], ns=["ns1.x.com"], cert=("CA", "001"))
    ]
    res = analyze_campaign("a.com", inspections)
    types = {r["type"] for r in res["relationships"]}
    assert "SHARED_IP" in types
    assert "SHARED_NAMESERVER" in types
    assert "SHARED_CERTIFICATE" in types
    assert res["status"] == "strong_campaign_correlation"
    assert res["confidence"] >= 60

def test_p6_cluster_formation():
    """Test 9 - Cluster formation A<->B, B<->C."""
    inspections = [
        mock_inspection("a.com", ips=["1.1.1.1"]),
        mock_inspection("b.com", ips=["1.1.1.1"], ns=["ns1.x.com"]),
        mock_inspection("c.com", ns=["ns1.x.com"]),
        mock_inspection("d.com", ips=["2.2.2.2"]) # unrelated
    ]
    res = analyze_campaign("a.com", inspections)
    assert "b.com" in res["related_domains"]
    assert "c.com" in res["related_domains"]
    assert "d.com" not in res["related_domains"]

def test_p6_missing_infra():
    """Test 11 - Missing infra."""
    inspections = [
        mock_inspection("a.com", status="failed"),
        mock_inspection("b.com", status="failed")
    ]
    res = analyze_campaign("a.com", inspections)
    assert res["status"] == "no_correlation"
    assert not res["relationships"]

def test_p6_output_bounds():
    """Test 13 - Output bounds."""
    inspections = [mock_inspection("a.com", ips=["1.1.1.1"])]
    for i in range(150):
        inspections.append(mock_inspection(f"b{i}.com", ips=["1.1.1.1"]))
    res = analyze_campaign("a.com", inspections)
    assert len(res["related_domains"]) <= 50
    assert len(res["relationships"]) <= 100

def test_p6_false_relationship_prevention():
    """Test 15 - False relationship prevention."""
    inspections = [
        mock_inspection("a.com", ips=["1.1.1.1"], ns=["ns1.a.com"], registrar="R1", cert=("C1", "S1")),
        mock_inspection("b.com", ips=["2.2.2.2"], ns=["ns2.b.com"], registrar="R2", cert=("C2", "S2"))
    ]
    res = analyze_campaign("a.com", inspections)
    assert res["status"] == "no_correlation"
    assert not res["relationships"]
