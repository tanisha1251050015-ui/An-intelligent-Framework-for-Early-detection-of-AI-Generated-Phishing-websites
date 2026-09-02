"""Tests for Phase 2C intelligence through the API.

The SSL collector seam is mocked here so no real network connections are made.
"""

import json

import pytest
from sqlalchemy import select

import app.api.v1.inspect as inspect_module
from app.models import Inspection


def test_default_request_has_no_intelligence(client):
    """Default request (no intelligence flag) has null intelligence fields."""
    body = client.post("/api/v1/inspect", json={"url": "https://example.com/"}).json()
    assert body["ssl"] is None
    assert body["whois"] is None
    assert body["intelligence"] is None
    assert body["score"] == 0


def test_intelligence_false_never_runs_pipeline(client, monkeypatch):
    """intelligence=false never executes Phase 2C pipeline."""
    def boom(*args, **kwargs):
        raise AssertionError("Phase 2C must not run when intelligence=false")

    monkeypatch.setattr(inspect_module, "collect_ssl", boom)
    monkeypatch.setattr(inspect_module, "derive_domain_intelligence", boom)
    monkeypatch.setattr(inspect_module, "fuse_intelligence", boom)

    body = client.post(
        "/api/v1/inspect", json={"url": "https://example.com/", "intelligence": False}
    ).json()
    assert body["ssl"] is None
    assert body["intelligence"] is None


def test_intelligence_true_runs_pipeline(client, monkeypatch):
    """intelligence=true executes Phase 2C pipeline."""
    fake_ssl = {"status": "collected", "hostname": "example.com", "is_expired": False}
    fake_whois = {"status": "not_configured", "hostname": "example.com"}
    fake_intel = {"status": "informational", "signals": [], "risk_hints": []}

    monkeypatch.setattr(inspect_module, "collect_ssl", lambda h: fake_ssl)
    monkeypatch.setattr(inspect_module, "query_whois", lambda h: fake_whois)
    monkeypatch.setattr(
        inspect_module, "derive_domain_intelligence",
        lambda **kw: {"signals": [], "risk_hints": [], "reasoning": []},
    )
    monkeypatch.setattr(inspect_module, "fuse_intelligence", lambda **kw: fake_intel)

    body = client.post(
        "/api/v1/inspect", json={"url": "https://example.com/", "intelligence": True}
    ).json()

    assert body["ssl"] == fake_ssl
    assert body["whois"] == fake_whois
    assert body["intelligence"] == fake_intel
    assert body["score"] == 0  # Phase 1 unchanged


def test_collect_and_intelligence_combined(client, monkeypatch):
    """collect=true + intelligence=true runs both pipelines."""
    fake_collection = {"status": "collected", "http_status": 200}
    fake_ssl = {"status": "collected", "hostname": "example.com"}
    fake_whois = {"status": "not_configured", "hostname": "example.com"}
    fake_intel = {"status": "informational", "signals": [], "risk_hints": []}

    monkeypatch.setattr(inspect_module, "collect_url", lambda url: fake_collection)
    monkeypatch.setattr(inspect_module, "collect_ssl", lambda h: fake_ssl)
    monkeypatch.setattr(inspect_module, "query_whois", lambda h: fake_whois)
    monkeypatch.setattr(
        inspect_module, "derive_domain_intelligence",
        lambda **kw: {"signals": [], "risk_hints": [], "reasoning": []},
    )
    monkeypatch.setattr(inspect_module, "fuse_intelligence", lambda **kw: fake_intel)

    body = client.post(
        "/api/v1/inspect",
        json={"url": "https://example.com/", "collect": True, "intelligence": True},
    ).json()

    assert body["collection"] == fake_collection
    assert body["ssl"] == fake_ssl
    assert body["whois"] == fake_whois


def test_intelligence_persisted(client, db_session, monkeypatch):
    """Intelligence data is persisted in the database."""
    fake_ssl = {"status": "collected", "hostname": "example.com"}
    fake_whois = {"status": "not_configured", "hostname": "example.com"}
    fake_intel = {"status": "informational", "signals": [], "risk_hints": []}

    monkeypatch.setattr(inspect_module, "collect_ssl", lambda h: fake_ssl)
    monkeypatch.setattr(inspect_module, "query_whois", lambda h: fake_whois)
    monkeypatch.setattr(
        inspect_module, "derive_domain_intelligence",
        lambda **kw: {"signals": [], "risk_hints": [], "reasoning": []},
    )
    monkeypatch.setattr(inspect_module, "fuse_intelligence", lambda **kw: fake_intel)

    client.post(
        "/api/v1/inspect", json={"url": "https://example.com/", "intelligence": True}
    )

    row = db_session.scalar(select(Inspection))
    assert row.ssl_data is not None
    assert json.loads(row.ssl_data)["status"] == "collected"
    assert row.whois_data is not None
    assert json.loads(row.whois_data)["status"] == "not_configured"
    assert row.intelligence_json is not None


def test_intelligence_retrieved_by_id(client, monkeypatch):
    """Intelligence data is returned by GET /inspections/{id}."""
    fake_ssl = {"status": "collected", "hostname": "example.com"}
    fake_whois = {"status": "not_configured", "hostname": "example.com"}
    fake_intel = {"status": "informational", "signals": [], "risk_hints": []}

    monkeypatch.setattr(inspect_module, "collect_ssl", lambda h: fake_ssl)
    monkeypatch.setattr(inspect_module, "query_whois", lambda h: fake_whois)
    monkeypatch.setattr(
        inspect_module, "derive_domain_intelligence",
        lambda **kw: {"signals": [], "risk_hints": [], "reasoning": []},
    )
    monkeypatch.setattr(inspect_module, "fuse_intelligence", lambda **kw: fake_intel)

    created = client.post(
        "/api/v1/inspect", json={"url": "https://example.com/", "intelligence": True}
    ).json()

    got = client.get(f"/api/v1/inspections/{created['id']}").json()
    assert got["ssl"] == created["ssl"]
    assert got["whois"] == created["whois"]
    assert got["intelligence"] == created["intelligence"]


def test_list_inspections_includes_intelligence(client, monkeypatch):
    """Intelligence data is included in list endpoint."""
    fake_ssl = {"status": "collected", "hostname": "example.com"}
    fake_whois = {"status": "not_configured", "hostname": "example.com"}
    fake_intel = {"status": "informational", "signals": [], "risk_hints": []}

    monkeypatch.setattr(inspect_module, "collect_ssl", lambda h: fake_ssl)
    monkeypatch.setattr(inspect_module, "query_whois", lambda h: fake_whois)
    monkeypatch.setattr(
        inspect_module, "derive_domain_intelligence",
        lambda **kw: {"signals": [], "risk_hints": [], "reasoning": []},
    )
    monkeypatch.setattr(inspect_module, "fuse_intelligence", lambda **kw: fake_intel)

    client.post(
        "/api/v1/inspect", json={"url": "https://example.com/", "intelligence": True}
    )

    rows = client.get("/api/v1/inspections").json()
    assert len(rows) >= 1
    assert rows[0]["ssl"] is not None


def test_legacy_requests_remain_valid(client):
    """Existing request format without intelligence flag still works."""
    body = client.post("/api/v1/inspect", json={"url": "https://example.com/"}).json()
    assert body["score"] == 0
    assert body["classification"] == "safe"
    assert body["ssl"] is None
    assert body["whois"] is None
    assert body["intelligence"] is None


def test_no_intelligence_data_persisted_as_sql_null(client, db_session):
    """Without intelligence flag, columns are SQL NULL."""
    client.post("/api/v1/inspect", json={"url": "https://example.com/"})

    row = db_session.scalar(select(Inspection))
    assert row.ssl_data is None
    assert row.whois_data is None
    assert row.intelligence_json is None


def test_existing_records_have_null_intelligence(client, db_session):
    """Pre-Phase 2C records show null intelligence fields."""
    db_session.add(
        Inspection(url="https://legacy.example.com/", status="completed")
    )
    db_session.commit()

    from sqlalchemy import select as sa_select

    legacy = db_session.scalar(
        sa_select(Inspection).where(Inspection.url == "https://legacy.example.com/")
    )
    assert legacy.ssl_data is None
    assert legacy.whois_data is None
    assert legacy.intelligence_json is None

    response = client.get(f"/api/v1/inspections/{legacy.id}").json()
    assert response["ssl"] is None
    assert response["whois"] is None
    assert response["intelligence"] is None
