"""Tests for Phase 2A collection through the API.

The collector seam (collect_url) is faked here so no network is involved; the
real collector is exercised directly in test_collector.py with mock transports.
"""

import json

import pytest
from sqlalchemy import select

import app.api.v1.inspect as inspect_module
from app.models import Inspection


def test_default_request_has_no_collection(client):
    body = client.post("/api/v1/inspect", json={"url": "https://example.com/"}).json()
    assert body["collection"] is None
    assert body["score"] == 0  # Phase 1 scoring still runs
    assert body["classification"] == "safe"


def test_collect_false_never_runs_collector(client, monkeypatch):
    def boom(url):
        raise AssertionError("collection must not run when collect=false")

    monkeypatch.setattr(inspect_module, "collect_url", boom)

    body = client.post(
        "/api/v1/inspect", json={"url": "https://example.com/", "collect": False}
    ).json()
    assert body["collection"] is None


def test_collect_true_runs_collection(client, monkeypatch):
    fake = {"status": "collected", "http_status": 200, "html": {"title": "T"}}
    monkeypatch.setattr(inspect_module, "collect_url", lambda url: fake)

    body = client.post(
        "/api/v1/inspect", json={"url": "https://example.com/", "collect": True}
    ).json()
    assert body["collection"] == fake
    assert body["score"] == 0  # collection does not change Phase 1 scoring


def test_absent_collection_persisted_as_sql_null(client, db_session):
    client.post("/api/v1/inspect", json={"url": "https://example.com/"})

    row = db_session.scalar(select(Inspection))
    assert row.collection_json is None  # SQL NULL, not the text "null"


def test_present_collection_persisted_as_json(client, db_session, monkeypatch):
    fake = {"status": "collected", "http_status": 200}
    monkeypatch.setattr(inspect_module, "collect_url", lambda url: fake)

    client.post(
        "/api/v1/inspect", json={"url": "https://example.com/", "collect": True}
    )

    row = db_session.scalar(select(Inspection))
    assert json.loads(row.collection_json) == fake


def test_get_by_id_returns_collection(client, monkeypatch):
    fake = {"status": "collected", "http_status": 200}
    monkeypatch.setattr(inspect_module, "collect_url", lambda url: fake)

    created = client.post(
        "/api/v1/inspect", json={"url": "https://example.com/", "collect": True}
    ).json()
    got = client.get(f"/api/v1/inspections/{created['id']}").json()
    assert got["collection"] == fake


def test_get_by_id_without_collection_returns_null(client):
    created = client.post("/api/v1/inspect", json={"url": "https://example.com/"}).json()
    got = client.get(f"/api/v1/inspections/{created['id']}").json()
    assert got["collection"] is None


def test_list_inspections_includes_collection(client, monkeypatch):
    monkeypatch.setattr(
        inspect_module, "collect_url", lambda url: {"status": "collected"}
    )
    for i in range(3):
        client.post(
            "/api/v1/inspect",
            json={"url": f"https://example.com/{i}", "collect": True},
        )

    rows = client.get("/api/v1/inspections").json()
    assert len(rows) == 3
    assert all(row["collection"] == {"status": "collected"} for row in rows)
    assert rows[0]["id"] > rows[1]["id"] > rows[2]["id"]  # newest first


def test_list_inspections_respects_limit(client):
    for i in range(3):
        client.post("/api/v1/inspect", json={"url": f"https://example.com/{i}"})

    rows = client.get("/api/v1/inspections?limit=2").json()
    assert len(rows) == 2
