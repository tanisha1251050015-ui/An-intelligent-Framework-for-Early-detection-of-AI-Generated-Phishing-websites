"""Tests for POST /api/v1/inspect and GET /api/v1/inspections/{id}."""

import pytest
from sqlalchemy import select

from app.models import Inspection


def test_inspect_safe_url(client):
    response = client.post("/api/v1/inspect", json={"url": "https://example.com/"})
    assert response.status_code == 200
    body = response.json()
    assert body["url"] == "https://example.com/"
    assert body["status"] == "completed"
    assert body["score"] == 0
    assert body["classification"] == "safe"
    assert body["reasons"] == []


def test_inspect_suspicious_url(client):
    url = "https://login.example.tk/?a=1&b=2&c=3"
    response = client.post("/api/v1/inspect", json={"url": url})
    assert response.status_code == 200
    body = response.json()
    assert body["classification"] == "suspicious"
    assert 30 <= body["score"] <= 69
    assert body["reasons"]


def test_inspect_malicious_url(client):
    url = "http://user@a.b.c.example-verify-account.tk/?x=1&y=2&z=3"
    response = client.post("/api/v1/inspect", json={"url": url})
    assert response.status_code == 200
    body = response.json()
    assert body["classification"] == "malicious"
    assert body["score"] >= 70


@pytest.mark.parametrize(
    "bad_url",
    ["", "   ", "example.com", "not-a-url", "https://", "ftp://example.com/file"],
)
def test_inspect_malformed_url_returns_422(client, bad_url):
    response = client.post("/api/v1/inspect", json={"url": bad_url})
    assert response.status_code == 422


def test_inspect_persists_record(client, db_session):
    client.post("/api/v1/inspect", json={"url": "https://example.com/login"})

    row = db_session.scalar(select(Inspection))
    assert row is not None
    assert row.url == "https://example.com/login"
    assert row.status == "completed"
    assert row.score == 10
    assert row.classification == "safe"
    assert '"login"' in row.features_json
    assert "suspicious keyword" in row.reasons_json


def test_get_inspection_by_id(client):
    created = client.post(
        "/api/v1/inspect", json={"url": "https://example.com/verify"}
    ).json()

    response = client.get(f"/api/v1/inspections/{created['id']}")
    assert response.status_code == 200
    body = response.json()
    assert body["id"] == created["id"]
    assert body["score"] == created["score"]
    assert body["classification"] == created["classification"]
    assert body["features"] == created["features"]
    assert body["reasons"] == created["reasons"]


def test_get_inspection_missing_returns_404(client):
    response = client.get("/api/v1/inspections/9999")
    assert response.status_code == 404


def test_response_contains_features_and_reasons(client):
    body = client.post(
        "/api/v1/inspect", json={"url": "https://login.example.com/"}
    ).json()

    assert set(body["features"]) >= {
        "scheme",
        "hostname",
        "is_ip_hostname",
        "has_at_symbol",
        "suspicious_keywords",
        "url_length",
        "subdomain_count",
        "query_parameter_count",
        "tld",
        "is_suspicious_tld",
        "hostname_digit_count",
        "hostname_hyphen_count",
    }
    assert body["reasons"] == ["Hostname contains suspicious keyword(s): login"]


def test_inspect_echoes_submitted_url(client):
    response = client.post("/api/v1/inspect", json={"url": "https://example.com/"})
    assert response.json()["url"] == "https://example.com/"
