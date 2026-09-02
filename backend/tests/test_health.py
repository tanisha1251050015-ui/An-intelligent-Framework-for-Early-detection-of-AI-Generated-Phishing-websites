"""Tests for GET /api/v1/health."""

from app.core.config import settings


def test_health_returns_ok(client):
    response = client.get("/api/v1/health")

    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "ok"
    assert body["service"] == settings.app_name
    assert body["version"] == settings.app_version
    assert body["database"] == "ok"
    assert body["timestamp"]


def test_docs_are_available(client):
    response = client.get("/docs")
    assert response.status_code == 200


def test_unknown_api_route_returns_404(client):
    response = client.get("/api/v1/does-not-exist")
    assert response.status_code == 404
