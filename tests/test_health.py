"""Smoke test for the /v1/health endpoint."""

from __future__ import annotations

from fastapi.testclient import TestClient

from pythia import __version__


def test_health_endpoint(client: TestClient) -> None:
    response = client.get("/v1/health")
    assert response.status_code == 200
    body = response.json()
    assert body == {"status": "ok", "version": __version__}


def test_root_returns_metadata(client: TestClient) -> None:
    response = client.get("/")
    assert response.status_code == 200
    body = response.json()
    assert body["name"] == "Pythia"
    assert body["version"] == __version__
    assert body["docs"] == "/docs"


def test_openapi_schema_available(client: TestClient) -> None:
    response = client.get("/openapi.json")
    assert response.status_code == 200
    schema = response.json()
    assert schema["info"]["title"] == "Pythia"
