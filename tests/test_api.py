"""Smoke tests for IoCs, rules, threats, and parse endpoints."""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient


def test_list_iocs_returns_list(client: TestClient) -> None:
    r = client.get("/v1/iocs")
    assert r.status_code == 200
    assert isinstance(r.json(), list)


def test_list_iocs_type_filter(client: TestClient) -> None:
    r = client.get("/v1/iocs?type=cve&limit=5")
    assert r.status_code == 200
    data = r.json()
    assert isinstance(data, list)
    if data:
        assert all(i["type"] == "cve" for i in data)


def test_get_ioc_not_found(client: TestClient) -> None:
    r = client.get("/v1/iocs/nonexistent-uuid")
    assert r.status_code == 404


def test_list_rules_returns_list(client: TestClient) -> None:
    r = client.get("/v1/rules")
    assert r.status_code == 200
    assert isinstance(r.json(), list)


def test_list_rules_sigma_filter(client: TestClient) -> None:
    r = client.get("/v1/rules?rule_type=sigma&limit=5")
    assert r.status_code == 200
    data = r.json()
    assert isinstance(data, list)
    if data:
        assert all(rr["rule_type"] == "sigma" for rr in data)


def test_get_sigma_rule_not_found(client: TestClient) -> None:
    r = client.get("/v1/rules/sigma/nonexistent-uuid")
    assert r.status_code == 404


def test_list_threats_returns_list(client: TestClient) -> None:
    r = client.get("/v1/threats")
    assert r.status_code == 200
    assert isinstance(r.json(), list)


def test_get_threat_not_found(client: TestClient) -> None:
    r = client.get("/v1/threats/nonexistent-uuid")
    assert r.status_code == 404


def test_parse_requires_url_or_text(client: TestClient) -> None:
    r = client.post("/v1/parse", json={})
    assert r.status_code == 422


def test_parse_no_api_key_returns_503(client: TestClient) -> None:
    """POST /v1/parse with text should fail gracefully when ANTHROPIC_API_KEY not set."""
    r = client.post("/v1/parse", json={"text": "Lazarus Group used T1566.001 phishing."})
    # 503 when key absent, 201 if key happens to be set
    assert r.status_code in (201, 503)


def test_list_malware_families_returns_list(client: TestClient) -> None:
    r = client.get("/v1/malware")
    assert r.status_code == 200
    assert isinstance(r.json(), list)


def test_get_malware_family_not_found(client: TestClient) -> None:
    r = client.get("/v1/malware/nonexistent-family")
    assert r.status_code == 404


def test_sync_status_returns_dict(client: TestClient) -> None:
    r = client.get("/v1/sync/status")
    assert r.status_code == 200
    data = r.json()
    assert isinstance(data, dict)
    assert "sources" in data
    assert "scheduler_enabled" in data
    assert isinstance(data["sources"], dict)
    assert "attck" in data["sources"]
