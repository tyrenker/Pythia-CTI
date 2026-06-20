"""Tests for dark web forum monitoring endpoints."""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from pythia.core.db import SessionLocal
from pythia.models.dark_web import DarkWebForumSource, DarkWebPost


@pytest.fixture(autouse=True)
def clean_dark_web_tables() -> None:
    """Wipe dark web tables before each test to avoid cross-test pollution."""
    with SessionLocal() as session:
        session.query(DarkWebPost).delete()
        session.query(DarkWebForumSource).delete()
        session.commit()


def test_list_sources_empty(client: TestClient) -> None:
    r = client.get("/v1/dark-web/sources")
    assert r.status_code == 200
    assert isinstance(r.json(), list)


def test_add_source_requires_auth(client: TestClient) -> None:
    r = client.post(
        "/v1/dark-web/sources",
        json={"name": "Test", "onion_url": "test123.onion"},
    )
    assert r.status_code == 401


def test_add_and_list_source(client: TestClient, auth_headers: dict[str, str]) -> None:
    payload = {
        "name": "Test Leak Site",
        "onion_url": "testleak123456789.onion",
        "category": "ransomware",
        "poll_interval_h": 6,
        "auto_ingest": False,
    }
    r = client.post("/v1/dark-web/sources", json=payload, headers=auth_headers)
    assert r.status_code == 201
    data = r.json()
    assert data["name"] == "Test Leak Site"
    assert data["onion_url"] == "testleak123456789.onion"
    assert data["category"] == "ransomware"
    assert data["active"] is True
    source_id = data["id"]

    r2 = client.get("/v1/dark-web/sources")
    assert r2.status_code == 200
    ids = [s["id"] for s in r2.json()]
    assert source_id in ids


def test_add_source_duplicate_url(client: TestClient, auth_headers: dict[str, str]) -> None:
    payload = {"name": "Dup", "onion_url": "duplicate111.onion"}
    client.post("/v1/dark-web/sources", json=payload, headers=auth_headers)
    r2 = client.post("/v1/dark-web/sources", json=payload, headers=auth_headers)
    assert r2.status_code == 409


def test_patch_source(client: TestClient, auth_headers: dict[str, str]) -> None:
    r = client.post(
        "/v1/dark-web/sources",
        json={"name": "Patchable", "onion_url": "patchable99999.onion"},
        headers=auth_headers,
    )
    source_id = r.json()["id"]

    r2 = client.patch(
        f"/v1/dark-web/sources/{source_id}",
        json={"active": False, "auto_ingest": True},
        headers=auth_headers,
    )
    assert r2.status_code == 200
    assert r2.json()["active"] is False
    assert r2.json()["auto_ingest"] is True


def test_patch_source_not_found(client: TestClient, auth_headers: dict[str, str]) -> None:
    r = client.patch(
        "/v1/dark-web/sources/nonexistent-id",
        json={"active": False},
        headers=auth_headers,
    )
    assert r.status_code == 404


def test_delete_source(client: TestClient, auth_headers: dict[str, str]) -> None:
    r = client.post(
        "/v1/dark-web/sources",
        json={"name": "Deletable", "onion_url": "deletable12345.onion"},
        headers=auth_headers,
    )
    source_id = r.json()["id"]

    r2 = client.delete(f"/v1/dark-web/sources/{source_id}", headers=auth_headers)
    assert r2.status_code == 204

    r3 = client.get("/v1/dark-web/sources")
    ids = [s["id"] for s in r3.json()]
    assert source_id not in ids


def test_delete_source_not_found(client: TestClient, auth_headers: dict[str, str]) -> None:
    r = client.delete("/v1/dark-web/sources/nonexistent-id", headers=auth_headers)
    assert r.status_code == 404


def test_list_posts_empty(client: TestClient) -> None:
    r = client.get("/v1/dark-web/posts")
    assert r.status_code == 200
    assert isinstance(r.json(), list)


def test_get_post_not_found(client: TestClient) -> None:
    r = client.get("/v1/dark-web/posts/nonexistent-uuid")
    assert r.status_code == 404


def test_list_victims_empty(client: TestClient) -> None:
    r = client.get("/v1/dark-web/victims")
    assert r.status_code == 200
    assert isinstance(r.json(), list)


def test_stats_shape(client: TestClient) -> None:
    r = client.get("/v1/dark-web/stats")
    assert r.status_code == 200
    data = r.json()
    assert "active_sources" in data
    assert "total_sources" in data
    assert "posts_today" in data
    assert "victims_30d" in data
    assert "pending_ingest" in data
    assert "by_status" in data
    assert "by_category" in data


def test_source_category_filter(client: TestClient, auth_headers: dict[str, str]) -> None:
    client.post(
        "/v1/dark-web/sources",
        json={"name": "Forum A", "onion_url": "foruma11111.onion", "category": "forum"},
        headers=auth_headers,
    )
    client.post(
        "/v1/dark-web/sources",
        json={"name": "Ransom B", "onion_url": "ransomb2222.onion", "category": "ransomware"},
        headers=auth_headers,
    )
    r = client.get("/v1/dark-web/sources?category=forum")
    assert r.status_code == 200
    data = r.json()
    assert all(s["category"] == "forum" for s in data)


def test_source_active_only_filter(client: TestClient, auth_headers: dict[str, str]) -> None:
    r = client.post(
        "/v1/dark-web/sources",
        json={"name": "Inactive", "onion_url": "inactive33333.onion"},
        headers=auth_headers,
    )
    source_id = r.json()["id"]
    client.patch(
        f"/v1/dark-web/sources/{source_id}",
        json={"active": False},
        headers=auth_headers,
    )
    r2 = client.get("/v1/dark-web/sources?active_only=true")
    assert r2.status_code == 200
    ids = [s["id"] for s in r2.json()]
    assert source_id not in ids


def test_fetch_post_not_found(client: TestClient, auth_headers: dict[str, str]) -> None:
    r = client.post("/v1/dark-web/posts/nonexistent-id/fetch", headers=auth_headers)
    assert r.status_code == 404


def test_ingest_post_not_found(client: TestClient, auth_headers: dict[str, str]) -> None:
    r = client.post("/v1/dark-web/posts/nonexistent-id/ingest", headers=auth_headers)
    assert r.status_code == 422
