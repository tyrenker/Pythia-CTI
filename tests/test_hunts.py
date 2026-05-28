"""Tests for the threat hunt workbench endpoints."""

from __future__ import annotations

from fastapi.testclient import TestClient


# ---------------------------------------------------------------------------
# Session CRUD
# ---------------------------------------------------------------------------


def test_create_hunt_requires_auth(client: TestClient) -> None:
    r = client.post("/v1/hunts", json={"name": "Test Hunt"})
    assert r.status_code == 401


def test_create_and_get_hunt(client: TestClient, auth_headers: dict[str, str]) -> None:
    r = client.post(
        "/v1/hunts",
        json={
            "name": "Suspicious Lateral Movement",
            "hypothesis": "APT actor pivoting via WMI",
            "analyst": "test-analyst",
            "sector_focus": ["finance"],
            "motivation_focus": ["espionage"],
        },
        headers=auth_headers,
    )
    assert r.status_code == 201
    data = r.json()
    assert data["name"] == "Suspicious Lateral Movement"
    assert data["status"] == "active"
    assert data["observations"] == []

    hunt_id = data["id"]
    r2 = client.get(f"/v1/hunts/{hunt_id}")
    assert r2.status_code == 200
    assert r2.json()["id"] == hunt_id


def test_list_hunts(client: TestClient, auth_headers: dict[str, str]) -> None:
    client.post("/v1/hunts", json={"name": "Hunt A"}, headers=auth_headers)
    client.post("/v1/hunts", json={"name": "Hunt B"}, headers=auth_headers)
    r = client.get("/v1/hunts")
    assert r.status_code == 200
    assert isinstance(r.json(), list)


def test_get_hunt_not_found(client: TestClient) -> None:
    r = client.get("/v1/hunts/nonexistent-id")
    assert r.status_code == 404


def test_update_hunt(client: TestClient, auth_headers: dict[str, str]) -> None:
    r = client.post("/v1/hunts", json={"name": "Original Name"}, headers=auth_headers)
    hunt_id = r.json()["id"]

    r2 = client.put(
        f"/v1/hunts/{hunt_id}",
        json={"name": "Updated Name", "status": "closed"},
        headers=auth_headers,
    )
    assert r2.status_code == 200
    assert r2.json()["name"] == "Updated Name"
    assert r2.json()["status"] == "closed"


def test_archive_hunt(client: TestClient, auth_headers: dict[str, str]) -> None:
    r = client.post("/v1/hunts", json={"name": "To Archive"}, headers=auth_headers)
    hunt_id = r.json()["id"]

    r2 = client.delete(f"/v1/hunts/{hunt_id}", headers=auth_headers)
    assert r2.status_code == 204

    r3 = client.get(f"/v1/hunts/{hunt_id}")
    assert r3.json()["status"] == "archived"


# ---------------------------------------------------------------------------
# Observations
# ---------------------------------------------------------------------------


def _create_hunt(client: TestClient, headers: dict[str, str]) -> str:
    r = client.post("/v1/hunts", json={"name": "Obs Test Hunt"}, headers=headers)
    assert r.status_code == 201
    return r.json()["id"]


def test_add_and_list_observations(client: TestClient, auth_headers: dict[str, str]) -> None:
    hunt_id = _create_hunt(client, auth_headers)

    obs_cases = [
        {"obs_type": "ioc_ip", "value": "198.51.100.42"},
        {"obs_type": "ttp", "value": "T1059.001"},
        {"obs_type": "sector", "value": "healthcare"},
    ]
    for obs in obs_cases:
        r = client.post(f"/v1/hunts/{hunt_id}/observations", json=obs, headers=auth_headers)
        assert r.status_code == 201

    r2 = client.get(f"/v1/hunts/{hunt_id}")
    observations = r2.json()["observations"]
    assert len(observations) == 3


def test_observation_pyramid_tier_assigned(client: TestClient, auth_headers: dict[str, str]) -> None:
    hunt_id = _create_hunt(client, auth_headers)

    r = client.post(
        f"/v1/hunts/{hunt_id}/observations",
        json={"obs_type": "ioc_domain", "value": "evil.example.com"},
        headers=auth_headers,
    )
    assert r.status_code == 201
    assert r.json()["pyramid_tier"] == "domain"

    r2 = client.post(
        f"/v1/hunts/{hunt_id}/observations",
        json={"obs_type": "ttp", "value": "T1059"},
        headers=auth_headers,
    )
    assert r2.json()["pyramid_tier"] == "ttp"

    r3 = client.post(
        f"/v1/hunts/{hunt_id}/observations",
        json={"obs_type": "sector", "value": "finance"},
        headers=auth_headers,
    )
    assert r3.json()["pyramid_tier"] is None


def test_add_observation_invalid_type(client: TestClient, auth_headers: dict[str, str]) -> None:
    hunt_id = _create_hunt(client, auth_headers)
    r = client.post(
        f"/v1/hunts/{hunt_id}/observations",
        json={"obs_type": "invalid_type", "value": "x"},
        headers=auth_headers,
    )
    assert r.status_code == 422


def test_remove_observation(client: TestClient, auth_headers: dict[str, str]) -> None:
    hunt_id = _create_hunt(client, auth_headers)

    r = client.post(
        f"/v1/hunts/{hunt_id}/observations",
        json={"obs_type": "ioc_hash", "value": "abc123"},
        headers=auth_headers,
    )
    obs_id = r.json()["id"]

    r2 = client.delete(f"/v1/hunts/{hunt_id}/observations/{obs_id}", headers=auth_headers)
    assert r2.status_code == 204

    r3 = client.get(f"/v1/hunts/{hunt_id}")
    assert len(r3.json()["observations"]) == 0


# ---------------------------------------------------------------------------
# Notes
# ---------------------------------------------------------------------------


def test_get_notes_empty(client: TestClient, auth_headers: dict[str, str]) -> None:
    hunt_id = _create_hunt(client, auth_headers)
    r = client.get(f"/v1/hunts/{hunt_id}/notes")
    assert r.status_code == 200
    assert r.json()["content"] == ""


def test_upsert_notes(client: TestClient, auth_headers: dict[str, str]) -> None:
    hunt_id = _create_hunt(client, auth_headers)

    r = client.put(
        f"/v1/hunts/{hunt_id}/notes",
        json={"content": "# Hunt notes\n\nFound suspicious C2 traffic."},
        headers=auth_headers,
    )
    assert r.status_code == 200
    assert "C2 traffic" in r.json()["content"]

    # Upsert again
    r2 = client.put(
        f"/v1/hunts/{hunt_id}/notes",
        json={"content": "# Updated notes"},
        headers=auth_headers,
    )
    assert r2.status_code == 200
    assert r2.json()["content"] == "# Updated notes"

    r3 = client.get(f"/v1/hunts/{hunt_id}/notes")
    assert r3.json()["content"] == "# Updated notes"


# ---------------------------------------------------------------------------
# Draft detections CRUD (non-Claude paths)
# ---------------------------------------------------------------------------


def test_list_detections_empty(client: TestClient, auth_headers: dict[str, str]) -> None:
    hunt_id = _create_hunt(client, auth_headers)
    r = client.get(f"/v1/hunts/{hunt_id}/detections")
    assert r.status_code == 200
    assert r.json() == []


def test_update_detection_not_found(client: TestClient, auth_headers: dict[str, str]) -> None:
    hunt_id = _create_hunt(client, auth_headers)
    r = client.put(
        f"/v1/hunts/{hunt_id}/detections/nonexistent",
        json={"title": "New Title"},
        headers=auth_headers,
    )
    assert r.status_code == 404


# ---------------------------------------------------------------------------
# Status filter on list
# ---------------------------------------------------------------------------


def test_list_hunts_status_filter(client: TestClient, auth_headers: dict[str, str]) -> None:
    client.post("/v1/hunts", json={"name": "Active Hunt"}, headers=auth_headers)
    r_closed = client.post("/v1/hunts", json={"name": "Closed Hunt"}, headers=auth_headers)
    closed_id = r_closed.json()["id"]
    client.put(f"/v1/hunts/{closed_id}", json={"status": "closed"}, headers=auth_headers)

    r = client.get("/v1/hunts?status=active")
    statuses = [h["status"] for h in r.json()]
    assert all(s == "active" for s in statuses)
