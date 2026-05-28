"""Shared pytest fixtures."""

from __future__ import annotations

from collections.abc import Iterator

import pytest
from fastapi.testclient import TestClient

from pythia.api.main import create_app
from pythia.core.config import get_settings


@pytest.fixture()
def client() -> Iterator[TestClient]:
    with TestClient(create_app()) as c:
        yield c


@pytest.fixture()
def auth_headers() -> dict[str, str]:
    return {"X-API-Key": get_settings().api_key}
