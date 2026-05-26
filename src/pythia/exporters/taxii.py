"""Minimal TAXII 2.1 server endpoints."""

from __future__ import annotations


def collection_manifest(collection_id: str) -> dict[str, object]:
    raise NotImplementedError("Stand up TAXII 2.1 collection manifest")
