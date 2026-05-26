"""Normalize extracted intel into canonical Pythia entities.

Cross-references MITRE technique IDs against the seed STIX bundle to drop
hallucinated IDs; deduplicates IoCs; assigns kill-chain phases from TTPs.
"""

from __future__ import annotations


def normalize(raw: dict[str, object]) -> dict[str, object]:
    raise NotImplementedError
