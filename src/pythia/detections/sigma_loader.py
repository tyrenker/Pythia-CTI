"""Load and validate Sigma rules from data/sigma/."""

from __future__ import annotations

from pathlib import Path


def load_all(directory: Path | None = None) -> list[dict[str, object]]:
    raise NotImplementedError("Wire up pysigma + walk data/sigma/")
