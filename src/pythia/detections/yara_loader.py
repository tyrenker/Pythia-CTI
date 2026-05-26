"""Load and validate Yara rules from data/yara/."""

from __future__ import annotations

from pathlib import Path


def load_all(directory: Path | None = None) -> list[dict[str, object]]:
    raise NotImplementedError("Wire up yara-python + walk data/yara/")
