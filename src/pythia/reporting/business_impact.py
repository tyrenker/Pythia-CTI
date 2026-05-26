"""Translate technical intel into executive-language business impact.

This is Pythia's headline differentiator — see spec §2.6. Generates:
  - the "so what" paragraph (3 sentences for a CFO)
  - probable financial impact range
  - operational + regulatory impact
  - 3 recommended board-level actions
  - overall risk score (Low / Medium / High / Critical)
"""

from __future__ import annotations


def translate(intrusion_id: str) -> dict[str, object]:
    raise NotImplementedError("Wire up Claude with the business-impact prompt")
