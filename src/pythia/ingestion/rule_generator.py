"""AI-powered generation of Sigma and YARA rules from parsed threat intel."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import anthropic

from pythia.core.config import get_settings

_PROMPT_PATH = Path(__file__).parent / "prompts" / "generate_rules_prompt.md"
_SYSTEM_PROMPT = _PROMPT_PATH.read_text()


def generate_suggested_rules(parsed_data: dict[str, Any]) -> dict[str, Any]:
    """Send extracted threat intel to Claude and return suggested Sigma/YARA rules.

    Accepts the `parsed_data` dict from a SourceReport and returns a dict with
    `sigma_rules`, `yara_rules`, and `generation_notes`.
    """
    settings = get_settings()
    if not settings.anthropic_api_key:
        raise RuntimeError(
            "ANTHROPIC_API_KEY is not set. Add it to your .env file to use rule generation."
        )

    client = anthropic.Anthropic(api_key=settings.anthropic_api_key)

    # Build a focused context payload from the parsed data
    context = {
        "title": parsed_data.get("title"),
        "ttps": parsed_data.get("ttps") or [],
        "iocs": parsed_data.get("iocs") or [],
        "actors": parsed_data.get("actors") or [],
        "cves": parsed_data.get("cves") or [],
        "killchain_phases": parsed_data.get("killchain_phases") or [],
        "sectors_targeted": parsed_data.get("sectors_targeted") or [],
    }

    user_content = json.dumps(context, indent=2)

    message = client.messages.create(
        model=settings.claude_model,
        max_tokens=8192,
        system=_SYSTEM_PROMPT,
        messages=[{"role": "user", "content": user_content}],
    )

    raw = message.content[0].text.strip()
    # Strip markdown code fences if Claude wraps the JSON
    if raw.startswith("```"):
        raw = raw.split("```")[1]
        if raw.startswith("json"):
            raw = raw[4:]
        raw = raw.strip()

    result = json.loads(raw)

    # Ensure expected keys exist
    result.setdefault("sigma_rules", [])
    result.setdefault("yara_rules", [])
    result.setdefault("generation_notes", "")

    return result  # type: ignore[no-any-return]
