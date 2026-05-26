"""Claude-powered extraction of structured intel from raw articles."""

from __future__ import annotations

import json
from pathlib import Path

import anthropic

from pythia.core.config import get_settings

_PROMPT_PATH = Path(__file__).parent / "prompts" / "extract_intel.md"
_SYSTEM_PROMPT = _PROMPT_PATH.read_text()


def parse_article(text: str, *, source_url: str | None = None) -> dict[str, object]:
    """Send `text` to Claude and return structured intel as a dict.

    Returns an empty dict if the API key is not configured.
    """
    settings = get_settings()
    if not settings.anthropic_api_key:
        raise RuntimeError(
            "ANTHROPIC_API_KEY is not set. Add it to your .env file to use the parser."
        )

    client = anthropic.Anthropic(api_key=settings.anthropic_api_key)

    user_content = text
    if source_url:
        user_content = f"Source URL: {source_url}\n\n{text}"

    message = client.messages.create(
        model=settings.claude_model,
        max_tokens=4096,
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

    return json.loads(raw)  # type: ignore[no-any-return]
