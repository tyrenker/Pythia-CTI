"""Claude-powered extraction of structured intel from dark web forum posts."""

from __future__ import annotations

import json
import re
import uuid
from pathlib import Path
from typing import TYPE_CHECKING, Any

import anthropic

from pythia.core.config import get_settings

if TYPE_CHECKING:
    from pythia.models.dark_web import DarkWebPost

_PROMPT_PATH = Path(__file__).parent / "prompts" / "extract_forum_intel.md"
_SYSTEM_PROMPT = _PROMPT_PATH.read_text()

# Regex guards: refuse to store any string that looks like credentials or PII.
_PII_PATTERNS = [
    re.compile(r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b"),  # email
    re.compile(r"\b\d{3}-\d{2}-\d{4}\b"),  # SSN
    re.compile(r"\b(?:\d[ -]?){13,16}\b"),  # credit card-ish
    re.compile(r'(?i)"password"\s*:\s*"[^"]{1,}?"'),  # JSON password field
]


def _strip_pii(value: str) -> str:
    for pat in _PII_PATTERNS:
        value = pat.sub("[REDACTED]", value)
    return value


def _sanitize(obj: Any) -> Any:
    """Recursively redact any PII-looking strings from parsed Claude output."""
    if isinstance(obj, str):
        return _strip_pii(obj)
    if isinstance(obj, list):
        return [_sanitize(i) for i in obj]
    if isinstance(obj, dict):
        return {k: _sanitize(v) for k, v in obj.items()}
    return obj


def parse_forum_post(text: str) -> dict[str, Any]:
    """Send dark web post content to Claude and return structured intel dict."""
    settings = get_settings()
    if not settings.anthropic_api_key:
        raise RuntimeError("ANTHROPIC_API_KEY is not set.")

    client = anthropic.Anthropic(api_key=settings.anthropic_api_key)
    message = client.messages.create(
        model=settings.claude_model,
        max_tokens=2048,
        system=_SYSTEM_PROMPT,
        messages=[{"role": "user", "content": text[:30_000]}],
    )

    block = message.content[0]
    raw: str = block.text.strip()  # type: ignore[union-attr]
    if raw.startswith("```"):
        raw = raw.split("```")[1]
        if raw.startswith("json"):
            raw = raw[4:]
        raw = raw.strip()

    parsed: dict[str, Any] = json.loads(raw)
    sanitized: dict[str, Any] = _sanitize(parsed)
    return sanitized


def parse_dark_web_post(session: Any, post: DarkWebPost) -> str:
    """Run Claude on a DarkWebPost, create a SourceReport, and return its ID.

    Also back-fills victim/actor metadata on the post for fast UI queries.
    """
    from pythia.models.dark_web import DarkWebForumSource
    from pythia.models.report import SourceReport

    source: DarkWebForumSource | None = session.get(DarkWebForumSource, post.source_id)
    source_name = source.name if source else "Dark Web"

    assert post.raw_content is not None  # caller must guarantee

    try:
        parsed = parse_forum_post(post.raw_content)
    except Exception:
        raise

    # Back-fill cached metadata on the post row
    post.victim_org = parsed.get("victim_org")
    post.victim_sector = parsed.get("victim_sector")
    post.victim_country = parsed.get("victim_country")
    post.threat_actor = parsed.get("threat_actor")
    post.tlp = str(parsed.get("tlp") or "WHITE")
    post.admiralty_code = str(parsed.get("admiralty_code") or "E3")

    summary = parsed.get("summary") or ""
    title = post.title or parsed.get("victim_org") or "Dark web post"

    report = SourceReport(
        id=str(uuid.uuid4()),
        title=f"[{source_name}] {title}",
        url=post.post_url,
        raw_text=(post.raw_content or "")[:50_000],
        publication_date=post.published_at,
        status="pending_review",
        parsed_data={
            "title": title,
            "summary": summary,
            "post_type": parsed.get("post_type"),
            "threat_actor": parsed.get("threat_actor"),
            "victim_org": parsed.get("victim_org"),
            "victim_sector": parsed.get("victim_sector"),
            "victim_country": parsed.get("victim_country"),
            "claimed_data": parsed.get("claimed_data"),
            "claimed_data_size": parsed.get("claimed_data_size"),
            "deadline": parsed.get("deadline"),
            "ttps": [
                {"technique_id": t.get("technique_id"), "evidence": t.get("evidence")}
                for t in (parsed.get("ttps") or [])
            ],
            "iocs": parsed.get("iocs") or [],
            "analyst_notes": parsed.get("analyst_notes"),
            "admiralty_code": parsed.get("admiralty_code", "E3"),
            "source": source_name,
        },
        tlp=str(parsed.get("tlp") or "WHITE"),
    )
    session.add(report)
    session.flush()
    return report.id
