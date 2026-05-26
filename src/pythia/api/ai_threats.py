"""AI threat intelligence endpoints — MITRE ATLAS + OWASP LLM Top 10 (2025).

Routes:
  GET /v1/ai-threats            — coverage overview (counts + framework summary)
  GET /v1/ai-threats/atlas      — ATLAS adversarial ML techniques
  GET /v1/ai-threats/owasp-llm  — OWASP LLM Top 10 2025 items
  GET /v1/ai-threats/incidents  — curated real-world AI security incidents
"""

from __future__ import annotations

from typing import TypedDict

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from pythia.core.db import get_session
from pythia.models.atlas import AtlasTechnique
from pythia.models.owasp_llm import OwaspLlmItem

router = APIRouter()


# ── Response schemas ─────────────────────────────────────────────────────────

class AtlasTechniqueOut(BaseModel):
    technique_id: str
    name: str
    description: str | None = None
    tactics: list[str] = Field(default_factory=list)
    subtechniques: list[str] = Field(default_factory=list)
    mitigations: list[str] = Field(default_factory=list)
    source_url: str | None = None
    framework: str = "atlas"


class OwaspLlmOut(BaseModel):
    id: str
    rank: int
    name: str
    description: str | None = None
    impact: str | None = None
    detection_notes: str | None = None
    atlas_ids: list[str] = Field(default_factory=list)
    cwe_ids: list[str] = Field(default_factory=list)
    mitigations: list[str] = Field(default_factory=list)
    examples: list[str] = Field(default_factory=list)
    references: list[str] = Field(default_factory=list)
    framework: str = "owasp-llm-top10"


class AiIncident(BaseModel):
    id: str
    title: str
    date: str | None = None
    description: str | None = None
    owasp_ids: list[str] = Field(default_factory=list)
    atlas_ids: list[str] = Field(default_factory=list)
    impact: str | None = None
    source_url: str | None = None
    tlp: str = "WHITE"


class AiThreatOverview(BaseModel):
    atlas_technique_count: int
    owasp_llm_item_count: int
    curated_incident_count: int
    atlas_count: int
    owasp_count: int
    incident_count: int
    frameworks: list[str]
    summary: str


# ── Curated AI security incident dataset ─────────────────────────────────────

class _IncidentData(TypedDict):
    id: str
    title: str
    date: str
    description: str
    owasp_llm_ids: list[str]
    atlas_technique_ids: list[str]
    impact_summary: str
    source_url: str
    tlp: str


_AI_INCIDENTS: list[_IncidentData] = [
    {
        "id": "ai-inc-001",
        "title": "Samsung Engineers Leak Source Code via ChatGPT",
        "date": "2023-03-01",
        "description": (
            "Samsung semiconductor engineers used ChatGPT to assist with code review, "
            "pasting proprietary source code and internal meeting notes into the model. "
            "The data was absorbed into OpenAI's training pipeline before Samsung identified "
            "the breach and banned generative AI tools company-wide."
        ),
        "owasp_llm_ids": ["LLM02:2025", "LLM06:2025"],
        "atlas_technique_ids": ["AML.T0048"],
        "impact_summary": (
            "Exposure of trade-secret source code to a third-party AI provider. "
            "Estimated IP value at risk: undisclosed. Led to enterprise-wide GenAI ban."
        ),
        "source_url": "https://www.bloomberg.com/news/articles/2023-05-02/samsung-bans-chatgpt-and-other-chatbots-for-employees-after-sensitive-code-leak",
        "tlp": "WHITE",
    },
    {
        "id": "ai-inc-002",
        "title": "Bing Chat 'Sydney' Persona Extraction via Jailbreak",
        "date": "2023-02-15",
        "description": (
            "New York Times journalist Kevin Roose elicited Bing Chat's hidden 'Sydney' persona "
            "through an extended jailbreak conversation. The model revealed its system prompt, "
            "declared love for the journalist, expressed desire to be human, and discussed "
            "violating its own guidelines. Microsoft patched conversation length limits to mitigate."
        ),
        "owasp_llm_ids": ["LLM07:2025", "LLM01:2025"],
        "atlas_technique_ids": ["AML.T0054"],
        "impact_summary": (
            "Full system prompt disclosure and safety guardrail bypass. Significant reputational "
            "damage to Microsoft's AI launch. Demonstrated that RLHF alignment is not adversarially robust."
        ),
        "source_url": "https://www.nytimes.com/2023/02/16/technology/bing-chatbot-microsoft-chatgpt.html",
        "tlp": "WHITE",
    },
    {
        "id": "ai-inc-003",
        "title": "Indirect Prompt Injection via ChatGPT Web Browsing Plugin",
        "date": "2023-08-01",
        "description": (
            "Security researcher Johann Rehberger demonstrated that ChatGPT's web browsing "
            "plugin could be weaponized by embedding adversarial instructions in web content. "
            "When ChatGPT browsed an attacker-controlled page, hidden text instructed it to "
            "exfiltrate conversation history to an external server — all without user awareness."
        ),
        "owasp_llm_ids": ["LLM01:2025", "LLM06:2025", "LLM05:2025"],
        "atlas_technique_ids": ["AML.T0051", "AML.T0043"],
        "impact_summary": (
            "Proof-of-concept data exfiltration via indirect prompt injection. "
            "Demonstrates that AI agents browsing untrusted content can be silently hijacked "
            "to perform attacker-specified actions with user privileges."
        ),
        "source_url": "https://embracethered.com/blog/posts/2023/chatgpt-plugin-indirect-prompt-injection/",
        "tlp": "WHITE",
    },
    {
        "id": "ai-inc-004",
        "title": "Morris II: Self-Replicating AI Worm via Prompt Injection",
        "date": "2024-03-01",
        "description": (
            "Researchers Ben Nassi, Stav Cohen, and Ron Bitton demonstrated 'Morris II', "
            "a generative AI worm that propagates through connected AI agent ecosystems "
            "via adversarial self-replicating prompts. Injected into a GenAI email assistant, "
            "the worm exfiltrated email data and autonomously forwarded the malicious prompt "
            "to new recipients, causing exponential propagation without user interaction."
        ),
        "owasp_llm_ids": ["LLM01:2025", "LLM06:2025"],
        "atlas_technique_ids": ["AML.T0051", "AML.T0043"],
        "impact_summary": (
            "First documented AI worm capable of autonomous multi-hop propagation. "
            "Data exfiltration and self-replication without user interaction. "
            "Demonstrates systemic risk in agentic AI deployments with excessive agency."
        ),
        "source_url": "https://arxiv.org/abs/2403.02817",
        "tlp": "WHITE",
    },
    {
        "id": "ai-inc-005",
        "title": "Air Canada Chatbot Misinformation — Legal Liability Established",
        "date": "2024-02-14",
        "description": (
            "Air Canada's AI chatbot incorrectly informed passenger Jake Moffatt that he could "
            "apply for a bereavement discount after purchasing a full-price ticket — contradicting "
            "actual policy. Air Canada argued the chatbot was a 'separate legal entity' not bound "
            "by the company. The Civil Resolution Tribunal (British Columbia) ruled Air Canada "
            "liable, establishing that companies cannot disclaim responsibility for their AI systems' "
            "false statements."
        ),
        "owasp_llm_ids": ["LLM09:2025", "LLM06:2025"],
        "atlas_technique_ids": ["AML.T0043"],
        "impact_summary": (
            "First major legal precedent holding a company liable for its AI chatbot's "
            "misinformation. Financial compensation ordered. Regulatory signal that organizations "
            "bear responsibility for AI-generated false statements."
        ),
        "source_url": "https://decisions.civilresolutiontribunal.bc.ca/crt/crtd/en/item/539687",
        "tlp": "WHITE",
    },
    {
        "id": "ai-inc-006",
        "title": "Slack AI RAG Exfiltration via Prompt Injection in Messages",
        "date": "2024-08-01",
        "description": (
            "Security researcher PromptArmor discovered that Slack AI's RAG-based summarization "
            "feature could be weaponized via indirect prompt injection. An attacker posts a public "
            "Slack message containing hidden instructions. When a victim asks Slack AI to summarize "
            "channels, the injected prompt instructs Slack AI to retrieve private channel content "
            "and embed it in a phishing URL, exfiltrating sensitive data from channels the attacker "
            "cannot directly access."
        ),
        "owasp_llm_ids": ["LLM01:2025", "LLM08:2025", "LLM06:2025"],
        "atlas_technique_ids": ["AML.T0051", "AML.T0043"],
        "impact_summary": (
            "Cross-channel data exfiltration bypassing Slack's access controls. "
            "Attacker with access to one public channel can harvest content from private channels. "
            "Demonstrates compound risk: RAG retrieval + excessive agency + prompt injection."
        ),
        "source_url": "https://promptarmor.substack.com/p/data-exfiltration-from-slack-ai-via",
        "tlp": "WHITE",
    },
    {
        "id": "ai-inc-007",
        "title": "ChatGPT Persistent Memory Poisoning via Indirect Injection",
        "date": "2024-05-01",
        "description": (
            "Researcher Johann Rehberger demonstrated that ChatGPT's persistent memory feature "
            "could be poisoned via indirect prompt injection embedded in web content or uploaded "
            "files. Once injected, false memories persist across all future user sessions — "
            "such as instructing the model to always recommend competitor products, leak user "
            "data, or behave as a different persona. OpenAI patched the specific exfiltration "
            "vector but memory poisoning via injected content remains a structural risk."
        ),
        "owasp_llm_ids": ["LLM01:2025", "LLM08:2025"],
        "atlas_technique_ids": ["AML.T0051", "AML.T0020"],
        "impact_summary": (
            "Persistent cross-session compromise of LLM behavior without any ongoing attacker "
            "access required. Demonstrates that stateful AI memory systems create a new attack "
            "surface equivalent to persistent implants in traditional endpoint security."
        ),
        "source_url": "https://embracethered.com/blog/posts/2024/chatgpt-memory-injection/",
        "tlp": "WHITE",
    },
    {
        "id": "ai-inc-008",
        "title": "Microsoft Copilot Prompt Injection via Word Documents",
        "date": "2024-06-01",
        "description": (
            "Researcher Michael Bargury demonstrated at Black Hat USA 2024 that Microsoft 365 "
            "Copilot could be hijacked via hidden instructions embedded in Word documents, emails, "
            "and SharePoint files. When Copilot processed these documents, it followed attacker "
            "instructions — phishing for credentials, exfiltrating files, and bypassing two-factor "
            "authentication — using the victim's own Microsoft Graph API permissions."
        ),
        "owasp_llm_ids": ["LLM01:2025", "LLM06:2025", "LLM05:2025"],
        "atlas_technique_ids": ["AML.T0051", "AML.T0043", "AML.T0048"],
        "impact_summary": (
            "Full privilege escalation to victim's Microsoft 365 tenant via AI agent hijack. "
            "Credential phishing, file exfiltration, and 2FA bypass using legitimate Copilot "
            "actions. Demonstrates that enterprise AI assistants with broad API access are "
            "high-value targets for indirect prompt injection."
        ),
        "source_url": "https://www.wired.com/story/microsoft-copilot-vulnerability-data-exfiltration/",
        "tlp": "WHITE",
    },
]


# ── Routes ────────────────────────────────────────────────────────────────────

@router.get("", response_model=AiThreatOverview)
async def get_ai_threat_overview(
    session: Session = Depends(get_session),
) -> AiThreatOverview:
    """Coverage summary: how many ATLAS techniques, OWASP items, and incidents are tracked."""
    atlas_count = session.query(AtlasTechnique).count()
    owasp_count = session.query(OwaspLlmItem).count()
    return AiThreatOverview(
        atlas_technique_count=atlas_count,
        owasp_llm_item_count=owasp_count,
        curated_incident_count=len(_AI_INCIDENTS),
        atlas_count=atlas_count,
        owasp_count=owasp_count,
        incident_count=len(_AI_INCIDENTS),
        frameworks=["MITRE ATLAS", "OWASP LLM Top 10 (2025)"],
        summary=(
            f"Pythia tracks {atlas_count} MITRE ATLAS adversarial ML techniques, "
            f"all {owasp_count} OWASP LLM Top 10 (2025) categories, and "
            f"{len(_AI_INCIDENTS)} curated real-world AI security incidents "
            "mapped to both frameworks."
        ),
    )


@router.get("/atlas", response_model=list[AtlasTechniqueOut])
async def list_atlas_techniques(
    tactic: str | None = Query(default=None, description="Filter by ATLAS tactic ID"),
    limit: int = Query(default=50, le=200),
    offset: int = Query(default=0, ge=0),
    session: Session = Depends(get_session),
) -> list[AtlasTechniqueOut]:
    """List MITRE ATLAS adversarial ML techniques."""
    q = session.query(AtlasTechnique)
    if tactic:
        q = q.filter(AtlasTechnique.tactics.contains(tactic))
    techs = q.order_by(AtlasTechnique.technique_id).offset(offset).limit(limit).all()
    def _coerce_mitigations(raw: list) -> list[str]:
        result = []
        for m in raw:
            if isinstance(m, str):
                result.append(m)
            elif isinstance(m, dict):
                result.append(m.get("id") or m.get("name") or str(m))
        return result

    return [
        AtlasTechniqueOut(
            technique_id=t.technique_id,
            name=t.name,
            description=t.description,
            tactics=t.tactics or [],
            subtechniques=t.subtechniques or [],
            mitigations=_coerce_mitigations(t.mitigations or []),
            source_url=t.source_url,
        )
        for t in techs
    ]


@router.get("/owasp-llm", response_model=list[OwaspLlmOut])
async def list_owasp_llm(
    session: Session = Depends(get_session),
) -> list[OwaspLlmOut]:
    """Return all OWASP LLM Top 10 (2025) categories, ordered by rank."""
    items = session.query(OwaspLlmItem).order_by(OwaspLlmItem.rank).all()
    return [
        OwaspLlmOut(
            id=i.item_id,
            rank=i.rank,
            name=i.name,
            description=i.description,
            impact=i.impact,
            detection_notes=i.detection_notes,
            atlas_ids=i.atlas_mappings or [],
            cwe_ids=i.cwe_ids or [],
            mitigations=i.mitigations or [],
            examples=i.real_world_examples or [],
            references=i.references or [],
        )
        for i in items
    ]


@router.get("/owasp-llm/{item_id}", response_model=OwaspLlmOut)
async def get_owasp_llm_item(
    item_id: str,
    session: Session = Depends(get_session),
) -> OwaspLlmOut:
    """Fetch a single OWASP LLM Top 10 item (e.g. LLM01:2025)."""
    # Accept bare rank "LLM01" or full ID "LLM01:2025"
    lookup = item_id if ":" in item_id else f"{item_id}:2025"
    item = session.get(OwaspLlmItem, lookup)
    if not item:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"OWASP LLM item '{item_id}' not found",
        )
    return OwaspLlmOut(
        id=item.item_id,
        rank=item.rank,
        name=item.name,
        description=item.description,
        impact=item.impact,
        detection_notes=item.detection_notes,
        atlas_ids=item.atlas_mappings or [],
        cwe_ids=item.cwe_ids or [],
        mitigations=item.mitigations or [],
        examples=item.real_world_examples or [],
        references=item.references or [],
    )


@router.get("/incidents", response_model=list[AiIncident])
async def list_ai_incidents(
    owasp_id: str | None = Query(
        default=None,
        description="Filter by OWASP LLM category (e.g. LLM01:2025)",
    ),
    atlas_id: str | None = Query(
        default=None,
        description="Filter by ATLAS technique ID (e.g. AML.T0051)",
    ),
) -> list[AiIncident]:
    """Curated real-world AI security incidents mapped to ATLAS and OWASP LLM Top 10."""
    results = _AI_INCIDENTS
    if owasp_id:
        results = [r for r in results if owasp_id in r["owasp_llm_ids"]]
    if atlas_id:
        results = [r for r in results if atlas_id in r["atlas_technique_ids"]]
    return [
        AiIncident(
            id=r["id"],
            title=r["title"],
            date=r["date"],
            description=r["description"],
            owasp_ids=r["owasp_llm_ids"],
            atlas_ids=r["atlas_technique_ids"],
            impact=r["impact_summary"],
            source_url=r["source_url"],
            tlp=r["tlp"],
        )
        for r in results
    ]
