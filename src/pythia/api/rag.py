"""GraphRAG endpoint — query the relational database of actors, malware, and TTPs using an LLM."""

from __future__ import annotations

import json
from typing import Annotated

import anthropic
from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel
from sqlalchemy.orm import Session

from pythia.core.config import get_settings
from pythia.core.db import get_session
from pythia.core.security import require_api_key
from pythia.models.actor import ThreatActor
from pythia.models.malware import MalwareFamily

router = APIRouter()

class RAGQuery(BaseModel):
    query: str

class RAGResponse(BaseModel):
    answer: str
    context_used: int  # number of records used as context

@router.post("/query", response_model=RAGResponse)
def query_graphrag(
    request: RAGQuery,
    _: Annotated[None, Depends(require_api_key)],
    session: Session = Depends(get_session),
) -> RAGResponse:
    """Answers a user's CTI question using a simulated GraphRAG approach over Postgres."""
    settings = get_settings()
    if not settings.anthropic_api_key:
        raise HTTPException(
            status_code=status.HTTP_501_NOT_IMPLEMENTED,
            detail="ANTHROPIC_API_KEY is not set.",
        )

    client = anthropic.Anthropic(api_key=settings.anthropic_api_key)

    # In a real system, we'd use vector search or text search to find *relevant* nodes.
    # For this basic implementation, we'll pull a summary of the most active actors and malware
    # as our "graph context".
    
    # 1. Fetch top 50 actors by TTP count or sophistication
    actors = session.query(ThreatActor).order_by(ThreatActor.created_at.desc()).limit(50).all()
    
    # 2. Fetch top 50 malware families
    malware = session.query(MalwareFamily).order_by(MalwareFamily.created_at.desc()).limit(50).all()

    # Build context
    context_data = {
        "threat_actors": [
            {
                "name": a.name,
                "aliases": a.aliases,
                "sponsor_type": a.sponsor_type,
                "sectors_targeted": a.sectors_targeted,
                "geographies_targeted": a.geographies_targeted,
            }
            for a in actors
        ],
        "malware_families": [
            {
                "name": m.name,
                "aliases": m.aliases,
                "family_type": m.family_type,
                "used_by_actors": m.actor_ids,
            }
            for m in malware
        ]
    }

    system_prompt = (
        "You are an expert Cyber Threat Intelligence (CTI) analyst assistant. "
        "You are provided with a context graph of Threat Actors, their targeted sectors, "
        "and the Malware families they use (in JSON format). "
        "Use ONLY this context to answer the user's question. If the context does not contain "
        "the answer, state that you do not have enough information."
    )

    try:
        message = client.messages.create(
            model=settings.claude_model,
            max_tokens=1024,
            system=system_prompt,
            messages=[
                {
                    "role": "user",
                    "content": f"Context Graph:\n{json.dumps(context_data, indent=2)}\n\nQuestion: {request.query}"
                }
            ],
        )
        answer = message.content[0].text.strip()
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=f"LLM query failed: {exc}",
        ) from exc

    return RAGResponse(
        answer=answer,
        context_used=len(actors) + len(malware),
    )
