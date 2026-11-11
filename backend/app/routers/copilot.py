"""Copilot router - AI Q&A over log data."""

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from typing import Optional
from datetime import datetime
from app.services.copilot_service import CopilotService
from app.services.store import store

router = APIRouter()


class ChatRequest(BaseModel):
    question: str
    session_id: Optional[str] = None


class ChatResponse(BaseModel):
    question: str
    answer: str
    evidence: list
    confidence: str
    session_id: str
    timestamp: datetime


@router.post("/chat", response_model=ChatResponse)
async def chat(req: ChatRequest):
    """Ask the AI Copilot a question about the analysed logs."""
    sid = req.session_id or store.active_session_id
    if not sid:
        raise HTTPException(status_code=400, detail="No active session. Upload and analyse logs first.")

    entries = store.get_entries(sid)
    if not entries:
        raise HTTPException(status_code=400, detail="No log data available for this session.")

    anomalies = store.get_anomalies(sid)
    incidents = store.get_incidents(sid)
    attack_chains = store.get_attack_chains(sid)

    copilot = CopilotService(entries, anomalies, incidents, attack_chains)
    result = copilot.answer(req.question)

    return ChatResponse(
        question=req.question,
        answer=result.get("answer", "Unable to answer this question."),
        evidence=result.get("evidence", []),
        confidence=result.get("confidence", "low"),
        session_id=sid,
        timestamp=datetime.utcnow(),
    )


@router.get("/suggestions")
async def get_suggestions(session_id: Optional[str] = None):
    """Return contextual question suggestions based on session data."""
    sid = session_id or store.active_session_id
    base_suggestions = [
        "What happened in this attack chain?",
        "Which event occurred first?",
        "Which systems were affected?",
        "What evidence supports this attack?",
        "Was privilege escalation observed?",
        "Which stages remain unconfirmed?",
        "What should the security analyst investigate next?",
        "What is the overall summary of the logs?",
        "What are the most critical errors?",
        "Which IP addresses generated the most failed login attempts?",
        "Explain the detected anomalies",
    ]
    return {"suggestions": base_suggestions, "session_id": sid}
