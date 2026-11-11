"""Log upload and retrieval router."""

import uuid
import os
import aiofiles
from fastapi import APIRouter, UploadFile, File, HTTPException, Query
from typing import Optional, List
from app.services.log_parser import parse_log_content
from app.services.store import store
from app.models.log_entry import LogUploadResponse, LogEntryResponse, LogLevel
from app.config import settings

router = APIRouter()
MAX_SIZE = settings.MAX_UPLOAD_SIZE_MB * 1024 * 1024


@router.post("/upload", response_model=LogUploadResponse)
async def upload_log_file(file: UploadFile = File(...)):
    """Upload and parse a log file (.log, .txt, .csv)."""
    allowed = {".log", ".txt", ".csv"}
    ext = os.path.splitext(file.filename or "")[1].lower()
    if ext not in allowed:
        raise HTTPException(status_code=400, detail=f"Unsupported file type: {ext}. Allowed: {allowed}")

    content_bytes = await file.read()
    if len(content_bytes) > MAX_SIZE:
        raise HTTPException(status_code=413, detail=f"File too large. Max size: {settings.MAX_UPLOAD_SIZE_MB} MB")

    try:
        content = content_bytes.decode("utf-8", errors="replace")
    except Exception:
        raise HTTPException(status_code=400, detail="Could not decode file. Ensure it is UTF-8 encoded text.")

    session_id = str(uuid.uuid4())
    entries, session = parse_log_content(content, file.filename or "unknown.log", session_id)

    if not entries:
        raise HTTPException(status_code=422, detail="No parseable log entries found in the uploaded file.")

    store.set_session(session, entries)

    # Save file for later reference
    os.makedirs(settings.UPLOAD_DIR, exist_ok=True)
    save_path = os.path.join(settings.UPLOAD_DIR, f"{session_id}_{file.filename}")
    async with aiofiles.open(save_path, "wb") as f:
        await f.write(content_bytes)

    return LogUploadResponse(
        session_id=session_id,
        filename=file.filename or "unknown.log",
        total_lines=len(entries),
        file_size=len(content_bytes),
        status="ready",
        message=f"Successfully parsed {len(entries)} log entries.",
    )


@router.get("", response_model=dict)
async def get_logs(
    session_id: Optional[str] = Query(None),
    level: Optional[str] = Query(None),
    keyword: Optional[str] = Query(None),
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
):
    """Retrieve parsed log entries with optional filtering."""
    sid = session_id or store.active_session_id
    if not sid:
        raise HTTPException(status_code=404, detail="No active session. Upload a log file first.")

    entries = store.get_entries(sid)
    if not entries:
        raise HTTPException(status_code=404, detail=f"No entries found for session {sid}")

    # Filter
    if level:
        levels = [l.strip().upper() for l in level.split(",")]
        entries = [e for e in entries if e.level.value in levels]
    if keyword:
        kw = keyword.lower()
        entries = [e for e in entries if kw in (e.message or "").lower() or kw in e.raw_line.lower()]

    total = len(entries)
    start = (page - 1) * page_size
    page_entries = entries[start: start + page_size]

    # Get anomaly scores for these entries
    anomalies = store.get_anomalies(sid)
    anomaly_entry_ids = {eid: a.score for a in anomalies for eid in a.log_entry_ids}

    result = []
    for e in page_entries:
        d = e.model_dump()
        d["anomaly_score"] = anomaly_entry_ids.get(e.id)
        d["is_anomaly"] = e.id in anomaly_entry_ids
        result.append(d)

    return {
        "session_id": sid,
        "total": total,
        "page": page,
        "page_size": page_size,
        "entries": result,
    }


@router.get("/sessions")
async def list_sessions():
    """List all uploaded log sessions."""
    sessions = store.get_all_sessions()
    return {"sessions": [s.model_dump() for s in sessions]}


@router.get("/stats")
async def log_stats(session_id: Optional[str] = Query(None)):
    """Get level distribution and timeline stats for a session."""
    sid = session_id or store.active_session_id
    if not sid:
        return {"error": "No active session"}

    entries = store.get_entries(sid)
    from collections import Counter, defaultdict

    level_dist = Counter(e.level.value for e in entries)
    hourly: dict = defaultdict(int)
    for e in entries:
        if e.timestamp:
            key = e.timestamp.strftime("%Y-%m-%dT%H:00:00")
            hourly[key] += 1

    return {
        "session_id": sid,
        "total": len(entries),
        "level_distribution": dict(level_dist),
        "hourly_volume": [{"time": k, "count": v} for k, v in sorted(hourly.items())],
    }
