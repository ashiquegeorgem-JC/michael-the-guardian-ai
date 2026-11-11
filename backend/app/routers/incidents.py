"""Incidents router."""

from fastapi import APIRouter, HTTPException, Query
from typing import Optional
from app.services.store import store

router = APIRouter()


@router.get("")
async def list_incidents(
    session_id: Optional[str] = Query(None),
    severity: Optional[str] = Query(None),
    status: Optional[str] = Query(None),
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
):
    """List all incidents for a session with optional filters."""
    sid = session_id or store.active_session_id
    if not sid:
        return {"incidents": [], "total": 0}

    incidents = store.get_incidents(sid)

    if severity:
        severities = [s.strip().upper() for s in severity.split(",")]
        incidents = [i for i in incidents if i.severity in severities]
    if status:
        incidents = [i for i in incidents if i.status.value == status.lower()]

    total = len(incidents)
    start = (page - 1) * page_size
    page_items = incidents[start: start + page_size]

    return {
        "session_id": sid,
        "total": total,
        "page": page,
        "page_size": page_size,
        "incidents": [i.model_dump() for i in page_items],
    }


@router.get("/summary")
async def incident_summary(session_id: Optional[str] = Query(None)):
    """Get severity distribution and category breakdown."""
    sid = session_id or store.active_session_id
    incidents = store.get_incidents(sid or "")

    from collections import Counter
    severity_dist = Counter(i.severity for i in incidents)
    category_dist = Counter(i.category.value for i in incidents)

    return {
        "total": len(incidents),
        "severity_distribution": dict(severity_dist),
        "category_distribution": dict(category_dist),
    }


@router.get("/{incident_id}")
async def get_incident(incident_id: str):
    """Get full details of a single incident."""
    # Search across all sessions
    for sid, incidents in store.incidents.items():
        for incident in incidents:
            if incident.id == incident_id:
                return incident.model_dump()
    raise HTTPException(status_code=404, detail=f"Incident {incident_id} not found")


@router.patch("/{incident_id}/status")
async def update_status(incident_id: str, status: str = Query(...)):
    """Update incident status (open, investigating, resolved, false_positive)."""
    valid = {"open", "investigating", "resolved", "false_positive"}
    if status not in valid:
        raise HTTPException(status_code=400, detail=f"Invalid status. Valid: {valid}")

    for sid, incidents in store.incidents.items():
        for incident in incidents:
            if incident.id == incident_id:
                from app.models.incident import IncidentStatus
                incident.status = IncidentStatus(status)
                return {"message": "Status updated", "incident_id": incident_id, "status": status, "new_status": status}

    raise HTTPException(status_code=404, detail="Incident not found")
