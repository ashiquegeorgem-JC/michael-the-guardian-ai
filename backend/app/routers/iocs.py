"""
IOC router — Phase 4.2A.5.

Provides REST API endpoints for the Indicator of Compromise (IOC)
intelligence subsystem.

Endpoint order is CRITICAL for FastAPI route resolution:
  Static paths (/search, /summary) must be registered BEFORE
  the parameterised path (/{ioc_id}) to avoid accidental capture.

Security guarantees:
  - No external network calls (DNS, reputation, WHOIS, threat feeds).
  - No automatic malicious classification.
  - Original LogEntry / Anomaly / Incident / AttackChain objects are
    never mutated by any endpoint in this router.
  - Raw forensic evidence is read-only via the /evidence endpoint.
  - ValidationStatus is never modified by status transitions (they are
    separate concepts: analyst review vs. syntactic validity).
"""

from __future__ import annotations

import logging
from collections import defaultdict
from datetime import datetime
from typing import Dict, List, Optional, Set

from fastapi import APIRouter, Body, HTTPException, Query

from app.models.ioc import (
    IOC,
    IOCEvidence,
    IOCStatus,
    IOCStatusHistory,
    IOCStatusUpdate,
    IOCSummary,
    IOCType,
    ValidationStatus,
    VALID_IOC_STATUS_TRANSITIONS,
)
from app.services.ioc_repository import ioc_repository

logger = logging.getLogger("michael.iocs")

router = APIRouter()

# ─────────────────────────────────────────────────────────────────────────────
# Pagination helpers
# ─────────────────────────────────────────────────────────────────────────────

_PAGE_SIZE_MAX = 200


def _paginate(items: list, page: int, page_size: int) -> dict:
    """Apply bounded pagination to a list and return a metadata envelope."""
    page_size = min(page_size, _PAGE_SIZE_MAX)
    total = len(items)
    total_pages = max(1, (total + page_size - 1) // page_size) if total else 0
    start = (page - 1) * page_size
    return {
        "items": items[start: start + page_size],
        "total": total,
        "page": page,
        "page_size": page_size,
        "total_pages": total_pages,
    }


def _apply_filters(
    iocs: List[IOC],
    *,
    ioc_type: Optional[str],
    status: Optional[str],
    validation_status: Optional[str],
    normalized_value: Optional[str],
    session_id: Optional[str],
    event_id: Optional[str],
    anomaly_id: Optional[str],
    incident_id: Optional[str],
    attack_chain_id: Optional[str],
) -> List[IOC]:
    """Apply AND-combined filters to a list of IOCs."""
    result = iocs

    if ioc_type:
        try:
            ioc_type_enum = IOCType(ioc_type.lower())
            result = [i for i in result if i.ioc_type == ioc_type_enum]
        except ValueError:
            raise HTTPException(status_code=400, detail=f"Unknown ioc_type: '{ioc_type}'")

    if status:
        try:
            status_enum = IOCStatus(status.upper())
            result = [i for i in result if i.status == status_enum]
        except ValueError:
            raise HTTPException(status_code=400, detail=f"Unknown status: '{status}'")

    if validation_status:
        try:
            vs_enum = ValidationStatus(validation_status.upper())
            result = [
                i for i in result
                if any(
                    getattr(ev, "validation_status", None) == vs_enum
                    for ev in i.evidence_references
                )
            ]
        except ValueError:
            raise HTTPException(
                status_code=400, detail=f"Unknown validation_status: '{validation_status}'"
            )

    if normalized_value:
        needle = normalized_value.lower()
        result = [i for i in result if needle in i.normalized_value.lower()]

    if session_id:
        result = [i for i in result if session_id in i.source_sessions]

    if event_id:
        result = [
            i for i in result
            if any(ev.event_id == event_id for ev in i.evidence_references)
        ]

    if anomaly_id:
        result = [i for i in result if anomaly_id in i.associated_anomaly_ids]

    if incident_id:
        result = [i for i in result if incident_id in i.associated_incident_ids]

    if attack_chain_id:
        result = [i for i in result if attack_chain_id in i.associated_chain_ids]

    return result


# ─────────────────────────────────────────────────────────────────────────────
# A. IOC List
# ─────────────────────────────────────────────────────────────────────────────

@router.get("", summary="List IOCs with optional filters and pagination")
async def list_iocs(
    page: int = Query(1, ge=1, description="1-based page number"),
    page_size: int = Query(50, ge=1, le=200, description="Results per page (max 200)"),
    ioc_type: Optional[str] = Query(None, description="Filter by IOC type (ipv4, domain, url, …)"),
    status: Optional[str] = Query(None, description="Filter by review status"),
    validation_status: Optional[str] = Query(None, description="Filter by validation status (VALID, INVALID, SUSPICIOUS)"),
    normalized_value: Optional[str] = Query(None, description="Substring match on normalized_value"),
    session_id: Optional[str] = Query(None, description="Restrict to IOCs observed in this session"),
    event_id: Optional[str] = Query(None, description="Restrict to IOCs from this log event"),
    anomaly_id: Optional[str] = Query(None, description="Restrict to IOCs associated with this anomaly"),
    incident_id: Optional[str] = Query(None, description="Restrict to IOCs associated with this incident"),
    attack_chain_id: Optional[str] = Query(None, description="Restrict to IOCs associated with this attack chain"),
):
    """
    Return a paginated list of IOCs, optionally filtered.

    All supplied filters are combined with AND logic.
    Pagination is bounded: page_size is capped at 200.
    """
    # Use index-based lookup when a single foreign key is supplied for efficiency
    if event_id:
        all_iocs = ioc_repository.find_iocs_by_event(event_id)
    elif anomaly_id:
        all_iocs = ioc_repository.find_iocs_by_anomaly(anomaly_id)
    elif incident_id:
        all_iocs = ioc_repository.find_iocs_by_incident(incident_id)
    elif attack_chain_id:
        all_iocs = ioc_repository.find_iocs_by_attack_chain(attack_chain_id)
    elif session_id:
        all_iocs = ioc_repository.find_iocs_by_session(session_id)
    else:
        all_iocs = ioc_repository.list_iocs()

    filtered = _apply_filters(
        all_iocs,
        ioc_type=ioc_type,
        status=status,
        validation_status=validation_status,
        normalized_value=normalized_value,
        session_id=session_id if not (event_id or anomaly_id or incident_id or attack_chain_id) else None,
        event_id=None,          # already applied by index lookup above
        anomaly_id=None,
        incident_id=None,
        attack_chain_id=None,
    )

    # Sort by first_seen descending (most recent first)
    filtered.sort(key=lambda i: i.first_seen or datetime.min, reverse=True)

    result = _paginate(filtered, page, page_size)
    result["items"] = [ioc.model_dump(mode="json") for ioc in result["items"]]
    return result


# ─────────────────────────────────────────────────────────────────────────────
# B. IOC Search  (must come before /{ioc_id} to avoid route capture)
# ─────────────────────────────────────────────────────────────────────────────

@router.get("/search", summary="Multi-criteria IOC search")
async def search_iocs(
    normalized_value: Optional[str] = Query(None, description="Substring match on normalized_value"),
    ioc_type: Optional[str] = Query(None, description="Filter by IOC type"),
    status: Optional[str] = Query(None, description="Filter by review status"),
    validation_status: Optional[str] = Query(None, description="Filter by validation status"),
    session_id: Optional[str] = Query(None, description="Restrict to a specific session"),
    event_id: Optional[str] = Query(None, description="Restrict to a specific log event"),
    anomaly_id: Optional[str] = Query(None, description="Restrict to a specific anomaly"),
    incident_id: Optional[str] = Query(None, description="Restrict to a specific incident"),
    attack_chain_id: Optional[str] = Query(None, description="Restrict to a specific attack chain"),
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
):
    """
    Investigation-oriented IOC search using existing repository indexes.

    Uses indexed lookups when a specific foreign key is supplied.
    Returns paginated results sorted by first_seen descending.
    """
    # Determine base set using most selective available index
    if event_id:
        base = ioc_repository.find_iocs_by_event(event_id)
    elif anomaly_id:
        base = ioc_repository.find_iocs_by_anomaly(anomaly_id)
    elif incident_id:
        base = ioc_repository.find_iocs_by_incident(incident_id)
    elif attack_chain_id:
        base = ioc_repository.find_iocs_by_attack_chain(attack_chain_id)
    elif session_id:
        base = ioc_repository.find_iocs_by_session(session_id)
    else:
        base = ioc_repository.list_iocs()

    filtered = _apply_filters(
        base,
        ioc_type=ioc_type,
        status=status,
        validation_status=validation_status,
        normalized_value=normalized_value,
        session_id=session_id if not (event_id or anomaly_id or incident_id or attack_chain_id) else None,
        event_id=None,
        anomaly_id=None,
        incident_id=None,
        attack_chain_id=None,
    )

    filtered.sort(key=lambda i: i.first_seen or datetime.min, reverse=True)
    result = _paginate(filtered, page, page_size)
    result["items"] = [ioc.model_dump(mode="json") for ioc in result["items"]]
    return result


# ─────────────────────────────────────────────────────────────────────────────
# D. IOC Summary  (static path — must come before /{ioc_id})
# ─────────────────────────────────────────────────────────────────────────────

@router.get("/summary", summary="Aggregate IOC statistics")
async def get_ioc_summary(
    session_id: Optional[str] = Query(None, description="Scope summary to a specific session"),
):
    """
    Return aggregate IOC statistics for the current in-memory repository.

    Metrics are computed deterministically from repository state without
    any external network access.
    """
    if session_id:
        iocs = ioc_repository.find_iocs_by_session(session_id)
    else:
        iocs = ioc_repository.list_iocs()

    total = len(iocs)
    by_type: Dict[str, int] = defaultdict(int)
    by_status: Dict[str, int] = defaultdict(int)
    by_validation_status: Dict[str, int] = defaultdict(int)
    public_ip_count = 0
    private_ip_count = 0
    top_ip_counts: Dict[str, int] = {}
    top_domain_counts: Dict[str, int] = {}
    top_hash_counts: Dict[str, int] = {}
    chains_seen: Set[str] = set()
    incidents_seen: Set[str] = set()

    for ioc in iocs:
        by_type[ioc.ioc_type.value] += 1
        by_status[ioc.status.value] += 1

        # Validation status from evidence references (if any validator populated it)
        for ev in ioc.evidence_references:
            vs = getattr(ev, "validation_status", None)
            if vs is not None:
                by_validation_status[vs.value] += 1

        # IP scope breakdown (extracted from validator-populated metadata)
        if ioc.ioc_type in (IOCType.IPV4, IOCType.IPV6):
            # ip_scope is stored on IOCValidationResult, not IOC directly;
            # determine from tags if present, otherwise skip
            if "public-ip" in ioc.tags:
                public_ip_count += 1
            elif "private-ip" in ioc.tags:
                private_ip_count += 1

            top_ip_counts[ioc.normalized_value] = ioc.occurrence_count

        elif ioc.ioc_type == IOCType.DOMAIN:
            top_domain_counts[ioc.normalized_value] = ioc.occurrence_count

        elif ioc.ioc_type in (IOCType.MD5, IOCType.SHA1, IOCType.SHA256):
            top_hash_counts[ioc.normalized_value] = ioc.occurrence_count

        chains_seen.update(ioc.associated_chain_ids)
        incidents_seen.update(ioc.associated_incident_ids)

    # Top-10 by occurrence count
    top_ips = sorted(top_ip_counts.items(), key=lambda x: x[1], reverse=True)[:10]
    top_domains = sorted(top_domain_counts.items(), key=lambda x: x[1], reverse=True)[:10]
    top_hashes = sorted(top_hash_counts.items(), key=lambda x: x[1], reverse=True)[:10]

    return {
        "session_id": session_id,
        "total_iocs": total,
        "by_type": dict(by_type),
        "by_status": dict(by_status),
        "by_validation_status": dict(by_validation_status),
        "public_ip_count": public_ip_count,
        "private_ip_count": private_ip_count,
        "suspicious_count": by_status.get(IOCStatus.UNDER_REVIEW.value, 0),
        "confirmed_count": by_status.get(IOCStatus.CONFIRMED.value, 0),
        "under_review_count": by_status.get(IOCStatus.UNDER_REVIEW.value, 0),
        "false_positive_count": by_status.get(IOCStatus.FALSE_POSITIVE.value, 0),
        "top_ips": top_ips,
        "top_domains": top_domains,
        "top_hashes": top_hashes,
        "chains_with_iocs": len(chains_seen),
        "incidents_with_iocs": len(incidents_seen),
        "generated_at": datetime.utcnow().isoformat(),
    }


# ─────────────────────────────────────────────────────────────────────────────
# C. IOC Detail   (parameterised — must come AFTER all static paths)
# ─────────────────────────────────────────────────────────────────────────────

@router.get("/{ioc_id}", summary="Retrieve full IOC detail")
async def get_ioc(ioc_id: str):
    """
    Retrieve complete forensic detail for a single IOC by its unique identifier.

    Returns IOC identity, type, raw/normalized values, review status,
    confidence, chronology, extraction methods, tags, associated sessions,
    events, anomalies, incidents, and attack chains.
    """
    ioc = ioc_repository.get_ioc(ioc_id)
    if ioc is None:
        raise HTTPException(status_code=404, detail=f"IOC '{ioc_id}' not found.")
    return ioc.model_dump(mode="json")


# ─────────────────────────────────────────────────────────────────────────────
# E. IOC Evidence
# ─────────────────────────────────────────────────────────────────────────────

@router.get("/{ioc_id}/evidence", summary="Retrieve preserved evidence records for an IOC")
async def get_ioc_evidence(ioc_id: str):
    """
    Return the read-only forensic evidence records for a specific IOC.

    Each record preserves: event ID, session ID, timestamp, raw value,
    source field, line number, surrounding context, and relationship refs.
    Evidence is never modified through this endpoint.
    """
    ioc = ioc_repository.get_ioc(ioc_id)
    if ioc is None:
        raise HTTPException(status_code=404, detail=f"IOC '{ioc_id}' not found.")

    return {
        "ioc_id": ioc_id,
        "ioc_type": ioc.ioc_type.value,
        "normalized_value": ioc.normalized_value,
        "occurrence_count": ioc.occurrence_count,
        "evidence_count": len(ioc.evidence_references),
        "evidence": [ev.model_dump(mode="json") for ev in ioc.evidence_references],
    }


# ─────────────────────────────────────────────────────────────────────────────
# F. IOC Review Status Update
# ─────────────────────────────────────────────────────────────────────────────

@router.patch("/{ioc_id}/status", summary="Update IOC analyst review status")
async def update_ioc_status(
    ioc_id: str,
    update: IOCStatusUpdate = Body(...),
):
    """
    Transition an IOC to a new analyst review status.

    Allowed transitions:
      EXTRACTED      → UNDER_REVIEW | CONFIRMED | FALSE_POSITIVE
      UNDER_REVIEW   → CONFIRMED | FALSE_POSITIVE | EXTRACTED
      CONFIRMED      → UNDER_REVIEW | FALSE_POSITIVE
      FALSE_POSITIVE → UNDER_REVIEW | CONFIRMED

    Every transition requires a reason of at least 5 characters.
    ValidationStatus (syntactic validity) is NOT affected by this endpoint.
    Raw forensic evidence is never modified.
    """
    ioc = ioc_repository.get_ioc(ioc_id)
    if ioc is None:
        raise HTTPException(status_code=404, detail=f"IOC '{ioc_id}' not found.")

    current_status = ioc.status
    target_status = update.status

    allowed = VALID_IOC_STATUS_TRANSITIONS.get(current_status, set())
    if target_status not in allowed:
        allowed_names = ", ".join(s.value for s in allowed) if allowed else "none"
        raise HTTPException(
            status_code=422,
            detail=(
                f"Invalid status transition: {current_status.value} → {target_status.value}. "
                f"Allowed from {current_status.value}: {allowed_names}."
            ),
        )

    # Build history entry
    history_entry = IOCStatusHistory(
        previous_status=current_status,
        new_status=target_status,
        changed_at=datetime.utcnow(),
        changed_by=update.changed_by,
        reason=update.reason,
    )
    new_history = list(ioc.status_history) + [history_entry.model_dump(mode="json")]

    # Apply note if provided
    new_note = update.analyst_note if update.analyst_note is not None else ioc.analyst_note

    updated_ioc = ioc.model_copy(update={
        "status": target_status,
        "analyst_note": new_note,
        "status_history": new_history,
    })

    # Persist back through repository (re-add replaces existing canonical entry)
    ioc_repository._iocs[ioc_id] = updated_ioc
    ioc_repository._sync_store(updated_ioc)

    logger.info(
        "IOC %s status: %s → %s (by %s)",
        ioc_id, current_status.value, target_status.value, update.changed_by or "anonymous"
    )
    return updated_ioc.model_dump(mode="json")


# ─────────────────────────────────────────────────────────────────────────────
# G. IOC Investigation Relationships
# ─────────────────────────────────────────────────────────────────────────────

@router.get("/{ioc_id}/relationships", summary="Retrieve evidence-backed investigation relationships")
async def get_ioc_relationships(ioc_id: str):
    """
    Return structured, evidence-backed relationships for a single IOC.

    Relationships to sessions, events, anomalies, incidents, and attack chains
    are derived exclusively from the IOC's own evidence_references and
    associated_* fields — never inferred from session sharing alone.
    """
    ioc = ioc_repository.get_ioc(ioc_id)
    if ioc is None:
        raise HTTPException(status_code=404, detail=f"IOC '{ioc_id}' not found.")

    # Sessions
    sessions: List[Dict] = [
        {"session_id": sid} for sid in ioc.source_sessions
    ]

    # Events (from evidence references)
    seen_events: Set[str] = set()
    events: List[Dict] = []
    for ev in ioc.evidence_references:
        if ev.event_id not in seen_events:
            seen_events.add(ev.event_id)
            events.append({
                "event_id": ev.event_id,
                "session_id": ev.session_id,
                "timestamp": ev.timestamp.isoformat() if ev.timestamp else None,
                "line_number": ev.line_number,
                "raw_value": ev.raw_value,
                "source_field": ev.source_field,
                "surrounding_context": ev.surrounding_context,
            })

    # Anomalies
    anomalies: List[Dict] = [
        {"anomaly_id": aid} for aid in ioc.associated_anomaly_ids
    ]

    # Incidents
    incidents: List[Dict] = [
        {"incident_id": inc_id} for inc_id in ioc.associated_incident_ids
    ]

    # Attack chains
    attack_chains: List[Dict] = [
        {"chain_id": cid} for cid in ioc.associated_chain_ids
    ]

    return {
        "ioc_id": ioc_id,
        "ioc_type": ioc.ioc_type.value,
        "normalized_value": ioc.normalized_value,
        "relationship_count": len(sessions) + len(events) + len(anomalies) + len(incidents) + len(attack_chains),
        "unified_context_url": f"/api/threat-correlation/ioc/{ioc_id}/context",
        "sessions": sessions,
        "events": events,
        "anomalies": anomalies,
        "incidents": incidents,
        "attack_chains": attack_chains,
    }

