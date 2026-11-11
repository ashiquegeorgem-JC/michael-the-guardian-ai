"""
Attack Chains router — Phase 4.1 / 4.1A.

Provides endpoints for:
  • Reconstructed attack chain listing, detail, timeline and graph (Phase 4.1).
  • Advanced search, lifecycle management, event confirmation,
    related-entity discovery and aggregate summary (Phase 4.1A).

STORAGE NOTE:
  All chain data is held in the in-memory SessionStore.
  Data is lost on server restart.  A persistent repository is planned
  for a future phase and will be drop-in compatible with these endpoints.
"""

from fastapi import APIRouter, HTTPException, Query, Body
from typing import Optional, List
from datetime import datetime

from app.models.attack_chain import (
    AttackChain,
    AttackChainTimeline,
    AttackGraphData,
    AttackStage,
    ChainStatus,
    ChainStatusUpdate,
    ChainValidationResult,
    ChainSearchParams,
    ChainSearchResult,
    ChainSummary,
    RelatedEntitiesResponse,
)
from app.services.store import store
from app.services.chain_validator import ChainValidator
from app.services.chain_search_service import ChainSearchService
from app.services.chain_status_service import ChainStatusService
from app.services.cross_session_correlator import CrossSessionCorrelator

router = APIRouter()


@router.get("", response_model=List[AttackChain])
async def list_attack_chains(
    session_id: Optional[str] = Query(None, description="Filter by session ID"),
    severity: Optional[str] = Query(None, description="Filter by severity (LOW, MEDIUM, HIGH, CRITICAL)"),
    stage: Optional[str] = Query(None, description="Filter by attack stage name"),
):
    """
    Retrieve all reconstructed attack chains for a session with optional severity and stage filtering.
    """
    sid = session_id or store.active_session_id
    if not sid:
        return []

    chains = store.get_attack_chains(sid)

    # Filter by severity
    if severity:
        sev_upper = severity.upper()
        chains = [c for c in chains if c.severity == sev_upper]

    # Filter by stage
    if stage:
        chains = [
            c for c in chains
            if any(s.value.lower() == stage.lower() for s in c.stages_observed)
            or any(s.value.lower() == stage.lower() for s in c.stages_unconfirmed)
        ]

    return chains


# ─────────────────────────────────────────────────────────────────────────────
# Phase 4.1A — Static route endpoints (must precede parameterized /{chain_id})
# ─────────────────────────────────────────────────────────────────────────────

@router.get(
    "/summary",
    response_model=ChainSummary,
    summary="Aggregate attack-chain statistics",
    description=(
        "Returns total chain count, severity distribution, status distribution, "
        "MITRE stage distribution, top attacker IPs, average confidence and "
        "duration, and the five most recently observed chains. "
        "Results span all sessions in the current store."
    ),
)
async def get_chain_summary(
    session_id: Optional[str] = Query(None, description="Limit summary to a specific session"),
):
    """
    Aggregate statistics across all attack chains.
    Optionally scoped to a single session via session_id.
    """
    if session_id:
        chains = store.get_attack_chains(session_id)
    else:
        chains = [c for lst in store.attack_chains.values() for c in lst]

    total = len(chains)

    by_severity: dict = {}
    by_status: dict   = {}
    by_stage: dict    = {}
    ip_counts: dict   = {}
    confidence_sum    = 0.0
    duration_sum      = 0.0

    for c in chains:
        # Severity
        by_severity[c.severity] = by_severity.get(c.severity, 0) + 1

        # Status (default NEW for chains created before 4.1A)
        status_val = getattr(c, "status", ChainStatus.NEW)
        status_key = status_val.value if isinstance(status_val, ChainStatus) else str(status_val)
        by_status[status_key] = by_status.get(status_key, 0) + 1

        # Stages
        for s in c.stages_observed:
            by_stage[s.value] = by_stage.get(s.value, 0) + 1

        # Source IPs
        for ip in c.source_ips:
            ip_counts[ip] = ip_counts.get(ip, 0) + 1

        confidence_sum += c.confidence_score
        duration_sum   += c.duration_seconds

    avg_confidence = round(confidence_sum / total, 4) if total else 0.0
    avg_duration   = round(duration_sum   / total, 2) if total else 0.0

    top_ips = sorted(ip_counts.items(), key=lambda x: x[1], reverse=True)[:10]

    # Most recent chains (by first_seen descending; chains without timestamps last)
    def _ts_key(c: AttackChain):
        return c.first_seen or datetime.min

    recent = sorted(chains, key=_ts_key, reverse=True)[:5]

    return ChainSummary(
        total_chains=total,
        by_severity=by_severity,
        by_status=by_status,
        by_stage=by_stage,
        top_source_ips=top_ips,
        avg_confidence=avg_confidence,
        avg_duration_seconds=avg_duration,
        recent_chains=recent,
    )


@router.get(
    "/search",
    response_model=ChainSearchResult,
    summary="Advanced multi-criteria attack-chain search",
    description=(
        "Searches attack chains by any combination of: chain_id, session_id, "
        "source_ip, destination_ip, username, MITRE stage, severity, status, "
        "free-text keyword, time range, or event_id.  "
        "All supplied filters are applied together (AND logic).  "
        "Supports pagination (page / page_size) and sorting (sort_by / sort_desc)."
    ),
)
async def search_attack_chains(
    session_id:     Optional[str]  = Query(None,         description="Filter by session ID"),
    chain_id:       Optional[str]  = Query(None,         description="Exact chain ID match"),
    source_ip:      Optional[str]  = Query(None,         description="Source IP substring match"),
    destination_ip: Optional[str]  = Query(None,         description="Destination IP / target-host substring match"),
    username:       Optional[str]  = Query(None,         description="Affected username substring match"),
    stage:          Optional[str]  = Query(None,         description="MITRE attack stage (case-insensitive)"),
    severity:       Optional[str]  = Query(None,         description="Severity level: LOW / MEDIUM / HIGH / CRITICAL"),
    status:         Optional[ChainStatus] = Query(None,  description="Investigation status"),
    keyword:        Optional[str]  = Query(None,         description="Free-text search across title, summary and evidence"),
    start_time:     Optional[datetime] = Query(None,     description="Only chains seen on or after this time (ISO 8601)"),
    end_time:       Optional[datetime] = Query(None,     description="Only chains seen on or before this time (ISO 8601)"),
    event_id:       Optional[str]  = Query(None,         description="Match by ChainLinkEvent.id or log_entry_id"),
    page:           int            = Query(1,   ge=1,    description="Page number"),
    page_size:      int            = Query(20,  ge=1, le=100, description="Results per page"),
    sort_by:        str            = Query("first_seen", description="Field to sort by"),
    sort_desc:      bool           = Query(True,         description="Descending sort when true"),
):
    """
    Full-featured attack chain search with multi-dimensional filtering.
    Multiple filters are combined with AND logic.
    """
    params = ChainSearchParams(
        session_id=session_id,
        chain_id=chain_id,
        source_ip=source_ip,
        destination_ip=destination_ip,
        username=username,
        stage=stage,
        severity=severity,
        status=status,
        keyword=keyword,
        start_time=start_time,
        end_time=end_time,
        event_id=event_id,
        page=page,
        page_size=page_size,
        sort_by=sort_by,
        sort_desc=sort_desc,
    )
    return ChainSearchService.search(params)


# ─────────────────────────────────────────────────────────────────────────────
# Parameterized endpoints (/{chain_id})
# ─────────────────────────────────────────────────────────────────────────────

@router.get("/{chain_id}", response_model=AttackChain)
async def get_attack_chain(chain_id: str):
    """
    Retrieve full forensic details for a specific reconstructed attack chain.
    """
    chain = store.get_attack_chain(chain_id)
    if not chain:
        raise HTTPException(
            status_code=404,
            detail=f"Attack chain '{chain_id}' not found in active session store."
        )
    return chain


@router.get("/{chain_id}/timeline", response_model=AttackChainTimeline)
async def get_attack_chain_timeline(chain_id: str):
    """
    Retrieve the chronological timeline of events for an attack chain.
    """
    chain = store.get_attack_chain(chain_id)
    if not chain:
        raise HTTPException(
            status_code=404,
            detail=f"Attack chain '{chain_id}' not found."
        )

    return AttackChainTimeline(
        chain_id=chain.id,
        session_id=chain.session_id,
        first_seen=chain.first_seen,
        last_seen=chain.last_seen,
        duration_seconds=chain.duration_seconds,
        total_events=len(chain.events),
        events=chain.events,
    )


@router.get("/{chain_id}/graph", response_model=AttackGraphData)
async def get_attack_chain_graph(chain_id: str):
    """
    Retrieve entity-relationship graph data (nodes and directed edges) for visualization.
    """
    chain = store.get_attack_chain(chain_id)
    if not chain:
        raise HTTPException(
            status_code=404,
            detail=f"Attack chain '{chain_id}' not found."
        )

    return chain.graph_data or AttackGraphData(nodes=[], edges=[])


@router.patch(
    "/{chain_id}/status",
    response_model=AttackChain,
    summary="Update attack chain investigation status",
    description=(
        "Transition the investigation lifecycle status of an attack chain. "
        "Valid transitions: NEW→INVESTIGATING, NEW→FALSE_POSITIVE, "
        "INVESTIGATING→CONFIRMED, INVESTIGATING→FALSE_POSITIVE, "
        "INVESTIGATING→RESOLVED, CONFIRMED→RESOLVED, CONFIRMED→INVESTIGATING, "
        "FALSE_POSITIVE→INVESTIGATING, RESOLVED→INVESTIGATING. "
        "Every transition requires a mandatory reason. "
        "The full audit history is preserved in status_history."
    ),
)
async def update_chain_status(
    chain_id: str,
    update: ChainStatusUpdate = Body(..., description="New status, reason, and optional analyst ID"),
):
    """
    Update the investigation lifecycle status of a specific attack chain.
    Validates the transition and appends to the chain's audit history.
    """
    updated_chain, error = ChainStatusService.update_status(chain_id, update)

    if error:
        # Distinguish not-found vs invalid-transition
        if "not found" in error.lower():
            raise HTTPException(status_code=404, detail=error)
        raise HTTPException(status_code=422, detail=error)

    return updated_chain


@router.post(
    "/{chain_id}/events/{event_id}/confirm",
    response_model=dict,
    summary="Confirm or reject an event's association with the chain",
    description=(
        "Mark a specific ChainLinkEvent as analyst-confirmed or analyst-rejected. "
        "Matching is attempted by ChainLinkEvent.id, then by log_entry_id. "
        "A mandatory reason must be supplied. "
        "Only is_confirmed and correlation_reason are changed; all other "
        "event fields (raw_log, stage, timestamp, etc.) are preserved."
    ),
)
async def confirm_chain_event(
    chain_id: str,
    event_id: str,
    is_confirmed: bool = Body(..., description="True to confirm; False to reject"),
    reason: str = Body(..., min_length=3, description="Analyst reasoning (required)"),
    changed_by: Optional[str] = Body(None, description="Analyst username or ID"),
):
    """
    Confirm or reject a specific event's membership in an attack chain.
    """
    updated_event, error = ChainStatusService.confirm_event(
        chain_id=chain_id,
        event_id=event_id,
        is_confirmed=is_confirmed,
        reason=reason,
        changed_by=changed_by,
    )

    if error:
        if "not found" in error.lower():
            raise HTTPException(status_code=404, detail=error)
        raise HTTPException(status_code=422, detail=error)

    decision = "confirmed" if is_confirmed else "rejected"
    return {
        "chain_id": chain_id,
        "event_id": event_id,
        "decision": decision,
        "is_confirmed": updated_event.is_confirmed,
        "correlation_reason": updated_event.correlation_reason,
        "changed_by": changed_by,
    }


@router.get(
    "/{chain_id}/related",
    response_model=RelatedEntitiesResponse,
    summary="Related forensic entities and potential cross-session chains",
    description=(
        "Returns all forensic entities associated with this chain (source IPs, "
        "targeted users, host systems, upload session), plus any chains in other "
        "sessions that share corroborating evidence. "
        "Cross-session associations are marked is_confirmed=False and require "
        "analyst review before being treated as confirmed links. "
        "Seven false-correlation prevention rules are applied: a shared IP alone "
        "is not sufficient to emit a cross-session link."
    ),
)
async def get_related_entities(chain_id: str):
    """
    Retrieve all related forensic entities and potential cross-session associations
    for a specific attack chain.
    """
    chain = store.get_attack_chain(chain_id)
    if not chain:
        raise HTTPException(
            status_code=404,
            detail=f"Attack chain '{chain_id}' not found.",
        )

    return CrossSessionCorrelator.build_related_entities(chain)
