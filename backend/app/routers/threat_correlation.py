"""
Threat Correlation REST API Router for MICHAEL – THE GUARDIAN AI.

Phase 4.2B.4 — Threat Correlation & Unified Intelligence Engine.

Provides typed REST endpoints for:
- Retrieving unified threat investigation context
- Inspecting directional correlations between IOCs and events, anomalies, incidents, and attack chains
- Filtering correlations by type and confirmation state

ROUTE REGISTRATION NOTE:
=======================
Specific sub-paths (/context, /anomalies, /incidents, /attack-chains, /events)
are registered BEFORE the general parameterized path (/ioc/{ioc_id}) to prevent
any route shadowing.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, HTTPException, Query

from app.models.threat_correlation import (
    ThreatCorrelation,
    ThreatCorrelationType,
    UnifiedThreatContext,
)
from app.services.ioc_repository import ioc_repository
from app.services.threat_correlation_engine import threat_correlation_engine

logger = logging.getLogger("michael.threat_correlation.api")

router = APIRouter()


# ─────────────────────────────────────────────────────────────────────────────
# 1. Unified Threat Context
# ─────────────────────────────────────────────────────────────────────────────

@router.get(
    "/ioc/{ioc_id}/context",
    response_model=UnifiedThreatContext,
    summary="Retrieve full Unified Threat Context for an IOC",
)
async def get_unified_threat_context(
    ioc_id: str,
    force_refresh: bool = Query(
        default=False,
        description="Whether to bypass cache and recalculate external threat intelligence",
    ),
):
    """
    Returns the comprehensive, consolidated threat investigation context for an IOC.

    Includes:
    - IOC core properties and current analyst status
    - Threat assessment (score, severity, confidence, contributing signals)
    - Correlated log events, anomalies, incidents, and attack chains
    - Directional ThreatCorrelation evidence objects
    - Evidence-based investigation summary
    """
    ioc = ioc_repository.get_ioc(ioc_id)
    if ioc is None:
        raise HTTPException(status_code=404, detail=f"IOC '{ioc_id}' not found.")

    context = threat_correlation_engine.build_unified_context(
        ioc, force_refresh_assessment=force_refresh
    )
    return context


# ─────────────────────────────────────────────────────────────────────────────
# 2. Correlated Entities Sub-Endpoints
# ─────────────────────────────────────────────────────────────────────────────

@router.get(
    "/ioc/{ioc_id}/anomalies",
    summary="Retrieve anomalies correlated with an IOC",
)
async def get_correlated_anomalies(ioc_id: str) -> Dict[str, Any]:
    """Retrieve all anomalies correlated with this IOC, including evidence and confidence."""
    ioc = ioc_repository.get_ioc(ioc_id)
    if ioc is None:
        raise HTTPException(status_code=404, detail=f"IOC '{ioc_id}' not found.")

    correlations = threat_correlation_engine.correlate_anomalies(ioc)
    return {
        "ioc_id": ioc_id,
        "ioc_type": ioc.ioc_type.value,
        "normalized_value": ioc.normalized_value,
        "total": len(correlations),
        "anomalies": [c.model_dump(mode="json") for c in correlations],
    }


@router.get(
    "/ioc/{ioc_id}/incidents",
    summary="Retrieve incidents correlated with an IOC",
)
async def get_correlated_incidents(ioc_id: str) -> Dict[str, Any]:
    """Retrieve all security incidents correlated with this IOC, including evidence and confidence."""
    ioc = ioc_repository.get_ioc(ioc_id)
    if ioc is None:
        raise HTTPException(status_code=404, detail=f"IOC '{ioc_id}' not found.")

    anomaly_corrs = threat_correlation_engine.correlate_anomalies(ioc)
    incident_corrs = threat_correlation_engine.correlate_incidents(
        ioc, correlated_anomalies=anomaly_corrs
    )
    return {
        "ioc_id": ioc_id,
        "ioc_type": ioc.ioc_type.value,
        "normalized_value": ioc.normalized_value,
        "total": len(incident_corrs),
        "incidents": [c.model_dump(mode="json") for c in incident_corrs],
    }


@router.get(
    "/ioc/{ioc_id}/attack-chains",
    summary="Retrieve attack chains correlated with an IOC",
)
async def get_correlated_attack_chains(ioc_id: str) -> Dict[str, Any]:
    """Retrieve all attack chains correlated with this IOC, including MITRE stages and confidence."""
    ioc = ioc_repository.get_ioc(ioc_id)
    if ioc is None:
        raise HTTPException(status_code=404, detail=f"IOC '{ioc_id}' not found.")

    anomaly_corrs = threat_correlation_engine.correlate_anomalies(ioc)
    incident_corrs = threat_correlation_engine.correlate_incidents(
        ioc, correlated_anomalies=anomaly_corrs
    )
    chain_corrs = threat_correlation_engine.correlate_attack_chains(
        ioc,
        correlated_incidents=incident_corrs,
        correlated_anomalies=anomaly_corrs,
    )
    return {
        "ioc_id": ioc_id,
        "ioc_type": ioc.ioc_type.value,
        "normalized_value": ioc.normalized_value,
        "total": len(chain_corrs),
        "attack_chains": [c.model_dump(mode="json") for c in chain_corrs],
    }


@router.get(
    "/ioc/{ioc_id}/events",
    summary="Retrieve log events correlated with an IOC",
)
async def get_correlated_events(ioc_id: str) -> Dict[str, Any]:
    """Retrieve all log events where this IOC was extracted, including context and line numbers."""
    ioc = ioc_repository.get_ioc(ioc_id)
    if ioc is None:
        raise HTTPException(status_code=404, detail=f"IOC '{ioc_id}' not found.")

    event_corrs = threat_correlation_engine.correlate_events(ioc)
    return {
        "ioc_id": ioc_id,
        "ioc_type": ioc.ioc_type.value,
        "normalized_value": ioc.normalized_value,
        "total": len(event_corrs),
        "events": [c.model_dump(mode="json") for c in event_corrs],
    }


# ─────────────────────────────────────────────────────────────────────────────
# 3. All Correlations for IOC
# ─────────────────────────────────────────────────────────────────────────────

@router.get(
    "/ioc/{ioc_id}",
    summary="Retrieve all threat correlations for an IOC",
)
async def get_ioc_correlations(
    ioc_id: str,
    correlation_type: Optional[ThreatCorrelationType] = Query(
        default=None,
        description="Filter correlations by relationship type",
    ),
    confirmed_only: bool = Query(
        default=False,
        description="Only return confirmed correlations (exclude cross-session/unconfirmed)",
    ),
) -> Dict[str, Any]:
    """
    Returns all directional ThreatCorrelation objects for a given IOC.

    Allows filtering by correlation_type and confirmation state.
    """
    ioc = ioc_repository.get_ioc(ioc_id)
    if ioc is None:
        raise HTTPException(status_code=404, detail=f"IOC '{ioc_id}' not found.")

    correlations = threat_correlation_engine.correlate_ioc(ioc)

    if correlation_type:
        correlations = [c for c in correlations if c.correlation_type == correlation_type]

    if confirmed_only:
        correlations = [c for c in correlations if c.confirmed]

    confirmed_count = sum(1 for c in correlations if c.confirmed)
    unconfirmed_count = len(correlations) - confirmed_count

    return {
        "ioc_id": ioc_id,
        "ioc_type": ioc.ioc_type.value,
        "normalized_value": ioc.normalized_value,
        "total": len(correlations),
        "confirmed_count": confirmed_count,
        "unconfirmed_count": unconfirmed_count,
        "correlations": [c.model_dump(mode="json") for c in correlations],
    }

