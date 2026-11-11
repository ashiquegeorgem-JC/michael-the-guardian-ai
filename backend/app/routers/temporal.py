"""Temporal analysis router — exposes sliding-window telemetry and temporal anomaly data."""

from fastapi import APIRouter, HTTPException, Query
from typing import Optional
from app.services.store import store
from app.ml.temporal_engine import run_temporal_detection

router = APIRouter()


@router.get("/telemetry")
async def get_temporal_telemetry(session_id: Optional[str] = Query(None)):
    """
    Return temporal sliding-window telemetry for a session.
    Runs temporal detection on demand from stored entries.
    """
    sid = session_id or store.active_session_id
    if not sid:
        raise HTTPException(status_code=404, detail="No active session.")

    entries = store.get_entries(sid)
    if not entries:
        raise HTTPException(status_code=404, detail="No log entries found for this session.")

    try:
        _, telemetry = run_temporal_detection(entries, sid)
        return {
            "session_id": sid,
            "total_entries": len(entries),
            "telemetry": telemetry,
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Temporal analysis failed: {e}")


@router.get("/anomalies")
async def get_temporal_anomalies(session_id: Optional[str] = Query(None)):
    """
    Return only the temporal anomalies (method=temporal) for a session.
    Re-runs temporal detection from stored entries (lightweight).
    """
    sid = session_id or store.active_session_id
    if not sid:
        raise HTTPException(status_code=404, detail="No active session.")

    entries = store.get_entries(sid)
    if not entries:
        raise HTTPException(status_code=404, detail="No log entries found.")

    try:
        temporal_anomalies, telemetry = run_temporal_detection(entries, sid)
        return {
            "session_id": sid,
            "temporal_anomaly_count": len(temporal_anomalies),
            "anomalies": [a.model_dump() for a in temporal_anomalies],
            "summary": {
                "ip_spikes": len(telemetry.get("ip_spikes", [])),
                "endpoint_spikes": len(telemetry.get("endpoint_spikes", [])),
                "category_spikes": len(telemetry.get("category_spikes", [])),
                "auth_burst_ips": len(telemetry.get("auth_burst_ips", [])),
                "http_error_buckets": len(telemetry.get("http_error_rate_buckets", [])),
            },
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Temporal anomaly detection failed: {e}")


@router.get("/benchmark")
async def get_temporal_benchmark():
    """Retrieve independent Phase 3 / Phase 3.1 temporal benchmark results and audit metrics."""
    import os
    import json
    json_path = os.path.join(os.path.dirname(__file__), "..", "..", "data", "research", "temporal_evaluation_summary.json")
    if not os.path.exists(json_path):
        raise HTTPException(status_code=404, detail="Temporal benchmark evaluation data not yet generated.")
    try:
        with open(json_path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to read temporal benchmark data: {e}")

