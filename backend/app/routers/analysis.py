"""Analysis router - triggers ML pipeline and returns results."""

from fastapi import APIRouter, HTTPException, BackgroundTasks, Query
from typing import Optional
import logging

from app.models.anomaly import AnalysisRequest, AnalysisStatus
from app.ml.pipeline import run_anomaly_detection
from app.ml.attack_chain_engine import reconstruct_attack_chains
from app.services.incident_service import generate_all_incidents
from app.services.chain_validator import ChainValidator
from app.services.store import store
from app.config import settings

logger = logging.getLogger("michael.analysis")
router = APIRouter()
_analysis_status: dict = {}  # session_id → status dict


def _run_analysis(session_id: str, contamination: float):
    """Background task: run full ML pipeline."""
    _analysis_status[session_id] = {"status": "running", "progress": 10, "message": "Loading log entries..."}
    try:
        entries = store.get_entries(session_id)
        if not entries:
            _analysis_status[session_id] = {"status": "failed", "progress": 0, "message": "No entries found"}
            return

        _analysis_status[session_id] = {"status": "running", "progress": 30, "message": "Running anomaly detection..."}
        anomalies, metrics = run_anomaly_detection(entries, session_id, contamination)

        _analysis_status[session_id] = {"status": "running", "progress": 70, "message": "Generating incidents..."}
        incidents = generate_all_incidents(anomalies, entries)

        _analysis_status[session_id] = {"status": "running", "progress": 85, "message": "Reconstructing attack chains..."}
        attack_chains = reconstruct_attack_chains(entries, anomalies, incidents, session_id)

        # Validate generated attack chains
        for chain in attack_chains:
            val_res = ChainValidator.validate(chain)
            if not val_res.is_valid:
                logger.warning(
                    "Chain [%s] validation errors: %s",
                    chain.id,
                    [e.message for e in val_res.errors],
                )

        store.set_analysis(session_id, anomalies, metrics)
        store.set_incidents(session_id, incidents)
        store.set_attack_chains(session_id, attack_chains)

        # Phase 4.2A.4: IOC Extraction, Validation, Evidence Mapping & Repository Integration
        try:
            from app.services.ioc_evidence_mapper import IOCEvidenceMapper
            from app.services.ioc_repository import ioc_repository

            mapped_iocs = IOCEvidenceMapper.extract_and_map_from_events(
                entries=entries,
                anomalies=anomalies,
                incidents=incidents,
                attack_chains=attack_chains,
                session_id=session_id,
            )
            ioc_repository.add_iocs(mapped_iocs)
            logger.info("Mapped and stored %d IOCs for session %s", len(mapped_iocs), session_id)
        except Exception as e:
            logger.warning("IOC mapping for session %s failed: %s", session_id, e)

        _analysis_status[session_id] = {
            "status": "complete",
            "progress": 100,
            "message": f"Analysis complete: {len(anomalies)} anomalies, {len(incidents)} incidents, {len(attack_chains)} attack chains",
        }
    except Exception as e:
        _analysis_status[session_id] = {"status": "failed", "progress": 0, "message": str(e)}


@router.post("/run")
async def run_analysis(req: AnalysisRequest, bg: BackgroundTasks):
    """Trigger anomaly detection pipeline on an uploaded session."""
    session = store.get_session(req.session_id)
    if not session:
        raise HTTPException(status_code=404, detail="Session not found. Upload a log file first.")

    contamination = req.contamination or settings.MODEL_CONTAMINATION
    _analysis_status[req.session_id] = {"status": "pending", "progress": 0, "message": "Queued"}
    bg.add_task(_run_analysis, req.session_id, contamination)

    return {"message": "Analysis started", "session_id": req.session_id}


@router.get("/status/{session_id}")
async def analysis_status(session_id: str):
    """Check the progress of an ongoing analysis."""
    status = _analysis_status.get(session_id, {"status": "not_started", "progress": 0, "message": ""})
    return {"session_id": session_id, **status}


@router.get("/results")
async def get_results(session_id: Optional[str] = Query(None)):
    """Get anomaly detection results for a session."""
    sid = session_id or store.active_session_id
    if not sid:
        raise HTTPException(status_code=404, detail="No active session.")

    anomalies = store.get_anomalies(sid)
    metrics = store.get_metrics(sid)

    return {
        "session_id": sid,
        "anomalies": [a.model_dump() for a in anomalies],
        "metrics": metrics.model_dump() if metrics else None,
        "total_anomalies": len(anomalies),
    }


@router.get("/metrics")
async def get_metrics(session_id: Optional[str] = Query(None)):
    """Get model evaluation metrics for a session."""
    sid = session_id or store.active_session_id
    if not sid:
        raise HTTPException(status_code=404, detail="No active session.")
    metrics = store.get_metrics(sid)
    if not metrics:
        raise HTTPException(status_code=404, detail="No metrics available. Run analysis first.")
    return metrics.model_dump()


@router.get("/benchmark")
async def get_research_benchmark():
    """Retrieve independent research validation benchmark results and metrics."""
    import os
    import json
    json_path = os.path.join(os.path.dirname(__file__), "..", "..", "data", "research", "evaluation_summary.json")
    if not os.path.exists(json_path):
        raise HTTPException(status_code=404, detail="Benchmark evaluation data not yet generated.")
    try:
        with open(json_path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to read benchmark data: {e}")

