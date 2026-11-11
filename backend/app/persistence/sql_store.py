"""
SQL Persistence Repository Implementation for MICHAEL – THE GUARDIAN AI.

Phase 5.0 — Production Hardening & Persistence Integration.

Provides database-backed storage for sessions, log events, anomalies,
model metrics, incidents, attack chains, and IOCs using SQLAlchemy.
Seamlessly converts between domain Pydantic models and relational tables.
"""

from datetime import datetime, timezone
import json
import logging
from typing import Any, Dict, List, Optional, Set, Tuple
import uuid

from sqlalchemy import and_, func, or_
from sqlalchemy.orm import Session

from app.models.anomaly import Anomaly, DetectionMethod, ModelMetrics, SeverityLevel
from app.models.attack_chain import (
    AttackChain,
    AttackStage,
    ChainLinkEvent,
    ChainStatus,
    ChainStatusHistory,
)
from app.models.incident import Incident, IncidentCategory, IncidentStatus
from app.models.ioc import (
    IOC,
    IOCEvidence,
    IOCStatus,
    IOCStatusHistory,
    IOCType,
    IPScope,
    ValidationStatus,
)
from app.models.log_entry import LogEntry, LogLevel, LogSession
from app.models.threat_intel import (
    ThreatAssessment,
    ThreatIntelResult,
    ThreatIntelSource,
    ThreatIntelStatus,
    ThreatSeverity,
)
from app.models.threat_correlation import (
    CorrelationConfidence,
    CorrelationConfidenceLevel,
    ThreatCorrelation,
    ThreatCorrelationType,
)
from app.persistence.database import DatabaseManager, db_manager
from app.persistence.models import (
    DBAnomaly,
    DBAttackChain,
    DBAuditRecord,
    DBEvent,
    DBIncident,
    DBIOC,
    DBIOCEvidence,
    DBModelMetrics,
    DBSession,
    DBThreatAssessment,
    DBThreatCorrelation,
    DBThreatIntelResult,
)

logger = logging.getLogger("michael.persistence.sql_store")


def _to_utc(dt: Optional[datetime]) -> Optional[datetime]:
    if dt is None:
        return None
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


class SQLStoreRepository:
    """
    SQLAlchemy-backed implementation of SessionStore persistence.
    """

    def __init__(self, manager: Optional[DatabaseManager] = None):
        self._db = manager if manager is not None else db_manager

    # ── Sessions & Log Entries ───────────────────────────────────────────────

    def set_session(self, session: LogSession, entries: List[LogEntry]):
        with self._db.session() as db:
            db_sess = db.query(DBSession).filter(DBSession.id == session.id).first()
            if not db_sess:
                db_sess = DBSession(
                    id=session.id,
                    filename=session.filename,
                    uploaded_at=_to_utc(session.uploaded_at),
                    total_lines=session.total_lines,
                    file_size=session.file_size,
                    status=session.status,
                )
                db.add(db_sess)
            else:
                db_sess.filename = session.filename
                db_sess.uploaded_at = _to_utc(session.uploaded_at)
                db_sess.total_lines = session.total_lines
                db_sess.file_size = session.file_size
                db_sess.status = session.status

            # Batch insert log entries
            existing_event_ids = {e[0] for e in db.query(DBEvent.id).filter(DBEvent.session_id == session.id).all()}
            for entry in entries:
                if entry.id in existing_event_ids:
                    continue
                db_event = DBEvent(
                    id=entry.id,
                    session_id=session.id,
                    line_number=entry.line_number,
                    timestamp=_to_utc(entry.timestamp),
                    level=entry.level.value if hasattr(entry.level, "value") else str(entry.level),
                    source=entry.source,
                    message=entry.message,
                    raw=getattr(entry, "raw_line", getattr(entry, "raw", "")),
                    ip_address=getattr(entry, "ip_address", None),
                    user_name=getattr(entry, "user", getattr(entry, "user_name", None)),
                    action=getattr(entry, "action", None),
                    status_code=getattr(entry, "status_code", None),
                )
                db.add(db_event)

    def get_session(self, session_id: str) -> Optional[LogSession]:
        with self._db.session() as db:
            row = db.query(DBSession).filter(DBSession.id == session_id).first()
            if not row:
                return None
            return LogSession(
                id=row.id,
                filename=row.filename,
                uploaded_at=_to_utc(row.uploaded_at),
                total_lines=row.total_lines,
                file_size=row.file_size,
                status=row.status,
            )

    def get_all_sessions(self) -> List[LogSession]:
        with self._db.session() as db:
            rows = db.query(DBSession).order_by(DBSession.uploaded_at.desc()).all()
            return [
                LogSession(
                    id=r.id,
                    filename=r.filename,
                    uploaded_at=_to_utc(r.uploaded_at),
                    total_lines=r.total_lines,
                    file_size=r.file_size,
                    status=r.status,
                )
                for r in rows
            ]

    def get_entries(self, session_id: str) -> List[LogEntry]:
        with self._db.session() as db:
            rows = db.query(DBEvent).filter(DBEvent.session_id == session_id).order_by(DBEvent.line_number.asc()).all()
            entries = []
            for r in rows:
                entries.append(
                    LogEntry(
                        id=r.id,
                        session_id=r.session_id,
                        line_number=r.line_number,
                        timestamp=_to_utc(r.timestamp),
                        level=LogLevel(r.level) if r.level in LogLevel.__members__.values() else LogLevel.INFO,
                        source=r.source,
                        message=r.message,
                        raw_line=r.raw or "",
                    )
                )
            return entries

    # ── Anomalies & Metrics ──────────────────────────────────────────────────

    def set_analysis(self, session_id: str, anomalies: List[Anomaly], metrics: ModelMetrics):
        with self._db.session() as db:
            # Delete prior anomalies for this session to allow re-analysis
            db.query(DBAnomaly).filter(DBAnomaly.session_id == session_id).delete()
            for a in anomalies:
                db_anom = DBAnomaly(
                    id=a.id,
                    session_id=session_id,
                    score=a.score,
                    severity=a.severity.value if hasattr(a.severity, "value") else str(a.severity),
                    reason=a.reason,
                    method=a.method.value if hasattr(a.method, "value") else str(a.method),
                    detected_at=_to_utc(a.detected_at),
                    log_entry_ids=a.log_entry_ids,
                    features=a.features or {},
                )
                db.add(db_anom)

            # Upsert model metrics
            db_metrics = db.query(DBModelMetrics).filter(DBModelMetrics.session_id == session_id).first()
            if not db_metrics:
                db_metrics = DBModelMetrics(
                    id=f"metrics-{session_id}",
                    session_id=session_id,
                    total_logs=metrics.total_logs,
                    anomalies_detected=metrics.anomalies_detected,
                    contamination_rate=metrics.contamination_rate,
                    processing_time_ms=metrics.processing_time_ms,
                    baseline_deviation=metrics.baseline_deviation,
                    severity_distribution=metrics.severity_distribution,
                )
                db.add(db_metrics)
            else:
                db_metrics.total_logs = metrics.total_logs
                db_metrics.anomalies_detected = metrics.anomalies_detected
                db_metrics.contamination_rate = metrics.contamination_rate
                db_metrics.processing_time_ms = metrics.processing_time_ms
                db_metrics.baseline_deviation = metrics.baseline_deviation
                db_metrics.severity_distribution = metrics.severity_distribution

    def get_anomalies(self, session_id: str) -> List[Anomaly]:
        with self._db.session() as db:
            rows = db.query(DBAnomaly).filter(DBAnomaly.session_id == session_id).order_by(DBAnomaly.detected_at.asc()).all()
            result = []
            for r in rows:
                result.append(
                    Anomaly(
                        id=r.id,
                        session_id=r.session_id,
                        log_entry_ids=r.log_entry_ids or [],
                        score=r.score,
                        severity=SeverityLevel(r.severity) if r.severity in SeverityLevel.__members__.values() else SeverityLevel.MEDIUM,
                        reason=r.reason,
                        method=DetectionMethod(r.method) if r.method in DetectionMethod.__members__.values() else DetectionMethod.RULE_BASED,
                        detected_at=_to_utc(r.detected_at),
                        features=r.features or {},
                    )
                )
            return result

    def get_metrics(self, session_id: str) -> Optional[ModelMetrics]:
        with self._db.session() as db:
            r = db.query(DBModelMetrics).filter(DBModelMetrics.session_id == session_id).first()
            if not r:
                return None
            return ModelMetrics(
                total_logs=r.total_logs,
                anomalies_detected=r.anomalies_detected,
                contamination_rate=r.contamination_rate,
                processing_time_ms=r.processing_time_ms,
                baseline_deviation=r.baseline_deviation,
                severity_distribution=r.severity_distribution or {},
            )

    # ── Incidents ────────────────────────────────────────────────────────────

    def set_incidents(self, session_id: str, incidents: List[Incident]):
        with self._db.session() as db:
            for inc in incidents:
                db_inc = db.query(DBIncident).filter(DBIncident.id == inc.id).first()
                if not db_inc:
                    db_inc = DBIncident(
                        id=inc.id,
                        anomaly_id=inc.anomaly_id,
                        session_id=session_id,
                        category=inc.category.value if hasattr(inc.category, "value") else str(inc.category),
                        severity=inc.severity.value if hasattr(inc.severity, "value") else str(inc.severity),
                        title=inc.title,
                        description=inc.description,
                        root_cause_hypothesis=inc.root_cause_hypothesis,
                        potential_impact=inc.potential_impact,
                        first_seen=_to_utc(inc.first_seen),
                        last_seen=_to_utc(inc.last_seen),
                        status=inc.status.value if hasattr(inc.status, "value") else str(inc.status),
                        assigned_analyst=getattr(inc, "assigned_analyst", None),
                        remediation_steps=inc.remediation_steps or [],
                        evidence=inc.evidence or [],
                        evidence_log_lines=inc.evidence_log_lines or [],
                        affected_sources=inc.affected_sources or [],
                        affected_ips=inc.affected_ips or [],
                    )
                    db.add(db_inc)
                else:
                    db_inc.category = inc.category.value if hasattr(inc.category, "value") else str(inc.category)
                    db_inc.severity = inc.severity.value if hasattr(inc.severity, "value") else str(inc.severity)
                    db_inc.title = inc.title
                    db_inc.description = inc.description
                    db_inc.root_cause_hypothesis = inc.root_cause_hypothesis
                    db_inc.potential_impact = inc.potential_impact
                    db_inc.first_seen = _to_utc(inc.first_seen)
                    db_inc.last_seen = _to_utc(inc.last_seen)
                    db_inc.status = inc.status.value if hasattr(inc.status, "value") else str(inc.status)
                    db_inc.assigned_analyst = getattr(inc, "assigned_analyst", None)
                    db_inc.remediation_steps = inc.remediation_steps or []
                    db_inc.evidence = inc.evidence or []
                    db_inc.evidence_log_lines = inc.evidence_log_lines or []
                    db_inc.affected_sources = inc.affected_sources or []
                    db_inc.affected_ips = inc.affected_ips or []

    def get_incidents(self, session_id: str) -> List[Incident]:
        with self._db.session() as db:
            rows = db.query(DBIncident).filter(DBIncident.session_id == session_id).order_by(DBIncident.first_seen.asc()).all()
            incidents = []
            for r in rows:
                incidents.append(
                    Incident(
                        id=r.id,
                        anomaly_id=r.anomaly_id,
                        session_id=r.session_id,
                        category=IncidentCategory(r.category) if r.category in IncidentCategory.__members__.values() else IncidentCategory.UNKNOWN,
                        severity=SeverityLevel(r.severity) if r.severity in SeverityLevel.__members__.values() else SeverityLevel.MEDIUM,
                        title=r.title,
                        description=r.description,
                        root_cause_hypothesis=r.root_cause_hypothesis or "",
                        potential_impact=r.potential_impact or "",
                        first_seen=_to_utc(r.first_seen),
                        last_seen=_to_utc(r.last_seen),
                        status=IncidentStatus(r.status) if r.status in IncidentStatus.__members__.values() else IncidentStatus.OPEN,
                        remediation_steps=r.remediation_steps or [],
                        evidence=r.evidence or [],
                        evidence_log_lines=r.evidence_log_lines or [],
                        affected_sources=r.affected_sources or [],
                        affected_ips=r.affected_ips or [],
                    )
                )
            return incidents

    # ── Attack Chains ────────────────────────────────────────────────────────

    def set_attack_chains(self, session_id: str, chains: List[AttackChain]):
        with self._db.session() as db:
            for chain in chains:
                db_chain = db.query(DBAttackChain).filter(DBAttackChain.id == chain.id).first()
                chain_dict = chain.model_dump(mode="json")
                if not db_chain:
                    db_chain = DBAttackChain(
                        id=chain.id,
                        session_id=session_id,
                        title=chain.title,
                        summary=chain.summary,
                        severity=chain.severity,
                        confidence_score=chain.confidence_score,
                        first_seen=_to_utc(chain.first_seen),
                        last_seen=_to_utc(chain.last_seen),
                        duration_seconds=chain.duration_seconds,
                        stages_observed=chain_dict.get("stages_observed", []),
                        stages_unconfirmed=chain_dict.get("stages_unconfirmed", []),
                        source_ips=chain_dict.get("source_ips", []),
                        target_systems=chain_dict.get("target_systems", []),
                        affected_users=chain_dict.get("affected_users", []),
                        affected_processes=chain_dict.get("affected_processes", []),
                        associated_anomaly_ids=chain_dict.get("associated_anomaly_ids", []),
                        associated_incident_ids=chain_dict.get("associated_incident_ids", []),
                        event_ids=chain_dict.get("event_ids", []),
                        events=chain_dict.get("events", []),
                        supporting_evidence=chain_dict.get("supporting_evidence", []),
                        hypotheses_unconfirmed=chain_dict.get("hypotheses_unconfirmed", []),
                        potential_impact=chain.potential_impact,
                        correlation_explanation=chain.correlation_explanation,
                        recommended_actions=chain_dict.get("recommended_actions", []),
                        graph_data=chain_dict.get("graph_data", {}),
                        status=chain.status.value if hasattr(chain.status, "value") else str(chain.status),
                        analyst_note=chain.analyst_note,
                        status_history=chain_dict.get("status_history", []),
                        related_chain_ids=chain_dict.get("related_chain_ids", []),
                        cross_session_evidence=chain_dict.get("cross_session_evidence", []),
                    )
                    db.add(db_chain)
                else:
                    db_chain.title = chain.title
                    db_chain.summary = chain.summary
                    db_chain.severity = chain.severity
                    db_chain.confidence_score = chain.confidence_score
                    db_chain.first_seen = _to_utc(chain.first_seen)
                    db_chain.last_seen = _to_utc(chain.last_seen)
                    db_chain.duration_seconds = chain.duration_seconds
                    db_chain.stages_observed = chain_dict.get("stages_observed", [])
                    db_chain.stages_unconfirmed = chain_dict.get("stages_unconfirmed", [])
                    db_chain.source_ips = chain_dict.get("source_ips", [])
                    db_chain.target_systems = chain_dict.get("target_systems", [])
                    db_chain.affected_users = chain_dict.get("affected_users", [])
                    db_chain.affected_processes = chain_dict.get("affected_processes", [])
                    db_chain.associated_anomaly_ids = chain_dict.get("associated_anomaly_ids", [])
                    db_chain.associated_incident_ids = chain_dict.get("associated_incident_ids", [])
                    db_chain.event_ids = chain_dict.get("event_ids", [])
                    db_chain.events = chain_dict.get("events", [])
                    db_chain.supporting_evidence = chain_dict.get("supporting_evidence", [])
                    db_chain.hypotheses_unconfirmed = chain_dict.get("hypotheses_unconfirmed", [])
                    db_chain.potential_impact = chain.potential_impact
                    db_chain.correlation_explanation = chain.correlation_explanation
                    db_chain.recommended_actions = chain_dict.get("recommended_actions", [])
                    db_chain.graph_data = chain_dict.get("graph_data", {})
                    db_chain.status = chain.status.value if hasattr(chain.status, "value") else str(chain.status)
                    db_chain.analyst_note = chain.analyst_note
                    db_chain.status_history = chain_dict.get("status_history", [])
                    db_chain.related_chain_ids = chain_dict.get("related_chain_ids", [])
                    db_chain.cross_session_evidence = chain_dict.get("cross_session_evidence", [])

    def get_attack_chains(self, session_id: str) -> List[AttackChain]:
        with self._db.session() as db:
            rows = db.query(DBAttackChain).filter(DBAttackChain.session_id == session_id).order_by(DBAttackChain.first_seen.asc()).all()
            return [self._row_to_attack_chain(r) for r in rows]

    def get_attack_chain(self, chain_id: str) -> Optional[AttackChain]:
        with self._db.session() as db:
            row = db.query(DBAttackChain).filter(DBAttackChain.id == chain_id).first()
            if not row:
                return None
            return self._row_to_attack_chain(row)

    def _row_to_attack_chain(self, r: DBAttackChain) -> AttackChain:
        raw_events = r.events or []
        events = [ChainLinkEvent.model_validate(e) for e in raw_events]
        raw_history = r.status_history or []
        history = [ChainStatusHistory.model_validate(h) for h in raw_history]

        return AttackChain(
            id=r.id,
            session_id=r.session_id,
            title=r.title,
            summary=r.summary,
            severity=r.severity,
            confidence_score=r.confidence_score,
            first_seen=_to_utc(r.first_seen),
            last_seen=_to_utc(r.last_seen),
            duration_seconds=r.duration_seconds,
            stages_observed=r.stages_observed or [],
            stages_unconfirmed=r.stages_unconfirmed or [],
            source_ips=r.source_ips or [],
            target_systems=r.target_systems or [],
            affected_users=r.affected_users or [],
            affected_processes=r.affected_processes or [],
            associated_anomaly_ids=r.associated_anomaly_ids or [],
            associated_incident_ids=r.associated_incident_ids or [],
            event_ids=r.event_ids or [],
            events=events,
            supporting_evidence=r.supporting_evidence or [],
            hypotheses_unconfirmed=r.hypotheses_unconfirmed or [],
            potential_impact=r.potential_impact,
            correlation_explanation=r.correlation_explanation,
            recommended_actions=r.recommended_actions or [],
            graph_data=r.graph_data or {},
            status=ChainStatus(r.status) if r.status in ChainStatus.__members__.values() else ChainStatus.NEW,
            analyst_note=r.analyst_note,
            status_history=history,
            related_chain_ids=r.related_chain_ids or [],
            cross_session_evidence=r.cross_session_evidence or [],
        )

    # ── Dashboard Aggregate Stats ────────────────────────────────────────────

    def get_dashboard_stats(self) -> Dict[str, Any]:
        with self._db.session() as db:
            total_logs = db.query(func.count(DBEvent.id)).scalar() or 0
            total_anomalies = db.query(func.count(DBAnomaly.id)).scalar() or 0
            total_incidents = db.query(func.count(DBIncident.id)).scalar() or 0
            total_chains = db.query(func.count(DBAttackChain.id)).scalar() or 0
            total_iocs = db.query(func.count(DBIOC.id)).scalar() or 0
            critical = db.query(func.count(DBIncident.id)).filter(DBIncident.severity == "CRITICAL").scalar() or 0
            open_inc = db.query(func.count(DBIncident.id)).filter(DBIncident.status == "open").scalar() or 0
            total_sessions = db.query(func.count(DBSession.id)).scalar() or 0

            latest_session = db.query(DBSession.id).order_by(DBSession.uploaded_at.desc()).first()
            active_id = latest_session[0] if latest_session else None

            return {
                "total_logs": total_logs,
                "total_anomalies": total_anomalies,
                "total_incidents": total_incidents,
                "total_attack_chains": total_chains,
                "total_iocs": total_iocs,
                "critical_incidents": critical,
                "open_incidents": open_inc,
                "sessions": total_sessions,
                "active_session": active_id,
            }

    # ── Threat Intelligence & Assessments ───────────────────────────────────

    def save_threat_intel_result(self, result: ThreatIntelResult):
        with self._db.session() as db:
            type_str = result.ioc_type.value if hasattr(result.ioc_type, "value") else str(result.ioc_type)
            status_str = result.status.value if hasattr(result.status, "value") else str(result.status)
            source_str = result.source.value if hasattr(result.source, "value") else str(result.source)

            row = db.query(DBThreatIntelResult).filter(
                DBThreatIntelResult.provider_name == result.provider_name,
                DBThreatIntelResult.ioc_type == type_str,
                DBThreatIntelResult.normalized_value == result.normalized_value,
            ).first()

            if not row:
                row = DBThreatIntelResult(
                    id=result.id,
                    ioc_id=result.ioc_id,
                    provider_name=result.provider_name,
                    provider_version=result.provider_version,
                    ioc_type=type_str,
                    ioc_value=result.ioc_value,
                    normalized_value=result.normalized_value,
                    status=status_str,
                    confidence=result.confidence,
                    reputation_score=result.reputation_score or 0.0,
                    source=source_str,
                    detection_count=result.detection_count or 0,
                    total_engines=result.total_engines or 0,
                    categories=result.categories or [],
                    queried_at=_to_utc(result.queried_at),
                    expires_at=_to_utc(result.expires_at),
                    raw_metadata=result.raw_metadata or {},
                )
                db.add(row)
            else:
                row.status = status_str
                row.confidence = result.confidence
                row.reputation_score = result.reputation_score or 0.0
                row.detection_count = result.detection_count or 0
                row.total_engines = result.total_engines or 0
                row.categories = result.categories or []
                row.queried_at = _to_utc(result.queried_at)
                row.expires_at = _to_utc(result.expires_at)
                row.raw_metadata = result.raw_metadata or {}

    def get_threat_intel_result(
        self,
        provider_name: str,
        ioc_type: IOCType,
        normalized_value: str,
    ) -> Optional[ThreatIntelResult]:
        with self._db.session() as db:
            type_str = ioc_type.value if hasattr(ioc_type, "value") else str(ioc_type)
            row = db.query(DBThreatIntelResult).filter(
                DBThreatIntelResult.provider_name == provider_name,
                DBThreatIntelResult.ioc_type == type_str,
                DBThreatIntelResult.normalized_value == normalized_value,
            ).first()
            if not row:
                return None

            return ThreatIntelResult(
                id=row.id,
                ioc_id=row.ioc_id or f"ioc-{row.normalized_value}",
                ioc_type=IOCType(row.ioc_type) if row.ioc_type in IOCType.__members__.values() else IOCType.IPV4,
                ioc_value=row.ioc_value or row.normalized_value,
                normalized_value=row.normalized_value,
                status=ThreatIntelStatus(row.status) if row.status in ThreatIntelStatus.__members__.values() else ThreatIntelStatus.UNKNOWN,
                confidence=row.confidence,
                source=ThreatIntelSource(row.source) if row.source in ThreatIntelSource.__members__.values() else ThreatIntelSource.OFFLINE_MOCK,
                provider_name=row.provider_name,
                provider_version=row.provider_version or "1.0.0",
                queried_at=_to_utc(row.queried_at),
                expires_at=_to_utc(row.expires_at),
                detection_count=row.detection_count or 0,
                total_engines=row.total_engines,
                reputation_score=row.reputation_score,
                categories=row.categories or [],
                raw_metadata=row.raw_metadata or {},
            )

    def save_threat_correlation(self, correlation: ThreatCorrelation):
        with self._db.session() as db:
            cid = getattr(correlation, "correlation_id", getattr(correlation, "id", f"tc-{uuid.uuid4().hex[:12]}"))
            row = db.query(DBThreatCorrelation).filter(DBThreatCorrelation.correlation_id == cid).first()
            type_str = correlation.correlation_type.value if hasattr(correlation.correlation_type, "value") else str(correlation.correlation_type)

            if not row:
                row = DBThreatCorrelation(
                    correlation_id=cid,
                    correlation_type=type_str,
                    source_id=getattr(correlation, "source_id", getattr(correlation, "ioc_id", "")),
                    source_type=getattr(correlation, "source_type", "ioc"),
                    target_id=correlation.target_id,
                    target_type=correlation.target_type,
                    confidence=correlation.confidence.model_dump(mode="json"),
                    evidence=correlation.evidence or [],
                    correlation_method=correlation.correlation_method,
                    first_seen=_to_utc(correlation.first_seen),
                    last_seen=_to_utc(correlation.last_seen),
                    confirmed=correlation.confirmed,
                    analyst_note=correlation.analyst_note,
                    created_at=_to_utc(correlation.created_at),
                )
                db.add(row)
            else:
                row.confidence = correlation.confidence.model_dump(mode="json")
                row.evidence = correlation.evidence or []
                row.confirmed = correlation.confirmed
                row.analyst_note = correlation.analyst_note

    def get_threat_correlations_for_ioc(self, ioc_id: str) -> List[ThreatCorrelation]:
        with self._db.session() as db:
            rows = db.query(DBThreatCorrelation).filter(
                (DBThreatCorrelation.source_id == ioc_id) | (DBThreatCorrelation.target_id == ioc_id)
            ).all()
            corrs = []
            for r in rows:
                raw_conf = r.confidence or {}
                conf = CorrelationConfidence.model_validate(raw_conf)
                corrs.append(
                    ThreatCorrelation(
                        correlation_id=r.correlation_id,
                        correlation_type=ThreatCorrelationType(r.correlation_type) if r.correlation_type in ThreatCorrelationType.__members__.values() else ThreatCorrelationType.IOC_TO_EVENT,
                        source_id=r.source_id,
                        source_type=r.source_type,
                        target_id=r.target_id,
                        target_type=r.target_type,
                        confidence=conf,
                        evidence=r.evidence or [],
                        correlation_method=r.correlation_method,
                        first_seen=_to_utc(r.first_seen),
                        last_seen=_to_utc(r.last_seen),
                        confirmed=r.confirmed,
                        analyst_note=r.analyst_note,
                        created_at=_to_utc(r.created_at),
                    )
                )
            return corrs


class SQLIOCRepository:
    """
    SQLAlchemy-backed implementation of IOCRepository with canonical deduplication.
    """

    def __init__(self, manager: Optional[DatabaseManager] = None):
        self._db = manager if manager is not None else db_manager

    def add_ioc(self, ioc: IOC) -> IOC:
        """
        Add an IOC to database. Merges evidence if canonical (ioc_type, normalized_value) exists.
        """
        with self._db.session() as db:
            ioc_type_str = ioc.ioc_type.value if hasattr(ioc.ioc_type, "value") else str(ioc.ioc_type)
            db_ioc = (
                db.query(DBIOC)
                .filter(DBIOC.ioc_type == ioc_type_str, DBIOC.normalized_value == ioc.normalized_value)
                .first()
            )

            if db_ioc is not None:
                # Merge into existing record
                existing_evidence = db.query(DBIOCEvidence).filter(DBIOCEvidence.ioc_id == db_ioc.id).all()
                existing_sigs = {
                    (e.event_id, e.raw_value, e.source_field, e.line_number)
                    for e in existing_evidence
                }

                new_count = 0
                for ev in ioc.evidence_references:
                    sig = (ev.event_id, ev.raw_value, ev.source_field, ev.line_number)
                    if sig not in existing_sigs:
                        db_ev = DBIOCEvidence(
                            id=f"ev-{ev.event_id}-{len(existing_sigs) + new_count}",
                            ioc_id=db_ioc.id,
                            event_id=ev.event_id,
                            session_id=ev.session_id,
                            timestamp=_to_utc(ev.timestamp),
                            raw_value=ev.raw_value,
                            source_field=ev.source_field,
                            line_number=ev.line_number,
                            surrounding_context=ev.surrounding_context,
                            anomaly_id=ev.anomaly_id,
                            incident_id=ev.incident_id,
                            attack_chain_id=getattr(ev, "chain_link_event_id", getattr(ev, "attack_chain_id", None)),
                        )
                        db.add(db_ev)
                        existing_sigs.add(sig)
                        new_count += 1

                db_ioc.occurrence_count += max(new_count, 1)
                db_ioc.last_seen = max(_to_utc(db_ioc.last_seen), _to_utc(ioc.last_seen))

                # Merge list fields
                db_ioc.source_sessions = list(set((db_ioc.source_sessions or []) + ioc.source_sessions))
                db_ioc.associated_anomaly_ids = list(set((db_ioc.associated_anomaly_ids or []) + ioc.associated_anomaly_ids))
                db_ioc.associated_incident_ids = list(set((db_ioc.associated_incident_ids or []) + ioc.associated_incident_ids))
                db_ioc.associated_chain_ids = list(set((db_ioc.associated_chain_ids or []) + ioc.associated_chain_ids))
                db_ioc.tags = list(set((db_ioc.tags or []) + ioc.tags))

                db.flush()
                return self._row_to_ioc(db, db_ioc)

            else:
                # Insert new IOC
                db_ioc = DBIOC(
                    id=ioc.id,
                    ioc_type=ioc_type_str,
                    raw_value=ioc.raw_value,
                    normalized_value=ioc.normalized_value,
                    status=ioc.status.value if hasattr(ioc.status, "value") else str(ioc.status),
                    validation_status="VALID",
                    ip_scope=None,
                    confidence_score=getattr(ioc, "confidence", 0.5),
                    occurrence_count=ioc.occurrence_count,
                    first_seen=_to_utc(ioc.first_seen),
                    last_seen=_to_utc(ioc.last_seen),
                    source_sessions=ioc.source_sessions or [],
                    associated_anomaly_ids=ioc.associated_anomaly_ids or [],
                    associated_incident_ids=ioc.associated_incident_ids or [],
                    associated_chain_ids=ioc.associated_chain_ids or [],
                    tags=ioc.tags or [],
                    analyst_notes=getattr(ioc, "analyst_note", None),
                    status_history=[h.model_dump(mode="json") for h in ioc.status_history] if ioc.status_history else [],
                    raw_metadata={},
                )
                db.add(db_ioc)
                db.flush()

                for idx, ev in enumerate(ioc.evidence_references):
                    db_ev = DBIOCEvidence(
                        id=f"ev-{ev.event_id}-{idx}",
                        ioc_id=db_ioc.id,
                        event_id=ev.event_id,
                        session_id=ev.session_id,
                        timestamp=_to_utc(ev.timestamp),
                        raw_value=ev.raw_value,
                        source_field=ev.source_field,
                        line_number=ev.line_number,
                        surrounding_context=ev.surrounding_context,
                        anomaly_id=ev.anomaly_id,
                        incident_id=ev.incident_id,
                        attack_chain_id=getattr(ev, "chain_link_event_id", getattr(ev, "attack_chain_id", None)),
                    )
                    db.add(db_ev)

                db.flush()
                return self._row_to_ioc(db, db_ioc)

    def get_ioc(self, ioc_id: str) -> Optional[IOC]:
        with self._db.session() as db:
            row = db.query(DBIOC).filter(DBIOC.id == ioc_id).first()
            if not row:
                return None
            return self._row_to_ioc(db, row)

    def get_ioc_by_normalized_value(self, ioc_type: IOCType, normalized_value: str) -> Optional[IOC]:
        with self._db.session() as db:
            type_str = ioc_type.value if hasattr(ioc_type, "value") else str(ioc_type)
            row = db.query(DBIOC).filter(DBIOC.ioc_type == type_str, DBIOC.normalized_value == normalized_value).first()
            if not row:
                return None
            return self._row_to_ioc(db, row)

    def get_all_iocs(
        self,
        skip: int = 0,
        limit: int = 100,
        ioc_type: Optional[IOCType] = None,
        status: Optional[IOCStatus] = None,
    ) -> List[IOC]:
        with self._db.session() as db:
            q = db.query(DBIOC)
            if ioc_type:
                type_str = ioc_type.value if hasattr(ioc_type, "value") else str(ioc_type)
                q = q.filter(DBIOC.ioc_type == type_str)
            if status:
                status_str = status.value if hasattr(status, "value") else str(status)
                q = q.filter(DBIOC.status == status_str)
            rows = q.order_by(DBIOC.last_seen.desc()).offset(skip).limit(limit).all()
            return [self._row_to_ioc(db, r) for r in rows]

    def find_iocs_by_session(self, session_id: str) -> List[IOC]:
        with self._db.session() as db:
            # Query via evidence references or source_sessions
            evidence_ioc_ids = {e[0] for e in db.query(DBIOCEvidence.ioc_id).filter(DBIOCEvidence.session_id == session_id).all()}
            rows = db.query(DBIOC).all()
            result = []
            for r in rows:
                if r.id in evidence_ioc_ids or (r.source_sessions and session_id in r.source_sessions):
                    result.append(self._row_to_ioc(db, r))
            return result

    def find_iocs_by_event(self, event_id: str) -> List[IOC]:
        with self._db.session() as db:
            ioc_ids = {e[0] for e in db.query(DBIOCEvidence.ioc_id).filter(DBIOCEvidence.event_id == event_id).all()}
            if not ioc_ids:
                return []
            rows = db.query(DBIOC).filter(DBIOC.id.in_(ioc_ids)).all()
            return [self._row_to_ioc(db, r) for r in rows]

    def find_iocs_by_anomaly(self, anomaly_id: str) -> List[IOC]:
        with self._db.session() as db:
            evidence_ioc_ids = {e[0] for e in db.query(DBIOCEvidence.ioc_id).filter(DBIOCEvidence.anomaly_id == anomaly_id).all()}
            rows = db.query(DBIOC).all()
            result = []
            for r in rows:
                if r.id in evidence_ioc_ids or (r.associated_anomaly_ids and anomaly_id in r.associated_anomaly_ids):
                    result.append(self._row_to_ioc(db, r))
            return result

    def find_iocs_by_incident(self, incident_id: str) -> List[IOC]:
        with self._db.session() as db:
            evidence_ioc_ids = {e[0] for e in db.query(DBIOCEvidence.ioc_id).filter(DBIOCEvidence.incident_id == incident_id).all()}
            rows = db.query(DBIOC).all()
            result = []
            for r in rows:
                if r.id in evidence_ioc_ids or (r.associated_incident_ids and incident_id in r.associated_incident_ids):
                    result.append(self._row_to_ioc(db, r))
            return result

    def find_iocs_by_attack_chain(self, attack_chain_id: str) -> List[IOC]:
        with self._db.session() as db:
            evidence_ioc_ids = {e[0] for e in db.query(DBIOCEvidence.ioc_id).filter(DBIOCEvidence.attack_chain_id == attack_chain_id).all()}
            rows = db.query(DBIOC).all()
            result = []
            for r in rows:
                if r.id in evidence_ioc_ids or (r.associated_chain_ids and attack_chain_id in r.associated_chain_ids):
                    result.append(self._row_to_ioc(db, r))
            return result

    def update_ioc_status(
        self,
        ioc_id: str,
        new_status: IOCStatus,
        reason: str,
        analyst: Optional[str] = None,
    ) -> Optional[IOC]:
        with self._db.session() as db:
            r = db.query(DBIOC).filter(DBIOC.id == ioc_id).first()
            if not r:
                return None

            old_status = IOCStatus(r.status)
            target_status = new_status if isinstance(new_status, IOCStatus) else IOCStatus(new_status)

            history_entry = IOCStatusHistory(
                previous_status=old_status,
                new_status=target_status,
                changed_at=_utc_now(),
                changed_by=analyst,
                reason=reason,
            )

            current_history = r.status_history or []
            current_history.append(history_entry.model_dump(mode="json"))

            r.status = target_status.value
            r.status_history = current_history
            r.updated_at = _utc_now()
            db.flush()

            # Record audit record
            audit = DBAuditRecord(
                id=f"audit-status-{ioc_id}-{len(current_history)}",
                action="IOC_STATUS_UPDATE",
                entity_type="IOC",
                entity_id=ioc_id,
                analyst=analyst,
                details={
                    "old_status": old_status.value,
                    "new_status": target_status.value,
                    "reason": reason,
                },
            )
            db.add(audit)

            return self._row_to_ioc(db, r)

    def count_iocs(
        self,
        ioc_type: Optional[IOCType] = None,
        status: Optional[IOCStatus] = None,
    ) -> int:
        with self._db.session() as db:
            q = db.query(func.count(DBIOC.id))
            if ioc_type:
                type_str = ioc_type.value if hasattr(ioc_type, "value") else str(ioc_type)
                q = q.filter(DBIOC.ioc_type == type_str)
            if status:
                status_str = status.value if hasattr(status, "value") else str(status)
                q = q.filter(DBIOC.status == status_str)
            return q.scalar() or 0

    def get_stats(self) -> Dict[str, Any]:
        with self._db.session() as db:
            total = db.query(func.count(DBIOC.id)).scalar() or 0
            type_counts = {}
            for t, cnt in db.query(DBIOC.ioc_type, func.count(DBIOC.id)).group_by(DBIOC.ioc_type).all():
                type_counts[t] = cnt
            status_counts = {}
            for s, cnt in db.query(DBIOC.status, func.count(DBIOC.id)).group_by(DBIOC.status).all():
                status_counts[s] = cnt

            return {
                "total_iocs": total,
                "by_type": type_counts,
                "by_status": status_counts,
            }

    def _row_to_ioc(self, db: Session, r: DBIOC) -> IOC:
        # Load evidence references
        ev_rows = db.query(DBIOCEvidence).filter(DBIOCEvidence.ioc_id == r.id).order_by(DBIOCEvidence.created_at.asc()).all()
        evidence_list = []
        for ev in ev_rows:
            evidence_list.append(
                IOCEvidence(
                    event_id=ev.event_id,
                    session_id=ev.session_id,
                    timestamp=_to_utc(ev.timestamp),
                    raw_value=ev.raw_value,
                    source_field=ev.source_field,
                    line_number=ev.line_number,
                    surrounding_context=ev.surrounding_context,
                    anomaly_id=ev.anomaly_id,
                    incident_id=ev.incident_id,
                    chain_link_event_id=ev.attack_chain_id,
                )
            )

        history_list = []
        for h in r.status_history or []:
            history_list.append(IOCStatusHistory.model_validate(h))

        return IOC(
            id=r.id,
            ioc_type=IOCType(r.ioc_type) if r.ioc_type in IOCType.__members__.values() else IOCType.IPV4,
            raw_value=r.raw_value,
            normalized_value=r.normalized_value,
            status=IOCStatus(r.status) if r.status in IOCStatus.__members__.values() else IOCStatus.EXTRACTED,
            confidence=r.confidence_score,
            occurrence_count=r.occurrence_count,
            first_seen=_to_utc(r.first_seen),
            last_seen=_to_utc(r.last_seen),
            evidence_references=evidence_list,
            source_sessions=r.source_sessions or [],
            associated_anomaly_ids=r.associated_anomaly_ids or [],
            associated_incident_ids=r.associated_incident_ids or [],
            associated_chain_ids=r.associated_chain_ids or [],
            tags=r.tags or [],
            analyst_note=r.analyst_notes,
            status_history=history_list,
        )
