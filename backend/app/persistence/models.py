"""
SQLAlchemy ORM Models for MICHAEL – THE GUARDIAN AI.

Phase 5.0 — Production Hardening & Persistence Integration.

Defines persistence schemas compatible with PostgreSQL (Supabase) and SQLite (offline testing):
- Sessions
- Events (Log Entries)
- Anomalies
- Model Metrics
- Incidents
- Attack Chains
- IOCs (Indicators of Compromise)
- IOC Evidence References
- Threat Intel Results
- Threat Assessments
- Threat Correlations
- Audit Records
"""

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
import uuid

from sqlalchemy import (
    BigInteger,
    Boolean,
    Column,
    DateTime,
    Float,
    ForeignKey,
    Index,
    Integer,
    JSON,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import declarative_base, relationship

Base = declarative_base()


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


class DBSession(Base):
    __tablename__ = "sessions"

    id = Column(String(128), primary_key=True)
    filename = Column(Text, nullable=False)
    uploaded_at = Column(DateTime(timezone=True), nullable=False, default=_utc_now)
    total_lines = Column(Integer, nullable=False, default=0)
    file_size = Column(BigInteger, nullable=False, default=0)
    status = Column(String(50), nullable=False, default="uploaded")
    created_at = Column(DateTime(timezone=True), nullable=False, default=_utc_now)
    updated_at = Column(DateTime(timezone=True), nullable=False, default=_utc_now, onupdate=_utc_now)

    # Relationships
    events = relationship("DBEvent", back_populates="session", cascade="all, delete-orphan")
    anomalies = relationship("DBAnomaly", back_populates="session", cascade="all, delete-orphan")
    incidents = relationship("DBIncident", back_populates="session", cascade="all, delete-orphan")
    attack_chains = relationship("DBAttackChain", back_populates="session", cascade="all, delete-orphan")
    metrics = relationship("DBModelMetrics", back_populates="session", uselist=False, cascade="all, delete-orphan")


class DBEvent(Base):
    __tablename__ = "events"

    id = Column(String(128), primary_key=True)
    session_id = Column(String(128), ForeignKey("sessions.id", ondelete="CASCADE"), nullable=False, index=True)
    line_number = Column(Integer, nullable=False)
    timestamp = Column(DateTime(timezone=True), nullable=False, index=True)
    level = Column(String(20), nullable=False, index=True)
    source = Column(String(128), nullable=False)
    message = Column(Text, nullable=False)
    raw = Column(Text, nullable=False)
    ip_address = Column(String(128), nullable=True, index=True)
    user_name = Column(String(128), nullable=True)
    action = Column(String(128), nullable=True)
    status_code = Column(Integer, nullable=True)
    created_at = Column(DateTime(timezone=True), nullable=False, default=_utc_now)

    session = relationship("DBSession", back_populates="events")

    __table_args__ = (
        Index("idx_events_session_line", "session_id", "line_number"),
    )


class DBAnomaly(Base):
    __tablename__ = "anomalies"

    id = Column(String(128), primary_key=True)
    session_id = Column(String(128), ForeignKey("sessions.id", ondelete="CASCADE"), nullable=False, index=True)
    score = Column(Float, nullable=False)
    severity = Column(String(20), nullable=False, index=True)
    reason = Column(Text, nullable=False)
    method = Column(String(50), nullable=False)
    detected_at = Column(DateTime(timezone=True), nullable=False, default=_utc_now, index=True)
    log_entry_ids = Column(JSON, nullable=False, default=list)
    features = Column(JSON, nullable=True, default=dict)
    created_at = Column(DateTime(timezone=True), nullable=False, default=_utc_now)

    session = relationship("DBSession", back_populates="anomalies")


class DBModelMetrics(Base):
    __tablename__ = "model_metrics"

    id = Column(String(128), primary_key=True)
    session_id = Column(String(128), ForeignKey("sessions.id", ondelete="CASCADE"), nullable=False, unique=True)
    total_logs = Column(Integer, nullable=False, default=0)
    anomalies_detected = Column(Integer, nullable=False, default=0)
    contamination_rate = Column(Float, nullable=False, default=0.0)
    processing_time_ms = Column(Float, nullable=False, default=0.0)
    baseline_deviation = Column(Float, nullable=False, default=0.0)
    severity_distribution = Column(JSON, nullable=False, default=dict)
    created_at = Column(DateTime(timezone=True), nullable=False, default=_utc_now)

    session = relationship("DBSession", back_populates="metrics")


class DBIncident(Base):
    __tablename__ = "incidents"

    id = Column(String(128), primary_key=True)
    anomaly_id = Column(String(128), nullable=False, index=True)
    session_id = Column(String(128), ForeignKey("sessions.id", ondelete="CASCADE"), nullable=False, index=True)
    category = Column(String(50), nullable=False)
    severity = Column(String(20), nullable=False, index=True)
    title = Column(String(255), nullable=False)
    description = Column(Text, nullable=False)
    root_cause_hypothesis = Column(Text, nullable=False)
    potential_impact = Column(Text, nullable=False)
    first_seen = Column(DateTime(timezone=True), nullable=False, index=True)
    last_seen = Column(DateTime(timezone=True), nullable=False)
    status = Column(String(30), nullable=False, default="open", index=True)
    assigned_analyst = Column(String(128), nullable=True)
    remediation_steps = Column(JSON, nullable=True, default=list)
    evidence = Column(JSON, nullable=True, default=list)
    evidence_log_lines = Column(JSON, nullable=True, default=list)
    affected_sources = Column(JSON, nullable=True, default=list)
    affected_ips = Column(JSON, nullable=True, default=list)
    created_at = Column(DateTime(timezone=True), nullable=False, default=_utc_now)
    updated_at = Column(DateTime(timezone=True), nullable=False, default=_utc_now, onupdate=_utc_now)

    session = relationship("DBSession", back_populates="incidents")


class DBAttackChain(Base):
    __tablename__ = "attack_chains"

    id = Column(String(128), primary_key=True)
    session_id = Column(String(128), ForeignKey("sessions.id", ondelete="CASCADE"), nullable=False, index=True)
    title = Column(String(255), nullable=False)
    summary = Column(Text, nullable=False)
    severity = Column(String(20), nullable=False, index=True)
    confidence_score = Column(Float, nullable=False, default=0.5)
    first_seen = Column(DateTime(timezone=True), nullable=False)
    last_seen = Column(DateTime(timezone=True), nullable=False)
    duration_seconds = Column(Float, nullable=False, default=0.0)
    stages_observed = Column(JSON, nullable=True, default=list)
    stages_unconfirmed = Column(JSON, nullable=True, default=list)
    source_ips = Column(JSON, nullable=True, default=list)
    target_systems = Column(JSON, nullable=True, default=list)
    affected_users = Column(JSON, nullable=True, default=list)
    affected_processes = Column(JSON, nullable=True, default=list)
    associated_anomaly_ids = Column(JSON, nullable=True, default=list)
    associated_incident_ids = Column(JSON, nullable=True, default=list)
    event_ids = Column(JSON, nullable=True, default=list)
    events = Column(JSON, nullable=True, default=list)
    supporting_evidence = Column(JSON, nullable=True, default=list)
    hypotheses_unconfirmed = Column(JSON, nullable=True, default=list)
    potential_impact = Column(Text, nullable=False)
    correlation_explanation = Column(Text, nullable=False)
    recommended_actions = Column(JSON, nullable=True, default=list)
    graph_data = Column(JSON, nullable=True, default=dict)
    status = Column(String(30), nullable=False, default="NEW", index=True)
    analyst_note = Column(Text, nullable=True)
    status_history = Column(JSON, nullable=True, default=list)
    related_chain_ids = Column(JSON, nullable=True, default=list)
    cross_session_evidence = Column(JSON, nullable=True, default=list)
    created_at = Column(DateTime(timezone=True), nullable=False, default=_utc_now)
    updated_at = Column(DateTime(timezone=True), nullable=False, default=_utc_now, onupdate=_utc_now)

    session = relationship("DBSession", back_populates="attack_chains")


class DBIOC(Base):
    __tablename__ = "iocs"

    id = Column(String(128), primary_key=True)
    ioc_type = Column(String(30), nullable=False, index=True)
    raw_value = Column(Text, nullable=False)
    normalized_value = Column(Text, nullable=False, index=True)
    status = Column(String(30), nullable=False, default="EXTRACTED", index=True)
    validation_status = Column(String(30), nullable=False, default="VALID")
    ip_scope = Column(String(30), nullable=True)
    confidence_score = Column(Float, nullable=False, default=0.5)
    occurrence_count = Column(Integer, nullable=False, default=1)
    first_seen = Column(DateTime(timezone=True), nullable=False)
    last_seen = Column(DateTime(timezone=True), nullable=False, index=True)
    source_sessions = Column(JSON, nullable=True, default=list)
    associated_anomaly_ids = Column(JSON, nullable=True, default=list)
    associated_incident_ids = Column(JSON, nullable=True, default=list)
    associated_chain_ids = Column(JSON, nullable=True, default=list)
    tags = Column(JSON, nullable=True, default=list)
    analyst_notes = Column(Text, nullable=True)
    status_history = Column(JSON, nullable=True, default=list)
    raw_metadata = Column(JSON, nullable=True, default=dict)
    created_at = Column(DateTime(timezone=True), nullable=False, default=_utc_now)
    updated_at = Column(DateTime(timezone=True), nullable=False, default=_utc_now, onupdate=_utc_now)

    # Relationships
    evidence_references = relationship("DBIOCEvidence", back_populates="ioc", cascade="all, delete-orphan")
    threat_intel = relationship("DBThreatIntelResult", back_populates="ioc", cascade="all, delete-orphan")
    threat_assessments = relationship("DBThreatAssessment", back_populates="ioc", cascade="all, delete-orphan")

    __table_args__ = (
        UniqueConstraint("ioc_type", "normalized_value", name="uq_ioc_type_normalized"),
    )


class DBIOCEvidence(Base):
    __tablename__ = "ioc_evidence"

    id = Column(String(128), primary_key=True)
    ioc_id = Column(String(128), ForeignKey("iocs.id", ondelete="CASCADE"), nullable=False, index=True)
    event_id = Column(String(128), nullable=False, index=True)
    session_id = Column(String(128), nullable=False, index=True)
    timestamp = Column(DateTime(timezone=True), nullable=False)
    raw_value = Column(Text, nullable=False)
    source_field = Column(String(100), nullable=False)
    line_number = Column(Integer, nullable=True)
    surrounding_context = Column(Text, nullable=True)
    anomaly_id = Column(String(128), nullable=True, index=True)
    incident_id = Column(String(128), nullable=True, index=True)
    attack_chain_id = Column(String(128), nullable=True)
    created_at = Column(DateTime(timezone=True), nullable=False, default=_utc_now)

    ioc = relationship("DBIOC", back_populates="evidence_references")


class DBThreatIntelResult(Base):
    __tablename__ = "threat_intel_results"

    id = Column(String(128), primary_key=True)
    ioc_id = Column(String(128), ForeignKey("iocs.id", ondelete="CASCADE"), nullable=False, index=True)
    ioc_type = Column(String(30), nullable=False)
    ioc_value = Column(Text, nullable=False)
    normalized_value = Column(Text, nullable=False)
    status = Column(String(30), nullable=False, index=True)
    confidence = Column(Float, nullable=False, default=0.0)
    source = Column(String(50), nullable=False)
    provider_name = Column(String(50), nullable=False)
    provider_version = Column(String(30), nullable=True)
    queried_at = Column(DateTime(timezone=True), nullable=False, default=_utc_now)
    expires_at = Column(DateTime(timezone=True), nullable=False, index=True)
    lookup_latency_ms = Column(Float, nullable=True)
    detection_count = Column(Integer, nullable=True)
    total_engines = Column(Integer, nullable=True)
    reputation_score = Column(Float, nullable=True)
    categories = Column(JSON, nullable=True, default=list)
    tags = Column(JSON, nullable=True, default=list)
    country = Column(String(10), nullable=True)
    asn = Column(String(50), nullable=True)
    raw_metadata = Column(JSON, nullable=True, default=dict)
    created_at = Column(DateTime(timezone=True), nullable=False, default=_utc_now)

    ioc = relationship("DBIOC", back_populates="threat_intel")

    __table_args__ = (
        UniqueConstraint("provider_name", "ioc_type", "normalized_value", name="uq_provider_ioc"),
    )


class DBThreatAssessment(Base):
    __tablename__ = "threat_assessments"

    assessment_id = Column(String(128), primary_key=True)
    ioc_id = Column(String(128), ForeignKey("iocs.id", ondelete="CASCADE"), nullable=False, index=True)
    ioc_type = Column(String(30), nullable=False)
    ioc_value = Column(Text, nullable=False)
    normalized_value = Column(Text, nullable=False)
    threat_score = Column(Float, nullable=False)
    confidence = Column(Float, nullable=False)
    severity = Column(String(30), nullable=False, index=True)
    status = Column(String(30), nullable=False)
    reasons = Column(JSON, nullable=True, default=list)
    contributing_signals = Column(JSON, nullable=True, default=list)
    assessed_at = Column(DateTime(timezone=True), nullable=False, default=_utc_now)
    expires_at = Column(DateTime(timezone=True), nullable=False)
    engine_version = Column(String(30), nullable=False)
    raw_metadata = Column(JSON, nullable=True, default=dict)
    created_at = Column(DateTime(timezone=True), nullable=False, default=_utc_now)

    ioc = relationship("DBIOC", back_populates="threat_assessments")


class DBThreatCorrelation(Base):
    __tablename__ = "threat_correlations"

    correlation_id = Column(String(128), primary_key=True)
    correlation_type = Column(String(50), nullable=False, index=True)
    source_id = Column(String(128), nullable=False, index=True)
    source_type = Column(String(50), nullable=False)
    target_id = Column(String(128), nullable=False, index=True)
    target_type = Column(String(50), nullable=False)
    confidence = Column(JSON, nullable=False)
    evidence = Column(JSON, nullable=False, default=list)
    correlation_method = Column(String(100), nullable=False)
    first_seen = Column(DateTime(timezone=True), nullable=True)
    last_seen = Column(DateTime(timezone=True), nullable=True)
    confirmed = Column(Boolean, nullable=False, default=True, index=True)
    analyst_note = Column(Text, nullable=True)
    created_at = Column(DateTime(timezone=True), nullable=False, default=_utc_now)


class DBAuditRecord(Base):
    __tablename__ = "audit_records"

    id = Column(String(128), primary_key=True)
    action = Column(String(100), nullable=False)
    entity_type = Column(String(50), nullable=False, index=True)
    entity_id = Column(String(128), nullable=False, index=True)
    analyst = Column(String(128), nullable=True)
    details = Column(JSON, nullable=True, default=dict)
    ip_address = Column(String(128), nullable=True)
    created_at = Column(DateTime(timezone=True), nullable=False, default=_utc_now, index=True)

