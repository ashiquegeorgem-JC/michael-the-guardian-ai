"""
Threat Correlation Data Models for MICHAEL – THE GUARDIAN AI.

Phase 4.2B.4 — Threat Correlation & Unified Intelligence Engine.

Defines strongly typed schemas for correlating Indicators of Compromise (IOCs)
and Threat Assessments with Anomalies, Incidents, Attack Chains, and Log Events.

DESIGN INVARIANTS:
==================
1. Correlation is NOT classification: Correlating an IOC to an incident or anomaly
   does NOT alter IOCStatus, ThreatIntelStatus, Incident severity, or AttackChain status.
2. Cross-session safety: Cross-session correlations are marked confirmed=False (UNCONFIRMED)
   unless explicit cross-session corroborating evidence exists.
3. Decoupled metrics: Correlation confidence measures relationship certainty; it is
   strictly decoupled from Threat Confidence (intelligence credibility) and Threat Score (risk).
4. Forensic immutability: Source investigation entities are never mutated by correlation.
5. All timestamps must be timezone-aware (UTC).
"""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional
import uuid

from pydantic import BaseModel, Field, field_validator, model_validator

from app.models.ioc import IOCStatus, IOCType
from app.models.threat_intel import ThreatAssessment, ThreatIntelResult


# ─────────────────────────────────────────────────────────────────────────────
# Enumerations
# ─────────────────────────────────────────────────────────────────────────────

class ThreatCorrelationType(str, Enum):
    """Classification of the directional relationship between security objects."""
    IOC_TO_ANOMALY                    = "IOC_TO_ANOMALY"
    IOC_TO_INCIDENT                   = "IOC_TO_INCIDENT"
    IOC_TO_ATTACK_CHAIN               = "IOC_TO_ATTACK_CHAIN"
    IOC_TO_EVENT                      = "IOC_TO_EVENT"
    THREAT_ASSESSMENT_TO_INCIDENT     = "THREAT_ASSESSMENT_TO_INCIDENT"
    THREAT_ASSESSMENT_TO_ATTACK_CHAIN = "THREAT_ASSESSMENT_TO_ATTACK_CHAIN"


class CorrelationConfidenceLevel(str, Enum):
    """Categorical confidence level derived from the numerical score."""
    LOW       = "LOW"       # 0.00 <= score < 0.40 (tentative or temporal-only)
    MEDIUM    = "MEDIUM"    # 0.40 <= score < 0.70 (partial or indirect correlation)
    HIGH      = "HIGH"      # 0.70 <= score <= 1.00 (strong direct or structural evidence)


# ─────────────────────────────────────────────────────────────────────────────
# Core Models
# ─────────────────────────────────────────────────────────────────────────────

class CorrelationConfidence(BaseModel):
    """
    Measures the certainty that two distinct security objects are legitimately related.

    Strictly separate from threat confidence (which measures intelligence credibility).
    """
    score: float = Field(
        ge=0.0,
        le=1.0,
        description="Correlation confidence score bounded between 0.0 and 1.0",
    )
    confidence_level: CorrelationConfidenceLevel = Field(
        default=CorrelationConfidenceLevel.LOW,
        description="Categorical confidence tier (LOW, MEDIUM, HIGH)",
    )
    evidence_count: int = Field(
        default=0,
        ge=0,
        description="Total number of discrete evidence items supporting this correlation",
    )
    correlation_method: str = Field(
        description="Machine name of the primary correlation rule or method used",
    )
    calculated_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="Timestamp when correlation was computed (timezone-aware UTC)",
    )
    correlated_at: Optional[datetime] = Field(
        default=None,
        description="Alias timestamp for backwards-compatibility (UTC)",
    )

    @field_validator("calculated_at", "correlated_at")
    @classmethod
    def validate_timezone_awareness(cls, dt: Optional[datetime]) -> Optional[datetime]:
        """Ensure timestamps are explicitly timezone-aware."""
        if dt is not None and (dt.tzinfo is None or dt.tzinfo.utcoffset(dt) is None):
            raise ValueError("Timestamp must be timezone-aware (e.g. timezone.utc)")
        return dt

    @model_validator(mode="before")
    @classmethod
    def sync_calculated_and_correlated_at(cls, data: Any) -> Any:
        """Sync calculated_at and correlated_at fields."""
        if isinstance(data, dict):
            if "correlated_at" in data and "calculated_at" not in data:
                data["calculated_at"] = data["correlated_at"]
            elif "calculated_at" in data and "correlated_at" not in data:
                data["correlated_at"] = data["calculated_at"]
        return data

    @model_validator(mode="after")
    def derive_confidence_level(self) -> CorrelationConfidence:
        """Derive confidence_level deterministically from score if default was used."""
        if self.score >= 0.70:
            self.confidence_level = CorrelationConfidenceLevel.HIGH
        elif self.score >= 0.40:
            self.confidence_level = CorrelationConfidenceLevel.MEDIUM
        else:
            self.confidence_level = CorrelationConfidenceLevel.LOW
        return self


class ThreatCorrelation(BaseModel):
    """
    Represents an explainable, evidence-backed relationship between security objects.

    Additive and non-destructive: Source entities remain unmodified.
    """
    correlation_id: str = Field(
        default_factory=lambda: f"tc-{uuid.uuid4().hex[:12]}",
        description="Unique correlation record identifier with 'tc-' prefix",
    )
    correlation_type: ThreatCorrelationType = Field(
        description="Directional relationship category",
    )
    source_id: str = Field(
        min_length=1,
        description="Identifier of the origin entity (e.g. ioc_id, assessment_id)",
    )
    source_type: str = Field(
        min_length=1,
        description="Entity type of the origin (e.g. 'ioc', 'threat_assessment')",
    )
    target_id: str = Field(
        min_length=1,
        description="Identifier of the destination entity (e.g. event_id, anomaly_id, incident_id, chain_id)",
    )
    target_type: str = Field(
        min_length=1,
        description="Entity type of the destination (e.g. 'event', 'anomaly', 'incident', 'attack_chain')",
    )
    confidence: CorrelationConfidence = Field(
        description="Structured confidence measurement for this correlation link",
    )
    evidence: List[str] = Field(
        default_factory=list,
        description="Human-readable evidence bullet points explaining why this relationship exists",
    )
    correlation_method: str = Field(
        description="Primary heuristic or rule that identified this link",
    )
    first_seen: Optional[datetime] = Field(
        default=None,
        description="Earliest timestamp associated with either linked object (UTC)",
    )
    last_seen: Optional[datetime] = Field(
        default=None,
        description="Latest timestamp associated with either linked object (UTC)",
    )
    created_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="Timestamp when this correlation record was generated (UTC)",
    )
    confirmed: bool = Field(
        default=True,
        description="False for unconfirmed cross-session or speculative temporal-only links",
    )
    analyst_note: Optional[str] = Field(
        default=None,
        description="Optional human analyst review annotation",
    )

    # ── Field Validators ─────────────────────────────────────────────────────

    @field_validator("created_at", "first_seen", "last_seen")
    @classmethod
    def validate_timezone_awareness(cls, dt: Optional[datetime]) -> Optional[datetime]:
        """Ensure all timestamps are timezone-aware."""
        if dt is not None and (dt.tzinfo is None or dt.tzinfo.utcoffset(dt) is None):
            raise ValueError("Timestamps must be timezone-aware (e.g. timezone.utc)")
        return dt

    @model_validator(mode="after")
    def validate_chronology(self) -> ThreatCorrelation:
        """Enforce that first_seen <= last_seen when both are present."""
        if self.first_seen is not None and self.last_seen is not None:
            if self.first_seen > self.last_seen:
                raise ValueError(
                    f"first_seen ({self.first_seen}) cannot be after last_seen ({self.last_seen})"
                )
        return self


# ─────────────────────────────────────────────────────────────────────────────
# Unified Threat Context Model
# ─────────────────────────────────────────────────────────────────────────────

class UnifiedThreatContext(BaseModel):
    """
    Consolidated investigation context for an Indicator of Compromise.

    Aggregates:
    - Core IOC identification and analyst triage lifecycle status
    - External/Offline ThreatAssessment (reputation score, severity, signals)
    - All related Security Objects (Events, Anomalies, Incidents, Attack Chains)
    - Structured ThreatCorrelation relationship models
    - Overall correlation confidence and evidence-based investigation summary
    """
    ioc_id: str = Field(description="Unique IOC identifier")
    ioc_value: str = Field(description="Raw indicator value as observed in logs")
    normalized_value: str = Field(description="Normalized canonical indicator value")
    ioc_type: IOCType = Field(description="Indicator category")
    analyst_status: IOCStatus = Field(description="Current analyst triage lifecycle status")
    threat_intel_result: Optional[ThreatIntelResult] = Field(
        default=None,
        description="Raw threat intelligence provider result if available",
    )
    threat_assessment: Optional[ThreatAssessment] = Field(
        default=None,
        description="Threat assessment produced by ThreatReputationEngine if available",
    )
    related_events: List[Dict[str, Any]] = Field(
        default_factory=list,
        description="Forensic log event details where this indicator appeared",
    )
    related_anomalies: List[Dict[str, Any]] = Field(
        default_factory=list,
        description="Correlated anomaly detection results",
    )
    related_incidents: List[Dict[str, Any]] = Field(
        default_factory=list,
        description="Correlated security incident records",
    )
    related_attack_chains: List[Dict[str, Any]] = Field(
        default_factory=list,
        description="Correlated end-to-end reconstructed attack sequences",
    )
    correlations: List[ThreatCorrelation] = Field(
        default_factory=list,
        description="All directional correlation relationships computed for this IOC",
    )
    overall_correlation_confidence: float = Field(
        default=0.0,
        ge=0.0,
        le=1.0,
        description="Deterministic overall correlation confidence across confirmed links",
    )
    investigation_summary: Dict[str, Any] = Field(
        default_factory=dict,
        description="Factual, evidence-based investigation summary metrics and telemetry",
    )
    generated_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="Timestamp when this unified context was assembled (UTC)",
    )

    @field_validator("generated_at")
    @classmethod
    def validate_timezone_awareness(cls, dt: Optional[datetime]) -> Optional[datetime]:
        """Ensure generated_at is timezone-aware."""
        if dt is not None and (dt.tzinfo is None or dt.tzinfo.utcoffset(dt) is None):
            raise ValueError("generated_at must be timezone-aware (e.g. timezone.utc)")
        return dt

