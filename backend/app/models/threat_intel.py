"""
Threat Intelligence Data Models for MICHAEL – THE GUARDIAN AI.

Phase 4.2B.1 — Threat Intelligence Data Model & Provider Interface.

Defines strongly typed, validated models and enums for threat intelligence enrichment.

DESIGN INVARIANTS:
==================
1. ThreatIntelStatus (UNKNOWN, CLEAN, SUSPICIOUS, MALICIOUS, ERROR) represents
   external/mock intelligence findings and is strictly decoupled from IOCStatus
   (analyst investigation lifecycle: EXTRACTED, UNDER_REVIEW, CONFIRMED, FALSE_POSITIVE).
2. All timestamps must be timezone-aware (UTC).
3. Detection count cannot be negative and cannot exceed total_engines when both are present.
4. Confidence and reputation scores are strictly bounded between 0.0 and 1.0.
5. Raw metadata is sanitized to prevent inadvertent credential/secret exposure.
6. Offline and simulated results are explicitly distinguished via provider attribution.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from enum import Enum
import re
from typing import Any, Dict, List, Optional
import uuid

from pydantic import BaseModel, Field, field_validator, model_validator

from app.models.ioc import IOCType


# ─────────────────────────────────────────────────────────────────────────────
# Enumerations
# ─────────────────────────────────────────────────────────────────────────────

class ThreatIntelStatus(str, Enum):
    """
    Threat intelligence verdict outcome from provider evaluation.

    IMPORTANT: This represents intelligence findings and MUST remain
    strictly separate from analyst review lifecycle state (IOCStatus).
    """
    UNKNOWN    = "UNKNOWN"     # No definitive intelligence or insufficient telemetry
    CLEAN      = "CLEAN"       # Known benign / legitimate infrastructure / whitelisted
    SUSPICIOUS = "SUSPICIOUS"  # Heuristically risky, low detection ratio, or anomalous
    MALICIOUS  = "MALICIOUS"   # Known threat actor, confirmed malware hash, active C2
    ERROR      = "ERROR"       # Provider lookup failure, timeout, or rate-limited


class ThreatIntelSource(str, Enum):
    """
    Identification of the threat intelligence feed or provider.

    Extensible string-enum to accommodate future real-world integrations
    without breaking core models.
    """
    OFFLINE_MOCK = "offline_mock"  # Deterministic offline mock provider
    VIRUSTOTAL   = "virustotal"    # VirusTotal (Future Phase 4.2B.3)
    ABUSEIPDB    = "abuseipdb"     # AbuseIPDB (Future Phase 4.2B.3)
    URLHAUS      = "urlhaus"       # Abuse.ch URLhaus (Future Phase 4.2B.3)
    GREYNOISE    = "greynoise"     # GreyNoise (Future Phase 4.2B.3)
    ALIENVAULT   = "alienvault"    # AlienVault OTX (Future Phase 4.2B.3)
    CUSTOM       = "custom"        # Custom internal intelligence feed


class ThreatSeverity(str, Enum):
    """
    Threat severity tier derived deterministically from threat scoring and confidence.

    Phase 4.2B.2 — Offline Threat Reputation & Scoring Engine.

    UNKNOWN  - Insufficient intelligence, low confidence, or unmapped indicator.
    LOW      - Benign infrastructure, verified clean, or minimal score (0.0 - 24.9).
    MEDIUM   - Suspicious telemetry, reconnaissance probes, or moderate score (25.0 - 59.9).
    HIGH     - High detection ratio, confirmed malicious tags, or elevated score (60.0 - 84.9).
    CRITICAL - Active C2, confirmed malware hash, widespread detection, or critical score (85.0 - 100.0).
    """
    UNKNOWN  = "UNKNOWN"
    LOW      = "LOW"
    MEDIUM   = "MEDIUM"
    HIGH     = "HIGH"
    CRITICAL = "CRITICAL"


# Keys that must never be exposed or persisted in threat intel metadata
_SENSITIVE_KEY_PATTERN = re.compile(
    r"(?:api[_-]?key|secret|password|bearer|auth|token|private[_-]?key)",
    re.IGNORECASE,
)


def _sanitize_metadata(data: Optional[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
    """Recursively scrub sensitive credential keys from provider metadata dictionaries."""
    if not data or not isinstance(data, dict):
        return data

    sanitized: Dict[str, Any] = {}
    for key, value in data.items():
        if _SENSITIVE_KEY_PATTERN.search(str(key)):
            sanitized[key] = "[REDACTED]"
        elif isinstance(value, dict):
            sanitized[key] = _sanitize_metadata(value)
        else:
            sanitized[key] = value
    return sanitized


# ─────────────────────────────────────────────────────────────────────────────
# Core Threat Intelligence Result Model
# ─────────────────────────────────────────────────────────────────────────────

class ThreatIntelResult(BaseModel):
    """
    Normalized, immutable result of a threat intelligence provider query.

    Encapsulates detection ratios, engine scores, confidence metrics,
    geographical context, and source attribution.
    """
    id: str = Field(
        default_factory=lambda: f"ti-{uuid.uuid4().hex[:12]}",
        description="Unique threat intelligence record ID",
    )
    ioc_id: str = Field(
        description="ID of the associated IOC entity",
    )
    ioc_type: IOCType = Field(
        description="Indicator category evaluated",
    )
    ioc_value: str = Field(
        description="Original indicator value evaluated",
    )
    normalized_value: str = Field(
        description="Canonical normalized indicator value",
    )
    status: ThreatIntelStatus = Field(
        default=ThreatIntelStatus.UNKNOWN,
        description="Intelligence verdict (UNKNOWN, CLEAN, SUSPICIOUS, MALICIOUS, ERROR)",
    )
    confidence: float = Field(
        default=0.0,
        ge=0.0,
        le=1.0,
        description="Confidence score in the verdict (0.0 to 1.0)",
    )
    source: ThreatIntelSource = Field(
        default=ThreatIntelSource.OFFLINE_MOCK,
        description="Provider source category",
    )
    provider_name: str = Field(
        description="Human-readable provider identifier (e.g. 'offline_mock')",
    )
    provider_version: Optional[str] = Field(
        default="1.0.0",
        description="Version string of the provider implementation",
    )
    queried_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="Time when the provider query was executed (timezone-aware UTC)",
    )
    expires_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc) + timedelta(hours=1),
        description="Time after which this cached intelligence is considered stale (UTC)",
    )
    lookup_latency_ms: Optional[float] = Field(
        default=None,
        ge=0.0,
        description="Lookup execution latency in milliseconds",
    )
    source_reference: Optional[str] = Field(
        default=None,
        description="External reference URL, report permalink, or rule ID",
    )
    detection_count: Optional[int] = Field(
        default=None,
        ge=0,
        description="Number of engines reporting the indicator as malicious or suspicious",
    )
    total_engines: Optional[int] = Field(
        default=None,
        ge=0,
        description="Total number of threat intelligence engines queried",
    )
    reputation_score: Optional[float] = Field(
        default=None,
        ge=0.0,
        le=1.0,
        description="Normalized reputation score: 0.0 (benign) to 1.0 (malicious)",
    )
    categories: List[str] = Field(
        default_factory=list,
        description="Threat categories (e.g. ['botnet', 'c2', 'scanner'])",
    )
    tags: List[str] = Field(
        default_factory=list,
        description="Descriptive metadata tags from provider",
    )
    country: Optional[str] = Field(
        default=None,
        description="ISO 3166-1 alpha-2 country code where applicable",
    )
    asn: Optional[str] = Field(
        default=None,
        description="Autonomous System Number (e.g. 'AS15169')",
    )
    first_seen: Optional[datetime] = Field(
        default=None,
        description="Earliest observation timestamp reported by the provider",
    )
    last_seen: Optional[datetime] = Field(
        default=None,
        description="Latest observation timestamp reported by the provider",
    )
    raw_metadata: Optional[Dict[str, Any]] = Field(
        default=None,
        description="Optional sanitized raw provider response payload",
    )

    # ── Field Validators ─────────────────────────────────────────────────────

    @field_validator("queried_at", "expires_at", "first_seen", "last_seen")
    @classmethod
    def validate_timezone_awareness(cls, dt: Optional[datetime]) -> Optional[datetime]:
        """Ensure all timestamps are explicitly timezone-aware."""
        if dt is not None:
            if dt.tzinfo is None or dt.tzinfo.utcoffset(dt) is None:
                raise ValueError("Timestamps must be timezone-aware (e.g. timezone.utc)")
        return dt

    @field_validator("raw_metadata")
    @classmethod
    def sanitize_raw_metadata(cls, v: Optional[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
        """Sanitize raw metadata to strip accidental secrets or API keys."""
        return _sanitize_metadata(v)

    # ── Model Validators ─────────────────────────────────────────────────────

    @model_validator(mode="after")
    def validate_detection_ratio(self) -> ThreatIntelResult:
        """Enforce that detection_count cannot exceed total_engines when both are specified."""
        if self.detection_count is not None and self.total_engines is not None:
            if self.detection_count > self.total_engines:
                raise ValueError(
                    f"detection_count ({self.detection_count}) cannot exceed total_engines ({self.total_engines})"
                )
        return self

    @model_validator(mode="after")
    def validate_expiration_chronology(self) -> ThreatIntelResult:
        """Enforce that expires_at must be equal to or greater than queried_at."""
        if self.expires_at < self.queried_at:
            raise ValueError(
                f"expires_at ({self.expires_at}) cannot be before queried_at ({self.queried_at})"
            )
        return self


ThreatIntelResult.model_rebuild()


# ─────────────────────────────────────────────────────────────────────────────
# Contributing Signal & Threat Assessment Models (Phase 4.2B.2)
# ─────────────────────────────────────────────────────────────────────────────

class ContributingSignal(BaseModel):
    """
    Individual structured intelligence telemetry signal used in threat score calculation.

    Phase 4.2B.2 — Offline Threat Reputation & Scoring Engine.
    """
    signal_name: str = Field(
        description="Machine name of the signal (e.g. 'provider_status', 'detection_ratio')",
    )
    value: Any = Field(
        description="Observed value of the signal (e.g. 0.75, 'MALICIOUS', ['c2_server'])",
    )
    weight: float = Field(
        ge=0.0,
        le=1.0,
        description="Relative weight allocated to this signal in the scoring engine (0.0 to 1.0)",
    )
    contribution: float = Field(
        ge=0.0,
        le=100.0,
        description="Points contributed by this signal to the total threat score (0.0 to 100.0)",
    )
    explanation: str = Field(
        description="Human-readable explanation of the signal observation and its impact",
    )
    available: bool = Field(
        default=True,
        description="Whether this signal was available in the source telemetry",
    )


class ThreatAssessment(BaseModel):
    """
    Explainable, deterministic threat evaluation produced by ThreatReputationEngine.

    Phase 4.2B.2 — Offline Threat Reputation & Scoring Engine.

    Encapsulates:
    - Deterministic threat score (0.0 to 100.0)
    - Independent confidence metric (0.0 to 1.0)
    - Categorical severity tier (UNKNOWN, LOW, MEDIUM, HIGH, CRITICAL)
    - Human-readable explanation reasons
    - Structured contributing signals
    - Non-mutation guarantee of parent IOC and analyst triage state (IOCStatus)
    """
    assessment_id: str = Field(
        default_factory=lambda: f"ta-{uuid.uuid4().hex[:12]}",
        description="Unique identifier for this assessment event",
    )
    ioc_id: str = Field(
        description="ID of the associated IOC entity",
    )
    ioc_type: IOCType = Field(
        description="Indicator category evaluated",
    )
    ioc_value: str = Field(
        description="Original indicator value evaluated",
    )
    normalized_value: str = Field(
        description="Canonical normalized indicator value",
    )
    threat_score: float = Field(
        default=0.0,
        ge=0.0,
        le=100.0,
        description="Deterministic threat score from 0.0 (benign) to 100.0 (critical threat)",
    )
    confidence: float = Field(
        default=0.0,
        ge=0.0,
        le=1.0,
        description="Evidence confidence metric from 0.0 (no confidence) to 1.0 (highest confidence)",
    )
    severity: ThreatSeverity = Field(
        default=ThreatSeverity.UNKNOWN,
        description="Derived severity tier (UNKNOWN, LOW, MEDIUM, HIGH, CRITICAL)",
    )
    status: ThreatIntelStatus = Field(
        default=ThreatIntelStatus.UNKNOWN,
        description="Threat intelligence status verdict from evaluation",
    )
    reasons: List[str] = Field(
        default_factory=list,
        description="Human-readable explanation bullet points detailing the score factors",
    )
    contributing_signals: List[ContributingSignal] = Field(
        default_factory=list,
        description="Structured breakdown of signals and point contributions",
    )
    assessed_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="Timestamp when assessment was computed (timezone-aware UTC)",
    )
    expires_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc) + timedelta(hours=1),
        description="Timestamp after which this assessment is considered stale (UTC)",
    )
    engine_version: str = Field(
        default="1.0.0",
        description="Version of the reputation scoring engine algorithm",
    )
    raw_metadata: Optional[Dict[str, Any]] = Field(
        default=None,
        description="Sanitized contextual metadata from scoring evaluation",
    )

    # ── Field Validators ─────────────────────────────────────────────────────

    @field_validator("assessed_at", "expires_at")
    @classmethod
    def validate_timezone_awareness(cls, dt: Optional[datetime]) -> Optional[datetime]:
        """Ensure all timestamps are explicitly timezone-aware."""
        if dt is not None:
            if dt.tzinfo is None or dt.tzinfo.utcoffset(dt) is None:
                raise ValueError("Timestamps must be timezone-aware (e.g. timezone.utc)")
        return dt

    @field_validator("raw_metadata")
    @classmethod
    def sanitize_raw_metadata(cls, v: Optional[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
        """Sanitize raw metadata to strip accidental secrets or API keys."""
        return _sanitize_metadata(v)

    # ── Model Validators ─────────────────────────────────────────────────────

    @model_validator(mode="after")
    def validate_expiration_chronology(self) -> ThreatAssessment:
        """Enforce that expires_at must be equal to or greater than assessed_at."""
        if self.expires_at < self.assessed_at:
            raise ValueError(
                f"expires_at ({self.expires_at}) cannot be before assessed_at ({self.assessed_at})"
            )
        return self


ContributingSignal.model_rebuild()
ThreatAssessment.model_rebuild()


