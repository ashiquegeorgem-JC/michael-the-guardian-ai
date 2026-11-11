"""
Pydantic models for Indicator of Compromise (IOC) intelligence subsystem.

Phase 4.2A — IOC Extraction & Normalization.

DESIGN NOTES
============
- IOC objects represent *extracted and normalized* indicators, not confirmed threats.
- Extracted indicators default to status EXTRACTED; analyst confirmation is required
  to advance to CONFIRMED.
- External reputation lookups are NOT performed in this phase.
- Original raw values are always preserved alongside normalized forms.
- All mutable collection fields use default_factory to prevent shared-state bugs.
- Models follow the same Pydantic v2 / (str, Enum) conventions used throughout MICHAEL.

STORAGE NOTE: All state is held in-memory (SessionStore).
Data is lost on server restart. A persistent Supabase/PostgreSQL
repository is planned for a future phase.
"""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional, Set, Tuple
import uuid

from pydantic import BaseModel, Field, field_validator


# ─────────────────────────────────────────────────────────────────────────────
# Enumerations
# ─────────────────────────────────────────────────────────────────────────────

class IOCType(str, Enum):
    """Classification of an extracted indicator."""
    IPV4      = "ipv4"
    IPV6      = "ipv6"
    DOMAIN    = "domain"
    URL       = "url"
    MD5       = "md5"
    SHA1      = "sha1"
    SHA256    = "sha256"
    EMAIL     = "email"
    FILE_PATH = "file_path"


class IOCStatus(str, Enum):
    """Analyst review lifecycle for a single IOC."""
    EXTRACTED      = "EXTRACTED"       # Raw output — not yet reviewed
    UNDER_REVIEW   = "UNDER_REVIEW"    # Analyst is actively investigating
    CONFIRMED      = "CONFIRMED"       # Analyst confirmed as a genuine indicator
    FALSE_POSITIVE = "FALSE_POSITIVE"  # Analyst determined benign


class ValidationStatus(str, Enum):
    """Deterministic syntax and structure validation status."""
    VALID      = "VALID"       # Syntactically sound and passes all format rules
    INVALID    = "INVALID"     # Malformed, impossible value, or syntax violation
    SUSPICIOUS = "SUSPICIOUS"  # Syntactically valid but anomalous or suspicious pattern (not marked malicious)


class IPScope(str, Enum):
    """Network address scope classification based on RFC standards."""
    PUBLIC      = "public"
    PRIVATE     = "private"
    LOOPBACK    = "loopback"
    LINK_LOCAL  = "link-local"
    MULTICAST   = "multicast"
    RESERVED    = "reserved"
    UNSPECIFIED = "unspecified"


# Valid analyst review state transitions: current status -> set of allowed target statuses
VALID_IOC_STATUS_TRANSITIONS: Dict[IOCStatus, Set[IOCStatus]] = {
    IOCStatus.EXTRACTED:      {IOCStatus.UNDER_REVIEW, IOCStatus.CONFIRMED, IOCStatus.FALSE_POSITIVE},
    IOCStatus.UNDER_REVIEW:   {IOCStatus.CONFIRMED, IOCStatus.FALSE_POSITIVE, IOCStatus.EXTRACTED},
    IOCStatus.CONFIRMED:      {IOCStatus.UNDER_REVIEW, IOCStatus.FALSE_POSITIVE},
    IOCStatus.FALSE_POSITIVE: {IOCStatus.UNDER_REVIEW, IOCStatus.CONFIRMED},
}


class IOCStatusHistory(BaseModel):
    """Single entry in an IOC's status audit trail."""
    previous_status: IOCStatus
    new_status: IOCStatus
    changed_at: datetime = Field(default_factory=datetime.utcnow)
    changed_by: Optional[str] = Field(default=None, description="Analyst identifier")
    reason: str = Field(description="Mandatory reason for the status change")


# ─────────────────────────────────────────────────────────────────────────────
# Evidence — single occurrence in a log line
# ─────────────────────────────────────────────────────────────────────────────

class IOCEvidence(BaseModel):
    """
    Records one specific occurrence of an IOC value in a log event.

    Every IOC must trace back to at least one IOCEvidence entry so that
    analysts can navigate from indicator → log line → raw text.
    """
    event_id: str = Field(
        description="LogEntry.id of the log entry that contained this indicator"
    )
    session_id: str = Field(
        description="Session under which the log was uploaded"
    )
    timestamp: Optional[datetime] = Field(
        default=None,
        description="Parsed timestamp of the originating log entry, if available",
    )
    raw_value: str = Field(
        description="Exact character sequence as it appeared in the log line"
    )
    source_field: str = Field(
        default="raw_line",
        description=(
            "Named field from which the indicator was extracted "
            "(e.g. 'raw_line', 'message', 'source_ip')"
        ),
    )
    line_number: Optional[int] = Field(
        default=None,
        description="1-based line number within the uploaded file",
    )
    surrounding_context: str = Field(
        default="",
        description=(
            "Up to 120 characters of surrounding text centred on the match, "
            "for analyst review without opening the full log."
        ),
    )
    # Optional upstream linkages (populated when available)
    chain_link_event_id: Optional[str] = Field(
        default=None,
        description="ChainLinkEvent.id when the evidence comes from an attack chain event",
    )
    incident_id: Optional[str] = Field(
        default=None,
        description="Incident.id when the log line was already correlated to an incident",
    )
    anomaly_id: Optional[str] = Field(
        default=None,
        description="Anomaly.id when the log line triggered an anomaly detection result",
    )


# ─────────────────────────────────────────────────────────────────────────────
# Core IOC model
# ─────────────────────────────────────────────────────────────────────────────

class IOC(BaseModel):
    """
    A deduplicated, normalized Indicator of Compromise.

    When the same indicator value is extracted multiple times (across
    different log lines or sessions) the occurrences are merged into a
    single IOC entry: occurrence_count is incremented and each occurrence
    is appended to evidence_references.
    """
    id: str = Field(
        default_factory=lambda: f"ioc-{uuid.uuid4().hex[:12]}",
        description="Unique IOC identifier with 'ioc-' prefix",
    )
    ioc_type: IOCType = Field(description="Indicator category")

    # Raw and normalized values are always stored separately
    raw_value: str = Field(
        description="Verbatim value as first extracted from the log"
    )
    normalized_value: str = Field(
        description=(
            "Canonical form after normalization "
            "(e.g. lowercase, leading-zero removal for IPs, lowercase hex for hashes)"
        )
    )

    # Review lifecycle
    status: IOCStatus = Field(
        default=IOCStatus.EXTRACTED,
        description="Analyst review status; defaults to EXTRACTED on creation",
    )

    # Confidence: 0.0 (speculative) – 1.0 (high confidence)
    confidence: float = Field(
        default=0.5,
        ge=0.0,
        le=1.0,
        description="Extraction/classification confidence score (0.0 – 1.0)",
    )

    # Chronology
    first_seen: Optional[datetime] = Field(
        default=None,
        description="Earliest log-entry timestamp at which this indicator was observed",
    )
    last_seen: Optional[datetime] = Field(
        default=None,
        description="Latest log-entry timestamp at which this indicator was observed",
    )
    extracted_at: datetime = Field(
        default_factory=datetime.utcnow,
        description="Wall-clock time at which this IOC record was first created",
    )

    # Aggregation
    occurrence_count: int = Field(
        default=1,
        ge=1,
        description="Total number of log lines in which this indicator was found",
    )

    # Evidence traceability — one entry per unique log-line occurrence
    evidence_references: List[IOCEvidence] = Field(
        default_factory=list,
        description="Ordered list of individual log-line occurrences",
    )

    # Session and extraction metadata
    source_sessions: List[str] = Field(
        default_factory=list,
        description="Distinct session IDs in which this indicator was observed",
    )
    extraction_methods: List[str] = Field(
        default_factory=list,
        description=(
            "Ordered list of extraction strategies that identified this indicator "
            "(e.g. ['regex_ipv4', 'chain_engine'])"
        ),
    )

    # Upstream linkages (populated by evidence mapper)
    associated_chain_ids: List[str] = Field(
        default_factory=list,
        description="Attack chain IDs in which this indicator appears",
    )
    associated_incident_ids: List[str] = Field(
        default_factory=list,
        description="Incident IDs in which this indicator appears",
    )
    associated_anomaly_ids: List[str] = Field(
        default_factory=list,
        description="Anomaly IDs in which this indicator appears",
    )

    # Analyst annotations
    analyst_note: Optional[str] = Field(
        default=None,
        description="Free-text annotation added by an analyst",
    )

    # Status audit trail (populated by IOC status service)
    status_history: List[Any] = Field(
        default_factory=list,
        description="Ordered audit trail of analyst status changes",
    )
    tags: List[str] = Field(
        default_factory=list,
        description="Analyst-applied classification tags (e.g. 'C2', 'lateral-movement')",
    )

    # ── Extensibility hooks for future enrichment phases ─────────────────────
    # These fields are intentionally sparse in Phase 4.2A.
    # External reputation data and MITRE associations will be added in Phase 4.3+.
    mitre_technique_ids: List[str] = Field(
        default_factory=list,
        description="MITRE ATT&CK technique IDs associated with this indicator (future enrichment)",
    )
    reputation_score: Optional[float] = Field(
        default=None,
        ge=0.0,
        le=1.0,
        description=(
            "External threat-intelligence reputation score, 0.0 (benign) – 1.0 (malicious). "
            "NOT populated in Phase 4.2A — reserved for future enrichment."
        ),
    )

    @field_validator("occurrence_count")
    @classmethod
    def occurrence_must_be_positive(cls, v: int) -> int:
        if v < 1:
            raise ValueError("occurrence_count must be at least 1")
        return v

    @field_validator("normalized_value")
    @classmethod
    def normalized_must_not_be_empty(cls, v: str) -> str:
        if not v or not v.strip():
            raise ValueError("normalized_value must not be empty or whitespace")
        return v

    @field_validator("raw_value")
    @classmethod
    def raw_must_not_be_empty(cls, v: str) -> str:
        if not v or not v.strip():
            raise ValueError("raw_value must not be empty or whitespace")
        return v


# ─────────────────────────────────────────────────────────────────────────────
# Extraction Result
# ─────────────────────────────────────────────────────────────────────────────

class IOCExtractionResult(BaseModel):
    """
    Summary returned after processing a single log entry or batch.

    Separates newly-created IOCs from those that were merged into existing
    records (duplicates within the same session).
    """
    total_extracted: int = Field(
        default=0,
        ge=0,
        description="Total raw indicator matches found before deduplication",
    )
    unique_iocs: int = Field(
        default=0,
        ge=0,
        description="Number of distinct IOC records after deduplication",
    )
    duplicate_count: int = Field(
        default=0,
        ge=0,
        description=(
            "Number of occurrences merged into existing IOC records "
            "(total_extracted - unique_iocs)"
        ),
    )
    iocs: List[IOC] = Field(
        default_factory=list,
        description="Resulting IOC records (new and updated)",
    )
    extraction_errors: List[str] = Field(
        default_factory=list,
        description=(
            "Non-fatal extraction warnings, e.g. 'Skipped invalid IP 999.0.0.1'"
        ),
    )
    processed_at: datetime = Field(
        default_factory=datetime.utcnow,
        description="Timestamp of this extraction run",
    )


# ─────────────────────────────────────────────────────────────────────────────
# Search
# ─────────────────────────────────────────────────────────────────────────────

class IOCSearchParams(BaseModel):
    """
    Multi-criteria filter for IOC queries.

    All filters are combined with AND semantics.
    Omit a field to disable that filter.
    """
    session_id:   Optional[str]       = Field(default=None, description="Restrict to a specific session")
    ioc_type:     Optional[IOCType]   = Field(default=None, description="Restrict to a specific IOC type")
    status:       Optional[IOCStatus] = Field(default=None, description="Restrict to a specific review status")
    value:        Optional[str]       = Field(default=None, description="Substring match on normalized_value")
    chain_id:     Optional[str]       = Field(default=None, description="IOCs appearing in this attack chain")
    incident_id:  Optional[str]       = Field(default=None, description="IOCs appearing in this incident")
    anomaly_id:   Optional[str]       = Field(default=None, description="IOCs appearing in this anomaly")
    start_time:   Optional[datetime]  = Field(default=None, description="first_seen >= start_time")
    end_time:     Optional[datetime]  = Field(default=None, description="last_seen <= end_time")
    min_confidence: Optional[float]   = Field(default=None, ge=0.0, le=1.0, description="Minimum confidence threshold")
    page:         int  = Field(default=1,  ge=1,       description="1-based page number")
    page_size:    int  = Field(default=50, ge=1, le=200, description="Results per page")
    sort_by:      str  = Field(default="first_seen",  description="Field to sort by")
    sort_desc:    bool = Field(default=True,           description="Descending order when True")


class IOCSearchResult(BaseModel):
    """Paginated IOC search response."""
    items: List[IOC] = Field(default_factory=list)
    total: int = Field(default=0, ge=0)
    page: int = Field(default=1, ge=1)
    page_size: int = Field(default=50, ge=1)
    total_pages: int = Field(default=0, ge=0)


# ─────────────────────────────────────────────────────────────────────────────
# Status update
# ─────────────────────────────────────────────────────────────────────────────

class IOCStatusUpdate(BaseModel):
    """Request body for analyst-driven status transitions."""
    status: IOCStatus = Field(description="Target status")
    reason: str = Field(
        min_length=5,
        description="Mandatory reason for the status change (minimum 5 characters)",
    )
    changed_by: Optional[str] = Field(
        default=None,
        description="Analyst username or identifier",
    )
    analyst_note: Optional[str] = Field(
        default=None,
        description="Optional free-text note to attach to the IOC record",
    )


# ─────────────────────────────────────────────────────────────────────────────
# Summary / analytics
# ─────────────────────────────────────────────────────────────────────────────

class IOCSummary(BaseModel):
    """
    Aggregate statistics for the IOC dashboard.

    Covers either a specific session or the entire in-memory store
    (when session_id is omitted).
    """
    session_id: Optional[str] = Field(
        default=None,
        description="Session scope; None means store-wide",
    )
    total_iocs: int = Field(default=0, ge=0)
    by_type: Dict[str, int] = Field(
        default_factory=dict,
        description="IOC count per IOCType value (e.g. {'ipv4': 12, 'domain': 3})",
    )
    by_status: Dict[str, int] = Field(
        default_factory=dict,
        description="IOC count per IOCStatus value",
    )
    top_ips: List[Tuple[str, int]] = Field(
        default_factory=list,
        description="Top 10 IPv4/IPv6 addresses by occurrence_count, as (value, count) tuples",
    )
    top_domains: List[Tuple[str, int]] = Field(
        default_factory=list,
        description="Top 10 domains by occurrence_count, as (value, count) tuples",
    )
    top_hashes: List[Tuple[str, int]] = Field(
        default_factory=list,
        description="Top 10 file hashes by occurrence_count, as (value, count) tuples",
    )
    chains_with_iocs: int = Field(
        default=0,
        ge=0,
        description="Number of attack chains that have at least one associated IOC",
    )
    incidents_with_iocs: int = Field(
        default=0,
        ge=0,
        description="Number of incidents that have at least one associated IOC",
    )
    generated_at: datetime = Field(default_factory=datetime.utcnow)


# ─────────────────────────────────────────────────────────────────────────────
# Rebuild to resolve any forward references
# ─────────────────────────────────────────────────────────────────────────────
IOC.model_rebuild()
IOCExtractionResult.model_rebuild()
IOCSummary.model_rebuild()


# ─────────────────────────────────────────────────────────────────────────────
# Phase 4.2A.3 — Validation Result Model
# ─────────────────────────────────────────────────────────────────────────────

class IOCValidationResult(BaseModel):
    """
    Deterministic result of validating an extracted or canonical IOC candidate.

    Distinguishes VALID, INVALID, and SUSPICIOUS without assigning threat scores
    or querying external networks.
    """
    is_valid: bool = Field(
        description="True if validation_status is VALID or SUSPICIOUS; False if INVALID"
    )
    normalized_value: str = Field(
        description="Canonical representation after IOCNormalizer processing"
    )
    original_value: str = Field(
        description="Verbatim raw input before normalization"
    )
    ioc_type: IOCType = Field(
        description="Indicator category evaluated"
    )
    validation_status: ValidationStatus = Field(
        description="Status outcome: VALID, INVALID, or SUSPICIOUS"
    )
    validation_reason: Optional[str] = Field(
        default=None,
        description="Detailed explanation for INVALID or SUSPICIOUS classification",
    )
    ip_scope: Optional[IPScope] = Field(
        default=None,
        description="Network scope for IP indicators (public, private, loopback, etc.)",
    )
    validated_at: datetime = Field(
        default_factory=datetime.utcnow,
        description="Timestamp when validation was performed",
    )


IOCValidationResult.model_rebuild()

