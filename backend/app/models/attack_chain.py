"""
Pydantic models for Attack Chain Reconstruction (Phase 4.1 / 4.1A).

Defines schemas for correlated attack chains, MITRE attack stages,
timelines, interactive graph structures, lifecycle management,
validation results, and cross-session correlation.

STORAGE NOTE: All state is held in-memory (SessionStore).
Data is lost on server restart. A persistent Supabase/PostgreSQL
repository is planned for a future phase.
"""

from pydantic import BaseModel, Field, field_validator
from typing import Optional, List, Dict, Any, Tuple
from datetime import datetime
from enum import Enum
import uuid


class AttackStage(str, Enum):
    RECONNAISSANCE = "Reconnaissance"
    INITIAL_ACCESS = "Initial Access"
    CREDENTIAL_ATTACK = "Credential Attack"
    PRIVILEGE_ESCALATION = "Privilege Escalation"
    EXECUTION = "Execution"
    PERSISTENCE = "Persistence"
    COMMAND_AND_CONTROL = "Command and Control"
    LATERAL_MOVEMENT = "Lateral Movement"
    DATA_ACCESS = "Data Access"
    EXFILTRATION = "Exfiltration"
    UNKNOWN = "Unknown"


class GraphNodeType(str, Enum):
    SOURCE_IP = "source_ip"
    TARGET_HOST = "target_host"
    USER_ACCOUNT = "user_account"
    PROCESS = "process"
    ATTACK_STAGE = "attack_stage"
    INCIDENT = "incident"
    ENDPOINT = "endpoint"


class ChainLinkEvent(BaseModel):
    """A discrete event correlated into an attack sequence."""
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    log_entry_id: Optional[str] = None
    line_number: Optional[int] = None
    timestamp: Optional[datetime] = None
    stage: AttackStage = AttackStage.UNKNOWN
    stage_confidence: float = Field(default=0.8, ge=0.0, le=1.0)
    source_ip: Optional[str] = None
    destination_ip: Optional[str] = None
    target_resource: Optional[str] = None
    user: Optional[str] = None
    process: Optional[str] = None
    raw_log: str
    message: str
    correlation_reason: str
    anomaly_id: Optional[str] = None
    incident_id: Optional[str] = None
    is_confirmed: bool = True


class AttackGraphNode(BaseModel):
    """Node in forensic entity-relationship graph."""
    id: str
    label: str
    type: GraphNodeType
    details: Dict[str, Any] = {}
    severity: Optional[str] = None  # LOW, MEDIUM, HIGH, CRITICAL


class AttackGraphEdge(BaseModel):
    """Directed edge linking forensic entities or steps."""
    id: str
    source: str
    target: str
    label: str
    timestamp: Optional[str] = None
    confidence: float = 1.0
    stage: Optional[str] = None
    evidence: Optional[str] = None


class AttackGraphData(BaseModel):
    """Full graph structure for React/SVG rendering."""
    nodes: List[AttackGraphNode] = []
    edges: List[AttackGraphEdge] = []


class AttackChainTimeline(BaseModel):
    """Chronological timeline view for an attack chain."""
    chain_id: str
    session_id: str
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None
    duration_seconds: float = 0.0
    total_events: int = 0
    events: List[ChainLinkEvent] = []


# ─────────────────────────────────────────────────────────────────────────────
# Phase 4.1A — Lifecycle Management Models
# ─────────────────────────────────────────────────────────────────────────────

class ChainStatus(str, Enum):
    """Investigation lifecycle status for an attack chain."""
    NEW           = "NEW"
    INVESTIGATING = "INVESTIGATING"
    CONFIRMED     = "CONFIRMED"
    FALSE_POSITIVE = "FALSE_POSITIVE"
    RESOLVED      = "RESOLVED"


# Valid state transitions: maps current status → set of allowed next statuses
VALID_STATUS_TRANSITIONS: Dict[ChainStatus, set] = {
    ChainStatus.NEW:            {ChainStatus.INVESTIGATING, ChainStatus.FALSE_POSITIVE},
    ChainStatus.INVESTIGATING:  {ChainStatus.CONFIRMED, ChainStatus.FALSE_POSITIVE, ChainStatus.RESOLVED},
    ChainStatus.CONFIRMED:      {ChainStatus.RESOLVED, ChainStatus.INVESTIGATING},
    ChainStatus.FALSE_POSITIVE: {ChainStatus.INVESTIGATING},  # Allow re-opening if misclassified
    ChainStatus.RESOLVED:       {ChainStatus.INVESTIGATING},  # Allow re-opening
}


class ChainStatusHistory(BaseModel):
    """Single entry in the chain's status audit trail."""
    previous_status: ChainStatus
    new_status: ChainStatus
    changed_at: datetime = Field(default_factory=datetime.utcnow)
    changed_by: Optional[str] = Field(default=None, description="Analyst identifier (optional)")
    reason: str = Field(description="Mandatory reason for the status change")


class ChainStatusUpdate(BaseModel):
    """Request body for updating a chain's investigation status."""
    status: ChainStatus
    reason: str = Field(min_length=5, description="Reason for the status change (required)")
    changed_by: Optional[str] = Field(default=None, description="Analyst username or ID")


class AttackChain(BaseModel):
    """
    Forensic model representing an end-to-end reconstructed attack chain.
    Correlates multiple anomalies, log entries, and incidents.
    """
    id: str = Field(default_factory=lambda: f"chain-{uuid.uuid4().hex[:12]}")
    session_id: str
    title: str
    summary: str
    severity: str = "HIGH"  # LOW | MEDIUM | HIGH | CRITICAL
    confidence_score: float = Field(default=0.85, ge=0.0, le=1.0)

    # Chronology
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None
    duration_seconds: float = 0.0

    # Stages
    stages_observed: List[AttackStage] = []
    stages_unconfirmed: List[AttackStage] = []

    # Forensic Entities
    source_ips: List[str] = []
    target_systems: List[str] = []
    affected_users: List[str] = []
    affected_processes: List[str] = []

    # Correlated components
    associated_anomaly_ids: List[str] = []
    associated_incident_ids: List[str] = []
    event_ids: List[str] = []
    events: List[ChainLinkEvent] = []

    # Traceable evidence & AI explanations
    supporting_evidence: List[str] = []
    hypotheses_unconfirmed: List[str] = []
    potential_impact: str
    correlation_explanation: str
    recommended_actions: List[str] = []

    # Graph
    graph_data: Optional[AttackGraphData] = None

    # ── Phase 4.1A additions (backward-compatible optional fields) ──────────
    # Investigation lifecycle
    status: ChainStatus = Field(default=ChainStatus.NEW, description="Current investigation status")
    analyst_note: Optional[str] = Field(default=None, description="Free-text analyst annotation")
    status_history: List[ChainStatusHistory] = Field(
        default_factory=list,
        description="Audit trail of all status changes",
    )

    # Cross-session association (weak links — not confirmed merges)
    related_chain_ids: List[str] = Field(
        default_factory=list,
        description="IDs of chains in other sessions with corroborating evidence",
    )
    cross_session_evidence: List[str] = Field(
        default_factory=list,
        description="Explanations for each cross-session relationship",
    )


# ─────────────────────────────────────────────────────────────────────────────
# Phase 4.1A — Validation Result Models
# ─────────────────────────────────────────────────────────────────────────────

class ValidationSeverity(str, Enum):
    INFO    = "INFO"
    WARNING = "WARNING"
    ERROR   = "ERROR"


class ValidationFinding(BaseModel):
    """A single structural or logical finding from ChainValidator."""
    severity: ValidationSeverity
    code: str = Field(description="Short machine-readable finding code, e.g. 'DUPLICATE_EVENT'")
    message: str
    affected_event_ids: List[str] = Field(default_factory=list)


class ChainValidationResult(BaseModel):
    """Structured result returned by ChainValidator.validate()."""
    chain_id: str
    is_valid: bool = Field(description="True when no ERROR-level findings exist")
    findings: List[ValidationFinding] = Field(default_factory=list)
    validated_at: datetime = Field(default_factory=datetime.utcnow)

    @property
    def errors(self) -> List[ValidationFinding]:
        return [f for f in self.findings if f.severity == ValidationSeverity.ERROR]

    @property
    def warnings(self) -> List[ValidationFinding]:
        return [f for f in self.findings if f.severity == ValidationSeverity.WARNING]


# ─────────────────────────────────────────────────────────────────────────────
# Phase 4.1A — Search / Summary Models
# ─────────────────────────────────────────────────────────────────────────────

class ChainSearchParams(BaseModel):
    """Query parameters for advanced chain search."""
    session_id:    Optional[str]         = None
    chain_id:      Optional[str]         = None
    source_ip:     Optional[str]         = None
    destination_ip: Optional[str]        = None
    username:      Optional[str]         = None
    stage:         Optional[str]         = None   # AttackStage value string
    severity:      Optional[str]         = None   # LOW / MEDIUM / HIGH / CRITICAL
    status:        Optional[ChainStatus] = None
    keyword:       Optional[str]         = None   # Free-text across title/summary/evidence
    start_time:    Optional[datetime]    = None
    end_time:      Optional[datetime]    = None
    event_id:      Optional[str]         = None
    page:          int = Field(default=1, ge=1)
    page_size:     int = Field(default=20, ge=1, le=100)
    sort_by:       str = Field(default="first_seen", description="Field to sort by")
    sort_desc:     bool = Field(default=True, description="Sort descending when True")


class ChainSearchResult(BaseModel):
    """Paginated search response."""
    total: int
    page: int
    page_size: int
    chains: List[AttackChain]


class ChainSummary(BaseModel):
    """Aggregate statistics across all chains in the store."""
    total_chains: int
    by_severity: Dict[str, int]
    by_status:   Dict[str, int]
    by_stage:    Dict[str, int]
    top_source_ips: List[Tuple[str, int]]   # (ip, chain_count)
    avg_confidence: float
    avg_duration_seconds: float
    recent_chains: List[AttackChain]        # Up to 5 most recent


# ─────────────────────────────────────────────────────────────────────────────
# Phase 4.1A — Related Entities Models
# ─────────────────────────────────────────────────────────────────────────────

class RelatedEntity(BaseModel):
    """A single forensic entity related to a chain with evidence."""
    entity_type: str         # "ip" | "user" | "host" | "session" | "chain"
    entity_value: str
    relationship_type: str   # "attacker_ip" | "targeted_user" | "shared_stage" | etc.
    evidence: List[str] = Field(default_factory=list)
    confidence: float = Field(default=1.0, ge=0.0, le=1.0)


class RelatedChainLink(BaseModel):
    """A potential cross-session or cross-chain association."""
    chain_id: str
    session_id: str
    title: str
    severity: str
    shared_signals: List[str] = Field(
        description="Specific shared fields (e.g. IP, username) supporting the link"
    )
    correlation_explanation: str
    confidence: float = Field(ge=0.0, le=1.0)
    is_confirmed: bool = False


class RelatedEntitiesResponse(BaseModel):
    """Response for GET /{chain_id}/related."""
    chain_id: str
    related_ips: List[RelatedEntity] = []
    related_users: List[RelatedEntity] = []
    related_hosts: List[RelatedEntity] = []
    related_sessions: List[RelatedEntity] = []
    related_chains: List[RelatedChainLink] = []
    total_relationships: int = 0


# ─────────────────────────────────────────────────────────────────────────────
# Rebuild AttackChain with forward-reference resolution
# ─────────────────────────────────────────────────────────────────────────────
AttackChain.model_rebuild()
ChainSummary.model_rebuild()
