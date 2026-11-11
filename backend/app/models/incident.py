"""
Pydantic models for incidents.
"""

from pydantic import BaseModel, Field
from typing import Optional, List
from datetime import datetime
from enum import Enum
import uuid


class IncidentStatus(str, Enum):
    OPEN = "open"
    INVESTIGATING = "investigating"
    RESOLVED = "resolved"
    FALSE_POSITIVE = "false_positive"


class IncidentCategory(str, Enum):
    AUTHENTICATION_FAILURE = "Authentication Failure"
    INTRUSION_ATTEMPT = "Intrusion Attempt"
    SYSTEM_CRASH = "System Crash"
    RESOURCE_EXHAUSTION = "Resource Exhaustion"
    DATABASE_ANOMALY = "Database Anomaly"
    NETWORK_ANOMALY = "Network Anomaly"
    APPLICATION_ERROR = "Application Error"
    PRIVILEGE_ESCALATION = "Privilege Escalation"
    DATA_EXFILTRATION = "Data Exfiltration"
    MALWARE_INDICATOR = "Malware Indicator"
    CONFIGURATION_CHANGE = "Configuration Change"
    UNKNOWN = "Unknown"


class Incident(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    anomaly_id: str
    session_id: str
    category: IncidentCategory
    severity: str  # LOW | MEDIUM | HIGH | CRITICAL
    title: str
    description: str

    # Evidence (grounded in actual log data)
    evidence: List[str] = []
    evidence_log_lines: List[str] = []

    # AI-generated analysis (clearly marked)
    root_cause_hypothesis: str  # AI-generated
    potential_impact: str       # AI-generated
    remediation_steps: List[str] = []  # AI-generated

    # Timestamps
    first_seen: datetime
    last_seen: datetime
    created_at: datetime = Field(default_factory=datetime.utcnow)

    # Status
    status: IncidentStatus = IncidentStatus.OPEN
    affected_sources: List[str] = []
    affected_ips: List[str] = []


class IncidentFilter(BaseModel):
    session_id: Optional[str] = None
    severity: Optional[str] = None
    category: Optional[str] = None
    status: Optional[str] = None
    page: int = 1
    page_size: int = 20
