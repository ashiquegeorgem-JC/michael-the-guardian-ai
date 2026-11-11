"""
Pydantic models for anomalies.
"""

from pydantic import BaseModel, Field
from typing import Optional, List, Dict, Any
from datetime import datetime
from enum import Enum
import uuid


class SeverityLevel(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class DetectionMethod(str, Enum):
    ISOLATION_FOREST = "isolation_forest"
    STATISTICAL = "statistical"
    TFIDF = "tfidf"
    RULE_BASED = "rule_based"
    TEMPORAL = "temporal"


class Anomaly(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    session_id: str
    log_entry_ids: List[str] = []
    score: float  # 0.0 – 1.0, higher = more anomalous
    severity: SeverityLevel
    reason: str
    detected_at: datetime = Field(default_factory=datetime.utcnow)
    method: DetectionMethod
    supporting_logs: List[str] = []  # raw log lines
    metadata: Dict[str, Any] = {}


class AnomalyResponse(Anomaly):
    incident_id: Optional[str] = None


class ModelMetrics(BaseModel):
    session_id: str
    total_logs: int
    anomalies_detected: int
    contamination_rate: float
    detection_methods: List[str]
    tfidf_top_terms: List[Dict[str, Any]] = []
    isolation_forest_params: Dict[str, Any] = {}
    analysis_duration_seconds: float
    temporal_telemetry: Dict[str, Any] = {}
    evaluated_at: datetime = Field(default_factory=datetime.utcnow)


class AnalysisRequest(BaseModel):
    session_id: str
    contamination: Optional[float] = None  # Override default


class AnalysisStatus(BaseModel):
    session_id: str
    status: str  # pending | running | complete | failed
    progress: int = 0  # 0–100
    message: str = ""
