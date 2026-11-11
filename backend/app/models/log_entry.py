"""
Pydantic models for database entities.
"""

from pydantic import BaseModel, Field
from typing import Optional, List
from datetime import datetime
from enum import Enum
import uuid


class LogLevel(str, Enum):
    DEBUG = "DEBUG"
    INFO = "INFO"
    WARNING = "WARNING"
    ERROR = "ERROR"
    CRITICAL = "CRITICAL"
    UNKNOWN = "UNKNOWN"


class LogSession(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    filename: str
    uploaded_at: datetime = Field(default_factory=datetime.utcnow)
    total_lines: int = 0
    file_size: int = 0
    status: str = "pending"  # pending | processing | ready | failed


class LogEntry(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    session_id: str
    timestamp: Optional[datetime] = None
    level: LogLevel = LogLevel.UNKNOWN
    source: Optional[str] = None
    message: str
    raw_line: str
    line_number: int


class LogEntryResponse(LogEntry):
    anomaly_score: Optional[float] = None
    is_anomaly: bool = False


class LogFilter(BaseModel):
    session_id: Optional[str] = None
    level: Optional[List[LogLevel]] = None
    keyword: Optional[str] = None
    start_time: Optional[datetime] = None
    end_time: Optional[datetime] = None
    page: int = 1
    page_size: int = 50


class LogUploadResponse(BaseModel):
    session_id: str
    filename: str
    total_lines: int
    file_size: int
    status: str
    message: str
