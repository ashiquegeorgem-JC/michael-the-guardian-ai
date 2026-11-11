"""
Abstract Persistence Repository Interfaces for MICHAEL – THE GUARDIAN AI.

Phase 5.0 — Production Hardening & Persistence Integration.

Defines repository contracts for:
- Session & Log Data persistence
- Incident & Anomaly persistence
- Attack Chain persistence
- IOC & Forensic Evidence persistence
"""

from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional

from app.models.anomaly import Anomaly, ModelMetrics
from app.models.attack_chain import AttackChain
from app.models.incident import Incident
from app.models.ioc import IOC, IOCEvidence, IOCStatus, IOCType
from app.models.log_entry import LogEntry, LogSession


class BaseSessionStore(ABC):
    """Abstract interface for session-scoped analysis storage."""

    @abstractmethod
    def set_session(self, session: LogSession, entries: List[LogEntry]):
        pass

    @abstractmethod
    def get_session(self, session_id: str) -> Optional[LogSession]:
        pass

    @abstractmethod
    def get_entries(self, session_id: str) -> List[LogEntry]:
        pass

    @abstractmethod
    def get_all_sessions(self) -> List[LogSession]:
        pass

    @abstractmethod
    def set_analysis(self, session_id: str, anomalies: List[Anomaly], metrics: ModelMetrics):
        pass

    @abstractmethod
    def get_anomalies(self, session_id: str) -> List[Anomaly]:
        pass

    @abstractmethod
    def get_metrics(self, session_id: str) -> Optional[ModelMetrics]:
        pass

    @abstractmethod
    def set_incidents(self, session_id: str, incidents: List[Incident]):
        pass

    @abstractmethod
    def get_incidents(self, session_id: str) -> List[Incident]:
        pass

    @abstractmethod
    def set_attack_chains(self, session_id: str, chains: List[AttackChain]):
        pass

    @abstractmethod
    def get_attack_chains(self, session_id: str) -> List[AttackChain]:
        pass

    @abstractmethod
    def get_attack_chain(self, chain_id: str) -> Optional[AttackChain]:
        pass

    @abstractmethod
    def get_dashboard_stats(self) -> Dict[str, Any]:
        pass


class BaseIOCRepository(ABC):
    """Abstract interface for canonical IOC storage & retrieval."""

    @abstractmethod
    def add_ioc(self, ioc: IOC) -> IOC:
        pass

    @abstractmethod
    def get_ioc(self, ioc_id: str) -> Optional[IOC]:
        pass

    @abstractmethod
    def get_ioc_by_normalized_value(self, ioc_type: IOCType, normalized_value: str) -> Optional[IOC]:
        pass

    @abstractmethod
    def get_all_iocs(
        self,
        skip: int = 0,
        limit: int = 100,
        ioc_type: Optional[IOCType] = None,
        status: Optional[IOCStatus] = None,
    ) -> List[IOC]:
        pass

    @abstractmethod
    def find_iocs_by_session(self, session_id: str) -> List[IOC]:
        pass

    @abstractmethod
    def find_iocs_by_event(self, event_id: str) -> List[IOC]:
        pass

    @abstractmethod
    def find_iocs_by_anomaly(self, anomaly_id: str) -> List[IOC]:
        pass

    @abstractmethod
    def find_iocs_by_incident(self, incident_id: str) -> List[IOC]:
        pass

    @abstractmethod
    def find_iocs_by_attack_chain(self, attack_chain_id: str) -> List[IOC]:
        pass

    @abstractmethod
    def update_ioc_status(
        self,
        ioc_id: str,
        new_status: IOCStatus,
        reason: str,
        analyst: Optional[str] = None,
    ) -> Optional[IOC]:
        pass

    @abstractmethod
    def count_iocs(
        self,
        ioc_type: Optional[IOCType] = None,
        status: Optional[IOCStatus] = None,
    ) -> int:
        pass

    @abstractmethod
    def get_stats(self) -> Dict[str, Any]:
        pass

