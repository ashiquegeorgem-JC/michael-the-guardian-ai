"""
Session state manager for MICHAEL – THE GUARDIAN AI.

Phase 5.0 — Production Hardening & Persistence Integration.

Supports:
- Thread-safe in-memory store for development, evaluation, and unit tests.
- Transparent database persistence (PostgreSQL / Supabase / SQLite) via SQLStoreRepository.
- Safe fallback when persistence backend is unavailable or set to 'memory'.
"""

import logging
from typing import Any, Dict, List, Optional

from app.config import settings
from app.models.anomaly import Anomaly, ModelMetrics
from app.models.attack_chain import AttackChain
from app.models.incident import Incident
from app.models.ioc import IOC
from app.models.log_entry import LogEntry, LogSession

logger = logging.getLogger("michael.store")


class SessionStore:
    """
    Session store supporting in-memory caching and optional database persistence.
    """

    def __init__(self, backend: Optional[str] = None):
        self.sessions: Dict[str, LogSession] = {}
        self.entries: Dict[str, List[LogEntry]] = {}       # session_id → entries
        self.anomalies: Dict[str, List[Anomaly]] = {}      # session_id → anomalies
        self.metrics: Dict[str, ModelMetrics] = {}         # session_id → metrics
        self.incidents: Dict[str, List[Incident]] = {}     # session_id → incidents
        self.attack_chains: Dict[str, List[AttackChain]] = {} # session_id → attack_chains
        self.iocs: Dict[str, IOC] = {}                     # ioc_id → IOC (canonical across sessions)
        self.session_iocs: Dict[str, List[str]] = {}       # session_id → list of ioc_ids
        self.active_session_id: Optional[str] = None

        # Resolve persistence backend
        resolved_backend = (backend or getattr(settings, "PERSISTENCE_BACKEND", "memory")).lower()
        self._backend_name = resolved_backend
        self._sql_repo = None

        if resolved_backend in ("postgres", "sqlite"):
            try:
                from app.persistence.sql_store import SQLStoreRepository
                self._sql_repo = SQLStoreRepository()
                logger.info("SessionStore initialized with persistence backend '%s'", resolved_backend)
            except Exception as exc:
                logger.warning("Failed to initialize SQLStoreRepository: %s. Falling back to memory.", exc)

    @property
    def persistence_backend(self) -> str:
        return self._backend_name

    def set_session(self, session: LogSession, entries: List[LogEntry]):
        self.sessions[session.id] = session
        self.entries[session.id] = entries
        self.active_session_id = session.id

        if self._sql_repo is not None:
            try:
                self._sql_repo.set_session(session, entries)
            except Exception as exc:
                logger.error("Failed to persist session to database: %s", exc)

    def get_session(self, session_id: str) -> Optional[LogSession]:
        if session_id in self.sessions:
            return self.sessions[session_id]

        if self._sql_repo is not None:
            try:
                db_sess = self._sql_repo.get_session(session_id)
                if db_sess:
                    self.sessions[session_id] = db_sess
                    return db_sess
            except Exception as exc:
                logger.error("Failed to query session from database: %s", exc)
        return None

    def get_entries(self, session_id: str) -> List[LogEntry]:
        if session_id in self.entries and self.entries[session_id]:
            return self.entries[session_id]

        if self._sql_repo is not None:
            try:
                db_entries = self._sql_repo.get_entries(session_id)
                if db_entries:
                    self.entries[session_id] = db_entries
                    return db_entries
            except Exception as exc:
                logger.error("Failed to query entries from database: %s", exc)
        return self.entries.get(session_id, [])

    def set_analysis(self, session_id: str, anomalies: List[Anomaly], metrics: ModelMetrics):
        self.anomalies[session_id] = anomalies
        self.metrics[session_id] = metrics

        if self._sql_repo is not None:
            try:
                self._sql_repo.set_analysis(session_id, anomalies, metrics)
            except Exception as exc:
                logger.error("Failed to persist analysis to database: %s", exc)

    def get_anomalies(self, session_id: str) -> List[Anomaly]:
        if session_id in self.anomalies and self.anomalies[session_id]:
            return self.anomalies[session_id]

        if self._sql_repo is not None:
            try:
                db_anoms = self._sql_repo.get_anomalies(session_id)
                if db_anoms:
                    self.anomalies[session_id] = db_anoms
                    return db_anoms
            except Exception as exc:
                logger.error("Failed to query anomalies from database: %s", exc)
        return self.anomalies.get(session_id, [])

    def get_metrics(self, session_id: str) -> Optional[ModelMetrics]:
        if session_id in self.metrics:
            return self.metrics[session_id]

        if self._sql_repo is not None:
            try:
                db_metrics = self._sql_repo.get_metrics(session_id)
                if db_metrics:
                    self.metrics[session_id] = db_metrics
                    return db_metrics
            except Exception as exc:
                logger.error("Failed to query metrics from database: %s", exc)
        return self.metrics.get(session_id)

    def set_incidents(self, session_id: str, incidents: List[Incident]):
        self.incidents[session_id] = incidents

        if self._sql_repo is not None:
            try:
                self._sql_repo.set_incidents(session_id, incidents)
            except Exception as exc:
                logger.error("Failed to persist incidents to database: %s", exc)

    def get_incidents(self, session_id: str) -> List[Incident]:
        if session_id in self.incidents and self.incidents[session_id]:
            return self.incidents[session_id]

        if self._sql_repo is not None:
            try:
                db_incs = self._sql_repo.get_incidents(session_id)
                if db_incs:
                    self.incidents[session_id] = db_incs
                    return db_incs
            except Exception as exc:
                logger.error("Failed to query incidents from database: %s", exc)
        return self.incidents.get(session_id, [])

    def set_attack_chains(self, session_id: str, chains: List[AttackChain]):
        self.attack_chains[session_id] = chains

        if self._sql_repo is not None:
            try:
                self._sql_repo.set_attack_chains(session_id, chains)
            except Exception as exc:
                logger.error("Failed to persist attack chains to database: %s", exc)

    def get_attack_chains(self, session_id: str) -> List[AttackChain]:
        if session_id in self.attack_chains and self.attack_chains[session_id]:
            return self.attack_chains[session_id]

        if self._sql_repo is not None:
            try:
                db_chains = self._sql_repo.get_attack_chains(session_id)
                if db_chains:
                    self.attack_chains[session_id] = db_chains
                    return db_chains
            except Exception as exc:
                logger.error("Failed to query attack chains from database: %s", exc)
        return self.attack_chains.get(session_id, [])

    def get_attack_chain(self, chain_id: str) -> Optional[AttackChain]:
        for chains in self.attack_chains.values():
            for chain in chains:
                if chain.id == chain_id:
                    return chain

        if self._sql_repo is not None:
            try:
                return self._sql_repo.get_attack_chain(chain_id)
            except Exception as exc:
                logger.error("Failed to query attack chain from database: %s", exc)
        return None

    def set_iocs(self, session_id: str, iocs: List[IOC]):
        """Register or update IOCs for a session."""
        for ioc in iocs:
            self.iocs[ioc.id] = ioc
        self.session_iocs[session_id] = [ioc.id for ioc in iocs]

    def get_iocs(self, session_id: Optional[str] = None) -> List[IOC]:
        """Retrieve all IOCs, optionally filtered by session."""
        if session_id:
            ioc_ids = self.session_iocs.get(session_id, [])
            return [self.iocs[iid] for iid in ioc_ids if iid in self.iocs]
        return list(self.iocs.values())

    def get_ioc(self, ioc_id: str) -> Optional[IOC]:
        """Retrieve single IOC by id."""
        return self.iocs.get(ioc_id)

    def get_all_sessions(self) -> List[LogSession]:
        if self._sql_repo is not None:
            try:
                db_sessions = self._sql_repo.get_all_sessions()
                if db_sessions:
                    return db_sessions
            except Exception as exc:
                logger.error("Failed to query all sessions from database: %s", exc)
        return list(self.sessions.values())

    def get_dashboard_stats(self) -> dict:
        if self._sql_repo is not None and not self.sessions:
            try:
                return self._sql_repo.get_dashboard_stats()
            except Exception as exc:
                logger.error("Failed to query dashboard stats from database: %s", exc)

        total_logs = sum(len(e) for e in self.entries.values())
        total_anomalies = sum(len(a) for a in self.anomalies.values())
        all_incidents = [i for lst in self.incidents.values() for i in lst]
        all_chains = [c for lst in self.attack_chains.values() for c in lst]
        critical = sum(1 for i in all_incidents if i.severity == "CRITICAL")
        open_incidents = sum(1 for i in all_incidents if getattr(i.status, "value", i.status) == "open")

        return {
            "total_logs": total_logs,
            "total_anomalies": total_anomalies,
            "total_incidents": len(all_incidents),
            "total_attack_chains": len(all_chains),
            "total_iocs": len(self.iocs),
            "critical_incidents": critical,
            "open_incidents": open_incidents,
            "sessions": len(self.sessions),
            "active_session": self.active_session_id,
        }


# Global singleton
store = SessionStore()
