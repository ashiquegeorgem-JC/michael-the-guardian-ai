"""
IOC Repository Service for MICHAEL – THE GUARDIAN AI.

Phase 4.2A.4 — IOC Evidence Mapper & Repository Integration.

Provides an in-memory, thread-safe repository managing canonical IOC entities.
Enforces deduplication using canonical identity (IOCType + normalized_value).
Maintains append-only forensic evidence and multi-dimensional indexes:
- ID index: get_ioc(ioc_id)
- Canonical index: get_ioc_by_normalized_value(ioc_type, normalized_value)
- Session index: find_iocs_by_session(session_id)
- Event index: find_iocs_by_event(event_id)
- Anomaly index: find_iocs_by_anomaly(anomaly_id)
- Incident index: find_iocs_by_incident(incident_id)
- Attack Chain index: find_iocs_by_attack_chain(attack_chain_id)

Synchronizes with SessionStore for global investigation consistency.
"""

from __future__ import annotations

from collections import defaultdict
import logging
import threading
from typing import Dict, List, Optional, Set, Tuple, Union

from app.config import settings
from app.models.ioc import IOC, IOCEvidence, IOCStatus, IOCStatusHistory, IOCType
from app.services.store import store as default_store, SessionStore

logger = logging.getLogger("michael.ioc_repository")


def _merge_unique(base: List[str], incoming: List[str]) -> List[str]:
    """Merge two string lists preserving original order and uniqueness."""
    seen = set(base)
    result = list(base)
    for item in incoming:
        if item and item not in seen:
            result.append(item)
            seen.add(item)
    return result


class IOCRepository:
    """
    In-memory IOC Repository with canonical deduplication and multi-index lookups.
    """

    def __init__(self, session_store: Optional[SessionStore] = None, backend: Optional[str] = None):
        self._lock = threading.RLock()
        self._store = session_store if session_store is not None else default_store

        # Storage: primary entity map by ID
        self._iocs: Dict[str, IOC] = {}

        # Canonical index: (IOCType, normalized_value) -> ioc_id
        self._by_canonical: Dict[Tuple[IOCType, str], str] = {}

        # Relationship indexes (map foreign ID -> set of ioc_ids)
        self._by_session: Dict[str, Set[str]] = defaultdict(set)
        self._by_event: Dict[str, Set[str]] = defaultdict(set)
        self._by_anomaly: Dict[str, Set[str]] = defaultdict(set)
        self._by_incident: Dict[str, Set[str]] = defaultdict(set)
        self._by_chain: Dict[str, Set[str]] = defaultdict(set)
        self._by_type: Dict[IOCType, Set[str]] = defaultdict(set)

        # Resolve persistence backend
        resolved_backend = (backend or getattr(settings, "PERSISTENCE_BACKEND", "memory")).lower()
        self._backend_name = resolved_backend
        self._sql_repo = None

        if resolved_backend in ("postgres", "sqlite"):
            try:
                from app.persistence.sql_store import SQLIOCRepository
                self._sql_repo = SQLIOCRepository()
                logger.info("IOCRepository initialized with persistence backend '%s'", resolved_backend)
            except Exception as exc:
                logger.warning("Failed to initialize SQLIOCRepository: %s. Falling back to memory.", exc)

    @property
    def persistence_backend(self) -> str:
        return self._backend_name

    # ─────────────────────────────────────────────────────────────────────────
    # Core CRUD & Deduplication Operations
    # ─────────────────────────────────────────────────────────────────────────

    def add_ioc(self, ioc: IOC) -> IOC:
        """
        Add an IOC to the repository.
        If an IOC with the same (ioc_type, normalized_value) exists, merges evidence
        and metadata into the existing record without losing historical context.
        """
        with self._lock:
            canon_key = (ioc.ioc_type, ioc.normalized_value)

            if canon_key in self._by_canonical:
                existing_id = self._by_canonical[canon_key]
                existing = self._iocs[existing_id]

                # Merge evidence references preventing exact duplicates
                existing_sigs = {
                    (ev.event_id, ev.raw_value, ev.source_field, ev.line_number)
                    for ev in existing.evidence_references
                }
                merged_evidence = list(existing.evidence_references)
                new_occurrences_added = 0

                for ev in ioc.evidence_references:
                    sig = (ev.event_id, ev.raw_value, ev.source_field, ev.line_number)
                    if sig not in existing_sigs:
                        merged_evidence.append(ev)
                        existing_sigs.add(sig)
                        new_occurrences_added += 1

                # Calculate updated occurrence count
                updated_count = existing.occurrence_count + (
                    new_occurrences_added if new_occurrences_added > 0 else (
                        ioc.occurrence_count if not ioc.evidence_references else 0
                    )
                )

                # Merge first_seen / last_seen timestamps
                candidates_first = [t for t in (existing.first_seen, ioc.first_seen) if t is not None]
                candidates_last = [t for t in (existing.last_seen, ioc.last_seen) if t is not None]
                new_first_seen = min(candidates_first) if candidates_first else None
                new_last_seen = max(candidates_last) if candidates_last else None

                # Merge metadata lists
                merged_sessions = _merge_unique(existing.source_sessions, ioc.source_sessions)
                merged_methods = _merge_unique(existing.extraction_methods, ioc.extraction_methods)
                merged_anomalies = _merge_unique(existing.associated_anomaly_ids, ioc.associated_anomaly_ids)
                merged_incidents = _merge_unique(existing.associated_incident_ids, ioc.associated_incident_ids)
                merged_chains = _merge_unique(existing.associated_chain_ids, ioc.associated_chain_ids)
                merged_tags = _merge_unique(existing.tags, ioc.tags)

                updated_ioc = existing.model_copy(update={
                    "occurrence_count": updated_count,
                    "first_seen": new_first_seen,
                    "last_seen": new_last_seen,
                    "evidence_references": merged_evidence,
                    "source_sessions": merged_sessions,
                    "extraction_methods": merged_methods,
                    "associated_anomaly_ids": merged_anomalies,
                    "associated_incident_ids": merged_incidents,
                    "associated_chain_ids": merged_chains,
                    "tags": merged_tags,
                })

                self._iocs[existing.id] = updated_ioc
                self._update_indexes(updated_ioc)
                self._sync_store(updated_ioc)

                if self._sql_repo is not None:
                    try:
                        self._sql_repo.add_ioc(updated_ioc)
                    except Exception as exc:
                        logger.error("Failed to persist updated IOC to database: %s", exc)

                return updated_ioc

            else:
                self._iocs[ioc.id] = ioc
                self._by_canonical[canon_key] = ioc.id
                self._update_indexes(ioc)
                self._sync_store(ioc)

                if self._sql_repo is not None:
                    try:
                        self._sql_repo.add_ioc(ioc)
                    except Exception as exc:
                        logger.error("Failed to persist IOC to database: %s", exc)

                return ioc

    def add_iocs(self, iocs: List[IOC]) -> List[IOC]:
        """Batch insertion/merging of multiple IOC entities."""
        return [self.add_ioc(ioc) for ioc in iocs]

    def get_ioc(self, ioc_id: str) -> Optional[IOC]:
        """Lookup single IOC by ID."""
        with self._lock:
            if ioc_id in self._iocs:
                return self._iocs[ioc_id]

            if self._sql_repo is not None:
                try:
                    db_ioc = self._sql_repo.get_ioc(ioc_id)
                    if db_ioc:
                        self._iocs[db_ioc.id] = db_ioc
                        self._by_canonical[(db_ioc.ioc_type, db_ioc.normalized_value)] = db_ioc.id
                        self._update_indexes(db_ioc)
                        return db_ioc
                except Exception as exc:
                    logger.error("Failed to query IOC %s from database: %s", ioc_id, exc)

            return None

    def get_ioc_by_normalized_value(
        self,
        ioc_type: Union[IOCType, str],
        normalized_value: str,
    ) -> Optional[IOC]:
        """Lookup single IOC by its canonical key (IOCType + normalized_value)."""
        with self._lock:
            if isinstance(ioc_type, str):
                try:
                    ioc_type = IOCType(ioc_type.lower())
                except ValueError:
                    return None

            canon_key = (ioc_type, normalized_value)
            ioc_id = self._by_canonical.get(canon_key)
            if ioc_id and ioc_id in self._iocs:
                return self._iocs[ioc_id]

            if self._sql_repo is not None:
                try:
                    db_ioc = self._sql_repo.get_ioc_by_normalized_value(ioc_type, normalized_value)
                    if db_ioc:
                        self._iocs[db_ioc.id] = db_ioc
                        self._by_canonical[canon_key] = db_ioc.id
                        self._update_indexes(db_ioc)
                        return db_ioc
                except Exception as exc:
                    logger.error("Failed to query IOC by normalized value from database: %s", exc)

            return None

    def list_iocs(self, session_id: Optional[str] = None) -> List[IOC]:
        """List all IOCs, optionally restricted to a specific session."""
        with self._lock:
            if session_id:
                results = self.find_iocs_by_session(session_id)
                if results:
                    return results
                if self._sql_repo is not None:
                    try:
                        db_iocs = self._sql_repo.find_iocs_by_session(session_id)
                        for item in db_iocs:
                            self._iocs[item.id] = item
                            self._by_canonical[(item.ioc_type, item.normalized_value)] = item.id
                            self._update_indexes(item)
                        return db_iocs
                    except Exception as exc:
                        logger.error("Failed to query session IOCs from database: %s", exc)
                return []

            if not self._iocs and self._sql_repo is not None:
                try:
                    db_iocs = self._sql_repo.get_all_iocs(limit=1000)
                    for item in db_iocs:
                        self._iocs[item.id] = item
                        self._by_canonical[(item.ioc_type, item.normalized_value)] = item.id
                        self._update_indexes(item)
                except Exception as exc:
                    logger.error("Failed to preload IOCs from database: %s", exc)

            return list(self._iocs.values())

    # ─────────────────────────────────────────────────────────────────────────
    # Index-Based Query Operations
    # ─────────────────────────────────────────────────────────────────────────

    def find_iocs_by_session(self, session_id: str) -> List[IOC]:
        """Return all IOCs observed in a specific session."""
        with self._lock:
            ioc_ids = self._by_session.get(session_id, set())
            in_mem = [self._iocs[iid] for iid in ioc_ids if iid in self._iocs]
            if in_mem:
                return in_mem
            if self._sql_repo is not None:
                try:
                    db_iocs = self._sql_repo.find_iocs_by_session(session_id)
                    for item in db_iocs:
                        self._iocs[item.id] = item
                        self._by_canonical[(item.ioc_type, item.normalized_value)] = item.id
                        self._update_indexes(item)
                    return db_iocs
                except Exception as exc:
                    logger.error("Failed to query IOCs by session from database: %s", exc)
            return []

    def find_iocs_by_event(self, event_id: str) -> List[IOC]:
        """Return all IOCs extracted from or linked to a specific log event ID."""
        with self._lock:
            ioc_ids = self._by_event.get(event_id, set())
            in_mem = [self._iocs[iid] for iid in ioc_ids if iid in self._iocs]
            if in_mem:
                return in_mem
            if self._sql_repo is not None:
                try:
                    db_iocs = self._sql_repo.find_iocs_by_event(event_id)
                    for item in db_iocs:
                        self._iocs[item.id] = item
                        self._by_canonical[(item.ioc_type, item.normalized_value)] = item.id
                        self._update_indexes(item)
                    return db_iocs
                except Exception as exc:
                    logger.error("Failed to query IOCs by event from database: %s", exc)
            return []

    def find_iocs_by_anomaly(self, anomaly_id: str) -> List[IOC]:
        """Return all IOCs linked to a specific anomaly ID."""
        with self._lock:
            ioc_ids = self._by_anomaly.get(anomaly_id, set())
            in_mem = [self._iocs[iid] for iid in ioc_ids if iid in self._iocs]
            if in_mem:
                return in_mem
            if self._sql_repo is not None:
                try:
                    db_iocs = self._sql_repo.find_iocs_by_anomaly(anomaly_id)
                    for item in db_iocs:
                        self._iocs[item.id] = item
                        self._by_canonical[(item.ioc_type, item.normalized_value)] = item.id
                        self._update_indexes(item)
                    return db_iocs
                except Exception as exc:
                    logger.error("Failed to query IOCs by anomaly from database: %s", exc)
            return []

    def find_iocs_by_incident(self, incident_id: str) -> List[IOC]:
        """Return all IOCs linked to a specific incident ID."""
        with self._lock:
            ioc_ids = self._by_incident.get(incident_id, set())
            in_mem = [self._iocs[iid] for iid in ioc_ids if iid in self._iocs]
            if in_mem:
                return in_mem
            if self._sql_repo is not None:
                try:
                    db_iocs = self._sql_repo.find_iocs_by_incident(incident_id)
                    for item in db_iocs:
                        self._iocs[item.id] = item
                        self._by_canonical[(item.ioc_type, item.normalized_value)] = item.id
                        self._update_indexes(item)
                    return db_iocs
                except Exception as exc:
                    logger.error("Failed to query IOCs by incident from database: %s", exc)
            return []

    def find_iocs_by_attack_chain(self, attack_chain_id: str) -> List[IOC]:
        """Return all IOCs linked to a specific attack chain ID."""
        with self._lock:
            ioc_ids = self._by_chain.get(attack_chain_id, set())
            in_mem = [self._iocs[iid] for iid in ioc_ids if iid in self._iocs]
            if in_mem:
                return in_mem
            if self._sql_repo is not None:
                try:
                    db_iocs = self._sql_repo.find_iocs_by_attack_chain(attack_chain_id)
                    for item in db_iocs:
                        self._iocs[item.id] = item
                        self._by_canonical[(item.ioc_type, item.normalized_value)] = item.id
                        self._update_indexes(item)
                    return db_iocs
                except Exception as exc:
                    logger.error("Failed to query IOCs by chain from database: %s", exc)
            return []

    def update_ioc_status(
        self,
        ioc_id: str,
        new_status: IOCStatus,
        reason: str,
        analyst: Optional[str] = None,
    ) -> Optional[IOC]:
        """Update the workflow status of an IOC and record status history."""
        with self._lock:
            ioc = self.get_ioc(ioc_id)
            if not ioc:
                return None

            history_entry = IOCStatusHistory(
                previous_status=ioc.status,
                new_status=new_status,
                changed_by=analyst,
                reason=reason,
            )

            updated_history = list(ioc.status_history) + [history_entry]
            updated_ioc = ioc.model_copy(update={
                "status": new_status,
                "status_history": updated_history,
            })

            self._iocs[ioc_id] = updated_ioc
            self._sync_store(updated_ioc)

            if self._sql_repo is not None:
                try:
                    self._sql_repo.update_ioc_status(ioc_id, new_status, reason, analyst)
                except Exception as exc:
                    logger.error("Failed to update IOC status in database: %s", exc)

            return updated_ioc

    def clear(self) -> None:
        """Clear all repository state (used primarily in test teardowns)."""
        with self._lock:
            self._iocs.clear()
            self._by_canonical.clear()
            self._by_session.clear()
            self._by_event.clear()
            self._by_anomaly.clear()
            self._by_incident.clear()
            self._by_chain.clear()
            self._by_type.clear()

    # ─────────────────────────────────────────────────────────────────────────
    # Internal Index Management
    # ─────────────────────────────────────────────────────────────────────────

    def _update_indexes(self, ioc: IOC) -> None:
        """Index an IOC across foreign keys and categorical dimensions."""
        iid = ioc.id

        # Type index
        self._by_type[ioc.ioc_type].add(iid)

        # Session index (from source_sessions & evidence references)
        for sid in ioc.source_sessions:
            if sid:
                self._by_session[sid].add(iid)
        for ev in ioc.evidence_references:
            if ev.session_id:
                self._by_session[ev.session_id].add(iid)
            if ev.event_id:
                self._by_event[ev.event_id].add(iid)
            if ev.anomaly_id:
                self._by_anomaly[ev.anomaly_id].add(iid)
            if ev.incident_id:
                self._by_incident[ev.incident_id].add(iid)
            if ev.chain_link_event_id:
                self._by_event[ev.chain_link_event_id].add(iid)

        # Anomaly index
        for aid in ioc.associated_anomaly_ids:
            if aid:
                self._by_anomaly[aid].add(iid)

        # Incident index
        for inc_id in ioc.associated_incident_ids:
            if inc_id:
                self._by_incident[inc_id].add(iid)

        # Attack chain index
        for cid in ioc.associated_chain_ids:
            if cid:
                self._by_chain[cid].add(iid)

    def _sync_store(self, ioc: IOC) -> None:
        """Synchronize repository IOC changes into SessionStore."""
        if self._store is not None:
            self._store.iocs[ioc.id] = ioc
            for sid in ioc.source_sessions:
                if sid not in self._store.session_iocs:
                    self._store.session_iocs[sid] = []
                if ioc.id not in self._store.session_iocs[sid]:
                    self._store.session_iocs[sid].append(ioc.id)


# Global default repository singleton
ioc_repository = IOCRepository()

