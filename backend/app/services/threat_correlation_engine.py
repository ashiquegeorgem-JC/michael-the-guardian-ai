"""
Threat Correlation & Unified Intelligence Engine for MICHAEL – THE GUARDIAN AI.

Phase 4.2B.4 — Threat Correlation & Unified Intelligence Engine.

Correlates Indicators of Compromise (IOCs) and Threat Assessments with:
- Log Events (via forensic extraction evidence)
- Anomalies (via shared events, explicit links, and temporal proximity)
- Incidents (via direct references, anomaly chains, and entity matches)
- Attack Chains (via chain events, MITRE stages, and multi-hop links)

DESIGN INVARIANTS:
==================
1. Correlation is NOT classification: Correlating an IOC to an anomaly or incident
   never modifies IOCStatus, ThreatIntelStatus, Incident severity, or AttackChain status.
2. Cross-session safety: Cross-session links without explicit cross-session proof
   are marked confirmed=False (UNCONFIRMED).
3. Deterministic scoring: Correlation confidence is computed via an explicit,
   explainable formula based on structural evidence and controlled temporal windows.
4. Targeted lookup: Leverages existing indexes and session objects (O(E + A + I + C))
   rather than O(N^2) full-system log scans.
5. Immutability: Input entities are strictly read-only and never mutated.
6. Zero network activity: 100% offline and deterministic.
"""

from __future__ import annotations

from datetime import datetime, timezone
import logging
from typing import Any, Dict, List, Optional, Set, Tuple

from app.models.anomaly import Anomaly
from app.models.attack_chain import AttackChain, ChainLinkEvent
from app.models.incident import Incident
from app.models.ioc import IOC, IOCEvidence, IOCType
from app.models.log_entry import LogEntry
from app.models.threat_correlation import (
    CorrelationConfidence,
    CorrelationConfidenceLevel,
    ThreatCorrelation,
    ThreatCorrelationType,
    UnifiedThreatContext,
)
from app.models.threat_intel import ThreatAssessment, ThreatIntelResult
from app.services.ioc_repository import ioc_repository, IOCRepository
from app.services.store import store, SessionStore
from app.services.threat_intel_service import threat_intel_service, ThreatIntelService
from app.services.threat_reputation_engine import (
    threat_reputation_engine,
    ThreatReputationEngine,
)

logger = logging.getLogger("michael.threat_correlation")


# ─────────────────────────────────────────────────────────────────────────────
# Correlation Weights and Threshold Constants
# ─────────────────────────────────────────────────────────────────────────────

# Base correlation scores by link type
BASE_SCORE_EXPLICIT_ID: float = 0.85
BASE_SCORE_SHARED_EVENT: float = 0.80
BASE_SCORE_ANOMALY_CHAIN: float = 0.75
BASE_SCORE_ENTITY_MATCH: float = 0.70
BASE_SCORE_TEMPORAL_IMMEDIATE: float = 0.40    # <= 30 seconds
BASE_SCORE_TEMPORAL_SHORT: float = 0.30        # <= 5 minutes
BASE_SCORE_TEMPORAL_EXTENDED: float = 0.20     # <= 15 minutes

# Corroborating bonuses
BONUS_SAME_SESSION: float = 0.05
BONUS_IMMEDIATE_PROXIMITY: float = 0.05
BONUS_MULTI_EVIDENCE: float = 0.05

# Cross-session constraints
CROSS_SESSION_PENALTY_MULTIPLIER: float = 0.40
CROSS_SESSION_MAX_UNCONFIRMED_SCORE: float = 0.35

# Temporal windows (seconds)
TEMPORAL_WINDOW_IMMEDIATE_SEC: float = 30.0
TEMPORAL_WINDOW_SHORT_SEC: float = 300.0       # 5 minutes
TEMPORAL_WINDOW_EXTENDED_SEC: float = 900.0    # 15 minutes


def _to_utc(dt: Optional[datetime]) -> Optional[datetime]:
    """Ensure a datetime object is explicitly timezone-aware in UTC."""
    if dt is None:
        return None
    if dt.tzinfo is None or dt.tzinfo.utcoffset(dt) is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


# ─────────────────────────────────────────────────────────────────────────────
# ThreatCorrelationEngine Implementation
# ─────────────────────────────────────────────────────────────────────────────

class ThreatCorrelationEngine:
    """
    Deterministic correlation engine linking IOCs to security objects.
    """

    ENGINE_VERSION: str = "1.0.0"

    def __init__(
        self,
        ioc_repo: Optional[IOCRepository] = None,
        session_store: Optional[SessionStore] = None,
        reputation_engine: Optional[ThreatReputationEngine] = None,
        threat_service: Optional[ThreatIntelService] = None,
    ):
        self._ioc_repo = ioc_repo if ioc_repo is not None else ioc_repository
        self._store = session_store if session_store is not None else store
        self._reputation_engine = (
            reputation_engine if reputation_engine is not None else threat_reputation_engine
        )
        self._threat_service = (
            threat_service if threat_service is not None else threat_intel_service
        )

    # ─────────────────────────────────────────────────────────────────────────
    # Public API
    # ─────────────────────────────────────────────────────────────────────────

    def correlate_ioc(
        self,
        ioc: IOC,
        threat_assessment: Optional[ThreatAssessment] = None,
    ) -> List[ThreatCorrelation]:
        """
        Compute all directional correlations for a given IOC entity.

        Links IOC to:
        1. Events (from evidence references)
        2. Anomalies (from shared events, IDs, and temporal proximity)
        3. Incidents (from anomaly chains, entity matches, and direct links)
        4. Attack Chains (from chain events, stage membership, and incident links)
        5. Threat Assessment links to Incidents and Attack Chains
        """
        correlations: List[ThreatCorrelation] = []

        # 1. IOC -> Events
        event_corrs = self.correlate_events(ioc)
        correlations.extend(event_corrs)

        # 2. IOC -> Anomalies
        anomaly_corrs = self.correlate_anomalies(ioc)
        correlations.extend(anomaly_corrs)

        # 3. IOC -> Incidents
        incident_corrs = self.correlate_incidents(ioc, correlated_anomalies=anomaly_corrs)
        correlations.extend(incident_corrs)

        # 4. IOC -> Attack Chains
        chain_corrs = self.correlate_attack_chains(
            ioc,
            correlated_incidents=incident_corrs,
            correlated_anomalies=anomaly_corrs,
        )
        correlations.extend(chain_corrs)

        # 5. Threat Assessment linkages (if assessment provided or available)
        if threat_assessment is not None:
            assessment_corrs = self._correlate_threat_assessment(
                ioc,
                threat_assessment,
                incident_corrs=incident_corrs,
                chain_corrs=chain_corrs,
            )
            correlations.extend(assessment_corrs)

        return correlations

    def correlate_ioc_by_id(
        self,
        ioc_id: str,
        threat_assessment: Optional[ThreatAssessment] = None,
    ) -> List[ThreatCorrelation]:
        """Lookup IOC by ID and compute its correlations."""
        ioc = self._ioc_repo.get_ioc(ioc_id)
        if ioc is None:
            return []
        return self.correlate_ioc(ioc, threat_assessment=threat_assessment)

    # ─────────────────────────────────────────────────────────────────────────
    # 1. IOC -> Event Correlation
    # ─────────────────────────────────────────────────────────────────────────

    def correlate_events(self, ioc: IOC) -> List[ThreatCorrelation]:
        """
        Correlate IOC with originating Log Events using evidence references.

        Complexity: O(E) where E is the number of evidence references on the IOC.
        """
        correlations: List[ThreatCorrelation] = []
        seen_events: Set[Tuple[str, str]] = set()  # (event_id, session_id)

        for ev in ioc.evidence_references:
            pair = (ev.event_id, ev.session_id)
            if pair in seen_events:
                continue
            seen_events.add(pair)

            evidence_bullets: List[str] = [
                f"IOC '{ioc.normalized_value}' was directly extracted from Log Event '{ev.event_id}'.",
                f"Event belongs to Session '{ev.session_id}'"
                + (f" at line {ev.line_number}." if ev.line_number else "."),
                f"Extraction field: '{ev.source_field}'. Raw value: '{ev.raw_value}'.",
            ]
            if ev.surrounding_context:
                evidence_bullets.append(f"Context: \"{ev.surrounding_context.strip()}\"")

            ev_time = _to_utc(ev.timestamp)
            conf_score = 0.95
            if ev.line_number is not None:
                conf_score = 1.00

            confidence = CorrelationConfidence(
                score=conf_score,
                evidence_count=len(evidence_bullets),
                correlation_method="evidence_extraction",
            )

            correlations.append(
                ThreatCorrelation(
                    correlation_type=ThreatCorrelationType.IOC_TO_EVENT,
                    source_id=ioc.id,
                    source_type="ioc",
                    target_id=ev.event_id,
                    target_type="event",
                    confidence=confidence,
                    evidence=evidence_bullets,
                    correlation_method="evidence_extraction",
                    first_seen=ev_time,
                    last_seen=ev_time,
                    confirmed=True,
                )
            )

        return correlations

    # ─────────────────────────────────────────────────────────────────────────
    # 2. IOC -> Anomaly Correlation
    # ─────────────────────────────────────────────────────────────────────────

    def correlate_anomalies(self, ioc: IOC) -> List[ThreatCorrelation]:
        """
        Correlate IOC with Anomalies using:
        - Explicit anomaly references (ev.anomaly_id, ioc.associated_anomaly_ids)
        - Shared log event IDs (anomaly.log_entry_ids contains IOC event_id)
        - Controlled temporal proximity within the same session

        Targeted lookup: O(A_sessions) only inspecting anomalies in IOC's sessions.
        """
        correlations: List[ThreatCorrelation] = []
        ioc_event_ids: Set[str] = {ev.event_id for ev in ioc.evidence_references if ev.event_id}
        explicit_anomaly_ids: Set[str] = set(ioc.associated_anomaly_ids)
        for ev in ioc.evidence_references:
            if ev.anomaly_id:
                explicit_anomaly_ids.add(ev.anomaly_id)

        # Collect evidence timestamps by session for temporal correlation
        session_event_times: Dict[str, List[datetime]] = {}
        for ev in ioc.evidence_references:
            if ev.session_id and ev.timestamp:
                utc_t = _to_utc(ev.timestamp)
                if utc_t:
                    session_event_times.setdefault(ev.session_id, []).append(utc_t)

        candidate_sessions = set(ioc.source_sessions)
        for ev in ioc.evidence_references:
            if ev.session_id:
                candidate_sessions.add(ev.session_id)

        # Inspect all sessions present across sessions, anomalies, or candidate sessions
        all_store_sessions = (
            set(self._store.sessions.keys())
            | set(self._store.anomalies.keys())
            | candidate_sessions
        )
        processed_anomaly_ids: Set[str] = set()

        for sid in all_store_sessions:
            anomalies = self._store.get_anomalies(sid)
            for anomaly in anomalies:
                if anomaly.id in processed_anomaly_ids:
                    continue

                is_same_session = sid in candidate_sessions
                has_explicit_id = anomaly.id in explicit_anomaly_ids
                shared_events = set(anomaly.log_entry_ids).intersection(ioc_event_ids)

                # Check temporal proximity if in same session
                temporal_diff_sec: Optional[float] = None
                anomaly_time = _to_utc(anomaly.detected_at)
                if is_same_session and anomaly_time and sid in session_event_times:
                    diffs = [
                        abs((anomaly_time - ev_t).total_seconds())
                        for ev_t in session_event_times[sid]
                    ]
                    if diffs:
                        temporal_diff_sec = min(diffs)

                # Determine if correlation exists
                if not (has_explicit_id or shared_events or (temporal_diff_sec is not None and temporal_diff_sec <= TEMPORAL_WINDOW_EXTENDED_SEC)):
                    continue

                processed_anomaly_ids.add(anomaly.id)
                evidence_bullets: List[str] = []
                method: str = ""
                base_score: float = 0.0
                confirmed: bool = True

                if has_explicit_id:
                    base_score = BASE_SCORE_EXPLICIT_ID
                    method = "explicit_reference"
                    evidence_bullets.append(
                        f"Explicit link: Anomaly '{anomaly.id}' is directly associated with IOC '{ioc.normalized_value}'."
                    )
                elif shared_events:
                    base_score = BASE_SCORE_SHARED_EVENT
                    method = "shared_event"
                    evidence_bullets.append(
                        f"Shared event: Anomaly '{anomaly.id}' shares log event(s) {sorted(list(shared_events))} with IOC."
                    )
                elif temporal_diff_sec is not None and temporal_diff_sec <= TEMPORAL_WINDOW_EXTENDED_SEC:
                    if temporal_diff_sec <= TEMPORAL_WINDOW_IMMEDIATE_SEC:
                        base_score = BASE_SCORE_TEMPORAL_IMMEDIATE
                        method = "temporal_proximity_immediate"
                        evidence_bullets.append(
                            f"Temporal proximity: Anomaly '{anomaly.id}' occurred within {temporal_diff_sec:.1f}s (<= 30s) of IOC event."
                        )
                    elif temporal_diff_sec <= TEMPORAL_WINDOW_SHORT_SEC:
                        base_score = BASE_SCORE_TEMPORAL_SHORT
                        method = "temporal_proximity_short"
                        evidence_bullets.append(
                            f"Temporal proximity: Anomaly '{anomaly.id}' occurred within {temporal_diff_sec:.1f}s (<= 5m) of IOC event."
                        )
                        confirmed = False  # Weak temporal match remains unconfirmed
                    else:
                        base_score = BASE_SCORE_TEMPORAL_EXTENDED
                        method = "temporal_proximity_extended"
                        evidence_bullets.append(
                            f"Temporal proximity: Anomaly '{anomaly.id}' occurred within {temporal_diff_sec:.1f}s (<= 15m) of IOC event."
                        )
                        confirmed = False

                evidence_bullets.append(
                    f"Anomaly details: Severity={anomaly.severity.value}, Score={anomaly.score:.2f}, Reason='{anomaly.reason}'."
                )

                # Corroborating bonuses
                score = base_score
                if is_same_session:
                    score += BONUS_SAME_SESSION
                    evidence_bullets.append(f"Same session corroboration (Session '{sid}').")
                else:
                    # Cross-session penalty
                    score = min(score * CROSS_SESSION_PENALTY_MULTIPLIER, CROSS_SESSION_MAX_UNCONFIRMED_SCORE)
                    confirmed = False
                    evidence_bullets.append(
                        f"Cross-session relationship across sessions remains UNCONFIRMED (Session '{sid}')."
                    )

                if temporal_diff_sec is not None and temporal_diff_sec <= TEMPORAL_WINDOW_IMMEDIATE_SEC:
                    score += BONUS_IMMEDIATE_PROXIMITY

                if len(shared_events) >= 2 or len(ioc.evidence_references) >= 2:
                    score += BONUS_MULTI_EVIDENCE

                final_score = max(0.0, min(1.0, round(score, 3)))

                confidence = CorrelationConfidence(
                    score=final_score,
                    evidence_count=len(evidence_bullets),
                    correlation_method=method,
                )

                correlations.append(
                    ThreatCorrelation(
                        correlation_type=ThreatCorrelationType.IOC_TO_ANOMALY,
                        source_id=ioc.id,
                        source_type="ioc",
                        target_id=anomaly.id,
                        target_type="anomaly",
                        confidence=confidence,
                        evidence=evidence_bullets,
                        correlation_method=method,
                        first_seen=anomaly_time,
                        last_seen=anomaly_time,
                        confirmed=confirmed,
                    )
                )

        return correlations

    # ─────────────────────────────────────────────────────────────────────────
    # 3. IOC -> Incident Correlation
    # ─────────────────────────────────────────────────────────────────────────

    def correlate_incidents(
        self,
        ioc: IOC,
        correlated_anomalies: Optional[List[ThreatCorrelation]] = None,
    ) -> List[ThreatCorrelation]:
        """
        Correlate IOC with Incidents using:
        - Explicit incident references (ev.incident_id, ioc.associated_incident_ids)
        - Anomaly chains (incident.anomaly_id matches a correlated anomaly)
        - Entity matching (ioc.normalized_value in incident.affected_ips)

        Targeted lookup: O(I_sessions) for candidate sessions.
        """
        correlations: List[ThreatCorrelation] = []
        explicit_incident_ids: Set[str] = set(ioc.associated_incident_ids)
        for ev in ioc.evidence_references:
            if ev.incident_id:
                explicit_incident_ids.add(ev.incident_id)

        # Map correlated anomaly IDs
        anomaly_corr_map: Dict[str, ThreatCorrelation] = {}
        if correlated_anomalies is not None:
            for ac in correlated_anomalies:
                if ac.target_type == "anomaly":
                    anomaly_corr_map[ac.target_id] = ac

        candidate_sessions = set(ioc.source_sessions)
        for ev in ioc.evidence_references:
            if ev.session_id:
                candidate_sessions.add(ev.session_id)

        all_store_sessions = (
            set(self._store.sessions.keys())
            | set(self._store.incidents.keys())
            | candidate_sessions
        )
        processed_incident_ids: Set[str] = set()

        for sid in all_store_sessions:
            incidents = self._store.get_incidents(sid)
            for incident in incidents:
                if incident.id in processed_incident_ids:
                    continue

                is_same_session = sid in candidate_sessions
                has_explicit_id = incident.id in explicit_incident_ids
                linked_anomaly_corr = anomaly_corr_map.get(incident.anomaly_id)
                has_entity_match = (
                    ioc.normalized_value in incident.affected_ips
                    or ioc.raw_value in incident.affected_ips
                )

                if not (has_explicit_id or linked_anomaly_corr or has_entity_match):
                    continue

                processed_incident_ids.add(incident.id)
                evidence_bullets: List[str] = []
                method: str = ""
                base_score: float = 0.0
                confirmed: bool = True

                if has_explicit_id:
                    base_score = BASE_SCORE_EXPLICIT_ID
                    method = "explicit_reference"
                    evidence_bullets.append(
                        f"Explicit link: Incident '{incident.id}' is directly associated with IOC '{ioc.normalized_value}'."
                    )
                elif linked_anomaly_corr:
                    base_score = BASE_SCORE_ANOMALY_CHAIN
                    method = "correlated_anomaly_chain"
                    evidence_bullets.append(
                        f"Anomaly chain: Incident '{incident.id}' is derived from Anomaly '{incident.anomaly_id}', "
                        f"which is correlated with IOC (anomaly confidence: {linked_anomaly_corr.confidence.score:.2f})."
                    )
                    confirmed = linked_anomaly_corr.confirmed
                elif has_entity_match:
                    base_score = BASE_SCORE_ENTITY_MATCH
                    method = "affected_entity_match"
                    evidence_bullets.append(
                        f"Entity match: IOC '{ioc.normalized_value}' appears in Incident '{incident.id}' affected_ips list."
                    )

                evidence_bullets.append(
                    f"Incident details: Title='{incident.title}', Severity={incident.severity}, Category='{incident.category.value}', Status={incident.status.value}."
                )

                # Corroborating bonuses
                score = base_score
                if is_same_session:
                    score += BONUS_SAME_SESSION
                    evidence_bullets.append(f"Same session corroboration (Session '{sid}').")
                else:
                    score = min(score * CROSS_SESSION_PENALTY_MULTIPLIER, CROSS_SESSION_MAX_UNCONFIRMED_SCORE)
                    confirmed = False
                    evidence_bullets.append(
                        f"Cross-session relationship across sessions remains UNCONFIRMED (Session '{sid}')."
                    )

                inc_first = _to_utc(incident.first_seen)
                inc_last = _to_utc(incident.last_seen)

                final_score = max(0.0, min(1.0, round(score, 3)))

                confidence = CorrelationConfidence(
                    score=final_score,
                    evidence_count=len(evidence_bullets),
                    correlation_method=method,
                )

                correlations.append(
                    ThreatCorrelation(
                        correlation_type=ThreatCorrelationType.IOC_TO_INCIDENT,
                        source_id=ioc.id,
                        source_type="ioc",
                        target_id=incident.id,
                        target_type="incident",
                        confidence=confidence,
                        evidence=evidence_bullets,
                        correlation_method=method,
                        first_seen=inc_first,
                        last_seen=inc_last,
                        confirmed=confirmed,
                    )
                )

        return correlations

    # ─────────────────────────────────────────────────────────────────────────
    # 4. IOC -> Attack Chain Correlation
    # ─────────────────────────────────────────────────────────────────────────

    def correlate_attack_chains(
        self,
        ioc: IOC,
        correlated_incidents: Optional[List[ThreatCorrelation]] = None,
        correlated_anomalies: Optional[List[ThreatCorrelation]] = None,
    ) -> List[ThreatCorrelation]:
        """
        Correlate IOC with Attack Chains using:
        - Direct chain references (ioc.associated_chain_ids)
        - Chain event membership (ev.event_id in chain.event_ids or chain.events)
        - Correlated incident membership (chain.associated_incident_ids)
        - Correlated anomaly membership (chain.associated_anomaly_ids)
        - Forensic entity matching (ioc.normalized_value in chain.source_ips)

        Includes MITRE attack stage where available.
        Targeted lookup: O(C_sessions).
        """
        correlations: List[ThreatCorrelation] = []
        ioc_event_ids: Set[str] = {ev.event_id for ev in ioc.evidence_references if ev.event_id}
        explicit_chain_ids: Set[str] = set(ioc.associated_chain_ids)

        corr_incident_ids: Set[str] = set()
        if correlated_incidents is not None:
            corr_incident_ids = {ic.target_id for ic in correlated_incidents if ic.target_type == "incident"}

        corr_anomaly_ids: Set[str] = set()
        if correlated_anomalies is not None:
            corr_anomaly_ids = {ac.target_id for ac in correlated_anomalies if ac.target_type == "anomaly"}

        candidate_sessions = set(ioc.source_sessions)
        for ev in ioc.evidence_references:
            if ev.session_id:
                candidate_sessions.add(ev.session_id)

        all_store_sessions = (
            set(self._store.sessions.keys())
            | set(self._store.attack_chains.keys())
            | candidate_sessions
        )
        processed_chain_ids: Set[str] = set()

        for sid in all_store_sessions:
            chains = self._store.get_attack_chains(sid)
            for chain in chains:
                if chain.id in processed_chain_ids:
                    continue

                is_same_session = sid in candidate_sessions
                has_explicit_id = chain.id in explicit_chain_ids
                shared_events = set(chain.event_ids).intersection(ioc_event_ids)

                # Check chain events directly for event_id, stage, or source_ip
                matching_chain_events: List[ChainLinkEvent] = []
                for ce in chain.events:
                    if (ce.log_entry_id and ce.log_entry_id in ioc_event_ids) or (
                        ce.id in ioc_event_ids
                    ):
                        matching_chain_events.append(ce)
                        shared_events.add(ce.log_entry_id or ce.id)

                has_incident_link = bool(set(chain.associated_incident_ids).intersection(corr_incident_ids))
                has_anomaly_link = bool(set(chain.associated_anomaly_ids).intersection(corr_anomaly_ids))
                has_entity_match = (
                    ioc.normalized_value in chain.source_ips
                    or ioc.raw_value in chain.source_ips
                )

                if not (has_explicit_id or shared_events or has_incident_link or has_anomaly_link or has_entity_match):
                    continue

                processed_chain_ids.add(chain.id)
                evidence_bullets: List[str] = []
                method: str = ""
                base_score: float = 0.0
                confirmed: bool = True

                if has_explicit_id:
                    base_score = BASE_SCORE_EXPLICIT_ID
                    method = "direct_chain_reference"
                    evidence_bullets.append(
                        f"Direct reference: Attack Chain '{chain.id}' is directly linked to IOC '{ioc.normalized_value}'."
                    )
                elif shared_events:
                    base_score = BASE_SCORE_SHARED_EVENT
                    method = "chain_event_membership"
                    evidence_bullets.append(
                        f"Event membership: Attack Chain '{chain.id}' contains log event(s) {sorted(list(shared_events))} where IOC was extracted."
                    )
                elif has_incident_link:
                    base_score = BASE_SCORE_ANOMALY_CHAIN
                    method = "incident_chain_link"
                    evidence_bullets.append(
                        f"Incident link: Attack Chain '{chain.id}' encompasses correlated incident(s) {sorted(list(set(chain.associated_incident_ids).intersection(corr_incident_ids)))}."
                    )
                elif has_anomaly_link:
                    base_score = BASE_SCORE_ANOMALY_CHAIN
                    method = "anomaly_chain_link"
                    evidence_bullets.append(
                        f"Anomaly link: Attack Chain '{chain.id}' encompasses correlated anomaly(s) {sorted(list(set(chain.associated_anomaly_ids).intersection(corr_anomaly_ids)))}."
                    )
                elif has_entity_match:
                    base_score = BASE_SCORE_ENTITY_MATCH
                    method = "forensic_entity_match"
                    evidence_bullets.append(
                        f"Entity match: IOC '{ioc.normalized_value}' is an identified source IP in Attack Chain '{chain.id}'."
                    )

                # Include MITRE stages from matching events or chain stages
                observed_stages = [st.value for st in chain.stages_observed]
                if matching_chain_events:
                    event_stages = [ce.stage.value for ce in matching_chain_events if ce.stage]
                    evidence_bullets.append(
                        f"Associated MITRE Stage(s) for event: {', '.join(set(event_stages))}."
                    )
                elif observed_stages:
                    evidence_bullets.append(
                        f"Attack Chain observed MITRE stage(s): {', '.join(observed_stages)}."
                    )

                evidence_bullets.append(
                    f"Chain details: Title='{chain.title}', Severity={chain.severity}, Status={chain.status.value}, Confidence={chain.confidence_score:.2f}."
                )

                # Corroborating bonuses
                score = base_score
                if is_same_session:
                    score += BONUS_SAME_SESSION
                    evidence_bullets.append(f"Same session corroboration (Session '{sid}').")
                else:
                    score = min(score * CROSS_SESSION_PENALTY_MULTIPLIER, CROSS_SESSION_MAX_UNCONFIRMED_SCORE)
                    confirmed = False
                    evidence_bullets.append(
                        f"Cross-session relationship across sessions remains UNCONFIRMED (Session '{sid}')."
                    )

                chain_first = _to_utc(chain.first_seen)
                chain_last = _to_utc(chain.last_seen)

                final_score = max(0.0, min(1.0, round(score, 3)))

                confidence = CorrelationConfidence(
                    score=final_score,
                    evidence_count=len(evidence_bullets),
                    correlation_method=method,
                )

                correlations.append(
                    ThreatCorrelation(
                        correlation_type=ThreatCorrelationType.IOC_TO_ATTACK_CHAIN,
                        source_id=ioc.id,
                        source_type="ioc",
                        target_id=chain.id,
                        target_type="attack_chain",
                        confidence=confidence,
                        evidence=evidence_bullets,
                        correlation_method=method,
                        first_seen=chain_first,
                        last_seen=chain_last,
                        confirmed=confirmed,
                    )
                )

        return correlations

    # ─────────────────────────────────────────────────────────────────────────
    # 5. Threat Assessment Linkages
    # ─────────────────────────────────────────────────────────────────────────

    def _correlate_threat_assessment(
        self,
        ioc: IOC,
        assessment: ThreatAssessment,
        incident_corrs: List[ThreatCorrelation],
        chain_corrs: List[ThreatCorrelation],
    ) -> List[ThreatCorrelation]:
        """
        Derive THREAT_ASSESSMENT_TO_INCIDENT and THREAT_ASSESSMENT_TO_ATTACK_CHAIN links.

        Adds threat context (severity, threat score, provider verdict) to correlated incidents and chains.
        """
        correlations: List[ThreatCorrelation] = []

        # Threat Assessment -> Incidents
        for ic in incident_corrs:
            evidence_bullets = [
                f"ThreatAssessment '{assessment.assessment_id}' evaluated IOC '{ioc.normalized_value}' with verdict '{assessment.status.value}'.",
                f"Threat Score: {assessment.threat_score:.1f}/100, Severity: {assessment.severity.value}, Assessment Confidence: {assessment.confidence:.2f}.",
                f"Bridges intelligence telemetry to correlated Incident '{ic.target_id}'.",
            ]
            evidence_bullets.extend(ic.evidence[:2])

            correlations.append(
                ThreatCorrelation(
                    correlation_type=ThreatCorrelationType.THREAT_ASSESSMENT_TO_INCIDENT,
                    source_id=assessment.assessment_id,
                    source_type="threat_assessment",
                    target_id=ic.target_id,
                    target_type="incident",
                    confidence=ic.confidence,
                    evidence=evidence_bullets,
                    correlation_method="threat_assessment_bridge",
                    first_seen=ic.first_seen,
                    last_seen=ic.last_seen,
                    confirmed=ic.confirmed,
                )
            )

        # Threat Assessment -> Attack Chains
        for cc in chain_corrs:
            evidence_bullets = [
                f"ThreatAssessment '{assessment.assessment_id}' evaluated IOC '{ioc.normalized_value}' with verdict '{assessment.status.value}'.",
                f"Threat Score: {assessment.threat_score:.1f}/100, Severity: {assessment.severity.value}, Assessment Confidence: {assessment.confidence:.2f}.",
                f"Bridges intelligence telemetry to correlated Attack Chain '{cc.target_id}'.",
            ]
            evidence_bullets.extend(cc.evidence[:2])

            correlations.append(
                ThreatCorrelation(
                    correlation_type=ThreatCorrelationType.THREAT_ASSESSMENT_TO_ATTACK_CHAIN,
                    source_id=assessment.assessment_id,
                    source_type="threat_assessment",
                    target_id=cc.target_id,
                    target_type="attack_chain",
                    confidence=cc.confidence,
                    evidence=evidence_bullets,
                    correlation_method="threat_assessment_bridge",
                    first_seen=cc.first_seen,
                    last_seen=cc.last_seen,
                    confirmed=cc.confirmed,
                )
            )

        return correlations

    # ─────────────────────────────────────────────────────────────────────────
    # 6. Unified Threat Context Builder
    # ─────────────────────────────────────────────────────────────────────────

    def build_unified_context(
        self,
        ioc: Union[IOC, str],
        threat_assessment: Optional[ThreatAssessment] = None,
        threat_intel_result: Optional[ThreatIntelResult] = None,
        force_refresh_assessment: bool = False,
    ) -> UnifiedThreatContext:
        """
        Assemble the complete UnifiedThreatContext for an IOC.

        Combines:
        - IOC identity and analyst status
        - Raw ThreatIntelResult from provider if available
        - Threat Assessment (computed if absent)
        - Related events, anomalies, incidents, attack chains
        - All directional ThreatCorrelation records
        - Overall correlation confidence and structured investigation summary
        """
        if isinstance(ioc, str):
            ioc_obj = self._ioc_repo.get_ioc(ioc)
            if ioc_obj is None:
                raise ValueError(f"IOC with ID '{ioc}' not found in repository")
            ioc = ioc_obj

        # Obtain raw threat intel result if available
        intel_result = threat_intel_result
        if intel_result is None and self._threat_service is not None:
            try:
                intel_result = self._threat_service.lookup(
                    ioc, force_refresh=force_refresh_assessment
                )
            except Exception as e:
                logger.debug("Optional threat intel lookup omitted or failed for %s: %s", getattr(ioc, "id", str(ioc)), e)

        # Obtain assessment if not explicitly provided
        assessment = threat_assessment
        if assessment is None and self._reputation_engine is not None:
            try:
                assessment = self._reputation_engine.assess_ioc(
                    ioc, force_refresh=force_refresh_assessment
                )
            except Exception as e:
                logger.warning("Failed to retrieve threat assessment for IOC %s: %s", getattr(ioc, "id", str(ioc)), e)

        # Compute correlations
        correlations = self.correlate_ioc(ioc, threat_assessment=assessment)

        # Group related entities
        related_events: List[Dict[str, Any]] = []
        related_anomalies: List[Dict[str, Any]] = []
        related_incidents: List[Dict[str, Any]] = []
        related_attack_chains: List[Dict[str, Any]] = []

        seen_event_ids: Set[str] = set()
        seen_anomaly_ids: Set[str] = set()
        seen_incident_ids: Set[str] = set()
        seen_chain_ids: Set[str] = set()

        for c in correlations:
            if c.target_type == "event" and c.target_id not in seen_event_ids:
                seen_event_ids.add(c.target_id)
                related_events.append({
                    "event_id": c.target_id,
                    "confidence": c.confidence.score,
                    "confirmed": c.confirmed,
                    "evidence": c.evidence,
                })
            elif c.target_type == "anomaly" and c.target_id not in seen_anomaly_ids:
                seen_anomaly_ids.add(c.target_id)
                related_anomalies.append({
                    "anomaly_id": c.target_id,
                    "confidence": c.confidence.score,
                    "confirmed": c.confirmed,
                    "evidence": c.evidence,
                })
            elif c.target_type == "incident" and c.target_id not in seen_incident_ids:
                seen_incident_ids.add(c.target_id)
                related_incidents.append({
                    "incident_id": c.target_id,
                    "confidence": c.confidence.score,
                    "confirmed": c.confirmed,
                    "evidence": c.evidence,
                })
            elif c.target_type == "attack_chain" and c.target_id not in seen_chain_ids:
                seen_chain_ids.add(c.target_id)
                related_attack_chains.append({
                    "chain_id": c.target_id,
                    "confidence": c.confidence.score,
                    "confirmed": c.confirmed,
                    "evidence": c.evidence,
                })

        # Calculate overall correlation confidence
        # Formula: Highest confidence among confirmed correlations, or 0.0 if empty
        confirmed_corrs = [c for c in correlations if c.confirmed]
        if confirmed_corrs:
            overall_conf = max(c.confidence.score for c in confirmed_corrs)
        elif correlations:
            overall_conf = max(c.confidence.score for c in correlations) * 0.5
        else:
            overall_conf = 0.0
        overall_conf = round(overall_conf, 3)

        # Build investigation summary
        confirmed_count = len(confirmed_corrs)
        unconfirmed_count = len(correlations) - confirmed_count

        key_findings: List[str] = [
            f"Indicator '{ioc.normalized_value}' ({ioc.ioc_type.value}) observed across {len(related_events)} event(s) in {len(ioc.source_sessions)} session(s)."
        ]
        if assessment:
            key_findings.append(
                f"Threat reputation assessment: {assessment.status.value} (Score: {assessment.threat_score:.1f}, Severity: {assessment.severity.value})."
            )
        if related_incidents:
            key_findings.append(f"Correlated to {len(related_incidents)} security incident(s).")
        if related_attack_chains:
            key_findings.append(f"Correlated to {len(related_attack_chains)} reconstructed attack chain(s).")
        if unconfirmed_count > 0:
            key_findings.append(
                f"{unconfirmed_count} cross-session or temporal relationship(s) remain UNCONFIRMED pending analyst validation."
            )

        summary: Dict[str, Any] = {
            "total_correlations": len(correlations),
            "confirmed_correlations": confirmed_count,
            "unconfirmed_correlations": unconfirmed_count,
            "event_count": len(related_events),
            "anomaly_count": len(related_anomalies),
            "incident_count": len(related_incidents),
            "attack_chain_count": len(related_attack_chains),
            "highest_confidence": overall_conf,
            "highest_confidence_level": (
                CorrelationConfidenceLevel.HIGH.value
                if overall_conf >= 0.70
                else CorrelationConfidenceLevel.MEDIUM.value
                if overall_conf >= 0.40
                else CorrelationConfidenceLevel.LOW.value
            ),
            "key_findings": key_findings,
        }

        return UnifiedThreatContext(
            ioc_id=ioc.id,
            ioc_value=ioc.raw_value,
            normalized_value=ioc.normalized_value,
            ioc_type=ioc.ioc_type,
            analyst_status=ioc.status,
            threat_intel_result=intel_result,
            threat_assessment=assessment,
            related_events=related_events,
            related_anomalies=related_anomalies,
            related_incidents=related_incidents,
            related_attack_chains=related_attack_chains,
            correlations=correlations,
            overall_correlation_confidence=overall_conf,
            investigation_summary=summary,
        )

    def build_unified_context_by_id(
        self,
        ioc_id: str,
        force_refresh_assessment: bool = False,
    ) -> Optional[UnifiedThreatContext]:
        """Lookup IOC by ID and assemble its UnifiedThreatContext."""
        ioc = self._ioc_repo.get_ioc(ioc_id)
        if ioc is None:
            return None
        return self.build_unified_context(
            ioc, force_refresh_assessment=force_refresh_assessment
        )


# Global singleton
threat_correlation_engine = ThreatCorrelationEngine()
