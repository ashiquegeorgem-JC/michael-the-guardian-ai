"""
IOC Evidence Mapper for MICHAEL – THE GUARDIAN AI.

Phase 4.2A.4 — IOC Evidence Mapper & Repository Integration.

Connects extracted, normalized, and validated IOC entities to existing forensic objects:
- LogEntry (originating event, line number, timestamp, raw line context)
- LogSession (session association)
- Anomaly (explicit event_id linkage via anomaly.log_entry_ids)
- Incident (explicit event_id or anomaly_id linkage)
- AttackChain (explicit event_id or chain.events linkage)

FORENSIC SAFEGUARDS
===================
1. False-Association Prevention: Never links an IOC to an anomaly, incident, or attack chain
   merely because they belong to the same session. An explicit event-level connection is required.
2. Evidence Immutability: Treats forensic evidence as strictly append-only.
   Never mutates original LogEntry, Anomaly, Incident, or AttackChain objects.
3. No Verdict Contamination: Does NOT mark IOC status as CONFIRMED or assign malicious reputation
   merely because an IOC is linked to an anomaly, incident, or attack chain.
4. Offline Integrity: Zero external DNS, WHOIS, or threat intelligence network calls.
"""

from __future__ import annotations

from collections import defaultdict
from typing import Any, Dict, List, Optional, Set, Tuple

from app.models.anomaly import Anomaly
from app.models.attack_chain import AttackChain, ChainLinkEvent
from app.models.incident import Incident
from app.models.ioc import (
    IOC,
    IOCEvidence,
    IOCExtractionResult,
    IOCStatus,
    IOCType,
    ValidationStatus,
)
from app.models.log_entry import LogEntry
from app.services.ioc_extractor import IOCExtractor
from app.services.ioc_validator import IOCValidator


class IOCEvidenceMapper:
    """
    Forensic mapper creating explicit, auditable relationships between IOCs
    and core investigation entities.
    """

    @classmethod
    def build_forensic_index(
        cls,
        entries: Optional[List[LogEntry]] = None,
        anomalies: Optional[List[Anomaly]] = None,
        incidents: Optional[List[Incident]] = None,
        attack_chains: Optional[List[AttackChain]] = None,
    ) -> Dict[str, Dict[str, Set[str]]]:
        """
        Build an in-memory reverse index mapping event_id -> explicit associated forensic entities.
        Structure:
            index[event_id] = {
                "anomaly_ids": set(),
                "incident_ids": set(),
                "chain_ids": set(),
                "chain_link_event_ids": set(),
            }
        Guarantees that associations are derived strictly from explicit relationships.
        """
        index: Dict[str, Dict[str, Set[str]]] = defaultdict(lambda: {
            "anomaly_ids": set(),
            "incident_ids": set(),
            "chain_ids": set(),
            "chain_link_event_ids": set(),
        })

        # 1. Map Anomalies to Event IDs
        anomaly_to_events: Dict[str, Set[str]] = defaultdict(set)
        if anomalies:
            for anom in anomalies:
                for eid in anom.log_entry_ids:
                    index[eid]["anomaly_ids"].add(anom.id)
                    anomaly_to_events[anom.id].add(eid)

        # 2. Map Incidents to Event IDs (via incident.anomaly_id or evidence_log_lines)
        if incidents:
            raw_to_eids: Dict[str, Set[str]] = defaultdict(set)
            if entries:
                for e in entries:
                    if e.raw_line:
                        raw_to_eids[e.raw_line].add(e.id)

            for inc in incidents:
                # Link via associated anomaly
                if inc.anomaly_id and inc.anomaly_id in anomaly_to_events:
                    for eid in anomaly_to_events[inc.anomaly_id]:
                        index[eid]["incident_ids"].add(inc.id)

                # Link via matching raw evidence log lines
                for line in inc.evidence_log_lines:
                    if line in raw_to_eids:
                        for eid in raw_to_eids[line]:
                            index[eid]["incident_ids"].add(inc.id)

        # 3. Map Attack Chains to Event IDs
        if attack_chains:
            for chain in attack_chains:
                for link in chain.events:
                    target_eid = link.log_entry_id or link.id
                    if target_eid:
                        index[target_eid]["chain_ids"].add(chain.id)
                        index[target_eid]["chain_link_event_ids"].add(link.id)
                        if link.anomaly_id:
                            index[target_eid]["anomaly_ids"].add(link.anomaly_id)
                        if link.incident_id:
                            index[target_eid]["incident_ids"].add(link.incident_id)

                for eid in chain.event_ids:
                    index[eid]["chain_ids"].add(chain.id)

        return index

    @classmethod
    def map_ioc_evidence(
        cls,
        ioc: IOC,
        forensic_index: Dict[str, Dict[str, Set[str]]],
    ) -> IOC:
        """
        Enrich an IOC and its evidence references using the pre-computed forensic index.
        Produces an immutable updated copy without mutating original objects.
        """
        updated_evidence: List[IOCEvidence] = []
        associated_anomalies: Set[str] = set(ioc.associated_anomaly_ids)
        associated_incidents: Set[str] = set(ioc.associated_incident_ids)
        associated_chains: Set[str] = set(ioc.associated_chain_ids)

        for ev in ioc.evidence_references:
            eid = ev.event_id
            linkage = forensic_index.get(eid, {
                "anomaly_ids": set(),
                "incident_ids": set(),
                "chain_ids": set(),
                "chain_link_event_ids": set(),
            })

            # Determine best single IDs for this specific occurrence
            anomaly_id = ev.anomaly_id or (next(iter(linkage["anomaly_ids"])) if linkage["anomaly_ids"] else None)
            incident_id = ev.incident_id or (next(iter(linkage["incident_ids"])) if linkage["incident_ids"] else None)
            chain_link_id = ev.chain_link_event_id or (next(iter(linkage["chain_link_event_ids"])) if linkage["chain_link_event_ids"] else None)

            # Record all matching foreign keys onto the IOC level
            associated_anomalies.update(linkage["anomaly_ids"])
            associated_incidents.update(linkage["incident_ids"])
            associated_chains.update(linkage["chain_ids"])

            # Create updated evidence copy
            updated_ev = ev.model_copy(update={
                "anomaly_id": anomaly_id,
                "incident_id": incident_id,
                "chain_link_event_id": chain_link_id,
            })
            updated_evidence.append(updated_ev)

        return ioc.model_copy(update={
            "evidence_references": updated_evidence,
            "associated_anomaly_ids": sorted(list(associated_anomalies)),
            "associated_incident_ids": sorted(list(associated_incidents)),
            "associated_chain_ids": sorted(list(associated_chains)),
        })

    @classmethod
    def extract_and_map_from_events(
        cls,
        entries: List[LogEntry],
        anomalies: Optional[List[Anomaly]] = None,
        incidents: Optional[List[Incident]] = None,
        attack_chains: Optional[List[AttackChain]] = None,
        session_id: Optional[str] = None,
    ) -> List[IOC]:
        """
        Complete pipeline execution:
        Log Events -> Extraction -> Normalization & Validation -> Evidence Mapping.

        Returns canonical, validated, forensic-linked IOC entities.
        Discards invalid IOC candidates.
        Preserves raw values and evidence references.
        """
        if not entries:
            return []

        # 1. Extraction
        ext_result = IOCExtractor.extract_from_events(entries)
        if not ext_result.iocs:
            return []

        # 2. Normalization & Validation
        validated_result, _ = IOCValidator.validate_extraction_result(ext_result)

        # Filter: retain only valid or suspicious (not invalid) IOCs
        clean_iocs: List[IOC] = []
        for ioc in validated_result.iocs:
            v_res = IOCValidator.validate(ioc.raw_value, ioc.ioc_type, ioc.normalized_value)
            if v_res.is_valid:
                clean_iocs.append(ioc)

        # 3. Build forensic relationship index
        forensic_index = cls.build_forensic_index(
            entries=entries,
            anomalies=anomalies,
            incidents=incidents,
            attack_chains=attack_chains,
        )

        # 4. Map Evidence and Foreign Keys
        mapped_iocs: List[IOC] = []
        for ioc in clean_iocs:
            mapped_ioc = cls.map_ioc_evidence(ioc, forensic_index)
            # Ensure session_id is recorded if passed
            if session_id and session_id not in mapped_ioc.source_sessions:
                mapped_ioc.source_sessions.append(session_id)
            mapped_iocs.append(mapped_ioc)

        return mapped_iocs

