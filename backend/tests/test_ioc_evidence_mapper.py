"""
Phase 4.2A.4 — IOC Evidence Mapper Tests

Tests IOCEvidenceMapper for:
- Explicit linkage: IOC -> event, IOC -> session, IOC -> anomaly, IOC -> incident, IOC -> attack chain.
- False association safeguards: unrelated anomalies/incidents/chains in the same session are NOT linked.
- Evidence immutability: LogEntry, Anomaly, Incident, AttackChain objects are never mutated.
- Raw value and normalized value preservation.
- Full pipeline integration: extract_and_map_from_events.
- Zero external network calls.
"""

from datetime import datetime
import os
import sys
import unittest
import uuid

# Path setup
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from app.models.anomaly import Anomaly, DetectionMethod, SeverityLevel
from app.models.attack_chain import AttackChain, AttackStage, ChainLinkEvent
from app.models.incident import Incident, IncidentCategory, IncidentStatus
from app.models.ioc import (
    IOC,
    IOCEvidence,
    IOCStatus,
    IOCType,
)
from app.models.log_entry import LogEntry, LogLevel
from app.services.ioc_evidence_mapper import IOCEvidenceMapper


class TestIOCEvidenceMapper(unittest.TestCase):

    def setUp(self):
        self.session_id = f"test-sess-{uuid.uuid4().hex[:8]}"
        self.t1 = datetime(2024, 1, 15, 10, 0, 0)
        self.t2 = datetime(2024, 1, 15, 10, 5, 0)

        # Base Log Entries
        self.entry1 = LogEntry(
            id="ev-001",
            session_id=self.session_id,
            timestamp=self.t1,
            level=LogLevel.CRITICAL,
            source="sshd",
            message="Failed login from 198.51.100.42 for user root",
            raw_line="Jan 15 10:00:00 sshd[100]: Failed login from 198.51.100.42 for user root",
            line_number=1,
        )
        self.entry2 = LogEntry(
            id="ev-002",
            session_id=self.session_id,
            timestamp=self.t2,
            level=LogLevel.WARNING,
            source="kernel",
            message="Downloaded payload http://evil.com/drop.sh to /tmp/malware.sh",
            raw_line="Jan 15 10:05:00 kernel: Downloaded payload http://evil.com/drop.sh to /tmp/malware.sh",
            line_number=2,
        )
        self.entry_unrelated = LogEntry(
            id="ev-999",
            session_id=self.session_id,
            timestamp=self.t1,
            level=LogLevel.INFO,
            source="systemd",
            message="Service started on 127.0.0.1",
            raw_line="Jan 15 10:00:00 systemd: Service started on 127.0.0.1",
            line_number=3,
        )

    # ─────────────────────────────────────────────────────────────────────────
    # 1. Forensic Index Building
    # ─────────────────────────────────────────────────────────────────────────

    def test_01_forensic_index_anomaly_linkage(self):
        """Index links event_id to anomaly_id via anomaly.log_entry_ids."""
        anom = Anomaly(
            id="anom-01",
            session_id=self.session_id,
            log_entry_ids=["ev-001"],
            score=0.9,
            severity=SeverityLevel.HIGH,
            reason="Brute force",
            method=DetectionMethod.RULE_BASED,
        )
        index = IOCEvidenceMapper.build_forensic_index(
            entries=[self.entry1],
            anomalies=[anom],
        )

        self.assertIn("ev-001", index)
        self.assertIn("anom-01", index["ev-001"]["anomaly_ids"])
        self.assertEqual(len(index["ev-999"]["anomaly_ids"]), 0)

    def test_02_forensic_index_incident_linkage(self):
        """Index links event_id to incident_id via anomaly reference."""
        anom = Anomaly(
            id="anom-01",
            session_id=self.session_id,
            log_entry_ids=["ev-001"],
            score=0.9,
            severity=SeverityLevel.HIGH,
            reason="Brute force",
            method=DetectionMethod.RULE_BASED,
        )
        inc = Incident(
            id="inc-01",
            anomaly_id="anom-01",
            session_id=self.session_id,
            category=IncidentCategory.AUTHENTICATION_FAILURE,
            severity="HIGH",
            title="SSH Auth Failure",
            description="Brute force",
            root_cause_hypothesis="Compromised credentials",
            potential_impact="Unauthorized access",
            first_seen=self.t1,
            last_seen=self.t2,
        )
        index = IOCEvidenceMapper.build_forensic_index(
            entries=[self.entry1],
            anomalies=[anom],
            incidents=[inc],
        )

        self.assertIn("inc-01", index["ev-001"]["incident_ids"])
        self.assertEqual(len(index["ev-999"]["incident_ids"]), 0)

    def test_03_forensic_index_attack_chain_linkage(self):
        """Index links event_id to attack_chain_id and chain_link_event_id."""
        link = ChainLinkEvent(
            id="link-01",
            log_entry_id="ev-001",
            raw_log=self.entry1.raw_line,
            message=self.entry1.message,
            correlation_reason="Reconnaissance signal",
            stage=AttackStage.RECONNAISSANCE,
        )
        chain = AttackChain(
            id="chain-01",
            session_id=self.session_id,
            title="Credential Attack Chain",
            summary="Attack summary",
            potential_impact="Severe",
            correlation_explanation="Correlated by IP",
            event_ids=["ev-001"],
            events=[link],
        )
        index = IOCEvidenceMapper.build_forensic_index(
            entries=[self.entry1],
            attack_chains=[chain],
        )

        self.assertIn("chain-01", index["ev-001"]["chain_ids"])
        self.assertIn("link-01", index["ev-001"]["chain_link_event_ids"])
        self.assertEqual(len(index["ev-999"]["chain_ids"]), 0)

    # ─────────────────────────────────────────────────────────────────────────
    # 2. False Association Safeguards
    # ─────────────────────────────────────────────────────────────────────────

    def test_04_no_false_association_across_events(self):
        """
        Unrelated event in the same session must NOT be associated with
        an anomaly, incident, or attack chain.
        """
        anom = Anomaly(
            id="anom-01",
            session_id=self.session_id,
            log_entry_ids=["ev-001"],
            score=0.9,
            severity=SeverityLevel.HIGH,
            reason="Anomaly on ev-001",
            method=DetectionMethod.RULE_BASED,
        )
        chain = AttackChain(
            id="chain-01",
            session_id=self.session_id,
            title="Chain on ev-001",
            summary="Summary",
            potential_impact="Impact",
            correlation_explanation="Explanation",
            event_ids=["ev-001"],
            events=[ChainLinkEvent(id="link-01", log_entry_id="ev-001", raw_log="x", message="x", correlation_reason="x")],
        )

        index = IOCEvidenceMapper.build_forensic_index(
            entries=[self.entry1, self.entry_unrelated],
            anomalies=[anom],
            attack_chains=[chain],
        )

        # ev-999 has NO associations
        unrelated_linkage = index["ev-999"]
        self.assertEqual(len(unrelated_linkage["anomaly_ids"]), 0)
        self.assertEqual(len(unrelated_linkage["incident_ids"]), 0)
        self.assertEqual(len(unrelated_linkage["chain_ids"]), 0)

    # ─────────────────────────────────────────────────────────────────────────
    # 3. Evidence Mapping onto IOC Entities
    # ─────────────────────────────────────────────────────────────────────────

    def test_05_map_ioc_evidence_populates_relationships(self):
        """Mapping enriches IOC evidence references with anomaly, incident, and chain IDs."""
        ev = IOCEvidence(
            event_id="ev-001",
            session_id=self.session_id,
            raw_value="198.51.100.42",
            line_number=1,
            surrounding_context="Failed login from 198.51.100.42",
        )
        ioc = IOC(
            ioc_type=IOCType.IPV4,
            raw_value="198.51.100.42",
            normalized_value="198.51.100.42",
            evidence_references=[ev],
        )

        forensic_index = {
            "ev-001": {
                "anomaly_ids": {"anom-01"},
                "incident_ids": {"inc-01"},
                "chain_ids": {"chain-01"},
                "chain_link_event_ids": {"link-01"},
            }
        }

        mapped_ioc = IOCEvidenceMapper.map_ioc_evidence(ioc, forensic_index)

        # Evidence references enriched
        self.assertEqual(len(mapped_ioc.evidence_references), 1)
        mapped_ev = mapped_ioc.evidence_references[0]
        self.assertEqual(mapped_ev.anomaly_id, "anom-01")
        self.assertEqual(mapped_ev.incident_id, "inc-01")
        self.assertEqual(mapped_ev.chain_link_event_id, "link-01")

        # Entity-level lists populated
        self.assertEqual(mapped_ioc.associated_anomaly_ids, ["anom-01"])
        self.assertEqual(mapped_ioc.associated_incident_ids, ["inc-01"])
        self.assertEqual(mapped_ioc.associated_chain_ids, ["chain-01"])

        # Status remains EXTRACTED (no verdict contamination)
        self.assertEqual(mapped_ioc.status, IOCStatus.EXTRACTED)

    # ─────────────────────────────────────────────────────────────────────────
    # 4. Immutability & Original Object Safety
    # ─────────────────────────────────────────────────────────────────────────

    def test_06_immutability_of_input_objects(self):
        """LogEntry, Anomaly, Incident, and AttackChain objects are never mutated by the mapper."""
        orig_raw = self.entry1.raw_line
        orig_msg = self.entry1.message

        anom = Anomaly(
            id="anom-01",
            session_id=self.session_id,
            log_entry_ids=["ev-001"],
            score=0.9,
            severity=SeverityLevel.HIGH,
            reason="Original reason",
            method=DetectionMethod.RULE_BASED,
        )
        chain = AttackChain(
            id="chain-01",
            session_id=self.session_id,
            title="Original Title",
            summary="Original Summary",
            potential_impact="Original Impact",
            correlation_explanation="Original Exp",
            event_ids=["ev-001"],
            events=[ChainLinkEvent(id="l1", log_entry_id="ev-001", raw_log=orig_raw, message=orig_msg, correlation_reason="r")],
        )

        _ = IOCEvidenceMapper.extract_and_map_from_events(
            entries=[self.entry1],
            anomalies=[anom],
            attack_chains=[chain],
            session_id=self.session_id,
        )

        # Assert zero mutations on inputs
        self.assertEqual(self.entry1.raw_line, orig_raw)
        self.assertEqual(self.entry1.message, orig_msg)
        self.assertEqual(anom.reason, "Original reason")
        self.assertEqual(chain.title, "Original Title")

    # ─────────────────────────────────────────────────────────────────────────
    # 5. End-to-End extract_and_map_from_events Pipeline
    # ─────────────────────────────────────────────────────────────────────────

    def test_07_extract_and_map_pipeline(self):
        """End-to-end pipeline extracts, normalizes, validates, and maps all indicators in batch."""
        anom = Anomaly(
            id="anom-01",
            session_id=self.session_id,
            log_entry_ids=["ev-001"],
            score=0.9,
            severity=SeverityLevel.HIGH,
            reason="SSH failure",
            method=DetectionMethod.RULE_BASED,
        )
        chain = AttackChain(
            id="chain-01",
            session_id=self.session_id,
            title="Attack Chain",
            summary="Summary",
            potential_impact="Impact",
            correlation_explanation="Exp",
            event_ids=["ev-001"],
            events=[ChainLinkEvent(id="link-01", log_entry_id="ev-001", raw_log=self.entry1.raw_line, message=self.entry1.message, correlation_reason="r")],
        )

        mapped_iocs = IOCEvidenceMapper.extract_and_map_from_events(
            entries=[self.entry1, self.entry2],
            anomalies=[anom],
            attack_chains=[chain],
            session_id=self.session_id,
        )

        self.assertTrue(len(mapped_iocs) >= 3)  # IP 198.51.100.42, URL http://evil.com/drop.sh, Path /tmp/malware.sh

        # Check IP IOC from ev-001
        ip_ioc = next((i for i in mapped_iocs if i.ioc_type == IOCType.IPV4 and i.normalized_value == "198.51.100.42"), None)
        self.assertIsNotNone(ip_ioc)
        self.assertIn("anom-01", ip_ioc.associated_anomaly_ids)
        self.assertIn("chain-01", ip_ioc.associated_chain_ids)

        # Check Path IOC from ev-002 (unassociated with anom-01)
        path_ioc = next((i for i in mapped_iocs if i.ioc_type == IOCType.FILE_PATH), None)
        self.assertIsNotNone(path_ioc)
        self.assertEqual(len(path_ioc.associated_anomaly_ids), 0)
        self.assertEqual(len(path_ioc.associated_chain_ids), 0)

    def test_08_empty_events_pipeline(self):
        """Calling extract_and_map_from_events on empty list returns empty list gracefully."""
        res = IOCEvidenceMapper.extract_and_map_from_events([])
        self.assertEqual(res, [])

    # ─────────────────────────────────────────────────────────────────────────
    # 6. Additional Detailed Association & Integrity Tests
    # ─────────────────────────────────────────────────────────────────────────

    def test_09_mapping_preserves_distinct_contexts_for_multiple_events(self):
        """Mapping multiple events to the same IOC preserves distinct context snippets."""
        entry3 = LogEntry(
            id="ev-003",
            session_id=self.session_id,
            timestamp=self.t2,
            level=LogLevel.ERROR,
            source="sshd",
            message="Second attempt from 198.51.100.42 blocked",
            raw_line="Jan 15 10:05:00 sshd: Second attempt from 198.51.100.42 blocked",
            line_number=3,
        )
        mapped_iocs = IOCEvidenceMapper.extract_and_map_from_events(
            entries=[self.entry1, entry3],
            session_id=self.session_id,
        )
        ip_ioc = next((i for i in mapped_iocs if i.normalized_value == "198.51.100.42"), None)
        self.assertIsNotNone(ip_ioc)
        self.assertEqual(ip_ioc.occurrence_count, 2)
        self.assertEqual(len(ip_ioc.evidence_references), 2)
        self.assertIn("ev-001", [ev.event_id for ev in ip_ioc.evidence_references])
        self.assertIn("ev-003", [ev.event_id for ev in ip_ioc.evidence_references])

    def test_10_mapping_preserves_extraction_methods(self):
        """Mapped IOC retains accurate machine-readable extraction_methods list."""
        mapped = IOCEvidenceMapper.extract_and_map_from_events([self.entry1])
        ip_ioc = next(i for i in mapped if i.normalized_value == "198.51.100.42")
        self.assertIn("regex_ipv4", ip_ioc.extraction_methods)

    def test_11_mapping_when_no_anomalies_or_incidents_exist(self):
        """Pipeline functions cleanly when anomalies/incidents/chains are None or empty."""
        mapped = IOCEvidenceMapper.extract_and_map_from_events(
            entries=[self.entry1],
            anomalies=None,
            incidents=None,
            attack_chains=None,
        )
        self.assertTrue(len(mapped) >= 1)
        ip_ioc = mapped[0]
        self.assertEqual(ip_ioc.associated_anomaly_ids, [])
        self.assertEqual(ip_ioc.associated_incident_ids, [])
        self.assertEqual(ip_ioc.associated_chain_ids, [])

    def test_12_mapping_does_not_mutate_ioc_raw_value(self):
        """Raw value is guaranteed preserved after evidence mapping."""
        ev = IOCEvidence(event_id="e1", session_id="s1", raw_value="10.001.020.005")
        ioc = IOC(
            ioc_type=IOCType.IPV4,
            raw_value="10.001.020.005",
            normalized_value="10.1.20.5",
            evidence_references=[ev],
        )
        mapped = IOCEvidenceMapper.map_ioc_evidence(ioc, {})
        self.assertEqual(mapped.raw_value, "10.001.020.005")
        self.assertEqual(mapped.normalized_value, "10.1.20.5")

    def test_13_mapping_multiple_chains_linked_to_same_event(self):
        """If an event belongs to multiple attack chains, all chain IDs are associated."""
        chain_a = AttackChain(
            id="chain-A",
            session_id=self.session_id,
            title="Chain A",
            summary="S",
            potential_impact="I",
            correlation_explanation="C",
            event_ids=["ev-001"],
            events=[ChainLinkEvent(id="link-a", log_entry_id="ev-001", raw_log="x", message="x", correlation_reason="x")],
        )
        chain_b = AttackChain(
            id="chain-B",
            session_id=self.session_id,
            title="Chain B",
            summary="S",
            potential_impact="I",
            correlation_explanation="C",
            event_ids=["ev-001"],
            events=[ChainLinkEvent(id="link-b", log_entry_id="ev-001", raw_log="x", message="x", correlation_reason="x")],
        )

        index = IOCEvidenceMapper.build_forensic_index(
            entries=[self.entry1],
            attack_chains=[chain_a, chain_b],
        )
        self.assertIn("chain-A", index["ev-001"]["chain_ids"])
        self.assertIn("chain-B", index["ev-001"]["chain_ids"])

        ev = IOCEvidence(event_id="ev-001", session_id=self.session_id, raw_value="198.51.100.42")
        ioc = IOC(ioc_type=IOCType.IPV4, raw_value="198.51.100.42", normalized_value="198.51.100.42", evidence_references=[ev])
        mapped = IOCEvidenceMapper.map_ioc_evidence(ioc, index)
        self.assertIn("chain-A", mapped.associated_chain_ids)
        self.assertIn("chain-B", mapped.associated_chain_ids)

    def test_14_mapping_with_incident_evidence_log_lines(self):
        """Incidents matching via evidence_log_lines are associated even if anomaly_id is unlinked."""
        inc = Incident(
            id="inc-direct-log",
            anomaly_id="unrelated-anom",
            session_id=self.session_id,
            category=IncidentCategory.AUTHENTICATION_FAILURE,
            severity="HIGH",
            title="SSH Auth Failure",
            description="Brute force",
            root_cause_hypothesis="Compromised credentials",
            potential_impact="Unauthorized access",
            evidence_log_lines=[self.entry1.raw_line],
            first_seen=self.t1,
            last_seen=self.t2,
        )
        index = IOCEvidenceMapper.build_forensic_index(
            entries=[self.entry1],
            incidents=[inc],
        )
        self.assertIn("inc-direct-log", index["ev-001"]["incident_ids"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
