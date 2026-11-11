"""
Unit and integration tests for ThreatCorrelationEngine.

Phase 4.2B.4 — Threat Correlation & Unified Intelligence Engine.
"""

from datetime import datetime, timedelta, timezone
import os
import sys
import unittest
import uuid

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from app.models.anomaly import Anomaly, DetectionMethod, SeverityLevel
from app.models.attack_chain import AttackChain, AttackStage, ChainLinkEvent, ChainStatus
from app.models.incident import Incident, IncidentCategory, IncidentStatus
from app.models.ioc import IOC, IOCEvidence, IOCStatus, IOCType
from app.models.threat_correlation import (
    CorrelationConfidenceLevel,
    ThreatCorrelationType,
)
from app.models.threat_intel import (
    ThreatAssessment,
    ThreatIntelResult,
    ThreatIntelSource,
    ThreatIntelStatus,
    ThreatSeverity,
)
from app.services.ioc_repository import IOCRepository
from app.services.store import SessionStore
from app.services.threat_correlation_engine import ThreatCorrelationEngine


class TestThreatCorrelationEngine(unittest.TestCase):
    """Thorough test suite for the Threat Correlation Engine."""

    def setUp(self):
        """Create isolated SessionStore, IOCRepository, and Engine instances."""
        self.store = SessionStore()
        self.ioc_repo = IOCRepository(session_store=self.store)
        self.engine = ThreatCorrelationEngine(
            ioc_repo=self.ioc_repo,
            session_store=self.store,
            reputation_engine=None,  # Pass explicitly in tests
        )

        self.session_id_1 = "sess-alpha-01"
        self.session_id_2 = "sess-beta-02"
        self.base_time = datetime(2026, 4, 10, 12, 0, 0, tzinfo=timezone.utc)

    # ─────────────────────────────────────────────────────────────────────────
    # 1. Event Correlation Tests
    # ─────────────────────────────────────────────────────────────────────────

    def test_correlate_events_with_line_number(self):
        """Verify direct event extraction with line number achieves 1.0 confidence."""
        ev = IOCEvidence(
            event_id="evt-101",
            session_id=self.session_id_1,
            timestamp=self.base_time,
            raw_value="198.51.100.42",
            source_field="raw_line",
            line_number=45,
            surrounding_context="SSH connection from 198.51.100.42 failed",
        )
        ioc = IOC(
            id="ioc-001",
            ioc_type=IOCType.IPV4,
            raw_value="198.51.100.42",
            normalized_value="198.51.100.42",
            evidence_references=[ev],
            source_sessions=[self.session_id_1],
        )

        corrs = self.engine.correlate_events(ioc)
        self.assertEqual(len(corrs), 1)
        c = corrs[0]
        self.assertEqual(c.correlation_type, ThreatCorrelationType.IOC_TO_EVENT)
        self.assertEqual(c.source_id, "ioc-001")
        self.assertEqual(c.target_id, "evt-101")
        self.assertEqual(c.confidence.score, 1.0)
        self.assertEqual(c.confidence.confidence_level, CorrelationConfidenceLevel.HIGH)
        self.assertTrue(c.confirmed)
        self.assertTrue(any("line 45" in line for line in c.evidence))

    def test_correlate_events_without_line_number(self):
        """Verify event extraction without line number yields 0.95 confidence."""
        ev = IOCEvidence(
            event_id="evt-102",
            session_id=self.session_id_1,
            timestamp=self.base_time,
            raw_value="malicious.example",
            source_field="message",
            line_number=None,
        )
        ioc = IOC(
            id="ioc-002",
            ioc_type=IOCType.DOMAIN,
            raw_value="malicious.example",
            normalized_value="malicious.example",
            evidence_references=[ev],
            source_sessions=[self.session_id_1],
        )

        corrs = self.engine.correlate_events(ioc)
        self.assertEqual(len(corrs), 1)
        self.assertEqual(corrs[0].confidence.score, 0.95)

    def test_correlate_events_empty_evidence(self):
        """IOC without evidence references produces no event correlations."""
        ioc = IOC(
            id="ioc-003",
            ioc_type=IOCType.IPV4,
            raw_value="10.0.0.1",
            normalized_value="10.0.0.1",
            evidence_references=[],
        )
        corrs = self.engine.correlate_events(ioc)
        self.assertEqual(len(corrs), 0)

    # ─────────────────────────────────────────────────────────────────────────
    # 2. Anomaly Correlation Tests
    # ─────────────────────────────────────────────────────────────────────────

    def test_correlate_anomalies_explicit_reference(self):
        """Anomaly linked via associated_anomaly_ids gets explicit_reference score."""
        anomaly = Anomaly(
            id="anom-101",
            session_id=self.session_id_1,
            log_entry_ids=["evt-201"],
            score=0.88,
            severity=SeverityLevel.HIGH,
            reason="Repeated login failures",
            method=DetectionMethod.RULE_BASED,
            detected_at=self.base_time,
        )
        self.store.anomalies[self.session_id_1] = [anomaly]

        ioc = IOC(
            id="ioc-101",
            ioc_type=IOCType.IPV4,
            raw_value="198.51.100.42",
            normalized_value="198.51.100.42",
            associated_anomaly_ids=["anom-101"],
            source_sessions=[self.session_id_1],
        )

        corrs = self.engine.correlate_anomalies(ioc)
        self.assertEqual(len(corrs), 1)
        c = corrs[0]
        self.assertEqual(c.target_id, "anom-101")
        self.assertEqual(c.correlation_method, "explicit_reference")
        self.assertTrue(c.confidence.score >= 0.85)
        self.assertTrue(c.confirmed)

    def test_correlate_anomalies_shared_event(self):
        """Anomaly sharing a log entry ID with an IOC gets shared_event score."""
        anomaly = Anomaly(
            id="anom-102",
            session_id=self.session_id_1,
            log_entry_ids=["evt-301", "evt-302"],
            score=0.92,
            severity=SeverityLevel.CRITICAL,
            reason="Outbound reverse shell",
            method=DetectionMethod.ISOLATION_FOREST,
            detected_at=self.base_time,
        )
        self.store.anomalies[self.session_id_1] = [anomaly]

        ev = IOCEvidence(
            event_id="evt-301",
            session_id=self.session_id_1,
            timestamp=self.base_time,
            raw_value="c2.attacker.com",
            source_field="raw_line",
        )
        ioc = IOC(
            id="ioc-102",
            ioc_type=IOCType.DOMAIN,
            raw_value="c2.attacker.com",
            normalized_value="c2.attacker.com",
            evidence_references=[ev],
            source_sessions=[self.session_id_1],
        )

        corrs = self.engine.correlate_anomalies(ioc)
        self.assertEqual(len(corrs), 1)
        c = corrs[0]
        self.assertEqual(c.target_id, "anom-102")
        self.assertEqual(c.correlation_method, "shared_event")
        self.assertTrue(c.confidence.score >= 0.80)
        self.assertTrue(c.confirmed)

    def test_correlate_anomalies_temporal_proximity(self):
        """Anomalies in same session within windows are correlated with appropriate confirmation."""
        # Anomaly 1: 15s away (immediate -> confirmed=True)
        anom_imm = Anomaly(
            id="anom-imm",
            session_id=self.session_id_1,
            log_entry_ids=["other-evt-1"],
            score=0.6,
            severity=SeverityLevel.MEDIUM,
            reason="Probe spike",
            method=DetectionMethod.STATISTICAL,
            detected_at=self.base_time + timedelta(seconds=15),
        )
        # Anomaly 2: 120s away (short -> confirmed=False)
        anom_short = Anomaly(
            id="anom-short",
            session_id=self.session_id_1,
            log_entry_ids=["other-evt-2"],
            score=0.5,
            severity=SeverityLevel.LOW,
            reason="Late burst",
            method=DetectionMethod.STATISTICAL,
            detected_at=self.base_time + timedelta(seconds=120),
        )
        # Anomaly 3: 2 hours away (outside window -> not correlated)
        anom_far = Anomaly(
            id="anom-far",
            session_id=self.session_id_1,
            log_entry_ids=["other-evt-3"],
            score=0.4,
            severity=SeverityLevel.LOW,
            reason="Far event",
            method=DetectionMethod.STATISTICAL,
            detected_at=self.base_time + timedelta(hours=2),
        )

        self.store.anomalies[self.session_id_1] = [anom_imm, anom_short, anom_far]

        ev = IOCEvidence(
            event_id="evt-origin",
            session_id=self.session_id_1,
            timestamp=self.base_time,
            raw_value="10.20.30.40",
            source_field="raw_line",
        )
        ioc = IOC(
            id="ioc-temp",
            ioc_type=IOCType.IPV4,
            raw_value="10.20.30.40",
            normalized_value="10.20.30.40",
            evidence_references=[ev],
            source_sessions=[self.session_id_1],
        )

        corrs = self.engine.correlate_anomalies(ioc)
        corr_map = {c.target_id: c for c in corrs}

        self.assertIn("anom-imm", corr_map)
        self.assertTrue(corr_map["anom-imm"].confirmed)
        self.assertEqual(corr_map["anom-imm"].correlation_method, "temporal_proximity_immediate")

        self.assertIn("anom-short", corr_map)
        self.assertFalse(corr_map["anom-short"].confirmed)
        self.assertEqual(corr_map["anom-short"].correlation_method, "temporal_proximity_short")

        self.assertNotIn("anom-far", corr_map)

    def test_correlate_anomalies_cross_session_penalty(self):
        """Cross-session shared event is penalized and marked unconfirmed."""
        anomaly = Anomaly(
            id="anom-cross",
            session_id=self.session_id_2,  # Different session
            log_entry_ids=["evt-shared"],
            score=0.8,
            severity=SeverityLevel.HIGH,
            reason="Cross session probe",
            method=DetectionMethod.RULE_BASED,
            detected_at=self.base_time,
        )
        self.store.anomalies[self.session_id_2] = [anomaly]

        ev = IOCEvidence(
            event_id="evt-shared",
            session_id=self.session_id_1,  # Session 1
            timestamp=self.base_time,
            raw_value="10.99.99.99",
            source_field="raw_line",
        )
        ioc = IOC(
            id="ioc-cross",
            ioc_type=IOCType.IPV4,
            raw_value="10.99.99.99",
            normalized_value="10.99.99.99",
            evidence_references=[ev],
            source_sessions=[self.session_id_1],
        )

        corrs = self.engine.correlate_anomalies(ioc)
        self.assertEqual(len(corrs), 1)
        c = corrs[0]
        self.assertFalse(c.confirmed)
        self.assertLessEqual(c.confidence.score, 0.35)
        self.assertTrue(any("UNCONFIRMED" in b for b in c.evidence))

    # ─────────────────────────────────────────────────────────────────────────
    # 3. Incident Correlation Tests
    # ─────────────────────────────────────────────────────────────────────────

    def test_correlate_incidents_explicit_reference(self):
        """Explicit incident reference creates high-confidence correlation."""
        incident = Incident(
            id="inc-501",
            anomaly_id="anom-none",
            session_id=self.session_id_1,
            category=IncidentCategory.INTRUSION_ATTEMPT,
            severity="HIGH",
            title="SSH Brute Force Detected",
            description="Repeated unauthorized access attempts",
            root_cause_hypothesis="Compromised credentials or dictionary attack",
            potential_impact="Unauthorized system access",
            first_seen=self.base_time,
            last_seen=self.base_time,
            status=IncidentStatus.OPEN,
        )
        self.store.incidents[self.session_id_1] = [incident]

        ioc = IOC(
            id="ioc-inc-1",
            ioc_type=IOCType.IPV4,
            raw_value="203.0.113.195",
            normalized_value="203.0.113.195",
            associated_incident_ids=["inc-501"],
            source_sessions=[self.session_id_1],
        )

        corrs = self.engine.correlate_incidents(ioc)
        self.assertEqual(len(corrs), 1)
        c = corrs[0]
        self.assertEqual(c.target_id, "inc-501")
        self.assertEqual(c.correlation_method, "explicit_reference")
        self.assertTrue(c.confirmed)
        self.assertTrue(c.confidence.score >= 0.85)

    def test_correlate_incidents_via_anomaly_chain(self):
        """Incident linked to a correlated anomaly gets correlated via anomaly chain."""
        anomaly = Anomaly(
            id="anom-root",
            session_id=self.session_id_1,
            log_entry_ids=["evt-root"],
            score=0.9,
            severity=SeverityLevel.HIGH,
            reason="Privilege escalation root shell",
            method=DetectionMethod.RULE_BASED,
            detected_at=self.base_time,
        )
        self.store.anomalies[self.session_id_1] = [anomaly]

        incident = Incident(
            id="inc-chain",
            anomaly_id="anom-root",
            session_id=self.session_id_1,
            category=IncidentCategory.PRIVILEGE_ESCALATION,
            severity="CRITICAL",
            title="Root Compromise",
            description="Unauthorized root elevation",
            root_cause_hypothesis="Kernel exploit executed",
            potential_impact="Full system compromise",
            first_seen=self.base_time,
            last_seen=self.base_time,
            status=IncidentStatus.INVESTIGATING,
        )
        self.store.incidents[self.session_id_1] = [incident]

        ev = IOCEvidence(
            event_id="evt-root",
            session_id=self.session_id_1,
            timestamp=self.base_time,
            raw_value="/tmp/exploit.bin",
            source_field="raw_line",
        )
        ioc = IOC(
            id="ioc-exploit",
            ioc_type=IOCType.FILE_PATH,
            raw_value="/tmp/exploit.bin",
            normalized_value="/tmp/exploit.bin",
            evidence_references=[ev],
            source_sessions=[self.session_id_1],
        )

        anomaly_corrs = self.engine.correlate_anomalies(ioc)
        incident_corrs = self.engine.correlate_incidents(ioc, correlated_anomalies=anomaly_corrs)

        self.assertEqual(len(incident_corrs), 1)
        c = incident_corrs[0]
        self.assertEqual(c.target_id, "inc-chain")
        self.assertEqual(c.correlation_method, "correlated_anomaly_chain")
        self.assertTrue(c.confirmed)
        self.assertTrue(any("derived from Anomaly 'anom-root'" in b for b in c.evidence))

    def test_correlate_incidents_entity_match(self):
        """Incident containing IOC in affected_ips gets correlated via affected_entity_match."""
        incident = Incident(
            id="inc-ip-match",
            anomaly_id="anom-other",
            session_id=self.session_id_1,
            category=IncidentCategory.DATA_EXFILTRATION,
            severity="HIGH",
            title="Outbound Transfer",
            description="Large volume data egress",
            root_cause_hypothesis="Compromised host exfiltrating data",
            potential_impact="Data breach",
            first_seen=self.base_time,
            last_seen=self.base_time,
            affected_ips=["198.51.100.99"],
            status=IncidentStatus.OPEN,
        )
        self.store.incidents[self.session_id_1] = [incident]

        ioc = IOC(
            id="ioc-match",
            ioc_type=IOCType.IPV4,
            raw_value="198.51.100.99",
            normalized_value="198.51.100.99",
            source_sessions=[self.session_id_1],
        )

        corrs = self.engine.correlate_incidents(ioc)
        self.assertEqual(len(corrs), 1)
        c = corrs[0]
        self.assertEqual(c.target_id, "inc-ip-match")
        self.assertEqual(c.correlation_method, "affected_entity_match")
        self.assertTrue(c.confirmed)

    # ─────────────────────────────────────────────────────────────────────────
    # 4. Attack Chain Correlation Tests
    # ─────────────────────────────────────────────────────────────────────────

    def test_correlate_attack_chains_chain_event_membership(self):
        """Attack chain containing matching event links IOC and captures MITRE stage."""
        chain_event = ChainLinkEvent(
            id="cle-01",
            log_entry_id="evt-chain-01",
            timestamp=self.base_time,
            stage=AttackStage.CREDENTIAL_ATTACK,
            raw_log="Failed password for admin",
            message="Failed auth",
            correlation_reason="High frequency auth failures",
        )
        chain = AttackChain(
            id="chain-701",
            session_id=self.session_id_1,
            title="Password Spray Campaign",
            summary="Multi-stage credential attack",
            severity="HIGH",
            stages_observed=[AttackStage.RECONNAISSANCE, AttackStage.CREDENTIAL_ATTACK],
            event_ids=["evt-chain-01"],
            events=[chain_event],
            potential_impact="Account takeover",
            correlation_explanation="Correlated by IP and timestamp",
        )
        self.store.attack_chains[self.session_id_1] = [chain]

        ev = IOCEvidence(
            event_id="evt-chain-01",
            session_id=self.session_id_1,
            timestamp=self.base_time,
            raw_value="198.51.100.22",
            source_field="source_ip",
        )
        ioc = IOC(
            id="ioc-chain-1",
            ioc_type=IOCType.IPV4,
            raw_value="198.51.100.22",
            normalized_value="198.51.100.22",
            evidence_references=[ev],
            source_sessions=[self.session_id_1],
        )

        corrs = self.engine.correlate_attack_chains(ioc)
        self.assertEqual(len(corrs), 1)
        c = corrs[0]
        self.assertEqual(c.target_id, "chain-701")
        self.assertEqual(c.correlation_method, "chain_event_membership")
        self.assertTrue(c.confirmed)
        self.assertTrue(any("Credential Attack" in b for b in c.evidence))

    def test_correlate_attack_chains_forensic_entity_match(self):
        """Attack chain listing IOC in source_ips gets correlated via forensic_entity_match."""
        chain = AttackChain(
            id="chain-702",
            session_id=self.session_id_1,
            title="Lateral Movement Recon",
            summary="Internal scanning",
            severity="MEDIUM",
            source_ips=["192.168.1.50"],
            stages_observed=[AttackStage.LATERAL_MOVEMENT],
            potential_impact="Network discovery",
            correlation_explanation="Internal port scans",
        )
        self.store.attack_chains[self.session_id_1] = [chain]

        ioc = IOC(
            id="ioc-chain-2",
            ioc_type=IOCType.IPV4,
            raw_value="192.168.1.50",
            normalized_value="192.168.1.50",
            source_sessions=[self.session_id_1],
        )

        corrs = self.engine.correlate_attack_chains(ioc)
        self.assertEqual(len(corrs), 1)
        c = corrs[0]
        self.assertEqual(c.target_id, "chain-702")
        self.assertEqual(c.correlation_method, "forensic_entity_match")
        self.assertTrue(c.confirmed)

    # ─────────────────────────────────────────────────────────────────────────
    # 5. Threat Assessment Bridge Tests
    # ─────────────────────────────────────────────────────────────────────────

    def test_threat_assessment_bridge_links(self):
        """Threat assessment bridges to correlated incidents and chains."""
        incident = Incident(
            id="inc-bridge",
            anomaly_id="anom-0",
            session_id=self.session_id_1,
            category=IncidentCategory.MALWARE_INDICATOR,
            severity="CRITICAL",
            title="Active C2 Connection",
            description="Beaconing observed",
            root_cause_hypothesis="Trojan infection",
            potential_impact="Remote code execution",
            first_seen=self.base_time,
            last_seen=self.base_time,
            affected_ips=["203.0.113.88"],
            status=IncidentStatus.OPEN,
        )
        chain = AttackChain(
            id="chain-bridge",
            session_id=self.session_id_1,
            title="C2 Beaconing Campaign",
            summary="Active C2 communication",
            severity="CRITICAL",
            source_ips=["203.0.113.88"],
            potential_impact="Data loss",
            correlation_explanation="DNS + HTTP beaconing",
        )
        self.store.incidents[self.session_id_1] = [incident]
        self.store.attack_chains[self.session_id_1] = [chain]

        ioc = IOC(
            id="ioc-bridge",
            ioc_type=IOCType.IPV4,
            raw_value="203.0.113.88",
            normalized_value="203.0.113.88",
            source_sessions=[self.session_id_1],
        )

        assessment = ThreatAssessment(
            ioc_id="ioc-bridge",
            ioc_type=IOCType.IPV4,
            ioc_value="203.0.113.88",
            normalized_value="203.0.113.88",
            threat_score=95.0,
            confidence=0.92,
            severity=ThreatSeverity.CRITICAL,
            status=ThreatIntelStatus.MALICIOUS,
        )

        corrs = self.engine.correlate_ioc(ioc, threat_assessment=assessment)
        types = {c.correlation_type for c in corrs}

        self.assertIn(ThreatCorrelationType.THREAT_ASSESSMENT_TO_INCIDENT, types)
        self.assertIn(ThreatCorrelationType.THREAT_ASSESSMENT_TO_ATTACK_CHAIN, types)

        bridge_inc = [c for c in corrs if c.correlation_type == ThreatCorrelationType.THREAT_ASSESSMENT_TO_INCIDENT][0]
        self.assertEqual(bridge_inc.source_id, assessment.assessment_id)
        self.assertEqual(bridge_inc.target_id, "inc-bridge")
        self.assertTrue(any("Threat Score: 95.0/100" in b for b in bridge_inc.evidence))

    # ─────────────────────────────────────────────────────────────────────────
    # 6. Immutability & Safety Tests
    # ─────────────────────────────────────────────────────────────────────────

    def test_immutability_of_source_objects(self):
        """Verify correlation execution causes zero mutations to source entities."""
        anomaly = Anomaly(
            id="anom-immut",
            session_id=self.session_id_1,
            log_entry_ids=["evt-immut"],
            score=0.75,
            severity=SeverityLevel.HIGH,
            reason="Original reason",
            method=DetectionMethod.RULE_BASED,
            detected_at=self.base_time,
        )
        incident = Incident(
            id="inc-immut",
            anomaly_id="anom-immut",
            session_id=self.session_id_1,
            category=IncidentCategory.MALWARE_INDICATOR,
            severity="HIGH",
            title="Original title",
            description="Original description",
            root_cause_hypothesis="Hypothesis",
            potential_impact="Impact",
            first_seen=self.base_time,
            last_seen=self.base_time,
            status=IncidentStatus.OPEN,
        )
        self.store.anomalies[self.session_id_1] = [anomaly]
        self.store.incidents[self.session_id_1] = [incident]

        ioc = IOC(
            id="ioc-immut",
            ioc_type=IOCType.IPV4,
            raw_value="198.51.100.1",
            normalized_value="198.51.100.1",
            status=IOCStatus.EXTRACTED,
            source_sessions=[self.session_id_1],
            associated_anomaly_ids=["anom-immut"],
            associated_incident_ids=["inc-immut"],
        )
        result = ThreatIntelResult(
            ioc_id="ioc-immut",
            ioc_type=IOCType.IPV4,
            ioc_value="198.51.100.1",
            normalized_value="198.51.100.1",
            status=ThreatIntelStatus.SUSPICIOUS,
            confidence=0.8,
            source=ThreatIntelSource.OFFLINE_MOCK,
            provider_name="offline_mock",
        )
        assessment = ThreatAssessment(
            ioc_id="ioc-immut",
            ioc_type=IOCType.IPV4,
            ioc_value="198.51.100.1",
            normalized_value="198.51.100.1",
            threat_score=65.0,
            confidence=0.8,
            severity=ThreatSeverity.HIGH,
            status=ThreatIntelStatus.SUSPICIOUS,
        )

        # Snapshots
        ioc_dict_before = ioc.model_dump()
        anom_dict_before = anomaly.model_dump()
        inc_dict_before = incident.model_dump()
        result_dict_before = result.model_dump()
        assessment_dict_before = assessment.model_dump()

        _ = self.engine.correlate_ioc(ioc, threat_assessment=assessment)

        # Assert no modifications across all objects
        self.assertEqual(ioc.status, IOCStatus.EXTRACTED)
        self.assertEqual(ioc.model_dump(), ioc_dict_before)
        self.assertEqual(anomaly.model_dump(), anom_dict_before)
        self.assertEqual(incident.model_dump(), inc_dict_before)
        self.assertEqual(result.model_dump(), result_dict_before)
        self.assertEqual(assessment.model_dump(), assessment_dict_before)

    # ─────────────────────────────────────────────────────────────────────────
    # 7. UnifiedThreatContext Builder Tests
    # ─────────────────────────────────────────────────────────────────────────

    def test_full_pipeline_integration(self):
        """
        Verify end-to-end integration:
        IOC -> ThreatIntelResult -> ThreatAssessment -> Event -> Anomaly -> Incident -> Attack Chain -> UnifiedThreatContext
        """
        ev = IOCEvidence(
            event_id="evt-e2e",
            session_id=self.session_id_1,
            timestamp=self.base_time,
            raw_value="185.220.101.5",
            source_field="source_ip",
            line_number=101,
        )
        ioc = IOC(
            id="ioc-e2e",
            ioc_type=IOCType.IPV4,
            raw_value="185.220.101.5",
            normalized_value="185.220.101.5",
            status=IOCStatus.UNDER_REVIEW,
            evidence_references=[ev],
            source_sessions=[self.session_id_1],
        )
        self.ioc_repo.add_ioc(ioc)

        ti_result = ThreatIntelResult(
            ioc_id=ioc.id,
            ioc_type=IOCType.IPV4,
            ioc_value=ioc.raw_value,
            normalized_value=ioc.normalized_value,
            status=ThreatIntelStatus.MALICIOUS,
            confidence=0.91,
            detection_count=18,
            total_engines=20,
            reputation_score=0.94,
            source=ThreatIntelSource.OFFLINE_MOCK,
            provider_name="offline_mock",
        )

        assessment = ThreatAssessment(
            ioc_id=ioc.id,
            ioc_type=IOCType.IPV4,
            ioc_value=ioc.raw_value,
            normalized_value=ioc.normalized_value,
            threat_score=94.0,
            confidence=0.91,
            severity=ThreatSeverity.CRITICAL,
            status=ThreatIntelStatus.MALICIOUS,
        )

        anomaly = Anomaly(
            id="anom-e2e",
            session_id=self.session_id_1,
            log_entry_ids=["evt-e2e"],
            score=0.95,
            severity=SeverityLevel.CRITICAL,
            reason="Confirmed malicious ingress probe",
            method=DetectionMethod.RULE_BASED,
            detected_at=self.base_time,
        )
        self.store.anomalies[self.session_id_1] = [anomaly]

        incident = Incident(
            id="inc-e2e",
            anomaly_id="anom-e2e",
            session_id=self.session_id_1,
            category=IncidentCategory.MALWARE_INDICATOR,
            severity="CRITICAL",
            title="C2 Ingress Attempt",
            description="Connection attempt from known malicious IP",
            root_cause_hypothesis="Compromised external scanner",
            potential_impact="Unauthorized ingress",
            first_seen=self.base_time,
            last_seen=self.base_time,
            affected_ips=["185.220.101.5"],
            status=IncidentStatus.INVESTIGATING,
        )
        self.store.incidents[self.session_id_1] = [incident]

        chain = AttackChain(
            id="chain-e2e",
            session_id=self.session_id_1,
            title="Initial Access Campaign",
            summary="Port scan and exploitation probe",
            severity="CRITICAL",
            source_ips=["185.220.101.5"],
            associated_anomaly_ids=["anom-e2e"],
            associated_incident_ids=["inc-e2e"],
            event_ids=["evt-e2e"],
            stages_observed=[AttackStage.INITIAL_ACCESS],
            potential_impact="Host compromise",
            correlation_explanation="Linked by malicious IP",
        )
        self.store.attack_chains[self.session_id_1] = [chain]

        # Execute full context build
        ctx = self.engine.build_unified_context(
            ioc,
            threat_assessment=assessment,
            threat_intel_result=ti_result,
        )

        # Verify all elements unified
        self.assertEqual(ctx.ioc_id, ioc.id)
        self.assertEqual(ctx.threat_intel_result.status, ThreatIntelStatus.MALICIOUS)
        self.assertEqual(ctx.threat_assessment.threat_score, 94.0)
        self.assertEqual(ctx.threat_assessment.severity, ThreatSeverity.CRITICAL)
        self.assertEqual(len(ctx.related_events), 1)
        self.assertEqual(len(ctx.related_anomalies), 1)
        self.assertEqual(len(ctx.related_incidents), 1)
        self.assertEqual(len(ctx.related_attack_chains), 1)
        self.assertGreaterEqual(ctx.overall_correlation_confidence, 0.90)
        self.assertEqual(ctx.investigation_summary["highest_confidence_level"], "HIGH")

    def test_build_unified_context_aggregation(self):
        """Unified context consolidates all security relationships and summary metrics."""
        ev = IOCEvidence(
            event_id="evt-u1",
            session_id=self.session_id_1,
            timestamp=self.base_time,
            raw_value="198.51.100.77",
            source_field="raw_line",
            line_number=10,
        )
        ioc = IOC(
            id="ioc-unified",
            ioc_type=IOCType.IPV4,
            raw_value="198.51.100.77",
            normalized_value="198.51.100.77",
            status=IOCStatus.UNDER_REVIEW,
            evidence_references=[ev],
            source_sessions=[self.session_id_1],
        )
        self.ioc_repo.add_ioc(ioc)

        assessment = ThreatAssessment(
            ioc_id="ioc-unified",
            ioc_type=IOCType.IPV4,
            ioc_value="198.51.100.77",
            normalized_value="198.51.100.77",
            threat_score=75.0,
            confidence=0.85,
            severity=ThreatSeverity.HIGH,
            status=ThreatIntelStatus.SUSPICIOUS,
        )

        ctx = self.engine.build_unified_context(ioc, threat_assessment=assessment)

        self.assertEqual(ctx.ioc_id, "ioc-unified")
        self.assertEqual(ctx.analyst_status, IOCStatus.UNDER_REVIEW)
        self.assertEqual(len(ctx.related_events), 1)
        self.assertEqual(ctx.overall_correlation_confidence, 1.0)  # Event with line number has 1.0
        self.assertIn("investigation_summary", ctx.model_dump())
        self.assertEqual(ctx.investigation_summary["event_count"], 1)
        self.assertEqual(ctx.investigation_summary["highest_confidence_level"], "HIGH")


if __name__ == "__main__":
    unittest.main()
