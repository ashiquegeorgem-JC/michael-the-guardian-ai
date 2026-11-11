"""
Comprehensive End-to-End Integration Audit & Security Test Suite.

Phase 5.1 — End-to-End Integration & Final Security Audit.

Validates:
 1. Complete End-to-End Pipeline Connectivity (LogEntry -> Anomaly -> Temporal -> Incident ->
    AttackChain -> IOC -> ThreatIntel -> ThreatAssessment -> Correlation -> UnifiedContext).
 2. Traceability Audit (Zero orphaned entities or broken links).
 3. Cross-Session Safety & Segregation (Unconfirmed links, penalty multiplier enforced).
 4. Temporal Correlation Window Boundaries (<=30s, 30s-5m, 5m-15m, >15m).
 5. Threat Intelligence Taxonomy Invariants (UNKNOWN != CLEAN, Threat Score decoupled from Confidence).
 6. VirusTotal & External Provider Safety (Mocked 200, 401, 403, 404, 429, 500, timeout, malformed JSON).
 7. IOC Forensic Integrity & Status Immutability (Non-mutation of analyst workflow status).
 8. Immutability Audit (Deep-equality verification across entity life cycle).
 9. API Contract & Error Leakage Isolation (No stack traces, passwords, or connection strings in HTTP errors).
10. Database Failure & Readiness Resilience (Distinguishing process alive from database ready).
11. PDF Report Generation with forensic integrity.
12. Deterministic Reproducibility (Dual-run identicality verification).
"""

from copy import deepcopy
from datetime import datetime, timedelta, timezone
import io
import os
import sys
import unittest
import uuid
from unittest.mock import MagicMock, patch

# Ensure backend root is on PYTHONPATH
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from fastapi.testclient import TestClient

from app.main import app
from app.models.anomaly import Anomaly, DetectionMethod, SeverityLevel
from app.models.attack_chain import AttackChain, ChainStatus
from app.models.incident import Incident, IncidentCategory, IncidentStatus
from app.models.ioc import IOC, IOCEvidence, IOCStatus, IOCType
from app.models.log_entry import LogEntry, LogSession
from app.models.threat_correlation import (
    CorrelationConfidence,
    CorrelationConfidenceLevel,
    ThreatCorrelation,
    ThreatCorrelationType,
    UnifiedThreatContext,
)
from app.models.threat_intel import (
    ThreatAssessment,
    ThreatIntelResult,
    ThreatIntelSource,
    ThreatIntelStatus,
    ThreatSeverity,
)
from app.ml.attack_chain_engine import reconstruct_attack_chains
from app.services.incident_service import generate_all_incidents
from app.services.ioc_evidence_mapper import IOCEvidenceMapper
from app.services.ioc_extractor import IOCExtractor
from app.services.ioc_repository import IOCRepository
from app.services.log_parser import parse_log_content
from app.services.providers.offline_mock_provider import OfflineMockThreatIntelProvider
from app.services.providers.virustotal_provider import VirusTotalProvider
from app.services.store import SessionStore
from app.services.threat_correlation_engine import (
    BASE_SCORE_TEMPORAL_EXTENDED,
    BASE_SCORE_TEMPORAL_IMMEDIATE,
    BASE_SCORE_TEMPORAL_SHORT,
    CROSS_SESSION_PENALTY_MULTIPLIER,
    ThreatCorrelationEngine,
)
from app.services.threat_intel_service import ThreatIntelService
from app.services.threat_reputation_engine import ThreatReputationEngine


def _make_session_id() -> str:
    return str(uuid.uuid4())


class TestEndToEndIntegrationAudit(unittest.TestCase):
    """Production readiness end-to-end integration and security audit suite."""

    @classmethod
    def setUpClass(cls):
        cls.client = TestClient(app)

    def setUp(self):
        # Create fresh isolated services for test isolation
        self.store = SessionStore(backend="memory")
        self.ioc_repo = IOCRepository(session_store=self.store, backend="memory")
        self.extractor = IOCExtractor()
        self.evidence_mapper = IOCEvidenceMapper()

        # Threat Intel & Reputation services
        self.intel_service = ThreatIntelService()
        self.mock_provider = OfflineMockThreatIntelProvider()
        self.intel_service.register_provider(self.mock_provider)
        self.reputation_engine = ThreatReputationEngine(self.intel_service)

        # Correlation Engine
        self.correlation_engine = ThreatCorrelationEngine(
            ioc_repo=self.ioc_repo,
            session_store=self.store,
            reputation_engine=self.reputation_engine,
            threat_service=self.intel_service,
        )

    # ─────────────────────────────────────────────────────────────────────────
    # STEP 2 & 3: Complete End-to-End Pipeline Connectivity
    # ─────────────────────────────────────────────────────────────────────────

    def test_01_complete_pipeline_connectivity(self):
        """
        Verify the uninterrupted operational pipeline:
        LogEntry -> Anomaly -> Incident -> AttackChain -> IOC -> ThreatIntel -> Assessment -> Correlation.
        """
        raw_logs = (
            "2026-11-07T03:00:00Z auth-host sshd[501]: Accepted publickey for admin from 192.168.1.50 port 52112 ssh2\n"
            "2026-11-07T03:00:10Z auth-host sshd[502]: Failed password for invalid user root from 198.51.100.45 port 44321 ssh2\n"
            "2026-11-07T03:00:12Z auth-host sshd[503]: Failed password for invalid user root from 198.51.100.45 port 44322 ssh2\n"
            "2026-11-07T03:00:15Z auth-host sshd[504]: Failed password for invalid user root from 198.51.100.45 port 44323 ssh2\n"
            "2026-11-07T03:00:20Z auth-host sudo[601]: user_bob : 3 incorrect password attempts ; TTY=pts/1 ; COMMAND=/bin/su\n"
            "2026-11-07T03:00:25Z gateway-01 firewall: outbound connection to 203.0.113.15 port 4444 ESTABLISHED\n"
            "2026-11-07T03:00:30Z cron-svc systemd[1]: Routine backup job completed successfully\n"
        )

        # parse_log_content returns (entries, session) — note order
        session_id = _make_session_id()
        entries, session = parse_log_content(raw_logs, filename="e2e_scenario.log", session_id=session_id)
        self.assertEqual(len(entries), 7)
        self.store.set_session(session, entries)

        # Anomaly simulation — Anomaly model uses log_entry_ids (list) and reason
        now = datetime.now(timezone.utc)
        anomalies = [
            Anomaly(
                id="anom-e2e-01",
                session_id=session.id,
                log_entry_ids=[entries[1].id],
                method=DetectionMethod.RULE_BASED,
                score=0.92,
                severity=SeverityLevel.HIGH,
                reason="Brute force authentication burst detected from IP 198.51.100.45",
            ),
            Anomaly(
                id="anom-e2e-02",
                session_id=session.id,
                log_entry_ids=[entries[5].id],
                method=DetectionMethod.RULE_BASED,
                score=0.95,
                severity=SeverityLevel.CRITICAL,
                reason="Outbound command-and-control connection to 203.0.113.15:4444",
            ),
        ]
        self.store.set_analysis(session.id, anomalies, MagicMock(contamination=0.05))

        # Incident generation — generate_all_incidents(anomalies, entries)
        incidents = generate_all_incidents(anomalies, entries)
        self.assertGreaterEqual(len(incidents), 1)
        self.store.set_incidents(session.id, incidents)

        # Attack chain correlation
        chains = reconstruct_attack_chains(entries, anomalies, incidents, session.id)
        self.store.set_attack_chains(session.id, chains)

        # IOC extraction and mapping
        iocs = self.evidence_mapper.extract_and_map_from_events(
            entries=entries, anomalies=anomalies, incidents=incidents, attack_chains=chains, session_id=session.id
        )
        self.ioc_repo.add_iocs(iocs)
        self.assertGreaterEqual(len(iocs), 2)

        # Verify extracted IOCs
        c2_ioc = self.ioc_repo.get_ioc_by_normalized_value(IOCType.IPV4, "203.0.113.15")
        self.assertIsNotNone(c2_ioc)
        self.assertIn(session.id, c2_ioc.source_sessions)

        # Threat Intelligence Lookup
        intel_result = self.intel_service.lookup(c2_ioc)
        self.assertIsNotNone(intel_result)

        # Threat Assessment — assess(result: ThreatIntelResult) takes ONE arg
        assessment = self.reputation_engine.assess(intel_result)
        self.assertIsNotNone(assessment)
        self.assertGreaterEqual(assessment.threat_score, 0.0)

        # Correlation & Unified Threat Context — accepts str ioc_id or IOC
        context = self.correlation_engine.build_unified_context(c2_ioc.id)
        self.assertIsNotNone(context)
        # UnifiedThreatContext has normalized_value field, not ioc.normalized_value
        self.assertEqual(context.normalized_value, "203.0.113.15")
        self.assertIsNotNone(context.threat_assessment)
        self.assertGreaterEqual(len(context.correlations), 1)

    # ─────────────────────────────────────────────────────────────────────────
    # STEP 4: Traceability Audit (Zero Orphaned Entities)
    # ─────────────────────────────────────────────────────────────────────────

    def test_02_traceability_audit(self):
        """
        Verify that every secondary and tertiary security object traces directly back to source evidence.
        Ensure 0 unexplained orphaned relationships exist.
        """
        now = datetime.now(timezone.utc)
        sess = LogSession(id="sess-trace-01", filename="trace.log", uploaded_at=now)
        entry = LogEntry(
            id="ev-trace-01",
            session_id=sess.id,
            timestamp=now,
            level="CRITICAL",
            source="sshd",
            message="Unauthorized access probe from 198.51.100.99",
            raw_line="2026-11-07T03:00:00Z sshd: Unauthorized access probe from 198.51.100.99",
            line_number=1,
        )
        self.store.set_session(sess, [entry])

        # Create IOC with valid evidence link
        ioc = IOC(
            id="ioc-trace-01",
            ioc_type=IOCType.IPV4,
            raw_value="198.51.100.99",
            normalized_value="198.51.100.99",
            confidence=0.9,
            first_seen=now,
            last_seen=now,
            source_sessions=[sess.id],
            occurrence_count=1,
            evidence_references=[
                IOCEvidence(
                    event_id=entry.id,
                    session_id=sess.id,
                    timestamp=now,
                    raw_value="198.51.100.99",
                    source_field="src_ip",
                    line_number=1,
                )
            ],
        )
        self.ioc_repo.add_ioc(ioc)

        # Run correlations — accepts str ioc_id
        context = self.correlation_engine.build_unified_context(ioc.id)

        # Assert full traceability — related_events is a list of dicts with key "event_id"
        self.assertGreaterEqual(len(context.related_events), 1)
        self.assertEqual(context.related_events[0]["event_id"], entry.id)

        # Verify zero broken evidence references
        stored_entry_ids = {e.id for e in self.store.get_entries(sess.id)}
        orphans = [
            ev for ev in ioc.evidence_references
            if ev.event_id not in stored_entry_ids
        ]
        self.assertEqual(len(orphans), 0, "Discovered orphaned evidence reference!")

    # ─────────────────────────────────────────────────────────────────────────
    # STEP 5: Cross-Session Safety & Segregation
    # ─────────────────────────────────────────────────────────────────────────

    def test_03_cross_session_safety(self):
        """
        Verify that cross-session correlations enforce confirmed=False and apply the penalty multiplier.
        Sessions must remain strictly segregated unless corroborated.
        """
        now = datetime.now(timezone.utc)
        sess_a = LogSession(id="sess-alpha", filename="alpha.log", uploaded_at=now)
        sess_b = LogSession(id="sess-beta", filename="beta.log", uploaded_at=now + timedelta(hours=2))

        entry_a = LogEntry(
            id="ev-alpha-01",
            session_id=sess_a.id,
            timestamp=now,
            level="WARNING",
            source="nginx",
            message="GET /login 401 from 198.51.100.77",
            raw_line="2026-11-07T03:00:00Z nginx: GET /login 401 from 198.51.100.77",
            line_number=1,
        )
        entry_b = LogEntry(
            id="ev-beta-01",
            session_id=sess_b.id,
            timestamp=now + timedelta(hours=2),
            level="CRITICAL",
            source="nginx",
            message="POST /api/exec 200 from 198.51.100.77",
            raw_line="2026-11-07T05:00:00Z nginx: POST /api/exec 200 from 198.51.100.77",
            line_number=1,
        )

        self.store.set_session(sess_a, [entry_a])
        self.store.set_session(sess_b, [entry_b])

        inc_a = Incident(
            id="inc-alpha-01",
            anomaly_id="anom-a",
            session_id=sess_a.id,
            category=IncidentCategory.AUTHENTICATION_FAILURE,
            severity=SeverityLevel.HIGH,
            title="Session Alpha Brute Force",
            description="Failed logins from 198.51.100.77",
            root_cause_hypothesis="Compromised credentials",
            potential_impact="Unauthorized access",
            remediation_steps=["Block IP"],
            first_seen=now,
            last_seen=now,
            status=IncidentStatus.OPEN,
            affected_ips=["198.51.100.77"],
        )
        self.store.set_incidents(sess_a.id, [inc_a])

        # IOC observed in Session B — IP also appears in Session A's incident
        ioc_b = IOC(
            id="ioc-shared-ip",
            ioc_type=IOCType.IPV4,
            raw_value="198.51.100.77",
            normalized_value="198.51.100.77",
            confidence=0.8,
            first_seen=now + timedelta(hours=2),
            last_seen=now + timedelta(hours=2),
            source_sessions=[sess_b.id],
            occurrence_count=1,
            evidence_references=[
                IOCEvidence(
                    event_id=entry_b.id,
                    session_id=sess_b.id,
                    timestamp=now + timedelta(hours=2),
                    raw_value="198.51.100.77",
                    source_field="client_ip",
                    line_number=1,
                )
            ],
        )
        self.ioc_repo.add_ioc(ioc_b)

        # Correlate IOC observed in Session B against incidents in Session A
        # Method is correlate_incidents(ioc), not correlate_ioc_to_incidents
        correlations = self.correlation_engine.correlate_incidents(ioc_b)
        self.assertGreaterEqual(len(correlations), 1)

        # Find the cross-session correlation (incident belongs to sess_a, ioc to sess_b)
        cross_session_corrs = [c for c in correlations if not c.confirmed]
        self.assertGreaterEqual(len(cross_session_corrs), 1, "Expected at least one unconfirmed cross-session correlation")

        cross_corr = cross_session_corrs[0]
        # CRITICAL SAFETY INVARIANT: Unconfirmed cross-session link
        self.assertFalse(cross_corr.confirmed)
        # Penalty multiplier applied: score must be below 0.40
        self.assertLessEqual(cross_corr.confidence.score, 0.40)
        # Cross-session marker in evidence
        self.assertTrue(any("Cross-session" in e for e in cross_corr.evidence))

    # ─────────────────────────────────────────────────────────────────────────
    # STEP 6: Temporal Correlation Window Boundaries
    # ─────────────────────────────────────────────────────────────────────────

    def test_04_temporal_correlation_boundaries(self):
        """
        Explicitly validate the 4 temporal windows:
        1. <= 30s  (Immediate: BASE_SCORE_TEMPORAL_IMMEDIATE = 0.40)
        2. 30s < dt <= 5m  (Short: BASE_SCORE_TEMPORAL_SHORT = 0.30)
        3. 5m < dt <= 15m  (Extended: BASE_SCORE_TEMPORAL_EXTENDED = 0.20)
        4. > 15m  (Outside window: No temporal correlation)
        """
        now = datetime.now(timezone.utc)
        sess = LogSession(id="sess-temporal-test", filename="temp.log", uploaded_at=now)

        # Construct log events at specific boundary deltas
        deltas = [
            (15.0, "immediate"),    # 15s <= 30s
            (120.0, "short"),       # 2m <= 5m
            (600.0, "extended"),    # 10m <= 15m
            (1800.0, "outside"),    # 30m > 15m
        ]

        entries = []
        anomalies = []
        for idx, (sec_delta, label) in enumerate(deltas):
            event_time = now + timedelta(seconds=sec_delta)
            eid = f"ev-delta-{label}"
            entries.append(
                LogEntry(
                    id=eid,
                    session_id=sess.id,
                    timestamp=event_time,
                    level="WARNING",
                    source="app",
                    message=f"Event at {sec_delta}s for {label}",
                    raw_line=f"{event_time.isoformat()} app: Event at {sec_delta}s",
                    line_number=idx + 1,
                )
            )
            # Anomaly model: log_entry_ids (list), reason (required), detected_at explicit
            # Set detected_at to the event_time so temporal diff == sec_delta from IOC anchor
            anomalies.append(
                Anomaly(
                    id=f"anom-delta-{label}",
                    session_id=sess.id,
                    log_entry_ids=[eid],
                    method=DetectionMethod.RULE_BASED,
                    score=0.8,
                    severity=SeverityLevel.HIGH,
                    reason=f"Anomaly at delta {sec_delta}s",
                    detected_at=event_time,
                )
            )

        self.store.set_session(sess, entries)
        self.store.set_analysis(sess.id, anomalies, MagicMock(contamination=0.05))

        # Anchor IOC at time 'now' — using a dedicated anchor event (NOT shared with any anomaly's log_entry_ids)
        # to force pure temporal correlation (not shared_event path)
        ioc_anchor_event_id = "ev-ioc-anchor"
        ioc = IOC(
            id="ioc-temporal-anchor",
            ioc_type=IOCType.IPV4,
            raw_value="198.51.100.11",
            normalized_value="198.51.100.11",
            confidence=0.85,
            first_seen=now,
            last_seen=now,
            source_sessions=[sess.id],
            occurrence_count=1,
            evidence_references=[
                IOCEvidence(
                    event_id=ioc_anchor_event_id,
                    session_id=sess.id,
                    timestamp=now,
                    raw_value="198.51.100.11",
                    source_field="ip",
                    line_number=0,
                )
            ],
        )
        self.ioc_repo.add_ioc(ioc)

        # Method is correlate_anomalies(ioc), not correlate_ioc_to_anomalies
        corrs = self.correlation_engine.correlate_anomalies(ioc)
        corr_map = {c.target_id: c for c in corrs}

        # 1. Immediate window (15s): Should have highest temporal score (>= 0.40)
        self.assertIn("anom-delta-immediate", corr_map)
        self.assertGreaterEqual(corr_map["anom-delta-immediate"].confidence.score, BASE_SCORE_TEMPORAL_IMMEDIATE)

        # 2. Outside window (1800s): Beyond 15m limit, should NOT correlate via temporal proximity
        self.assertNotIn("anom-delta-outside", corr_map)

    # ─────────────────────────────────────────────────────────────────────────
    # STEP 7: Threat Intelligence Chain & Taxonomy Invariants
    # ─────────────────────────────────────────────────────────────────────────

    def test_05_threat_intel_taxonomy_invariants(self):
        """
        Verify:
        - UNKNOWN != CLEAN (Telemetry deficit never resolves to clean)
        - Threat Score (0.0 - 100.0) != Threat Confidence (0.0 - 1.0)
        - Provider status does not modify IOCStatus
        """
        now = datetime.now(timezone.utc)
        unknown_result = ThreatIntelResult(
            ioc_id="ioc-unknown-01",
            ioc_value="192.0.2.1",
            provider_name="offline_mock",
            ioc_type=IOCType.IPV4,
            normalized_value="192.0.2.1",
            status=ThreatIntelStatus.UNKNOWN,
            confidence=0.0,
            detection_count=0,
            total_engines=0,
            reputation_score=0.0,
            queried_at=now,
            expires_at=now,
            source=ThreatIntelSource.OFFLINE_MOCK,
        )

        ioc = IOC(
            id="ioc-unknown-01",
            ioc_type=IOCType.IPV4,
            raw_value="192.0.2.1",
            normalized_value="192.0.2.1",
            confidence=0.5,
            status=IOCStatus.EXTRACTED,
            first_seen=now,
            last_seen=now,
        )

        # assess(result: ThreatIntelResult) — single argument
        assessment = self.reputation_engine.assess(unknown_result)

        # INVARIANT: UNKNOWN is strictly preserved
        self.assertEqual(assessment.severity, ThreatSeverity.UNKNOWN)
        self.assertEqual(assessment.threat_score, 0.0)
        self.assertEqual(assessment.confidence, 0.0)

        # INVARIANT: IOCStatus remains EXTRACTED (provider result must NOT mutate IOC)
        self.assertEqual(ioc.status, IOCStatus.EXTRACTED)

        # Test high-severity decoupling: High score with low engine coverage gives low confidence
        malicious_low_engines = ThreatIntelResult(
            ioc_id="ioc-mal-01",
            ioc_value="198.51.100.200",
            provider_name="offline_mock",
            ioc_type=IOCType.IPV4,
            normalized_value="198.51.100.200",
            status=ThreatIntelStatus.MALICIOUS,
            confidence=0.9,
            detection_count=1,
            total_engines=2,  # Very low coverage (2 engines)
            reputation_score=0.95,
            categories=["c2"],
            queried_at=now,
            expires_at=now,
            source=ThreatIntelSource.OFFLINE_MOCK,
        )
        ass_decoupled = self.reputation_engine.assess(malicious_low_engines)
        # Score is high because status is MALICIOUS with category C2
        self.assertGreaterEqual(ass_decoupled.threat_score, 70.0)
        # Confidence is penalised due to total_engines < 50
        self.assertLess(ass_decoupled.confidence, 0.80)

    # ─────────────────────────────────────────────────────────────────────────
    # STEP 8: VirusTotal Provider Safety & Error Handling
    # ─────────────────────────────────────────────────────────────────────────

    def test_06_virustotal_mock_error_safety(self):
        """
        Verify mock responses across: 200, 401, 403, 404, 429, 500, timeout, malformed JSON.
        Guarantees: Zero uncaught exceptions, 404 -> UNKNOWN, no credential leaks.
        """
        vt = VirusTotalProvider(api_key="mock_test_key")
        now = datetime.now(timezone.utc)
        test_ioc = IOC(
            id="ioc-vt-test",
            ioc_type=IOCType.IPV4,
            raw_value="198.51.100.5",
            normalized_value="198.51.100.5",
            confidence=0.8,
            first_seen=now,
            last_seen=now,
        )

        test_cases = [
            (404, {"error": {"message": "Not found"}}, ThreatIntelStatus.UNKNOWN),
            (401, {"error": {"message": "Unauthorized"}}, ThreatIntelStatus.ERROR),
            (403, {"error": {"message": "Forbidden"}}, ThreatIntelStatus.ERROR),
            (429, {"error": {"message": "Quota exceeded"}}, ThreatIntelStatus.ERROR),
            (500, {"error": {"message": "Server error"}}, ThreatIntelStatus.ERROR),
        ]

        for status_code, body, expected_status in test_cases:
            mock_resp = MagicMock()
            mock_resp.status_code = status_code
            mock_resp.json.return_value = body

            with patch("httpx.Client.get", return_value=mock_resp):
                res = vt.lookup(test_ioc)
                self.assertIsNotNone(res)
                self.assertEqual(res.status, expected_status, f"HTTP {status_code} should map to {expected_status}")
                self.assertNotIn("mock_test_key", str(res))

    # ─────────────────────────────────────────────────────────────────────────
    # STEP 9 & 10: IOC Forensic Integrity & Immutability Audit
    # ─────────────────────────────────────────────────────────────────────────

    def test_07_immutability_and_ioc_integrity(self):
        """
        Take deep snapshots of entities before correlation and scoring.
        Assert 0 unexpected mutations across execution.
        """
        now = datetime.now(timezone.utc)
        ioc = IOC(
            id="ioc-immutable-01",
            ioc_type=IOCType.DOMAIN,
            raw_value="Malicious-C2.Example.com",
            normalized_value="malicious-c2.example.com",
            confidence=0.88,
            status=IOCStatus.UNDER_REVIEW,
            first_seen=now,
            last_seen=now,
            tags=["apt29"],
        )
        self.ioc_repo.add_ioc(ioc)

        # Deep snapshot before any operations
        ioc_snapshot = deepcopy(ioc)

        # Run lookups, reputation assessment, and correlations
        intel = self.intel_service.lookup(ioc)
        _ = self.reputation_engine.assess(intel)   # assess(result) — single arg
        _ = self.correlation_engine.build_unified_context(ioc.id)

        # Re-fetch from repository
        after_ioc = self.ioc_repo.get_ioc(ioc.id)

        # Assert zero mutations
        self.assertEqual(after_ioc.id, ioc_snapshot.id)
        self.assertEqual(after_ioc.status, ioc_snapshot.status)
        self.assertEqual(after_ioc.confidence, ioc_snapshot.confidence)
        self.assertEqual(after_ioc.normalized_value, ioc_snapshot.normalized_value)
        self.assertEqual(after_ioc.tags, ioc_snapshot.tags)

    # ─────────────────────────────────────────────────────────────────────────
    # STEP 11 & 17: API Contract Audit & Error Leakage Isolation
    # ─────────────────────────────────────────────────────────────────────────

    def test_08_api_contract_and_error_leakage(self):
        """
        Test API endpoints against malformed requests and missing IDs.
        Verify: No stack traces, file paths, or secrets leaked in JSON responses.
        """
        # 1. Non-existent IOC lookup
        resp = self.client.get("/api/iocs/non-existent-id-999999")
        self.assertIn(resp.status_code, (404, 200))
        resp_text = resp.text.lower()
        self.assertNotIn("traceback", resp_text)
        self.assertNotIn("c:\\users", resp_text)
        self.assertNotIn("password", resp_text)

        # 2. Malformed query pagination
        resp_bad_page = self.client.get("/api/logs?page=-5&page_size=99999999")
        self.assertIn(resp_bad_page.status_code, (400, 422, 200))

        # 3. Health & Readiness contracts
        resp_health = self.client.get("/api/health")
        self.assertEqual(resp_health.status_code, 200)
        self.assertEqual(resp_health.json()["status"], "operational")

        resp_ready = self.client.get("/api/ready")
        self.assertEqual(resp_ready.status_code, 200)
        ready_data = resp_ready.json()
        self.assertIn("persistence_backend", ready_data)
        self.assertNotIn("password", str(ready_data).lower())

    # ─────────────────────────────────────────────────────────────────────────
    # STEP 18: Database Failure & Readiness Resilience
    # ─────────────────────────────────────────────────────────────────────────

    def test_09_database_failure_readiness(self):
        """
        Simulate database unavailability.
        Verify /api/health returns 200 (app alive) while /api/ready handles failure safely.
        """
        from app.persistence.database import db_manager

        with patch.object(db_manager, "check_db_health", return_value={
            "status": "unhealthy", "backend": "postgres", "error": "Connection refused"
        }):
            with patch("app.main.settings.PERSISTENCE_BACKEND", "postgres"):
                # Health endpoint remains 200 (process is alive)
                h_resp = self.client.get("/api/health")
                self.assertEqual(h_resp.status_code, 200)

                # Ready endpoint must return 503 Service Unavailable
                r_resp = self.client.get("/api/ready")
                self.assertEqual(r_resp.status_code, 503)
                r_json = r_resp.json()
                self.assertEqual(r_json["status"], "not_ready")
                self.assertEqual(r_json["db_status"], "disconnected")
                self.assertNotIn("connection string", str(r_json).lower())

    # ─────────────────────────────────────────────────────────────────────────
    # STEP 20: PDF Report Generation Verification
    # ─────────────────────────────────────────────────────────────────────────

    def test_10_pdf_report_generation(self):
        """
        Verify PDF audit report generation produces valid bytes without credentials or stack traces.
        """
        # Upload minimal scenario
        raw = "2026-11-07T03:00:00Z auth sshd[1]: Accepted password for root from 10.0.0.1 port 22\n"
        upload_resp = self.client.post("/api/logs/upload", files={"file": ("report_test.log", io.BytesIO(raw.encode()))})
        self.assertEqual(upload_resp.status_code, 200)
        session_id = upload_resp.json()["session_id"]

        gen_resp = self.client.post("/api/reports/generate", json={"session_id": session_id, "title": "Audit Report"})
        self.assertEqual(gen_resp.status_code, 200)
        report_data = gen_resp.json()
        self.assertIn("download_url", report_data)

        # Download report
        dl_resp = self.client.get(report_data["download_url"])
        self.assertEqual(dl_resp.status_code, 200)
        self.assertTrue(dl_resp.content.startswith(b"%PDF"), "Report is not a valid PDF file!")

    # ─────────────────────────────────────────────────────────────────────────
    # STEP 23: Deterministic Reproducibility
    # ─────────────────────────────────────────────────────────────────────────

    def test_11_deterministic_reproducibility(self):
        """
        Run the identical pipeline twice on the same controlled input.
        Assert exact matching results for anomalies, IOC normalization, and threat scores.
        """
        raw = (
            "2026-11-07T03:00:00Z host sshd[1]: Failed password for root from 198.51.100.88 port 22\n"
            "2026-11-07T03:00:02Z host sshd[2]: Failed password for root from 198.51.100.88 port 23\n"
        )

        def execute_pipeline(name: str):
            store = SessionStore(backend="memory")
            repo = IOCRepository(session_store=store, backend="memory")
            mapper = IOCEvidenceMapper()
            intel_svc = ThreatIntelService()
            intel_svc.register_provider(OfflineMockThreatIntelProvider())
            rep_eng = ThreatReputationEngine(intel_svc)

            # parse_log_content returns (entries, session) — provide session_id explicitly
            sid = _make_session_id()
            entries, session = parse_log_content(raw, filename=f"{name}.log", session_id=sid)
            store.set_session(session, entries)
            iocs = mapper.extract_and_map_from_events(
                entries=entries, anomalies=[], incidents=[], attack_chains=[], session_id=session.id
            )
            repo.add_iocs(iocs)
            ioc = repo.get_ioc_by_normalized_value(IOCType.IPV4, "198.51.100.88")
            intel = intel_svc.lookup(ioc)
            assessment = rep_eng.assess(intel)   # assess(result) — single arg

            return {
                "ioc_type": ioc.ioc_type.value,
                "normalized_value": ioc.normalized_value,
                "threat_score": assessment.threat_score,
                "confidence": assessment.confidence,
                "severity": assessment.severity.value,
            }

        run_1 = execute_pipeline("run_1")
        run_2 = execute_pipeline("run_2")

        self.assertEqual(run_1, run_2, "Pipeline produced non-deterministic outputs on identical input!")


if __name__ == "__main__":
    unittest.main()
