"""
Unit and Integration Tests for MICHAEL – THE GUARDIAN AI Persistence Subsystem.

Phase 5.0 — Production Hardening & Persistence Integration.

Tests:
1. DatabaseManager initialization, pooling, and health probing.
2. Secret scrubbing in database URLs and error messages.
3. SQLStoreRepository CRUD across Sessions, Events, Anomalies, Incidents, Attack Chains.
4. SQLIOCRepository canonical deduplication and multi-index queries.
5. ThreatIntel and ThreatAssessment persistence.
6. Real Restart Persistence Test (Process Restart Simulation):
   - Write data to SQLite file
   - Dispose engine / simulate process termination
   - Reopen fresh repository on same SQLite file
   - Verify 100% data recovery without data loss.
7. Health and Readiness endpoint verification.
"""

from datetime import datetime, timezone
import gc
import os
import sys
import tempfile
import unittest

# Ensure backend root is on PYTHONPATH
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from fastapi.testclient import TestClient

from app.main import app
from app.models.anomaly import Anomaly, SeverityLevel
from app.models.attack_chain import AttackChain, ChainLinkEvent, ChainStatus
from app.models.incident import Incident, IncidentCategory, IncidentStatus
from app.models.ioc import IOC, IOCEvidence, IOCStatus, IOCType
from app.models.log_entry import LogEntry, LogSession
from app.models.threat_correlation import (
    CorrelationConfidence,
    CorrelationConfidenceLevel,
    ThreatCorrelation,
    ThreatCorrelationType,
)
from app.models.threat_intel import (
    ThreatAssessment,
    ThreatIntelResult,
    ThreatIntelSource,
    ThreatIntelStatus,
    ThreatSeverity,
)
from app.persistence.database import DatabaseManager, sanitize_db_url
from app.persistence.sql_store import SQLIOCRepository, SQLStoreRepository
from app.services.store import SessionStore
from app.services.ioc_repository import IOCRepository


class TestPersistenceSubsystem(unittest.TestCase):
    """Validation test suite for Phase 5.0 persistence architecture."""

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = os.path.join(self.temp_dir.name, "test_michael.db")
        self.db_url = f"sqlite:///{self.db_path}"
        self.db_manager = DatabaseManager(database_url=self.db_url)
        self.assertTrue(self.db_manager.init_db())
        self.store_repo = SQLStoreRepository(self.db_manager)
        self.ioc_repo = SQLIOCRepository(self.db_manager)

    def tearDown(self):
        self.db_manager.close()
        gc.collect()
        try:
            self.temp_dir.cleanup()
        except Exception:
            pass

    # ─────────────────────────────────────────────────────────────────────────
    # 1. Secret Scrubbing & Error Isolation
    # ─────────────────────────────────────────────────────────────────────────

    def test_sanitize_db_url_masks_passwords(self):
        """Verify database credentials and tokens are scrubbed from connection strings."""
        sample_urls = [
            ("postgresql://admin:super_secret_pw@db.supabase.co:5432/postgres",
             "postgresql://admin:******@db.supabase.co:5432/postgres"),
            ("postgres://soc_analyst:P%40ssw0rd!@10.0.0.5:5432/michael",
             "postgres://soc_analyst:******@10.0.0.5:5432/michael"),
            ("sqlite:///./data/michael.db",
             "sqlite:///./data/michael.db"),
        ]
        for raw, expected in sample_urls:
            scrubbed = sanitize_db_url(raw)
            self.assertEqual(scrubbed, expected)
            self.assertNotIn("super_secret_pw", scrubbed)
            self.assertNotIn("P%40ssw0rd!", scrubbed)

    def test_database_health_check_safe(self):
        """Verify health check returns valid telemetry without credentials."""
        health = self.db_manager.check_db_health()
        self.assertIn(health["status"], ("healthy", "ready"))
        self.assertNotIn("password", str(health).lower())

    # ─────────────────────────────────────────────────────────────────────────
    # 2. Session and Event Persistence CRUD
    # ─────────────────────────────────────────────────────────────────────────

    def test_session_and_events_crud(self):
        """Test persistence of LogSession and associated LogEntry items."""
        now = datetime.now(timezone.utc)
        session = LogSession(
            id="sess-persist-01",
            filename="auth.log",
            file_size=1024,
            total_lines=2,
            uploaded_at=now,
        )
        entries = [
            LogEntry(
                id="ev-01",
                session_id=session.id,
                timestamp=now,
                level="INFO",
                source="sshd",
                message="Accepted publickey for ubuntu from 192.168.1.100 port 44322 ssh2",
                raw_line="2026-11-07T03:00:00Z sshd[101]: Accepted publickey for ubuntu from 192.168.1.100 port 44322 ssh2",
                line_number=1,
            ),
            LogEntry(
                id="ev-02",
                session_id=session.id,
                timestamp=now,
                level="WARNING",
                source="sudo",
                message="ubuntu : user NOT in sudoers ; TTY=pts/0 ; COMMAND=/bin/bash",
                raw_line="2026-11-07T03:00:05Z sudo[102]: ubuntu : user NOT in sudoers ; TTY=pts/0 ; COMMAND=/bin/bash",
                line_number=2,
            ),
        ]

        self.store_repo.set_session(session, entries)

        # Retrieve and verify
        fetched_sess = self.store_repo.get_session("sess-persist-01")
        self.assertIsNotNone(fetched_sess)
        self.assertEqual(fetched_sess.filename, "auth.log")
        self.assertEqual(fetched_sess.total_lines, 2)

        fetched_entries = self.store_repo.get_entries("sess-persist-01")
        self.assertEqual(len(fetched_entries), 2)
        self.assertEqual(fetched_entries[0].id, "ev-01")
        self.assertEqual(fetched_entries[0].source, "sshd")
        self.assertEqual(fetched_entries[1].level, "WARNING")

    # ─────────────────────────────────────────────────────────────────────────
    # 3. Anomaly, Incident & Attack Chain Persistence
    # ─────────────────────────────────────────────────────────────────────────

    def test_incident_and_chain_persistence(self):
        """Test persistence of Incidents and AttackChains with relationships."""
        now = datetime.now(timezone.utc)
        session = LogSession(
            id="sess-persist-02",
            filename="incident_test.log",
            file_size=2048,
            total_lines=10,
            uploaded_at=now,
        )
        self.store_repo.set_session(session, [])

        incident = Incident(
            id="inc-persist-01",
            anomaly_id="anom-01",
            session_id=session.id,
            category=IncidentCategory.PRIVILEGE_ESCALATION,
            severity=SeverityLevel.HIGH,
            title="Unauthorized Privilege Escalation Attempt",
            description="Repeated sudo abuse observed from host ubuntu",
            root_cause_hypothesis="Compromised ssh credentials used to escalate privileges",
            potential_impact="Complete host compromise",
            remediation_steps=["Revoke active SSH keys", "Quarantine host"],
            first_seen=now,
            last_seen=now,
            status=IncidentStatus.OPEN,
        )
        self.store_repo.set_incidents(session.id, [incident])

        chain = AttackChain(
            id="chain-persist-01",
            session_id=session.id,
            title="Initial Access to Privilege Escalation",
            summary="Attacker authenticated via compromised key then attempted root execution",
            severity="HIGH",
            confidence_score=0.89,
            first_seen=now,
            last_seen=now,
            stages_observed=["Initial Access", "Privilege Escalation"],
            associated_incident_ids=["inc-persist-01"],
            events=[
                ChainLinkEvent(
                    event_id="ev-01",
                    stage="Initial Access",
                    source="sshd",
                    timestamp=now,
                    raw_log="Accepted publickey for ubuntu",
                    message="Accepted publickey for ubuntu",
                    correlation_reason="Observed authentication event matching chain sequence",
                )
            ],
            potential_impact="Full root administrative compromise of host",
            correlation_explanation="Sequential correlation of initial access followed by privilege escalation attempt",
            status=ChainStatus.NEW,
        )
        self.store_repo.set_attack_chains(session.id, [chain])

        # Verify retrieval
        incidents = self.store_repo.get_incidents(session.id)
        self.assertEqual(len(incidents), 1)
        self.assertEqual(incidents[0].id, "inc-persist-01")
        self.assertEqual(incidents[0].title, "Unauthorized Privilege Escalation Attempt")

        chains = self.store_repo.get_attack_chains(session.id)
        self.assertEqual(len(chains), 1)
        self.assertEqual(chains[0].id, "chain-persist-01")
        self.assertEqual(chains[0].stages_observed, ["Initial Access", "Privilege Escalation"])
        self.assertEqual(len(chains[0].events), 1)

    # ─────────────────────────────────────────────────────────────────────────
    # 4. IOC Repository Canonical Deduplication & Queries
    # ─────────────────────────────────────────────────────────────────────────

    def test_sql_ioc_repository_deduplication(self):
        """Test canonical deduplication when same IOC is observed across multiple events."""
        now = datetime.now(timezone.utc)
        ioc_a = IOC(
            id="ioc-01",
            ioc_type=IOCType.IPV4,
            raw_value="198.51.100.23",
            normalized_value="198.51.100.23",
            confidence=0.8,
            first_seen=now,
            last_seen=now,
            source_sessions=["sess-01"],
            occurrence_count=1,
            evidence_references=[
                IOCEvidence(
                    event_id="ev-101",
                    session_id="sess-01",
                    timestamp=now,
                    raw_value="198.51.100.23",
                    source_field="client_ip",
                    line_number=1,
                )
            ],
        )
        saved_a = self.ioc_repo.add_ioc(ioc_a)
        self.assertEqual(saved_a.occurrence_count, 1)

        # Re-observe same canonical IP from different session
        ioc_b = IOC(
            id="ioc-02",  # Different ID, but identical canonical identity
            ioc_type=IOCType.IPV4,
            raw_value="198.51.100.23",
            normalized_value="198.51.100.23",
            confidence=0.8,
            first_seen=now,
            last_seen=now,
            source_sessions=["sess-02"],
            occurrence_count=1,
            evidence_references=[
                IOCEvidence(
                    event_id="ev-202",
                    session_id="sess-02",
                    timestamp=now,
                    raw_value="198.51.100.23",
                    source_field="dest_ip",
                    line_number=5,
                )
            ],
        )
        saved_b = self.ioc_repo.add_ioc(ioc_b)

        # Must merge into original IOC entity
        self.assertEqual(saved_b.id, "ioc-01")
        self.assertEqual(saved_b.occurrence_count, 2)
        self.assertEqual(len(saved_b.evidence_references), 2)
        self.assertIn("sess-01", saved_b.source_sessions)
        self.assertIn("sess-02", saved_b.source_sessions)

        # Lookup by canonical value
        lookup = self.ioc_repo.get_ioc_by_normalized_value(IOCType.IPV4, "198.51.100.23")
        self.assertIsNotNone(lookup)
        self.assertEqual(lookup.id, "ioc-01")

        # Query by session
        sess1_iocs = self.ioc_repo.find_iocs_by_session("sess-01")
        self.assertEqual(len(sess1_iocs), 1)
        sess2_iocs = self.ioc_repo.find_iocs_by_session("sess-02")
        self.assertEqual(len(sess2_iocs), 1)

    # ─────────────────────────────────────────────────────────────────────────
    # 5. Threat Intelligence and Correlation Persistence
    # ─────────────────────────────────────────────────────────────────────────

    def test_threat_intel_and_correlation_persistence(self):
        """Test persisting ThreatIntelResult, ThreatAssessment, and ThreatCorrelation."""
        now = datetime.now(timezone.utc)
        result = ThreatIntelResult(
            ioc_id="ioc-intel-01",
            ioc_value="203.0.113.15",
            provider_name="virustotal",
            ioc_type=IOCType.IPV4,
            normalized_value="203.0.113.15",
            status=ThreatIntelStatus.MALICIOUS,
            reputation_score=0.85,
            confidence=0.90,
            detection_count=18,
            total_engines=70,
            categories=["c2", "trojan"],
            queried_at=now,
            expires_at=now,
            source=ThreatIntelSource.VIRUSTOTAL,
        )
        self.store_repo.save_threat_intel_result(result)

        fetched_intel = self.store_repo.get_threat_intel_result("virustotal", IOCType.IPV4, "203.0.113.15")
        self.assertIsNotNone(fetched_intel)
        self.assertEqual(fetched_intel.status, ThreatIntelStatus.MALICIOUS)
        self.assertEqual(fetched_intel.reputation_score, 0.85)

        conf = CorrelationConfidence(
            score=0.85,
            confidence_level=CorrelationConfidenceLevel.HIGH,
            evidence_count=2,
            correlation_method="DIRECT_MATCH",
            calculated_at=now,
        )
        correlation = ThreatCorrelation(
            correlation_id="corr-persist-01",
            correlation_type=ThreatCorrelationType.IOC_TO_INCIDENT,
            source_id="ioc-corr-01",
            source_type="ioc",
            target_id="inc-corr-01",
            target_type="incident",
            confidence=conf,
            evidence=["Shared forensic log evidence"],
            correlation_method="DIRECT_MATCH",
            confirmed=True,
            created_at=now,
        )
        self.store_repo.save_threat_correlation(correlation)

        corrs = self.store_repo.get_threat_correlations_for_ioc("ioc-corr-01")
        self.assertEqual(len(corrs), 1)
        self.assertEqual(corrs[0].correlation_id, "corr-persist-01")
        self.assertEqual(corrs[0].confidence.score, 0.85)

    # ─────────────────────────────────────────────────────────────────────────
    # 6. Real Restart Persistence Test (Process Restart Simulation)
    # ─────────────────────────────────────────────────────────────────────────

    def test_process_restart_data_survival(self):
        """
        Verify that data written to disk survives process restart.
        1. Write full platform state to SQLite database.
        2. Explicitly dispose engine (simulating SIGTERM / process shutdown).
        3. Instantiate entirely new DatabaseManager and repositories from scratch.
        4. Verify all records, relationships, and metadata survive without loss.
        """
        now = datetime.now(timezone.utc)
        sess_id = "sess-restart-verify"

        # 1. Write state
        session = LogSession(
            id=sess_id,
            filename="production_audit.log",
            file_size=4096,
            total_lines=1,
            uploaded_at=now,
        )
        entries = [
            LogEntry(
                id="ev-restart-01",
                session_id=sess_id,
                timestamp=now,
                level="CRITICAL",
                source="kernel",
                message="Out of memory: Kill process 891 (attack_payload)",
                raw_line="2026-11-07T03:10:00Z kernel: Out of memory: Kill process 891 (attack_payload)",
                line_number=1,
            )
        ]
        self.store_repo.set_session(session, entries)

        ioc = IOC(
            id="ioc-restart-01",
            ioc_type=IOCType.SHA256,
            raw_value="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            normalized_value="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            confidence=0.9,
            first_seen=now,
            last_seen=now,
            source_sessions=[sess_id],
            occurrence_count=1,
            evidence_references=[
                IOCEvidence(
                    event_id="ev-restart-01",
                    session_id=sess_id,
                    timestamp=now,
                    raw_value="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                    source_field="sha256",
                    line_number=1,
                )
            ],
        )
        self.ioc_repo.add_ioc(ioc)

        # 2. Simulate process shutdown by closing engine
        self.db_manager.close()
        gc.collect()

        # 3. Reinitialize fresh manager and repositories on existing database file
        restart_db = DatabaseManager(database_url=self.db_url)
        fresh_store = SQLStoreRepository(restart_db)
        fresh_ioc_repo = SQLIOCRepository(restart_db)

        # 4. Verify data survived restart
        reloaded_sess = fresh_store.get_session(sess_id)
        self.assertIsNotNone(reloaded_sess)
        self.assertEqual(reloaded_sess.filename, "production_audit.log")

        reloaded_entries = fresh_store.get_entries(sess_id)
        self.assertEqual(len(reloaded_entries), 1)
        self.assertEqual(reloaded_entries[0].id, "ev-restart-01")
        self.assertEqual(reloaded_entries[0].source, "kernel")

        reloaded_ioc = fresh_ioc_repo.get_ioc("ioc-restart-01")
        self.assertIsNotNone(reloaded_ioc)
        self.assertEqual(reloaded_ioc.ioc_type, IOCType.SHA256)
        self.assertEqual(reloaded_ioc.occurrence_count, 1)
        self.assertEqual(len(reloaded_ioc.evidence_references), 1)

        restart_db.close()
        gc.collect()


class TestHealthAndReadinessEndpoints(unittest.TestCase):
    """Verify health and readiness probes with safety guarantees."""

    def test_health_endpoint(self):
        """Verify /api/health returns operational status."""
        client = TestClient(app)
        resp = client.get("/api/health")
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertEqual(data.get("status"), "operational")
        self.assertEqual(data.get("app"), "alive")
        self.assertIn("MICHAEL", data.get("service", ""))

    def test_ready_endpoint(self):
        """Verify /api/ready returns dependency readiness without credentials."""
        client = TestClient(app)
        resp = client.get("/api/ready")
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertIn(data.get("status"), ("ready", "not_ready"))
        self.assertIn("persistence_backend", data)
        self.assertIn("threat_intel_provider", data)
        self.assertIn("timestamp", data)
        # Ensure zero credentials leaked
        data_str = str(data).lower()
        self.assertNotIn("password", data_str)
        self.assertNotIn("token", data_str)
        self.assertNotIn("secret", data_str)


if __name__ == "__main__":
    unittest.main()
