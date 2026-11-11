"""
Unit & Integration Test Suite for Attack Chain Reconstruction (Phase 4.1).
Tests:
1. Multi-event attack correlation across MITRE stages.
2. Anti-false-correlation (unrelated events sharing IP outside window / disjoint activity).
3. Missing timestamps handling (fallback to line numbers, no crash).
4. Duplicate events deduplication.
5. Out-of-order events sorting.
6. Multiple concurrent attack chains separation.
7. Correct stage attribution (e.g., brute force -> Credential Attack, sudo -> Priv Esc).
8. Evidence traceability (line numbers, raw lines preserved).
9. Attack graph generation (nodes, directed edges, entities).
10. API integration (/api/attack-chains, /{id}, /{id}/timeline, /{id}/graph, Copilot).
"""

import os
import sys
import unittest
from datetime import datetime, timedelta
import uuid

# Ensure backend root is on PYTHONPATH
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from fastapi.testclient import TestClient
from app.main import app
from app.services.store import store
from app.models.log_entry import LogEntry, LogLevel, LogSession
from app.models.anomaly import Anomaly, SeverityLevel, DetectionMethod
from app.models.incident import Incident, IncidentCategory, IncidentStatus
from app.models.attack_chain import AttackStage, AttackChain, ChainStatus
from app.ml.attack_chain_engine import AttackChainEngine, reconstruct_attack_chains
from app.services.copilot_service import CopilotService


class TestAttackChainReconstruction(unittest.TestCase):

    def setUp(self):
        self.session_id = f"test-sess-{uuid.uuid4().hex[:8]}"
        self.engine = AttackChainEngine(correlation_window_minutes=30)
        self.client = TestClient(app)

    def test_01_multi_event_attack_correlation(self):
        """Verify correlation of multi-stage progression: Recon -> Initial Access -> Credential -> Priv Esc -> Exfiltration."""
        base_time = datetime(2026, 11, 3, 10, 0, 0)
        logs = [
            LogEntry(
                id="log-1", session_id=self.session_id, line_number=1,
                timestamp=base_time, level=LogLevel.WARNING, source="nginx",
                message="Port scan detected from 198.51.100.42 probing paths",
                raw_line="2026-11-03 10:00:00 [WARN] Port scan detected from 198.51.100.42 probing paths"
            ),
            LogEntry(
                id="log-2", session_id=self.session_id, line_number=2,
                timestamp=base_time + timedelta(minutes=5), level=LogLevel.ERROR, source="nginx",
                message="SQL Injection detected: UNION SELECT from 198.51.100.42 targeting 10.0.0.5",
                raw_line="2026-11-03 10:05:00 [ERROR] SQL Injection detected: UNION SELECT from 198.51.100.42 targeting 10.0.0.5"
            ),
            LogEntry(
                id="log-3", session_id=self.session_id, line_number=3,
                timestamp=base_time + timedelta(minutes=10), level=LogLevel.ERROR, source="sshd",
                message="Failed password for user admin from 198.51.100.42 ssh2",
                raw_line="2026-11-03 10:10:00 [ERROR] Failed password for user admin from 198.51.100.42 ssh2"
            ),
            LogEntry(
                id="log-4", session_id=self.session_id, line_number=4,
                timestamp=base_time + timedelta(minutes=15), level=LogLevel.CRITICAL, source="sudo",
                message="user admin: sudo: root session opened executing /bin/bash",
                raw_line="2026-11-03 10:15:00 [CRITICAL] user admin: sudo: root session opened executing /bin/bash"
            ),
            LogEntry(
                id="log-5", session_id=self.session_id, line_number=5,
                timestamp=base_time + timedelta(minutes=22), level=LogLevel.CRITICAL, source="network",
                message="Massive outbound data transfer exfiltrat 2.4GB from 10.0.0.5 to 198.51.100.42",
                raw_line="2026-11-03 10:22:00 [CRITICAL] Massive outbound data transfer exfiltrat 2.4GB from 10.0.0.5 to 198.51.100.42"
            ),
        ]

        chains = self.engine.correlate(logs, [], [], self.session_id)
        self.assertEqual(len(chains), 1, "Should correlate into a single unified attack chain")
        chain = chains[0]
        self.assertEqual(chain.severity, "CRITICAL")
        self.assertIn(AttackStage.RECONNAISSANCE, chain.stages_observed)
        self.assertIn(AttackStage.INITIAL_ACCESS, chain.stages_observed)
        self.assertIn(AttackStage.CREDENTIAL_ATTACK, chain.stages_observed)
        self.assertIn(AttackStage.PRIVILEGE_ESCALATION, chain.stages_observed)
        self.assertIn(AttackStage.EXFILTRATION, chain.stages_observed)
        self.assertEqual(len(chain.events), 5)
        self.assertIn("198.51.100.42", chain.source_ips)

    def test_02_unrelated_events_sharing_ip(self):
        """Events sharing an IP but separated by 8 hours (outside 30m window) should NOT be merged."""
        base_time = datetime(2026, 11, 3, 2, 0, 0)
        logs = [
            LogEntry(
                id="log-a1", session_id=self.session_id, line_number=10,
                timestamp=base_time, level=LogLevel.ERROR, source="sshd",
                message="Failed password for user guest from 203.0.113.88",
                raw_line="2026-11-03 02:00:00 Failed password for user guest from 203.0.113.88"
            ),
            LogEntry(
                id="log-a2", session_id=self.session_id, line_number=11,
                timestamp=base_time + timedelta(minutes=2), level=LogLevel.ERROR, source="sshd",
                message="Hydra brute force attempt from 203.0.113.88",
                raw_line="2026-11-03 02:02:00 Hydra brute force attempt from 203.0.113.88"
            ),
            # Completely separate incident 10 hours later
            LogEntry(
                id="log-b1", session_id=self.session_id, line_number=100,
                timestamp=base_time + timedelta(hours=10), level=LogLevel.ERROR, source="nginx",
                message="SQL Injection detected: union select from 203.0.113.88",
                raw_line="2026-11-03 12:00:00 SQL Injection detected: union select from 203.0.113.88"
            ),
        ]

        chains = self.engine.correlate(logs, [], [], self.session_id)
        # Must be separated into 2 distinct chains due to correlation window expiry
        self.assertEqual(len(chains), 2, "Events > 30 minutes apart must not be falsely merged into 1 chain")

    def test_03_missing_timestamps(self):
        """Gracefully handle log entries with None timestamp without exceptions."""
        logs = [
            LogEntry(
                id="log-notime-1", session_id=self.session_id, line_number=5,
                timestamp=None, level=LogLevel.ERROR, source="sshd",
                message="Invalid user admin from 10.10.10.10 hydra brute force",
                raw_line="Invalid user admin from 10.10.10.10 hydra brute force"
            ),
            LogEntry(
                id="log-notime-2", session_id=self.session_id, line_number=6,
                timestamp=None, level=LogLevel.CRITICAL, source="sudo",
                message="user admin: sudo: root privilege escalation",
                raw_line="user admin: sudo: root privilege escalation"
            ),
        ]

        chains = self.engine.correlate(logs, [], [], self.session_id)
        self.assertGreaterEqual(len(chains), 1)
        self.assertIsNone(chains[0].first_seen)
        self.assertEqual(chains[0].events[0].line_number, 5)

    def test_04_duplicate_events(self):
        """Ensure duplicate log entries do not create duplicate events or inflate chains."""
        base_time = datetime(2026, 11, 3, 14, 0, 0)
        entry = LogEntry(
            id="dup-log-1", session_id=self.session_id, line_number=1,
            timestamp=base_time, level=LogLevel.ERROR, source="auth",
            message="Hydra brute force from 192.168.1.100 user root",
            raw_line="2026-11-03 14:00:00 Hydra brute force from 192.168.1.100 user root"
        )
        logs = [entry, entry, entry]  # 3 duplicates

        chains = self.engine.correlate(logs, [], [], self.session_id)
        self.assertEqual(len(chains), 1)
        self.assertEqual(len(chains[0].events), 1, "Duplicate log entries must be deduplicated")

    def test_05_out_of_order_events(self):
        """Reconstruct true chronological sequence even if ingested out of order."""
        t1 = datetime(2026, 11, 3, 8, 0, 0)
        t2 = datetime(2026, 11, 3, 8, 10, 0)
        t3 = datetime(2026, 11, 3, 8, 20, 0)

        e3 = LogEntry(
            id="e3", session_id=self.session_id, line_number=30,
            timestamp=t3, level=LogLevel.CRITICAL, source="app",
            message="user bob sudo privilege escalation from 10.0.0.99",
            raw_line="2026-11-03 08:20:00 user bob sudo privilege escalation from 10.0.0.99"
        )
        e1 = LogEntry(
            id="e1", session_id=self.session_id, line_number=10,
            timestamp=t1, level=LogLevel.WARNING, source="app",
            message="Port scan probing paths from 10.0.0.99",
            raw_line="2026-11-03 08:00:00 Port scan probing paths from 10.0.0.99"
        )
        e2 = LogEntry(
            id="e2", session_id=self.session_id, line_number=20,
            timestamp=t2, level=LogLevel.ERROR, source="app",
            message="Failed login password for user bob from 10.0.0.99",
            raw_line="2026-11-03 08:10:00 Failed login password for user bob from 10.0.0.99"
        )

        # Ingest in scrambled order: e3, e1, e2
        chains = self.engine.correlate([e3, e1, e2], [], [], self.session_id)
        self.assertEqual(len(chains), 1)
        ordered_stages = [ev.stage for ev in chains[0].events]
        self.assertEqual(ordered_stages, [AttackStage.RECONNAISSANCE, AttackStage.CREDENTIAL_ATTACK, AttackStage.PRIVILEGE_ESCALATION])

    def test_06_multiple_concurrent_attack_chains(self):
        """Two concurrent attacks by different actors targeting different vectors should yield 2 separate chains."""
        t = datetime(2026, 11, 3, 9, 0, 0)
        # Attacker 1: 1.1.1.1 running SQLi & exfiltration
        a1_logs = [
            LogEntry(id="a1", session_id=self.session_id, line_number=1, timestamp=t, level=LogLevel.ERROR,
                     message="SQL injection union select from 1.1.1.1", raw_line="SQL injection union select from 1.1.1.1"),
            LogEntry(id="a2", session_id=self.session_id, line_number=2, timestamp=t + timedelta(minutes=2), level=LogLevel.CRITICAL,
                     message="exfiltrat database dump from 1.1.1.1", raw_line="exfiltrat database dump from 1.1.1.1"),
        ]
        # Attacker 2: 2.2.2.2 running SSH brute-force & sudo priv esc
        a2_logs = [
            LogEntry(id="b1", session_id=self.session_id, line_number=3, timestamp=t + timedelta(minutes=1), level=LogLevel.ERROR,
                     message="Failed password for user alice from 2.2.2.2", raw_line="Failed password for user alice from 2.2.2.2"),
            LogEntry(id="b2", session_id=self.session_id, line_number=4, timestamp=t + timedelta(minutes=3), level=LogLevel.CRITICAL,
                     message="user alice: sudo: root privilege escalation", raw_line="user alice: sudo: root privilege escalation"),
        ]

        all_logs = a1_logs + a2_logs
        chains = self.engine.correlate(all_logs, [], [], self.session_id)
        self.assertEqual(len(chains), 2, "Concurrent distinct attackers must form separate attack chains")
        chain_ips = {tuple(c.source_ips) for c in chains}
        self.assertIn(("1.1.1.1",), chain_ips)
        self.assertIn(("2.2.2.2",), chain_ips)

    def test_07_stage_attribution_accuracy(self):
        """Ensure correct MITRE attack stage mapping without hallucinations."""
        test_cases = [
            ("nmap port scan banner grab from 1.2.3.4", AttackStage.RECONNAISSANCE),
            ("CVE-2021-44228 log4j remote code execution from 1.2.3.4", AttackStage.INITIAL_ACCESS),
            ("Hydra brute force password spraying on user admin", AttackStage.CREDENTIAL_ATTACK),
            ("sudo: root privilege escalation setuid exploit", AttackStage.PRIVILEGE_ESCALATION),
            ("/bin/sh -i reverse shell spawn process", AttackStage.EXECUTION),
            ("authorized_keys backdoor account added crontab persistence", AttackStage.PERSISTENCE),
            ("c2 beaconing meterpreter connected outbound", AttackStage.COMMAND_AND_CONTROL),
            ("lateral movement psexec internal ssh", AttackStage.LATERAL_MOVEMENT),
            ("pg_dump select * from users sensitive data query", AttackStage.DATA_ACCESS),
            ("exfiltrat large file transfer dns tunneling", AttackStage.EXFILTRATION),
        ]

        for text, expected_stage in test_cases:
            stage, conf = self.engine.classify_stage(text)
            self.assertEqual(stage, expected_stage, f"Failed for text: {text}")
            self.assertGreaterEqual(conf, 0.6)

    def test_08_evidence_traceability(self):
        """Every correlated link must preserve line number, raw log, and rationale."""
        entry = LogEntry(
            id="evid-1", session_id=self.session_id, line_number=42,
            timestamp=datetime.utcnow(), level=LogLevel.CRITICAL, source="kernel",
            message="root session opened executing /bin/sh -i privilege escalation from 10.0.0.5",
            raw_line="2026-11-03 11:42:00 [CRIT] root session opened executing /bin/sh -i privilege escalation from 10.0.0.5"
        )
        chains = self.engine.correlate([entry], [], [], self.session_id)
        self.assertEqual(len(chains), 1)
        link = chains[0].events[0]
        self.assertEqual(link.line_number, 42)
        self.assertEqual(link.raw_log, entry.raw_line)
        self.assertIn("Line 42", chains[0].supporting_evidence[0])

    def test_09_graph_generation(self):
        """Validate nodes and directed edges structure in graph_data."""
        base_time = datetime(2026, 11, 3, 10, 0, 0)
        logs = [
            LogEntry(id="g1", session_id=self.session_id, line_number=1, timestamp=base_time, level=LogLevel.ERROR,
                     message="Hydra brute force against user root from 192.168.1.50 targeting 10.0.0.1",
                     raw_line="Hydra brute force against user root from 192.168.1.50 targeting 10.0.0.1"),
            LogEntry(id="g2", session_id=self.session_id, line_number=2, timestamp=base_time + timedelta(minutes=5), level=LogLevel.CRITICAL,
                     message="user root sudo privilege escalation on 10.0.0.1 from 192.168.1.50",
                     raw_line="user root sudo privilege escalation on 10.0.0.1 from 192.168.1.50"),
        ]

        chains = self.engine.correlate(logs, [], [], self.session_id)
        self.assertEqual(len(chains), 1)
        graph = chains[0].graph_data
        self.assertIsNotNone(graph)
        self.assertGreaterEqual(len(graph.nodes), 3, "Should have nodes for IP, Stage, User/Host")
        self.assertGreaterEqual(len(graph.edges), 2, "Should have directed edges connecting nodes")

        node_labels = [n.label for n in graph.nodes]
        self.assertTrue(any("192.168.1.50" in label for label in node_labels))
        self.assertTrue(any("Credential Attack" in label for label in node_labels))

    def test_10_api_endpoints_and_copilot_integration(self):
        """Test REST API endpoints and Copilot Q&A with reconstructed attack chain."""
        base_time = datetime(2026, 11, 3, 12, 0, 0)
        logs = [
            LogEntry(id="api-1", session_id=self.session_id, line_number=1, timestamp=base_time, level=LogLevel.ERROR,
                     message="Port scan from 172.16.0.4", raw_line="Port scan from 172.16.0.4"),
            LogEntry(id="api-2", session_id=self.session_id, line_number=2, timestamp=base_time + timedelta(minutes=4), level=LogLevel.CRITICAL,
                     message="user admin: sudo: root privilege escalation from 172.16.0.4 targeting 10.0.0.2",
                     raw_line="user admin: sudo: root privilege escalation from 172.16.0.4 targeting 10.0.0.2"),
        ]

        # Populate store
        session = LogSession(id=self.session_id, filename="test.log", uploaded_at=datetime.utcnow(), total_lines=2, file_size=100, status="ready")
        store.set_session(session, logs)
        chains = reconstruct_attack_chains(logs, [], [], self.session_id)
        store.set_attack_chains(self.session_id, chains)

        # 1. GET /api/attack-chains
        resp = self.client.get(f"/api/attack-chains?session_id={self.session_id}")
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertEqual(len(data), 1)
        chain_id = data[0]["id"]

        # 2. GET /api/attack-chains/{chain_id}
        resp = self.client.get(f"/api/attack-chains/{chain_id}")
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.json()["id"], chain_id)

        # 3. GET /api/attack-chains/{chain_id}/timeline
        resp = self.client.get(f"/api/attack-chains/{chain_id}/timeline")
        self.assertEqual(resp.status_code, 200)
        timeline = resp.json()
        self.assertEqual(timeline["chain_id"], chain_id)
        self.assertEqual(timeline["total_events"], 2)

        # 4. GET /api/attack-chains/{chain_id}/graph
        resp = self.client.get(f"/api/attack-chains/{chain_id}/graph")
        self.assertEqual(resp.status_code, 200)
        graph = resp.json()
        self.assertIn("nodes", graph)
        self.assertIn("edges", graph)

        # 5. Copilot Q&A integration
        copilot = CopilotService(logs, [], [], chains)
        
        # Test: What happened in this attack chain?
        q1_res = copilot.answer(f"What happened in this attack chain {chain_id}?")
        self.assertIn("Attack Chain Overview", q1_res["answer"])
        self.assertEqual(q1_res["confidence"], "high")

        # Test: Which event occurred first?
        q2_res = copilot.answer("Which event occurred first?")
        self.assertIn("initial event", q2_res["answer"].lower())
        self.assertIn("Port scan", q2_res["answer"])

        # Test: Was privilege escalation observed?
        q3_res = copilot.answer("Was privilege escalation observed?")
        self.assertIn("YES. Privilege escalation was OBSERVED", q3_res["answer"])

        # Test: What should the security analyst investigate next?
        q4_res = copilot.answer("What should the security analyst investigate next?")
        self.assertIn("Recommended Forensic Investigation Steps", q4_res["answer"])

    def test_11_chain_status_enum_default_and_serialization(self):
        """Verify that default status is ChainStatus.NEW and serializes/deserializes cleanly."""
        chain = AttackChain(
            session_id=self.session_id,
            title="Status Test Chain",
            summary="Testing ChainStatus enum defaults",
            potential_impact="None",
            correlation_explanation="Direct unit test instantiation",
        )
        # 1. Type and value assertion
        self.assertIsInstance(chain.status, ChainStatus)
        self.assertEqual(chain.status, ChainStatus.NEW)
        self.assertEqual(chain.status.value, "NEW")

        # 2. Dict serialization and deserialization
        dumped = chain.model_dump()
        self.assertIn("status", dumped)
        self.assertEqual(dumped["status"], ChainStatus.NEW)

        reconstructed = AttackChain.model_validate(dumped)
        self.assertIsInstance(reconstructed.status, ChainStatus)
        self.assertEqual(reconstructed.status, ChainStatus.NEW)

        # 3. JSON serialization round-trip
        json_str = chain.model_dump_json()
        self.assertIn('"status":"NEW"', json_str)
        from_json = AttackChain.model_validate_json(json_str)
        self.assertEqual(from_json.status, ChainStatus.NEW)

        # 4. Explicit non-default status
        chain_resolved = AttackChain(
            session_id=self.session_id,
            title="Resolved Chain",
            summary="Testing resolved status",
            potential_impact="None",
            correlation_explanation="Direct unit test",
            status=ChainStatus.RESOLVED,
        )
        self.assertEqual(chain_resolved.status, ChainStatus.RESOLVED)


if __name__ == "__main__":
    unittest.main()
