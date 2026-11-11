"""
Integration tests for Threat Correlation REST API endpoints.

Phase 4.2B.4 — Threat Correlation & Unified Intelligence Engine.
"""

from datetime import datetime, timezone
import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from fastapi.testclient import TestClient

from app.main import app
from app.models.anomaly import Anomaly, DetectionMethod, SeverityLevel
from app.models.attack_chain import AttackChain, AttackStage
from app.models.incident import Incident, IncidentCategory, IncidentStatus
from app.models.ioc import IOC, IOCEvidence, IOCStatus, IOCType
from app.services.ioc_repository import ioc_repository
from app.services.store import store


class TestThreatCorrelationAPI(unittest.TestCase):
    """Test suite for /api/threat-correlation REST endpoints."""

    def setUp(self):
        """Seed repository and store with test objects."""
        self.client = TestClient(app)
        ioc_repository.clear()
        store.iocs.clear()
        store.session_iocs.clear()
        store.anomalies.clear()
        store.incidents.clear()
        store.attack_chains.clear()

        self.session_id = "sess-api-01"
        self.now = datetime(2026, 4, 15, 10, 0, 0, tzinfo=timezone.utc)

        # 1. Seed IOC with evidence
        self.ev = IOCEvidence(
            event_id="evt-api-100",
            session_id=self.session_id,
            timestamp=self.now,
            raw_value="198.51.100.99",
            source_field="source_ip",
            line_number=55,
            surrounding_context="Inbound probe from 198.51.100.99",
        )
        self.ioc = IOC(
            id="ioc-api-01",
            ioc_type=IOCType.IPV4,
            raw_value="198.51.100.99",
            normalized_value="198.51.100.99",
            status=IOCStatus.UNDER_REVIEW,
            evidence_references=[self.ev],
            source_sessions=[self.session_id],
            associated_anomaly_ids=["anom-api-01"],
            associated_incident_ids=["inc-api-01"],
            associated_chain_ids=["chain-api-01"],
        )
        ioc_repository.add_ioc(self.ioc)

        # 2. Seed Anomaly
        self.anomaly = Anomaly(
            id="anom-api-01",
            session_id=self.session_id,
            log_entry_ids=["evt-api-100"],
            score=0.85,
            severity=SeverityLevel.HIGH,
            reason="Port sweep probe",
            method=DetectionMethod.RULE_BASED,
            detected_at=self.now,
        )
        store.anomalies[self.session_id] = [self.anomaly]

        # 3. Seed Incident
        self.incident = Incident(
            id="inc-api-01",
            anomaly_id="anom-api-01",
            session_id=self.session_id,
            category=IncidentCategory.INTRUSION_ATTEMPT,
            severity="HIGH",
            title="External Reconnaissance",
            description="Port sweep from untrusted IP",
            root_cause_hypothesis="Scanner botnet",
            potential_impact="Service discovery",
            first_seen=self.now,
            last_seen=self.now,
            affected_ips=["198.51.100.99"],
            status=IncidentStatus.INVESTIGATING,
        )
        store.incidents[self.session_id] = [self.incident]

        # 4. Seed Attack Chain
        self.chain = AttackChain(
            id="chain-api-01",
            session_id=self.session_id,
            title="External Recon Campaign",
            summary="Port sweep leading to unauthorized probes",
            severity="HIGH",
            stages_observed=[AttackStage.RECONNAISSANCE],
            source_ips=["198.51.100.99"],
            associated_anomaly_ids=["anom-api-01"],
            associated_incident_ids=["inc-api-01"],
            event_ids=["evt-api-100"],
            potential_impact="Network reconnaissance",
            correlation_explanation="Linked by IP and timestamp",
        )
        store.attack_chains[self.session_id] = [self.chain]

    def tearDown(self):
        """Clean repository state."""
        ioc_repository.clear()
        store.iocs.clear()
        store.session_iocs.clear()

    # ─────────────────────────────────────────────────────────────────────────
    # Endpoint Tests
    # ─────────────────────────────────────────────────────────────────────────

    def test_get_unified_threat_context_200(self):
        """GET /api/threat-correlation/ioc/{ioc_id}/context returns valid UnifiedThreatContext."""
        response = self.client.get(f"/api/threat-correlation/ioc/{self.ioc.id}/context")
        self.assertEqual(response.status_code, 200)
        data = response.json()

        self.assertEqual(data["ioc_id"], self.ioc.id)
        self.assertEqual(data["normalized_value"], "198.51.100.99")
        self.assertEqual(data["analyst_status"], "UNDER_REVIEW")
        self.assertIn("correlations", data)
        self.assertGreater(len(data["correlations"]), 0)
        self.assertIn("investigation_summary", data)
        self.assertGreaterEqual(data["overall_correlation_confidence"], 0.70)

    def test_get_unified_threat_context_404(self):
        """GET /api/threat-correlation/ioc/{ioc_id}/context returns 404 for unknown IOC."""
        response = self.client.get("/api/threat-correlation/ioc/ioc-nonexistent/context")
        self.assertEqual(response.status_code, 404)
        self.assertIn("not found", response.json()["detail"].lower())

    def test_get_correlated_anomalies_200(self):
        """GET /api/threat-correlation/ioc/{ioc_id}/anomalies returns correlated anomalies."""
        response = self.client.get(f"/api/threat-correlation/ioc/{self.ioc.id}/anomalies")
        self.assertEqual(response.status_code, 200)
        data = response.json()

        self.assertEqual(data["ioc_id"], self.ioc.id)
        self.assertEqual(data["total"], 1)
        self.assertEqual(data["anomalies"][0]["target_id"], "anom-api-01")
        self.assertEqual(data["anomalies"][0]["correlation_type"], "IOC_TO_ANOMALY")

    def test_get_correlated_anomalies_404(self):
        """GET /api/threat-correlation/ioc/{ioc_id}/anomalies returns 404 for unknown IOC."""
        response = self.client.get("/api/threat-correlation/ioc/ioc-ghost/anomalies")
        self.assertEqual(response.status_code, 404)

    def test_get_correlated_incidents_200(self):
        """GET /api/threat-correlation/ioc/{ioc_id}/incidents returns correlated incidents."""
        response = self.client.get(f"/api/threat-correlation/ioc/{self.ioc.id}/incidents")
        self.assertEqual(response.status_code, 200)
        data = response.json()

        self.assertEqual(data["ioc_id"], self.ioc.id)
        self.assertEqual(data["total"], 1)
        self.assertEqual(data["incidents"][0]["target_id"], "inc-api-01")
        self.assertEqual(data["incidents"][0]["correlation_type"], "IOC_TO_INCIDENT")

    def test_get_correlated_incidents_404(self):
        """GET /api/threat-correlation/ioc/{ioc_id}/incidents returns 404 for unknown IOC."""
        response = self.client.get("/api/threat-correlation/ioc/ioc-ghost/incidents")
        self.assertEqual(response.status_code, 404)

    def test_get_correlated_attack_chains_200(self):
        """GET /api/threat-correlation/ioc/{ioc_id}/attack-chains returns correlated chains."""
        response = self.client.get(f"/api/threat-correlation/ioc/{self.ioc.id}/attack-chains")
        self.assertEqual(response.status_code, 200)
        data = response.json()

        self.assertEqual(data["ioc_id"], self.ioc.id)
        self.assertEqual(data["total"], 1)
        self.assertEqual(data["attack_chains"][0]["target_id"], "chain-api-01")
        self.assertEqual(data["attack_chains"][0]["correlation_type"], "IOC_TO_ATTACK_CHAIN")

    def test_get_correlated_attack_chains_404(self):
        """GET /api/threat-correlation/ioc/{ioc_id}/attack-chains returns 404 for unknown IOC."""
        response = self.client.get("/api/threat-correlation/ioc/ioc-ghost/attack-chains")
        self.assertEqual(response.status_code, 404)

    def test_get_correlated_events_200(self):
        """GET /api/threat-correlation/ioc/{ioc_id}/events returns log extraction events."""
        response = self.client.get(f"/api/threat-correlation/ioc/{self.ioc.id}/events")
        self.assertEqual(response.status_code, 200)
        data = response.json()

        self.assertEqual(data["ioc_id"], self.ioc.id)
        self.assertEqual(data["total"], 1)
        self.assertEqual(data["events"][0]["target_id"], "evt-api-100")
        self.assertEqual(data["events"][0]["correlation_type"], "IOC_TO_EVENT")

    def test_get_correlated_events_404(self):
        """GET /api/threat-correlation/ioc/{ioc_id}/events returns 404 for unknown IOC."""
        response = self.client.get("/api/threat-correlation/ioc/ioc-ghost/events")
        self.assertEqual(response.status_code, 404)

    def test_get_ioc_correlations_with_filters(self):
        """GET /api/threat-correlation/ioc/{ioc_id} returns all correlations and supports filtering."""
        # 1. Unfiltered
        resp = self.client.get(f"/api/threat-correlation/ioc/{self.ioc.id}")
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertGreaterEqual(data["total"], 4)
        self.assertEqual(data["confirmed_count"], data["total"])
        self.assertEqual(data["unconfirmed_count"], 0)

        # 2. Filter by correlation_type
        resp_filtered = self.client.get(
            f"/api/threat-correlation/ioc/{self.ioc.id}?correlation_type=IOC_TO_EVENT"
        )
        self.assertEqual(resp_filtered.status_code, 200)
        data_filtered = resp_filtered.json()
        self.assertEqual(data_filtered["total"], 1)
        self.assertEqual(data_filtered["correlations"][0]["correlation_type"], "IOC_TO_EVENT")

        # 3. Filter by confirmed_only
        resp_conf = self.client.get(
            f"/api/threat-correlation/ioc/{self.ioc.id}?confirmed_only=true"
        )
        self.assertEqual(resp_conf.status_code, 200)
        self.assertEqual(resp_conf.json()["total"], data["confirmed_count"])

    def test_ioc_relationships_endpoint_includes_unified_url(self):
        """Verify GET /api/iocs/{ioc_id}/relationships includes unified_context_url."""
        response = self.client.get(f"/api/iocs/{self.ioc.id}/relationships")
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertIn("unified_context_url", data)
        self.assertEqual(
            data["unified_context_url"],
            f"/api/threat-correlation/ioc/{self.ioc.id}/context",
        )


if __name__ == "__main__":
    unittest.main()

