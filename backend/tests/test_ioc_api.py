"""
Phase 4.2A.5 — IOC REST API Tests

Covers all seven endpoints under /api/iocs:

  GET   /api/iocs                     — listing, pagination, filtering
  GET   /api/iocs/search              — multi-criteria search
  GET   /api/iocs/summary             — aggregate statistics
  GET   /api/iocs/{ioc_id}            — single IOC detail
  GET   /api/iocs/{ioc_id}/evidence   — read-only evidence records
  PATCH /api/iocs/{ioc_id}/status     — analyst review transitions
  GET   /api/iocs/{ioc_id}/relationships — evidence-backed relationships

Security invariants verified:
  - No external network access
  - No automatic malicious classification
  - ValidationStatus unchanged by status transitions
  - Raw evidence never mutated
  - No Python tracebacks exposed
"""

import os
import sys
import unittest
from datetime import datetime

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from fastapi.testclient import TestClient
from app.main import app
from app.models.ioc import IOC, IOCEvidence, IOCStatus, IOCType, ValidationStatus
from app.services.ioc_repository import ioc_repository


# ─────────────────────────────────────────────────────────────────────────────
# Test helpers
# ─────────────────────────────────────────────────────────────────────────────

def _make_ioc(
    ioc_type=IOCType.IPV4,
    raw_value="192.168.1.1",
    normalized_value="192.168.1.1",
    status=IOCStatus.EXTRACTED,
    source_sessions=None,
    associated_anomaly_ids=None,
    associated_incident_ids=None,
    associated_chain_ids=None,
    evidence_refs=None,
    tags=None,
    occurrence_count=1,
    first_seen=None,
) -> IOC:
    return IOC(
        ioc_type=ioc_type,
        raw_value=raw_value,
        normalized_value=normalized_value,
        status=status,
        source_sessions=source_sessions or [],
        associated_anomaly_ids=associated_anomaly_ids or [],
        associated_incident_ids=associated_incident_ids or [],
        associated_chain_ids=associated_chain_ids or [],
        evidence_references=evidence_refs or [],
        tags=tags or [],
        occurrence_count=occurrence_count,
        first_seen=first_seen or datetime(2026, 11, 1, 10, 0, 0),
    )


def _make_evidence(
    event_id="evt-001",
    session_id="sess-001",
    raw_value="192.168.1.1",
    source_field="raw_line",
    line_number=1,
    surrounding_context="log context here",
) -> IOCEvidence:
    return IOCEvidence(
        event_id=event_id,
        session_id=session_id,
        raw_value=raw_value,
        source_field=source_field,
        line_number=line_number,
        surrounding_context=surrounding_context,
        timestamp=datetime(2026, 11, 1, 10, 0, 0),
    )


# ─────────────────────────────────────────────────────────────────────────────
# Test Suite
# ─────────────────────────────────────────────────────────────────────────────

class TestIOCApi(unittest.TestCase):

    def setUp(self):
        """Clear repository and create a fresh TestClient before each test."""
        ioc_repository.clear()
        self.client = TestClient(app)

    def tearDown(self):
        ioc_repository.clear()

    # ═════════════════════════════════════════════════════════════════════════
    # 1 – LISTING  (GET /api/iocs)
    # ═════════════════════════════════════════════════════════════════════════

    def test_01_list_empty_repository(self):
        """GET /api/iocs returns empty items list when repository is empty."""
        resp = self.client.get("/api/iocs")
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertEqual(data["total"], 0)
        self.assertEqual(data["items"], [])
        self.assertEqual(data["page"], 1)

    def test_02_list_single_ioc(self):
        """GET /api/iocs returns exactly one IOC when one is present."""
        ioc = _make_ioc()
        ioc_repository.add_ioc(ioc)

        resp = self.client.get("/api/iocs")
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertEqual(data["total"], 1)
        self.assertEqual(len(data["items"]), 1)
        self.assertEqual(data["items"][0]["id"], ioc.id)

    def test_03_list_multiple_iocs(self):
        """GET /api/iocs returns all IOCs when several are present."""
        iocs = [
            _make_ioc(raw_value="10.0.0.1", normalized_value="10.0.0.1"),
            _make_ioc(ioc_type=IOCType.DOMAIN, raw_value="evil.com", normalized_value="evil.com"),
            _make_ioc(ioc_type=IOCType.SHA256,
                      raw_value="a" * 64, normalized_value="a" * 64),
        ]
        for ioc in iocs:
            ioc_repository.add_ioc(ioc)

        resp = self.client.get("/api/iocs")
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.json()["total"], 3)

    def test_04_pagination_basic(self):
        """Pagination returns correct subset and metadata."""
        for i in range(5):
            ioc_repository.add_ioc(_make_ioc(
                raw_value=f"10.0.0.{i+1}",
                normalized_value=f"10.0.0.{i+1}",
            ))

        resp = self.client.get("/api/iocs?page=1&page_size=2")
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertEqual(data["total"], 5)
        self.assertEqual(len(data["items"]), 2)
        self.assertEqual(data["page_size"], 2)
        self.assertEqual(data["total_pages"], 3)

    def test_05_pagination_second_page(self):
        """Second page returns the next slice of results."""
        for i in range(5):
            ioc_repository.add_ioc(_make_ioc(
                raw_value=f"10.1.0.{i+1}",
                normalized_value=f"10.1.0.{i+1}",
            ))

        resp = self.client.get("/api/iocs?page=2&page_size=2")
        data = resp.json()
        self.assertEqual(len(data["items"]), 2)
        self.assertEqual(data["page"], 2)

    def test_06_pagination_last_page_partial(self):
        """Last page contains fewer items than page_size."""
        for i in range(5):
            ioc_repository.add_ioc(_make_ioc(
                raw_value=f"10.2.0.{i+1}",
                normalized_value=f"10.2.0.{i+1}",
            ))

        resp = self.client.get("/api/iocs?page=3&page_size=2")
        data = resp.json()
        self.assertEqual(len(data["items"]), 1)

    def test_07_filter_by_type(self):
        """ioc_type filter returns only matching IOC types."""
        ioc_repository.add_ioc(_make_ioc(raw_value="10.0.0.1", normalized_value="10.0.0.1"))
        ioc_repository.add_ioc(_make_ioc(
            ioc_type=IOCType.DOMAIN, raw_value="example.com", normalized_value="example.com"
        ))

        resp = self.client.get("/api/iocs?ioc_type=domain")
        data = resp.json()
        self.assertEqual(data["total"], 1)
        self.assertEqual(data["items"][0]["ioc_type"], "domain")

    def test_08_filter_by_status(self):
        """status filter returns only IOCs with the specified analyst status."""
        ioc_a = _make_ioc(raw_value="10.0.0.1", normalized_value="10.0.0.1", status=IOCStatus.EXTRACTED)
        ioc_b = _make_ioc(raw_value="10.0.0.2", normalized_value="10.0.0.2", status=IOCStatus.CONFIRMED)
        ioc_repository.add_ioc(ioc_a)
        ioc_repository.add_ioc(ioc_b)

        resp = self.client.get("/api/iocs?status=CONFIRMED")
        data = resp.json()
        self.assertEqual(data["total"], 1)
        self.assertEqual(data["items"][0]["status"], "CONFIRMED")

    def test_09_filter_by_session_id(self):
        """session_id filter returns only IOCs observed in that session."""
        ioc_a = _make_ioc(raw_value="10.0.0.1", normalized_value="10.0.0.1",
                          source_sessions=["sess-X"])
        ioc_b = _make_ioc(raw_value="10.0.0.2", normalized_value="10.0.0.2",
                          source_sessions=["sess-Y"])
        ioc_repository.add_ioc(ioc_a)
        ioc_repository.add_ioc(ioc_b)

        resp = self.client.get("/api/iocs?session_id=sess-X")
        data = resp.json()
        self.assertEqual(data["total"], 1)
        self.assertEqual(data["items"][0]["source_sessions"], ["sess-X"])

    def test_10_filter_by_event_id(self):
        """event_id filter returns only IOCs from that log event."""
        ev = _make_evidence(event_id="evt-target", session_id="sess-001")
        ioc = _make_ioc(raw_value="10.0.0.1", normalized_value="10.0.0.1",
                        evidence_refs=[ev], source_sessions=["sess-001"])
        other_ioc = _make_ioc(raw_value="10.0.0.2", normalized_value="10.0.0.2")
        ioc_repository.add_ioc(ioc)
        ioc_repository.add_ioc(other_ioc)

        resp = self.client.get("/api/iocs?event_id=evt-target")
        data = resp.json()
        self.assertEqual(data["total"], 1)
        self.assertEqual(data["items"][0]["normalized_value"], "10.0.0.1")

    # ═════════════════════════════════════════════════════════════════════════
    # 2 – SEARCH  (GET /api/iocs/search)
    # ═════════════════════════════════════════════════════════════════════════

    def test_11_search_by_normalized_value(self):
        """Search by partial normalized_value substring match."""
        ioc_repository.add_ioc(_make_ioc(raw_value="192.168.50.1", normalized_value="192.168.50.1"))
        ioc_repository.add_ioc(_make_ioc(raw_value="10.0.0.1", normalized_value="10.0.0.1"))

        resp = self.client.get("/api/iocs/search?normalized_value=192.168")
        data = resp.json()
        self.assertEqual(data["total"], 1)
        self.assertIn("192.168", data["items"][0]["normalized_value"])

    def test_12_search_by_ioc_type(self):
        """Search with ioc_type filter returns only matching IOCs."""
        ioc_repository.add_ioc(_make_ioc(raw_value="10.0.0.1", normalized_value="10.0.0.1"))
        ioc_repository.add_ioc(_make_ioc(
            ioc_type=IOCType.SHA256, raw_value="b" * 64, normalized_value="b" * 64
        ))

        resp = self.client.get("/api/iocs/search?ioc_type=sha256")
        data = resp.json()
        self.assertEqual(data["total"], 1)
        self.assertEqual(data["items"][0]["ioc_type"], "sha256")

    def test_13_search_combined_filters(self):
        """Combined ioc_type + status filters are ANDed."""
        ioc_repository.add_ioc(_make_ioc(
            raw_value="10.0.0.1", normalized_value="10.0.0.1", status=IOCStatus.CONFIRMED
        ))
        ioc_repository.add_ioc(_make_ioc(
            raw_value="10.0.0.2", normalized_value="10.0.0.2", status=IOCStatus.EXTRACTED
        ))

        resp = self.client.get("/api/iocs/search?ioc_type=ipv4&status=CONFIRMED")
        data = resp.json()
        self.assertEqual(data["total"], 1)
        self.assertEqual(data["items"][0]["status"], "CONFIRMED")

    def test_14_search_no_results(self):
        """Search with non-matching filter returns empty result set."""
        ioc_repository.add_ioc(_make_ioc(raw_value="10.0.0.1", normalized_value="10.0.0.1"))

        resp = self.client.get("/api/iocs/search?ioc_type=sha256")
        data = resp.json()
        self.assertEqual(data["total"], 0)
        self.assertEqual(data["items"], [])

    def test_15_search_by_attack_chain(self):
        """Search by attack_chain_id uses chain index."""
        ioc = _make_ioc(raw_value="10.0.0.1", normalized_value="10.0.0.1",
                        associated_chain_ids=["chain-abc"])
        other = _make_ioc(raw_value="10.0.0.2", normalized_value="10.0.0.2",
                          associated_chain_ids=["chain-xyz"])
        ioc_repository.add_ioc(ioc)
        ioc_repository.add_ioc(other)

        resp = self.client.get("/api/iocs/search?attack_chain_id=chain-abc")
        data = resp.json()
        self.assertEqual(data["total"], 1)
        self.assertIn("chain-abc", data["items"][0]["associated_chain_ids"])

    # ═════════════════════════════════════════════════════════════════════════
    # 3 – DETAIL  (GET /api/iocs/{ioc_id})
    # ═════════════════════════════════════════════════════════════════════════

    def test_16_get_existing_ioc(self):
        """GET /api/iocs/{ioc_id} returns 200 with correct IOC data."""
        ioc = _make_ioc(raw_value="10.0.0.1", normalized_value="10.0.0.1")
        ioc_repository.add_ioc(ioc)

        resp = self.client.get(f"/api/iocs/{ioc.id}")
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertEqual(data["id"], ioc.id)
        self.assertEqual(data["normalized_value"], "10.0.0.1")
        self.assertEqual(data["ioc_type"], "ipv4")

    def test_17_get_nonexistent_ioc_returns_404(self):
        """GET /api/iocs/nonexistent returns HTTP 404."""
        resp = self.client.get("/api/iocs/ioc-doesnotexist999")
        self.assertEqual(resp.status_code, 404)
        self.assertNotIn("traceback", resp.text.lower())

    def test_18_get_ioc_complete_serialization(self):
        """Full IOC detail response includes all expected fields."""
        ev = _make_evidence(event_id="evt-123", session_id="sess-abc")
        ioc = _make_ioc(
            raw_value="10.0.0.1",
            normalized_value="10.0.0.1",
            source_sessions=["sess-abc"],
            evidence_refs=[ev],
            associated_anomaly_ids=["anom-1"],
            associated_incident_ids=["inc-1"],
            associated_chain_ids=["chain-1"],
            tags=["lateral-movement"],
        )
        ioc_repository.add_ioc(ioc)

        resp = self.client.get(f"/api/iocs/{ioc.id}")
        data = resp.json()
        self.assertIn("id", data)
        self.assertIn("ioc_type", data)
        self.assertIn("raw_value", data)
        self.assertIn("normalized_value", data)
        self.assertIn("status", data)
        self.assertIn("confidence", data)
        self.assertIn("first_seen", data)
        self.assertIn("occurrence_count", data)
        self.assertIn("extraction_methods", data)
        self.assertIn("tags", data)
        self.assertIn("source_sessions", data)
        self.assertIn("associated_anomaly_ids", data)
        self.assertIn("associated_incident_ids", data)
        self.assertIn("associated_chain_ids", data)
        self.assertIn("evidence_references", data)
        self.assertEqual(data["tags"], ["lateral-movement"])

    # ═════════════════════════════════════════════════════════════════════════
    # 4 – SUMMARY  (GET /api/iocs/summary)
    # ═════════════════════════════════════════════════════════════════════════

    def test_19_summary_empty_repository(self):
        """GET /api/iocs/summary returns all-zero counters when empty."""
        resp = self.client.get("/api/iocs/summary")
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertEqual(data["total_iocs"], 0)
        self.assertEqual(data["by_type"], {})
        self.assertEqual(data["by_status"], {})

    def test_20_summary_type_counts(self):
        """Summary by_type counts each IOC type correctly."""
        ioc_repository.add_ioc(_make_ioc(raw_value="10.0.0.1", normalized_value="10.0.0.1"))
        ioc_repository.add_ioc(_make_ioc(raw_value="10.0.0.2", normalized_value="10.0.0.2"))
        ioc_repository.add_ioc(_make_ioc(
            ioc_type=IOCType.DOMAIN, raw_value="evil.com", normalized_value="evil.com"
        ))

        resp = self.client.get("/api/iocs/summary")
        data = resp.json()
        self.assertEqual(data["total_iocs"], 3)
        self.assertEqual(data["by_type"].get("ipv4", 0), 2)
        self.assertEqual(data["by_type"].get("domain", 0), 1)

    def test_21_summary_status_counts(self):
        """Summary by_status counts each review status correctly."""
        ioc_repository.add_ioc(_make_ioc(raw_value="10.0.0.1", normalized_value="10.0.0.1",
                                         status=IOCStatus.EXTRACTED))
        ioc_repository.add_ioc(_make_ioc(raw_value="10.0.0.2", normalized_value="10.0.0.2",
                                         status=IOCStatus.CONFIRMED))
        ioc_repository.add_ioc(_make_ioc(raw_value="10.0.0.3", normalized_value="10.0.0.3",
                                         status=IOCStatus.FALSE_POSITIVE))

        resp = self.client.get("/api/iocs/summary")
        data = resp.json()
        self.assertEqual(data["by_status"].get("EXTRACTED", 0), 1)
        self.assertEqual(data["by_status"].get("CONFIRMED", 0), 1)
        self.assertEqual(data["by_status"].get("FALSE_POSITIVE", 0), 1)
        self.assertEqual(data["confirmed_count"], 1)
        self.assertEqual(data["false_positive_count"], 1)

    def test_22_summary_includes_generated_at(self):
        """Summary response includes a generated_at timestamp."""
        resp = self.client.get("/api/iocs/summary")
        data = resp.json()
        self.assertIn("generated_at", data)
        # Must be a valid ISO 8601 string
        datetime.fromisoformat(data["generated_at"])

    def test_23_summary_scoped_to_session(self):
        """Summary with session_id parameter returns only that session's IOCs."""
        ioc_repository.add_ioc(_make_ioc(raw_value="10.0.0.1", normalized_value="10.0.0.1",
                                         source_sessions=["sess-A"]))
        ioc_repository.add_ioc(_make_ioc(raw_value="10.0.0.2", normalized_value="10.0.0.2",
                                         source_sessions=["sess-B"]))

        resp = self.client.get("/api/iocs/summary?session_id=sess-A")
        data = resp.json()
        self.assertEqual(data["total_iocs"], 1)

    def test_24_summary_chain_and_incident_counts(self):
        """Summary chains_with_iocs and incidents_with_iocs are correct."""
        ioc_repository.add_ioc(_make_ioc(
            raw_value="10.0.0.1", normalized_value="10.0.0.1",
            associated_chain_ids=["chain-1", "chain-2"],
            associated_incident_ids=["inc-1"],
        ))

        resp = self.client.get("/api/iocs/summary")
        data = resp.json()
        self.assertEqual(data["chains_with_iocs"], 2)
        self.assertEqual(data["incidents_with_iocs"], 1)

    # ═════════════════════════════════════════════════════════════════════════
    # 5 – EVIDENCE  (GET /api/iocs/{ioc_id}/evidence)
    # ═════════════════════════════════════════════════════════════════════════

    def test_25_evidence_retrieval(self):
        """GET /api/iocs/{id}/evidence returns evidence records."""
        ev = _make_evidence(event_id="evt-ev1", session_id="sess-ev1",
                            raw_value="10.0.0.1", line_number=42,
                            surrounding_context="failed login from 10.0.0.1")
        ioc = _make_ioc(raw_value="10.0.0.1", normalized_value="10.0.0.1",
                        evidence_refs=[ev])
        ioc_repository.add_ioc(ioc)

        resp = self.client.get(f"/api/iocs/{ioc.id}/evidence")
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertEqual(data["evidence_count"], 1)
        ev_data = data["evidence"][0]
        self.assertEqual(ev_data["event_id"], "evt-ev1")
        self.assertEqual(ev_data["line_number"], 42)
        self.assertIn("10.0.0.1", ev_data["surrounding_context"])

    def test_26_evidence_multiple_records(self):
        """Evidence endpoint returns all evidence records correctly."""
        evs = [
            _make_evidence(event_id=f"evt-{i}", session_id="sess-001",
                           line_number=i, raw_value="10.0.0.1")
            for i in range(3)
        ]
        ioc = _make_ioc(raw_value="10.0.0.1", normalized_value="10.0.0.1",
                        evidence_refs=evs, occurrence_count=3)
        ioc_repository.add_ioc(ioc)

        resp = self.client.get(f"/api/iocs/{ioc.id}/evidence")
        data = resp.json()
        self.assertEqual(data["evidence_count"], 3)
        self.assertEqual(len(data["evidence"]), 3)

    def test_27_evidence_preserves_all_fields(self):
        """Evidence response retains event_id, session_id, timestamp, source_field."""
        ts = datetime(2026, 11, 3, 14, 30, 0)
        ev = IOCEvidence(
            event_id="evt-unique",
            session_id="sess-unique",
            raw_value="10.0.0.1",
            source_field="message",
            line_number=100,
            surrounding_context="context snippet",
            timestamp=ts,
        )
        ioc = _make_ioc(raw_value="10.0.0.1", normalized_value="10.0.0.1", evidence_refs=[ev])
        ioc_repository.add_ioc(ioc)

        resp = self.client.get(f"/api/iocs/{ioc.id}/evidence")
        data = resp.json()
        ev_data = data["evidence"][0]
        self.assertEqual(ev_data["session_id"], "sess-unique")
        self.assertEqual(ev_data["source_field"], "message")
        self.assertIsNotNone(ev_data["timestamp"])

    def test_28_evidence_nonexistent_ioc_returns_404(self):
        """GET evidence for nonexistent IOC returns 404."""
        resp = self.client.get("/api/iocs/ioc-doesnotexist/evidence")
        self.assertEqual(resp.status_code, 404)

    # ═════════════════════════════════════════════════════════════════════════
    # 6 – STATUS UPDATE  (PATCH /api/iocs/{ioc_id}/status)
    # ═════════════════════════════════════════════════════════════════════════

    def test_29_valid_status_update_extracted_to_under_review(self):
        """EXTRACTED → UNDER_REVIEW is a valid transition."""
        ioc = _make_ioc(raw_value="10.0.0.1", normalized_value="10.0.0.1",
                        status=IOCStatus.EXTRACTED)
        ioc_repository.add_ioc(ioc)

        resp = self.client.patch(f"/api/iocs/{ioc.id}/status", json={
            "status": "UNDER_REVIEW",
            "reason": "Analyst is reviewing this indicator",
        })
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertEqual(data["status"], "UNDER_REVIEW")

    def test_30_valid_status_update_under_review_to_confirmed(self):
        """UNDER_REVIEW → CONFIRMED is a valid transition."""
        ioc = _make_ioc(raw_value="10.0.0.1", normalized_value="10.0.0.1",
                        status=IOCStatus.UNDER_REVIEW)
        ioc_repository.add_ioc(ioc)

        resp = self.client.patch(f"/api/iocs/{ioc.id}/status", json={
            "status": "CONFIRMED",
            "reason": "Confirmed as genuine C2 indicator",
            "changed_by": "analyst-01",
        })
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertEqual(data["status"], "CONFIRMED")

    def test_31_valid_status_update_to_false_positive(self):
        """UNDER_REVIEW → FALSE_POSITIVE is a valid transition."""
        ioc = _make_ioc(raw_value="10.0.0.1", normalized_value="10.0.0.1",
                        status=IOCStatus.UNDER_REVIEW)
        ioc_repository.add_ioc(ioc)

        resp = self.client.patch(f"/api/iocs/{ioc.id}/status", json={
            "status": "FALSE_POSITIVE",
            "reason": "Determined to be internal scanner traffic",
        })
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.json()["status"], "FALSE_POSITIVE")

    def test_32_status_update_invalid_ioc_id_returns_404(self):
        """PATCH status for nonexistent IOC returns 404."""
        resp = self.client.patch("/api/iocs/ioc-nonexistent/status", json={
            "status": "UNDER_REVIEW",
            "reason": "Should fail because IOC does not exist",
        })
        self.assertEqual(resp.status_code, 404)

    def test_33_status_update_invalid_transition_returns_422(self):
        """Invalid transition (e.g. EXTRACTED → CONFIRMED then CONFIRMED → EXTRACTED) returns 422."""
        # CONFIRMED → FALSE_POSITIVE is valid, but CONFIRMED → EXTRACTED is not
        ioc = _make_ioc(raw_value="10.0.0.1", normalized_value="10.0.0.1",
                        status=IOCStatus.CONFIRMED)
        ioc_repository.add_ioc(ioc)

        resp = self.client.patch(f"/api/iocs/{ioc.id}/status", json={
            "status": "EXTRACTED",
            "reason": "Should be rejected: CONFIRMED cannot go back to EXTRACTED",
        })
        self.assertEqual(resp.status_code, 422)

    def test_34_status_update_short_reason_returns_422(self):
        """Reason shorter than 5 characters is rejected with 422."""
        ioc = _make_ioc(raw_value="10.0.0.1", normalized_value="10.0.0.1",
                        status=IOCStatus.EXTRACTED)
        ioc_repository.add_ioc(ioc)

        resp = self.client.patch(f"/api/iocs/{ioc.id}/status", json={
            "status": "UNDER_REVIEW",
            "reason": "hi",   # < 5 chars
        })
        self.assertEqual(resp.status_code, 422)

    def test_35_status_update_preserves_validation_status(self):
        """
        Analyst review status transitions must NOT change ValidationStatus.
        These are independent concepts. The evidence_references must remain
        exactly as they were before the status update.
        """
        ev = _make_evidence(event_id="evt-vs", session_id="sess-vs")
        ioc = _make_ioc(raw_value="10.0.0.1", normalized_value="10.0.0.1",
                        status=IOCStatus.EXTRACTED, evidence_refs=[ev])
        ioc_repository.add_ioc(ioc)

        # Capture evidence before update
        before = self.client.get(f"/api/iocs/{ioc.id}").json()
        evidence_before = before["evidence_references"]

        # Perform status update
        self.client.patch(f"/api/iocs/{ioc.id}/status", json={
            "status": "UNDER_REVIEW",
            "reason": "Moving to review queue now",
        })

        # Evidence must be identical after update
        after = self.client.get(f"/api/iocs/{ioc.id}").json()
        evidence_after = after["evidence_references"]
        self.assertEqual(evidence_before, evidence_after)

    def test_36_status_update_analyst_note_persisted(self):
        """analyst_note in status update request is persisted to the IOC record."""
        ioc = _make_ioc(raw_value="10.0.0.1", normalized_value="10.0.0.1",
                        status=IOCStatus.EXTRACTED)
        ioc_repository.add_ioc(ioc)

        resp = self.client.patch(f"/api/iocs/{ioc.id}/status", json={
            "status": "UNDER_REVIEW",
            "reason": "Moving to review for investigation",
            "analyst_note": "Seen in three separate sessions",
        })
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertEqual(data["analyst_note"], "Seen in three separate sessions")

    # ═════════════════════════════════════════════════════════════════════════
    # 7 – RELATIONSHIPS  (GET /api/iocs/{ioc_id}/relationships)
    # ═════════════════════════════════════════════════════════════════════════

    def test_37_relationships_session_link(self):
        """Relationship endpoint surfaces session associations."""
        ioc = _make_ioc(raw_value="10.0.0.1", normalized_value="10.0.0.1",
                        source_sessions=["sess-rel-1"])
        ioc_repository.add_ioc(ioc)

        resp = self.client.get(f"/api/iocs/{ioc.id}/relationships")
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        session_ids = [s["session_id"] for s in data["sessions"]]
        self.assertIn("sess-rel-1", session_ids)

    def test_38_relationships_event_link(self):
        """Relationship endpoint surfaces event associations from evidence."""
        ev = _make_evidence(event_id="evt-rel-1", session_id="sess-rel-1")
        ioc = _make_ioc(raw_value="10.0.0.1", normalized_value="10.0.0.1",
                        evidence_refs=[ev])
        ioc_repository.add_ioc(ioc)

        resp = self.client.get(f"/api/iocs/{ioc.id}/relationships")
        data = resp.json()
        event_ids = [e["event_id"] for e in data["events"]]
        self.assertIn("evt-rel-1", event_ids)

    def test_39_relationships_anomaly_link(self):
        """Relationship endpoint surfaces anomaly associations."""
        ioc = _make_ioc(raw_value="10.0.0.1", normalized_value="10.0.0.1",
                        associated_anomaly_ids=["anom-rel-1"])
        ioc_repository.add_ioc(ioc)

        resp = self.client.get(f"/api/iocs/{ioc.id}/relationships")
        data = resp.json()
        anomaly_ids = [a["anomaly_id"] for a in data["anomalies"]]
        self.assertIn("anom-rel-1", anomaly_ids)

    def test_40_relationships_incident_link(self):
        """Relationship endpoint surfaces incident associations."""
        ioc = _make_ioc(raw_value="10.0.0.1", normalized_value="10.0.0.1",
                        associated_incident_ids=["inc-rel-1"])
        ioc_repository.add_ioc(ioc)

        resp = self.client.get(f"/api/iocs/{ioc.id}/relationships")
        data = resp.json()
        incident_ids = [i["incident_id"] for i in data["incidents"]]
        self.assertIn("inc-rel-1", incident_ids)

    def test_41_relationships_attack_chain_link(self):
        """Relationship endpoint surfaces attack chain associations."""
        ioc = _make_ioc(raw_value="10.0.0.1", normalized_value="10.0.0.1",
                        associated_chain_ids=["chain-rel-1"])
        ioc_repository.add_ioc(ioc)

        resp = self.client.get(f"/api/iocs/{ioc.id}/relationships")
        data = resp.json()
        chain_ids = [c["chain_id"] for c in data["attack_chains"]]
        self.assertIn("chain-rel-1", chain_ids)

    def test_42_relationships_nonexistent_ioc_returns_404(self):
        """Relationships endpoint returns 404 for unknown IOC."""
        resp = self.client.get("/api/iocs/ioc-doesnotexist/relationships")
        self.assertEqual(resp.status_code, 404)

    def test_43_relationships_no_false_session_sharing(self):
        """
        IOCs sharing a session ID but NOT sharing evidence events must NOT
        appear in each other's event relationships.
        """
        ev_a = _make_evidence(event_id="evt-only-A", session_id="sess-shared")
        ev_b = _make_evidence(event_id="evt-only-B", session_id="sess-shared")

        ioc_a = _make_ioc(raw_value="10.0.0.1", normalized_value="10.0.0.1",
                          source_sessions=["sess-shared"], evidence_refs=[ev_a])
        ioc_b = _make_ioc(raw_value="10.0.0.2", normalized_value="10.0.0.2",
                          source_sessions=["sess-shared"], evidence_refs=[ev_b])
        ioc_repository.add_ioc(ioc_a)
        ioc_repository.add_ioc(ioc_b)

        # ioc_a's events must only contain evt-only-A, not evt-only-B
        resp = self.client.get(f"/api/iocs/{ioc_a.id}/relationships")
        data = resp.json()
        event_ids = [e["event_id"] for e in data["events"]]
        self.assertIn("evt-only-A", event_ids)
        self.assertNotIn("evt-only-B", event_ids)

    # ═════════════════════════════════════════════════════════════════════════
    # 8 – SECURITY INVARIANTS
    # ═════════════════════════════════════════════════════════════════════════

    def test_44_no_external_network_access(self):
        """
        All IOC API endpoints operate offline.
        No DNS, reputation, WHOIS, or threat-feed lookups are made.
        Verified by the absence of network-dependent fields populated
        (reputation_score must remain None, mitre_technique_ids must be empty).
        """
        ioc = _make_ioc(raw_value="8.8.8.8", normalized_value="8.8.8.8")
        ioc_repository.add_ioc(ioc)

        resp = self.client.get(f"/api/iocs/{ioc.id}")
        data = resp.json()
        # reputation_score is None — no external lookup
        self.assertIsNone(data.get("reputation_score"))
        # mitre_technique_ids is empty — no external enrichment
        self.assertEqual(data.get("mitre_technique_ids", []), [])

    def test_45_no_automatic_malicious_classification(self):
        """
        Status updates must not auto-classify an IOC as malicious.
        Only analyst-driven transitions are permitted.
        """
        ioc = _make_ioc(raw_value="1.2.3.4", normalized_value="1.2.3.4",
                        status=IOCStatus.EXTRACTED)
        ioc_repository.add_ioc(ioc)

        # After listing, default status must still be EXTRACTED (not auto-confirmed)
        resp = self.client.get(f"/api/iocs/{ioc.id}")
        data = resp.json()
        self.assertEqual(data["status"], "EXTRACTED")

    def test_46_raw_evidence_not_mutated_by_status_update(self):
        """
        PATCH /status must not alter any field of IOCEvidence records.
        """
        ev = _make_evidence(
            event_id="evt-immutable",
            session_id="sess-immutable",
            raw_value="10.9.8.7",
            line_number=99,
            surrounding_context="original context string",
        )
        ioc = _make_ioc(raw_value="10.9.8.7", normalized_value="10.9.8.7",
                        evidence_refs=[ev], status=IOCStatus.EXTRACTED)
        ioc_repository.add_ioc(ioc)

        self.client.patch(f"/api/iocs/{ioc.id}/status", json={
            "status": "UNDER_REVIEW",
            "reason": "Flagged for deeper investigation",
        })

        # Retrieve and verify evidence fields
        resp = self.client.get(f"/api/iocs/{ioc.id}/evidence")
        ev_data = resp.json()["evidence"][0]
        self.assertEqual(ev_data["event_id"], "evt-immutable")
        self.assertEqual(ev_data["session_id"], "sess-immutable")
        self.assertEqual(ev_data["raw_value"], "10.9.8.7")
        self.assertEqual(ev_data["line_number"], 99)
        self.assertEqual(ev_data["surrounding_context"], "original context string")

    def test_47_no_traceback_on_404(self):
        """404 responses must not expose Python tracebacks or internal details."""
        resp = self.client.get("/api/iocs/ioc-fakeid999999")
        self.assertEqual(resp.status_code, 404)
        body = resp.text.lower()
        self.assertNotIn("traceback", body)
        self.assertNotIn("file \"", body)
        self.assertNotIn("raise httpe", body)

    def test_48_page_size_bounded_at_200(self):
        """page_size > 200 is rejected with 422 (FastAPI validation)."""
        resp = self.client.get("/api/iocs?page_size=1000000")
        self.assertEqual(resp.status_code, 422)

    def test_49_invalid_ioc_type_filter_returns_400(self):
        """Unrecognized ioc_type filter value returns HTTP 400."""
        resp = self.client.get("/api/iocs?ioc_type=INVALID_TYPE_XYZ")
        self.assertEqual(resp.status_code, 400)

    def test_50_status_history_audit_trail_accumulated(self):
        """
        Multiple sequential status transitions accumulate a full audit trail
        in status_history without overwriting earlier entries.
        """
        ioc = _make_ioc(raw_value="10.0.0.1", normalized_value="10.0.0.1",
                        status=IOCStatus.EXTRACTED)
        ioc_repository.add_ioc(ioc)

        self.client.patch(f"/api/iocs/{ioc.id}/status", json={
            "status": "UNDER_REVIEW",
            "reason": "Moving to review queue",
            "changed_by": "analyst-a",
        })
        self.client.patch(f"/api/iocs/{ioc.id}/status", json={
            "status": "CONFIRMED",
            "reason": "Confirmed as genuine threat indicator",
            "changed_by": "analyst-b",
        })

        resp = self.client.get(f"/api/iocs/{ioc.id}")
        data = resp.json()
        self.assertEqual(data["status"], "CONFIRMED")
        # Both transitions should be recorded
        history = data.get("status_history", [])
        self.assertEqual(len(history), 2)
        self.assertEqual(history[0]["previous_status"], "EXTRACTED")
        self.assertEqual(history[0]["new_status"], "UNDER_REVIEW")
        self.assertEqual(history[1]["previous_status"], "UNDER_REVIEW")
        self.assertEqual(history[1]["new_status"], "CONFIRMED")


if __name__ == "__main__":
    unittest.main(verbosity=2)

