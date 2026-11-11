"""
Phase 4.2A.4 — IOC Repository Tests

Tests IOCRepository and SessionStore integration for:
- Basic CRUD operations: add_ioc, get_ioc, get_ioc_by_normalized_value, list_iocs.
- Index-based query operations:
  - find_iocs_by_session
  - find_iocs_by_event
  - find_iocs_by_anomaly
  - find_iocs_by_incident
  - find_iocs_by_attack_chain
- Canonical deduplication:
  - IOCType + normalized_value primary identity
  - Same IOC with different raw formatting (10.001.020.005 vs 10.1.20.5)
  - Duplicate occurrence count incrementing
  - Time window aggregation (first_seen / last_seen)
  - Exact duplicate evidence suppression
  - Distinct evidence append-only preservation
- Cross-session behavior:
  - Same normalized IOC appearing in multiple sessions
  - Single canonical record with multiple source_sessions
  - Independent session lookups
- SessionStore synchronization:
  - store.iocs and store.session_iocs accurate reflection
  - dashboard stats total_iocs accurate count
- Safety & Verdict immutability:
  - Status remains EXTRACTED (no verdict contamination)
  - No external network access
"""

from datetime import datetime
import os
import sys
import unittest
import uuid

# Path setup
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from app.models.ioc import (
    IOC,
    IOCEvidence,
    IOCStatus,
    IOCType,
)
from app.services.ioc_repository import IOCRepository
from app.services.store import SessionStore


class TestIOCRepository(unittest.TestCase):

    def setUp(self):
        # Create an isolated SessionStore and IOCRepository instance for testing
        self.mock_store = SessionStore()
        self.repo = IOCRepository(session_store=self.mock_store)

        self.t1 = datetime(2024, 1, 1, 10, 0, 0)
        self.t2 = datetime(2024, 1, 1, 10, 30, 0)

    # ─────────────────────────────────────────────────────────────────────────
    # 1. Basic CRUD Operations
    # ─────────────────────────────────────────────────────────────────────────

    def test_01_add_and_get_ioc_by_id(self):
        """Can add an IOC and retrieve it by its unique ID."""
        ioc = IOC(
            ioc_type=IOCType.IPV4,
            raw_value="198.51.100.1",
            normalized_value="198.51.100.1",
        )
        saved = self.repo.add_ioc(ioc)
        self.assertEqual(saved.id, ioc.id)

        retrieved = self.repo.get_ioc(ioc.id)
        self.assertIsNotNone(retrieved)
        self.assertEqual(retrieved.normalized_value, "198.51.100.1")

    def test_02_get_ioc_by_normalized_value(self):
        """Lookup by canonical key (IOCType + normalized_value)."""
        ioc = IOC(
            ioc_type=IOCType.DOMAIN,
            raw_value="evil-c2.net",
            normalized_value="evil-c2.net",
        )
        self.repo.add_ioc(ioc)

        # Lookup with Enum
        res1 = self.repo.get_ioc_by_normalized_value(IOCType.DOMAIN, "evil-c2.net")
        self.assertIsNotNone(res1)
        self.assertEqual(res1.id, ioc.id)

        # Lookup with string type
        res2 = self.repo.get_ioc_by_normalized_value("domain", "evil-c2.net")
        self.assertIsNotNone(res2)
        self.assertEqual(res2.id, ioc.id)

        # Non-matching value
        res3 = self.repo.get_ioc_by_normalized_value(IOCType.DOMAIN, "benign.com")
        self.assertIsNone(res3)

    def test_03_list_iocs(self):
        """list_iocs returns all stored IOCs."""
        ioc1 = IOC(ioc_type=IOCType.IPV4, raw_value="10.0.0.1", normalized_value="10.0.0.1")
        ioc2 = IOC(ioc_type=IOCType.MD5, raw_value="5d41402abc4b2a76b9719d911017c592", normalized_value="5d41402abc4b2a76b9719d911017c592")
        self.repo.add_iocs([ioc1, ioc2])

        all_iocs = self.repo.list_iocs()
        self.assertEqual(len(all_iocs), 2)

    # ─────────────────────────────────────────────────────────────────────────
    # 2. Canonical Deduplication
    # ─────────────────────────────────────────────────────────────────────────

    def test_04_deduplication_same_normalized_identity(self):
        """
        Adding the same normalized IOC twice merges into a single record
        and increments occurrence_count.
        """
        ioc1 = IOC(
            ioc_type=IOCType.IPV4,
            raw_value="10.0.0.1",
            normalized_value="10.0.0.1",
            occurrence_count=1,
            first_seen=self.t1,
            last_seen=self.t1,
        )
        ioc2 = IOC(
            ioc_type=IOCType.IPV4,
            raw_value="10.0.0.1",
            normalized_value="10.0.0.1",
            occurrence_count=1,
            first_seen=self.t2,
            last_seen=self.t2,
        )

        self.repo.add_ioc(ioc1)
        merged = self.repo.add_ioc(ioc2)

        self.assertEqual(len(self.repo.list_iocs()), 1)
        self.assertEqual(merged.id, ioc1.id)
        self.assertEqual(merged.occurrence_count, 2)
        self.assertEqual(merged.first_seen, self.t1)
        self.assertEqual(merged.last_seen, self.t2)

    def test_05_deduplication_different_raw_same_normalized(self):
        """
        Two candidates with different raw values that normalize to the same canonical value
        (e.g. 10.001.020.005 and 10.1.20.5) merge into one IOC record.
        """
        ev1 = IOCEvidence(event_id="e1", session_id="s1", raw_value="10.001.020.005", line_number=1)
        ioc1 = IOC(
            ioc_type=IOCType.IPV4,
            raw_value="10.001.020.005",
            normalized_value="10.1.20.5",
            evidence_references=[ev1],
        )

        ev2 = IOCEvidence(event_id="e2", session_id="s1", raw_value="10.1.20.5", line_number=2)
        ioc2 = IOC(
            ioc_type=IOCType.IPV4,
            raw_value="10.1.20.5",
            normalized_value="10.1.20.5",
            evidence_references=[ev2],
        )

        self.repo.add_ioc(ioc1)
        merged = self.repo.add_ioc(ioc2)

        self.assertEqual(len(self.repo.list_iocs()), 1)
        self.assertEqual(merged.occurrence_count, 2)
        # Both distinct raw evidence references are preserved
        self.assertEqual(len(merged.evidence_references), 2)
        self.assertEqual(merged.evidence_references[0].raw_value, "10.001.020.005")
        self.assertEqual(merged.evidence_references[1].raw_value, "10.1.20.5")

    def test_06_exact_duplicate_evidence_suppressed(self):
        """Re-submitting the exact same evidence occurrence does not create redundant duplicate evidence."""
        ev = IOCEvidence(event_id="e1", session_id="s1", raw_value="10.0.0.1", line_number=1, source_field="raw_line")
        ioc1 = IOC(
            ioc_type=IOCType.IPV4,
            raw_value="10.0.0.1",
            normalized_value="10.0.0.1",
            evidence_references=[ev],
        )
        ioc2 = IOC(
            ioc_type=IOCType.IPV4,
            raw_value="10.0.0.1",
            normalized_value="10.0.0.1",
            evidence_references=[ev],
        )

        self.repo.add_ioc(ioc1)
        merged = self.repo.add_ioc(ioc2)

        # Evidence list does not duplicate the identical entry
        self.assertEqual(len(merged.evidence_references), 1)

    # ─────────────────────────────────────────────────────────────────────────
    # 3. Cross-Session Aggregation
    # ─────────────────────────────────────────────────────────────────────────

    def test_07_cross_session_ioc_aggregation(self):
        """
        The same normalized IOC appearing in Session A and Session B merges into
        one record with source_sessions = ['sess-A', 'sess-B'].
        """
        ev_a = IOCEvidence(event_id="ea", session_id="sess-A", raw_value="198.51.100.20")
        ioc_a = IOC(
            ioc_type=IOCType.IPV4,
            raw_value="198.51.100.20",
            normalized_value="198.51.100.20",
            source_sessions=["sess-A"],
            evidence_references=[ev_a],
        )

        ev_b = IOCEvidence(event_id="eb", session_id="sess-B", raw_value="198.51.100.20")
        ioc_b = IOC(
            ioc_type=IOCType.IPV4,
            raw_value="198.51.100.20",
            normalized_value="198.51.100.20",
            source_sessions=["sess-B"],
            evidence_references=[ev_b],
        )

        self.repo.add_ioc(ioc_a)
        merged = self.repo.add_ioc(ioc_b)

        self.assertEqual(len(self.repo.list_iocs()), 1)
        self.assertIn("sess-A", merged.source_sessions)
        self.assertIn("sess-B", merged.source_sessions)
        self.assertEqual(merged.occurrence_count, 2)
        self.assertEqual(len(merged.evidence_references), 2)

    def test_08_find_iocs_by_session(self):
        """find_iocs_by_session retrieves IOCs observed in that session."""
        ioc_a = IOC(ioc_type=IOCType.IPV4, raw_value="1.1.1.1", normalized_value="1.1.1.1", source_sessions=["sess-A"])
        ioc_b = IOC(ioc_type=IOCType.IPV4, raw_value="2.2.2.2", normalized_value="2.2.2.2", source_sessions=["sess-B"])
        self.repo.add_iocs([ioc_a, ioc_b])

        res_a = self.repo.find_iocs_by_session("sess-A")
        self.assertEqual(len(res_a), 1)
        self.assertEqual(res_a[0].normalized_value, "1.1.1.1")

        res_b = self.repo.find_iocs_by_session("sess-B")
        self.assertEqual(len(res_b), 1)
        self.assertEqual(res_b[0].normalized_value, "2.2.2.2")

        res_none = self.repo.find_iocs_by_session("sess-unknown")
        self.assertEqual(len(res_none), 0)

    # ─────────────────────────────────────────────────────────────────────────
    # 4. Relationship Lookups (Event, Anomaly, Incident, Attack Chain)
    # ─────────────────────────────────────────────────────────────────────────

    def test_09_find_iocs_by_event(self):
        """find_iocs_by_event retrieves IOCs originating from a specific event ID."""
        ev = IOCEvidence(event_id="ev-100", session_id="s1", raw_value="evil.com")
        ioc = IOC(ioc_type=IOCType.DOMAIN, raw_value="evil.com", normalized_value="evil.com", evidence_references=[ev])
        self.repo.add_ioc(ioc)

        res = self.repo.find_iocs_by_event("ev-100")
        self.assertEqual(len(res), 1)
        self.assertEqual(res[0].normalized_value, "evil.com")

        self.assertEqual(len(self.repo.find_iocs_by_event("ev-unrelated")), 0)

    def test_10_find_iocs_by_anomaly(self):
        """find_iocs_by_anomaly retrieves IOCs associated with an anomaly ID."""
        ev = IOCEvidence(event_id="e1", session_id="s1", raw_value="10.0.0.1", anomaly_id="anom-42")
        ioc = IOC(
            ioc_type=IOCType.IPV4,
            raw_value="10.0.0.1",
            normalized_value="10.0.0.1",
            associated_anomaly_ids=["anom-42"],
            evidence_references=[ev],
        )
        self.repo.add_ioc(ioc)

        res = self.repo.find_iocs_by_anomaly("anom-42")
        self.assertEqual(len(res), 1)
        self.assertEqual(res[0].normalized_value, "10.0.0.1")

        self.assertEqual(len(self.repo.find_iocs_by_anomaly("anom-none")), 0)

    def test_11_find_iocs_by_incident(self):
        """find_iocs_by_incident retrieves IOCs associated with an incident ID."""
        ev = IOCEvidence(event_id="e1", session_id="s1", raw_value="10.0.0.1", incident_id="inc-99")
        ioc = IOC(
            ioc_type=IOCType.IPV4,
            raw_value="10.0.0.1",
            normalized_value="10.0.0.1",
            associated_incident_ids=["inc-99"],
            evidence_references=[ev],
        )
        self.repo.add_ioc(ioc)

        res = self.repo.find_iocs_by_incident("inc-99")
        self.assertEqual(len(res), 1)
        self.assertEqual(res[0].normalized_value, "10.0.0.1")

    def test_12_find_iocs_by_attack_chain(self):
        """find_iocs_by_attack_chain retrieves IOCs associated with an attack chain ID."""
        ev = IOCEvidence(event_id="e1", session_id="s1", raw_value="10.0.0.1", chain_link_event_id="link-7")
        ioc = IOC(
            ioc_type=IOCType.IPV4,
            raw_value="10.0.0.1",
            normalized_value="10.0.0.1",
            associated_chain_ids=["chain-777"],
            evidence_references=[ev],
        )
        self.repo.add_ioc(ioc)

        res = self.repo.find_iocs_by_attack_chain("chain-777")
        self.assertEqual(len(res), 1)
        self.assertEqual(res[0].normalized_value, "10.0.0.1")

    # ─────────────────────────────────────────────────────────────────────────
    # 5. SessionStore Synchronization
    # ─────────────────────────────────────────────────────────────────────────

    def test_13_session_store_synchronization(self):
        """Repository operations keep SessionStore.iocs and session_iocs synchronized."""
        ioc = IOC(
            ioc_type=IOCType.URL,
            raw_value="http://evil.com/payload.sh",
            normalized_value="http://evil.com/payload.sh",
            source_sessions=["sess-sync"],
        )
        self.repo.add_ioc(ioc)

        # Verify SessionStore contains the IOC
        self.assertIn(ioc.id, self.mock_store.iocs)
        self.assertEqual(self.mock_store.get_ioc(ioc.id).normalized_value, "http://evil.com/payload.sh")
        self.assertEqual(len(self.mock_store.get_iocs("sess-sync")), 1)

        # Verify dashboard stats
        stats = self.mock_store.get_dashboard_stats()
        self.assertEqual(stats["total_iocs"], 1)

    # ─────────────────────────────────────────────────────────────────────────
    # 6. Safety & Immutability
    # ─────────────────────────────────────────────────────────────────────────

    def test_14_no_verdict_contamination(self):
        """
        Associating an IOC with an anomaly, incident, or attack chain must NOT
        change its status to CONFIRMED or mark it malicious.
        """
        ioc = IOC(
            ioc_type=IOCType.IPV4,
            raw_value="198.51.100.1",
            normalized_value="198.51.100.1",
            status=IOCStatus.EXTRACTED,
            associated_chain_ids=["chain-critical"],
        )
        saved = self.repo.add_ioc(ioc)
        self.assertEqual(saved.status, IOCStatus.EXTRACTED)

    def test_15_clear_repository(self):
        """clear() removes all in-memory entities and indexes."""
        ioc = IOC(ioc_type=IOCType.IPV4, raw_value="1.1.1.1", normalized_value="1.1.1.1", source_sessions=["s1"])
        self.repo.add_ioc(ioc)
        self.assertEqual(len(self.repo.list_iocs()), 1)

        self.repo.clear()
        self.assertEqual(len(self.repo.list_iocs()), 0)
        self.assertEqual(len(self.repo.find_iocs_by_session("s1")), 0)

    def test_16_merge_tags_and_methods_union(self):
        """Merging IOC instances unions tags and extraction_methods without duplicates."""
        ioc1 = IOC(
            ioc_type=IOCType.IPV4,
            raw_value="10.0.0.1",
            normalized_value="10.0.0.1",
            tags=["c2"],
            extraction_methods=["regex_ipv4"],
        )
        ioc2 = IOC(
            ioc_type=IOCType.IPV4,
            raw_value="10.0.0.1",
            normalized_value="10.0.0.1",
            tags=["lateral-movement", "c2"],
            extraction_methods=["chain_engine", "regex_ipv4"],
        )
        self.repo.add_ioc(ioc1)
        merged = self.repo.add_ioc(ioc2)

        self.assertEqual(sorted(merged.tags), ["c2", "lateral-movement"])
        self.assertEqual(sorted(merged.extraction_methods), ["chain_engine", "regex_ipv4"])

    def test_17_find_iocs_by_type_index(self):
        """Internal type index groups IOCs correctly."""
        ioc1 = IOC(ioc_type=IOCType.IPV4, raw_value="1.1.1.1", normalized_value="1.1.1.1")
        ioc2 = IOC(ioc_type=IOCType.DOMAIN, raw_value="evil.com", normalized_value="evil.com")
        self.repo.add_iocs([ioc1, ioc2])

        self.assertIn(ioc1.id, self.repo._by_type[IOCType.IPV4])
        self.assertIn(ioc2.id, self.repo._by_type[IOCType.DOMAIN])

    def test_18_get_ioc_invalid_canonical_returns_none(self):
        """Searching for an invalid string type returns None safely."""
        res = self.repo.get_ioc_by_normalized_value("invalid_type", "10.0.0.1")
        self.assertIsNone(res)


if __name__ == "__main__":
    unittest.main(verbosity=2)
