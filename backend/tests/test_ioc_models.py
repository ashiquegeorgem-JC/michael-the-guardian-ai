"""
Phase 4.2A.1 — IOC Data Model Tests

Tests every IOC Pydantic model for:
- Correct enum definitions and values.
- Default status (EXTRACTED) on all new IOC objects.
- Confidence boundary enforcement (0.0 – 1.0).
- Invalid IOC type rejection.
- Required field validation.
- Evidence reference serialization and round-trip.
- Duplicate occurrence aggregation compatibility.
- JSON serialization and deserialization (model_dump / model_validate_json).
- model_copy update patterns used by future services.

These tests do NOT import or modify any existing MICHAEL module beyond
app.models.ioc. All existing test suites remain unaffected.
"""

import sys
import os
import unittest
from datetime import datetime, timezone

# ── Path setup ──────────────────────────────────────────────────────────────
# Allow running from project root:  python -m unittest backend/tests/test_ioc_models.py
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from app.models.ioc import (
    IOC,
    IOCEvidence,
    IOCExtractionResult,
    IOCSearchParams,
    IOCSearchResult,
    IOCStatus,
    IOCStatusUpdate,
    IOCSummary,
    IOCType,
)
from pydantic import ValidationError


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

def _make_ioc(**overrides) -> IOC:
    """Return a minimal valid IOC with sensible defaults, accepting keyword overrides."""
    defaults = dict(
        ioc_type=IOCType.IPV4,
        raw_value="192.168.1.100",
        normalized_value="192.168.1.100",
    )
    defaults.update(overrides)
    return IOC(**defaults)


def _make_evidence(**overrides) -> IOCEvidence:
    """Return a minimal valid IOCEvidence."""
    defaults = dict(
        event_id="entry-abc123",
        session_id="sess-001",
        raw_value="192.168.1.100",
    )
    defaults.update(overrides)
    return IOCEvidence(**defaults)


# ─────────────────────────────────────────────────────────────────────────────
# Test Suite
# ─────────────────────────────────────────────────────────────────────────────

class TestIOCModels(unittest.TestCase):

    # ── 01: IOCType enum completeness ────────────────────────────────────────

    def test_01_ioc_type_enum_values(self):
        """All nine IOCType members exist with correct string values."""
        expected = {
            "IPV4":      "ipv4",
            "IPV6":      "ipv6",
            "DOMAIN":    "domain",
            "URL":       "url",
            "MD5":       "md5",
            "SHA1":      "sha1",
            "SHA256":    "sha256",
            "EMAIL":     "email",
            "FILE_PATH": "file_path",
        }
        for name, value in expected.items():
            member = IOCType[name]
            self.assertEqual(member.value, value, f"IOCType.{name} value mismatch")

    # ── 02: IOCStatus enum completeness ──────────────────────────────────────

    def test_02_ioc_status_enum_values(self):
        """All four IOCStatus members exist with correct string values."""
        expected = {
            "EXTRACTED":      "EXTRACTED",
            "UNDER_REVIEW":   "UNDER_REVIEW",
            "CONFIRMED":      "CONFIRMED",
            "FALSE_POSITIVE": "FALSE_POSITIVE",
        }
        for name, value in expected.items():
            member = IOCStatus[name]
            self.assertEqual(member.value, value, f"IOCStatus.{name} value mismatch")

    # ── 03: Default IOC status is EXTRACTED ──────────────────────────────────

    def test_03_default_ioc_status_is_extracted(self):
        """A newly created IOC must default to IOCStatus.EXTRACTED."""
        ioc = _make_ioc()
        self.assertEqual(ioc.status, IOCStatus.EXTRACTED)

    # ── 04: IOC ID format ────────────────────────────────────────────────────

    def test_04_ioc_id_has_correct_prefix(self):
        """IOC IDs must start with 'ioc-' and have a 12-char hex suffix."""
        ioc = _make_ioc()
        self.assertTrue(ioc.id.startswith("ioc-"), f"Unexpected ID: {ioc.id!r}")
        hex_part = ioc.id[len("ioc-"):]
        self.assertEqual(len(hex_part), 12)
        self.assertTrue(all(c in "0123456789abcdef" for c in hex_part))

    # ── 05: Default confidence ───────────────────────────────────────────────

    def test_05_default_confidence_is_0_5(self):
        """Default confidence must be 0.5."""
        ioc = _make_ioc()
        self.assertAlmostEqual(ioc.confidence, 0.5)

    # ── 06: Confidence boundary — valid extremes ──────────────────────────────

    def test_06_confidence_boundary_valid(self):
        """confidence=0.0 and confidence=1.0 must both be accepted."""
        ioc_low  = _make_ioc(confidence=0.0)
        ioc_high = _make_ioc(confidence=1.0)
        self.assertAlmostEqual(ioc_low.confidence, 0.0)
        self.assertAlmostEqual(ioc_high.confidence, 1.0)

    # ── 07: Confidence boundary — invalid values rejected ─────────────────────

    def test_07_confidence_below_zero_rejected(self):
        """confidence < 0.0 must raise ValidationError."""
        with self.assertRaises(ValidationError):
            _make_ioc(confidence=-0.1)

    def test_07b_confidence_above_one_rejected(self):
        """confidence > 1.0 must raise ValidationError."""
        with self.assertRaises(ValidationError):
            _make_ioc(confidence=1.001)

    # ── 08: All nine IOC types can be instantiated ────────────────────────────

    def test_08_all_ioc_types_instantiate(self):
        """Every IOCType value must produce a valid IOC object."""
        samples = {
            IOCType.IPV4:      ("10.0.0.1",                                          "10.0.0.1"),
            IOCType.IPV6:      ("2001:DB8::1",                                       "2001:db8::1"),
            IOCType.DOMAIN:    ("Evil.Example.COM",                                  "evil.example.com"),
            IOCType.URL:       ("HTTPS://Bad.Actor.com/payload",                     "https://bad.actor.com/payload"),
            IOCType.MD5:       ("D41D8CD98F00B204E9800998ECF8427E",                  "d41d8cd98f00b204e9800998ecf8427e"),
            IOCType.SHA1:      ("DA39A3EE5E6B4B0D3255BFEF95601890AFD80709",          "da39a3ee5e6b4b0d3255bfef95601890afd80709"),
            IOCType.SHA256:    ("E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855",
                                "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"),
            IOCType.EMAIL:     ("attacker@evil.com",                                 "attacker@evil.com"),
            IOCType.FILE_PATH: ("/tmp/malware.sh",                                   "/tmp/malware.sh"),
        }
        for ioc_type, (raw, normalized) in samples.items():
            with self.subTest(ioc_type=ioc_type):
                ioc = IOC(ioc_type=ioc_type, raw_value=raw, normalized_value=normalized)
                self.assertEqual(ioc.ioc_type, ioc_type)
                self.assertEqual(ioc.raw_value, raw)
                self.assertEqual(ioc.normalized_value, normalized)

    # ── 09: Invalid IOC type string rejected ─────────────────────────────────

    def test_09_invalid_ioc_type_rejected(self):
        """An unrecognized ioc_type value must raise ValidationError."""
        with self.assertRaises(ValidationError):
            IOC(ioc_type="totally_unknown", raw_value="x", normalized_value="x")

    # ── 10: Empty raw_value rejected ─────────────────────────────────────────

    def test_10_empty_raw_value_rejected(self):
        """An empty or whitespace-only raw_value must raise ValidationError."""
        with self.assertRaises(ValidationError):
            _make_ioc(raw_value="")
        with self.assertRaises(ValidationError):
            _make_ioc(raw_value="   ")

    # ── 11: Empty normalized_value rejected ──────────────────────────────────

    def test_11_empty_normalized_value_rejected(self):
        """An empty or whitespace-only normalized_value must raise ValidationError."""
        with self.assertRaises(ValidationError):
            _make_ioc(normalized_value="")
        with self.assertRaises(ValidationError):
            _make_ioc(normalized_value="\t\n")

    # ── 12: occurrence_count must be >= 1 ────────────────────────────────────

    def test_12_occurrence_count_must_be_at_least_one(self):
        """occurrence_count=0 must raise ValidationError."""
        with self.assertRaises(ValidationError):
            _make_ioc(occurrence_count=0)

    def test_12b_occurrence_count_positive_accepted(self):
        """occurrence_count=5 must be accepted and stored correctly."""
        ioc = _make_ioc(occurrence_count=5)
        self.assertEqual(ioc.occurrence_count, 5)

    # ── 13: IOCEvidence structure ────────────────────────────────────────────

    def test_13_ioc_evidence_fields(self):
        """IOCEvidence must store all provided fields correctly."""
        ts = datetime(2024, 1, 15, 10, 30, 0)
        ev = IOCEvidence(
            event_id="entry-xyz",
            session_id="sess-999",
            timestamp=ts,
            raw_value="10.0.0.99",
            source_field="message",
            line_number=42,
            surrounding_context="failed login from 10.0.0.99 — brute force",
            incident_id="incident-001",
            anomaly_id="anomaly-abc",
        )
        self.assertEqual(ev.event_id, "entry-xyz")
        self.assertEqual(ev.session_id, "sess-999")
        self.assertEqual(ev.timestamp, ts)
        self.assertEqual(ev.raw_value, "10.0.0.99")
        self.assertEqual(ev.source_field, "message")
        self.assertEqual(ev.line_number, 42)
        self.assertIn("10.0.0.99", ev.surrounding_context)
        self.assertEqual(ev.incident_id, "incident-001")
        self.assertEqual(ev.anomaly_id, "anomaly-abc")

    def test_13b_ioc_evidence_defaults(self):
        """Optional IOCEvidence fields must default to None or empty string."""
        ev = _make_evidence()
        self.assertIsNone(ev.timestamp)
        self.assertEqual(ev.source_field, "raw_line")
        self.assertIsNone(ev.line_number)
        self.assertEqual(ev.surrounding_context, "")
        self.assertIsNone(ev.chain_link_event_id)
        self.assertIsNone(ev.incident_id)
        self.assertIsNone(ev.anomaly_id)

    # ── 14: Evidence references attached to IOC ───────────────────────────────

    def test_14_evidence_references_attached(self):
        """IOC must accept and store a list of IOCEvidence objects."""
        ev1 = _make_evidence(event_id="entry-001", line_number=5)
        ev2 = _make_evidence(event_id="entry-002", line_number=10)
        ioc = _make_ioc(evidence_references=[ev1, ev2])
        self.assertEqual(len(ioc.evidence_references), 2)
        self.assertEqual(ioc.evidence_references[0].event_id, "entry-001")
        self.assertEqual(ioc.evidence_references[1].event_id, "entry-002")

    # ── 15: Duplicate occurrence aggregation compatibility ────────────────────

    def test_15_duplicate_aggregation_via_model_copy(self):
        """
        Simulates the merge pattern future services will use:
        - Start with occurrence_count=1 and one evidence link.
        - model_copy to increment count and append a second evidence link.
        - Verify the resulting IOC reflects both occurrences.
        """
        ev1 = _make_evidence(event_id="entry-001", line_number=1)
        ev2 = _make_evidence(event_id="entry-002", line_number=7)

        ioc = _make_ioc(occurrence_count=1, evidence_references=[ev1])
        # Simulate the merge a future IOCRepository.merge() would perform
        merged = ioc.model_copy(update={
            "occurrence_count": ioc.occurrence_count + 1,
            "evidence_references": ioc.evidence_references + [ev2],
            "last_seen": datetime(2024, 6, 1, 0, 0, 0),
        })

        self.assertEqual(merged.occurrence_count, 2)
        self.assertEqual(len(merged.evidence_references), 2)
        self.assertEqual(merged.id, ioc.id)  # ID must be preserved
        self.assertIsNotNone(merged.last_seen)

    # ── 16: model_dump serialization ─────────────────────────────────────────

    def test_16_model_dump_produces_dict(self):
        """model_dump() must produce a dict with correct key names and enum values."""
        ioc = _make_ioc()
        d = ioc.model_dump()
        self.assertIsInstance(d, dict)
        self.assertIn("id", d)
        self.assertIn("ioc_type", d)
        self.assertIn("status", d)
        self.assertIn("confidence", d)
        self.assertIn("evidence_references", d)
        # Enum values must serialize as strings
        self.assertEqual(d["ioc_type"], "ipv4")
        self.assertEqual(d["status"], "EXTRACTED")

    # ── 17: JSON round-trip ───────────────────────────────────────────────────

    def test_17_json_round_trip(self):
        """model_dump_json → model_validate_json must produce an identical IOC."""
        ev = _make_evidence(event_id="entry-rt", line_number=99)
        original = _make_ioc(
            ioc_type=IOCType.SHA256,
            raw_value="E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855",
            normalized_value="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            confidence=0.9,
            occurrence_count=3,
            evidence_references=[ev],
            associated_chain_ids=["chain-abc123456789"],
            tags=["lateral-movement"],
        )
        json_str = original.model_dump_json()
        restored = IOC.model_validate_json(json_str)

        self.assertEqual(restored.id, original.id)
        self.assertEqual(restored.ioc_type, IOCType.SHA256)
        self.assertEqual(restored.status, IOCStatus.EXTRACTED)
        self.assertAlmostEqual(restored.confidence, 0.9)
        self.assertEqual(restored.occurrence_count, 3)
        self.assertEqual(len(restored.evidence_references), 1)
        self.assertEqual(restored.evidence_references[0].event_id, "entry-rt")
        self.assertEqual(restored.associated_chain_ids, ["chain-abc123456789"])
        self.assertEqual(restored.tags, ["lateral-movement"])

    # ── 18: IOCExtractionResult ───────────────────────────────────────────────

    def test_18_extraction_result_defaults(self):
        """IOCExtractionResult must initialise with zero counts and empty lists."""
        result = IOCExtractionResult()
        self.assertEqual(result.total_extracted, 0)
        self.assertEqual(result.unique_iocs, 0)
        self.assertEqual(result.duplicate_count, 0)
        self.assertEqual(result.iocs, [])
        self.assertEqual(result.extraction_errors, [])
        self.assertIsInstance(result.processed_at, datetime)

    def test_18b_extraction_result_with_data(self):
        """IOCExtractionResult must store IOC objects and error strings."""
        ioc = _make_ioc()
        result = IOCExtractionResult(
            total_extracted=5,
            unique_iocs=4,
            duplicate_count=1,
            iocs=[ioc],
            extraction_errors=["Skipped invalid IP: 999.0.0.1"],
        )
        self.assertEqual(result.total_extracted, 5)
        self.assertEqual(result.unique_iocs, 4)
        self.assertEqual(result.duplicate_count, 1)
        self.assertEqual(len(result.iocs), 1)
        self.assertEqual(len(result.extraction_errors), 1)
        self.assertIn("999.0.0.1", result.extraction_errors[0])

    # ── 19: IOCSearchParams defaults ─────────────────────────────────────────

    def test_19_search_params_defaults(self):
        """IOCSearchParams must default to page=1, page_size=50, sort_desc=True."""
        params = IOCSearchParams()
        self.assertIsNone(params.session_id)
        self.assertIsNone(params.ioc_type)
        self.assertIsNone(params.status)
        self.assertIsNone(params.value)
        self.assertEqual(params.page, 1)
        self.assertEqual(params.page_size, 50)
        self.assertTrue(params.sort_desc)
        self.assertEqual(params.sort_by, "first_seen")

    def test_19b_search_params_page_size_boundary(self):
        """page_size > 200 must raise ValidationError."""
        with self.assertRaises(ValidationError):
            IOCSearchParams(page_size=201)

    def test_19c_search_params_page_zero_rejected(self):
        """page=0 must raise ValidationError."""
        with self.assertRaises(ValidationError):
            IOCSearchParams(page=0)

    def test_19d_search_params_min_confidence_boundary(self):
        """min_confidence outside 0.0–1.0 must raise ValidationError."""
        with self.assertRaises(ValidationError):
            IOCSearchParams(min_confidence=1.5)
        with self.assertRaises(ValidationError):
            IOCSearchParams(min_confidence=-0.1)

    # ── 20: IOCStatusUpdate validation ───────────────────────────────────────

    def test_20_status_update_reason_too_short(self):
        """reason shorter than 5 characters must raise ValidationError."""
        with self.assertRaises(ValidationError):
            IOCStatusUpdate(status=IOCStatus.CONFIRMED, reason="ok")

    def test_20b_status_update_valid(self):
        """A valid IOCStatusUpdate must accept all fields and serialize correctly."""
        update = IOCStatusUpdate(
            status=IOCStatus.CONFIRMED,
            reason="Verified against known C2 infrastructure list.",
            changed_by="analyst-jane",
            analyst_note="Matches known APT29 infrastructure.",
        )
        self.assertEqual(update.status, IOCStatus.CONFIRMED)
        d = update.model_dump()
        self.assertEqual(d["status"], "CONFIRMED")

    # ── 21: IOCSummary structure ──────────────────────────────────────────────

    def test_21_ioc_summary_defaults(self):
        """IOCSummary must initialise with all-zero counters and empty collections."""
        summary = IOCSummary()
        self.assertIsNone(summary.session_id)
        self.assertEqual(summary.total_iocs, 0)
        self.assertEqual(summary.by_type, {})
        self.assertEqual(summary.by_status, {})
        self.assertEqual(summary.top_ips, [])
        self.assertEqual(summary.top_domains, [])
        self.assertEqual(summary.top_hashes, [])
        self.assertEqual(summary.chains_with_iocs, 0)
        self.assertEqual(summary.incidents_with_iocs, 0)
        self.assertIsInstance(summary.generated_at, datetime)

    def test_21b_ioc_summary_serializes(self):
        """IOCSummary with data must round-trip through JSON correctly."""
        summary = IOCSummary(
            session_id="sess-abc",
            total_iocs=15,
            by_type={"ipv4": 10, "domain": 5},
            by_status={"EXTRACTED": 13, "CONFIRMED": 2},
            top_ips=[("10.0.0.1", 8), ("10.0.0.2", 3)],
            chains_with_iocs=2,
        )
        d = summary.model_dump()
        self.assertEqual(d["total_iocs"], 15)
        self.assertEqual(d["by_type"]["ipv4"], 10)
        self.assertEqual(d["top_ips"][0], ("10.0.0.1", 8))

    # ── 22: IOCSearchResult structure ─────────────────────────────────────────

    def test_22_search_result_structure(self):
        """IOCSearchResult must correctly store paginated data."""
        ioc = _make_ioc()
        result = IOCSearchResult(
            items=[ioc],
            total=1,
            page=1,
            page_size=50,
            total_pages=1,
        )
        self.assertEqual(result.total, 1)
        self.assertEqual(result.total_pages, 1)
        self.assertEqual(len(result.items), 1)
        self.assertEqual(result.items[0].ioc_type, IOCType.IPV4)

    # ── 23: Mutable defaults are independent per instance ─────────────────────

    def test_23_mutable_fields_not_shared_between_instances(self):
        """
        Lists and dicts must not be shared between separate IOC instances.
        This verifies that default_factory is used correctly.
        """
        ioc_a = _make_ioc()
        ioc_b = _make_ioc()
        ioc_a.associated_chain_ids.append("chain-aaa")
        ioc_a.tags.append("test-tag")
        # ioc_b must not be affected
        self.assertEqual(ioc_b.associated_chain_ids, [])
        self.assertEqual(ioc_b.tags, [])

    # ── 24: Future-enrichment fields are nullable by default ──────────────────

    def test_24_future_enrichment_fields_default_none(self):
        """reputation_score must default to None; mitre_technique_ids to empty list."""
        ioc = _make_ioc()
        self.assertIsNone(ioc.reputation_score)
        self.assertEqual(ioc.mitre_technique_ids, [])

    def test_24b_reputation_score_boundaries(self):
        """reputation_score must be rejected outside 0.0 – 1.0 when provided."""
        ioc_ok = _make_ioc(reputation_score=0.75)
        self.assertAlmostEqual(ioc_ok.reputation_score, 0.75)
        with self.assertRaises(ValidationError):
            _make_ioc(reputation_score=1.1)
        with self.assertRaises(ValidationError):
            _make_ioc(reputation_score=-0.01)

    # ── 25: IOCEvidence JSON round-trip ───────────────────────────────────────

    def test_25_evidence_json_round_trip(self):
        """IOCEvidence must survive model_dump_json → model_validate_json."""
        ts = datetime(2024, 3, 10, 8, 15, 0)
        ev = IOCEvidence(
            event_id="entry-roundtrip",
            session_id="sess-rt",
            timestamp=ts,
            raw_value="evil.example.com",
            source_field="message",
            line_number=55,
            surrounding_context="DNS query to evil.example.com observed",
            chain_link_event_id="chain-link-001",
        )
        json_str = ev.model_dump_json()
        restored = IOCEvidence.model_validate_json(json_str)
        self.assertEqual(restored.event_id, "entry-roundtrip")
        self.assertEqual(restored.session_id, "sess-rt")
        self.assertEqual(restored.raw_value, "evil.example.com")
        self.assertEqual(restored.line_number, 55)
        self.assertEqual(restored.chain_link_event_id, "chain-link-001")


# ─────────────────────────────────────────────────────────────────────────────
# Entry point
# ─────────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    unittest.main(verbosity=2)

