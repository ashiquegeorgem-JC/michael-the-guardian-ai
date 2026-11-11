"""
Phase 4.2B.1 — Threat Intelligence Data Model Tests

Tests all threat intelligence models and enums for:
- Correct enum definitions and string representations (ThreatIntelStatus, ThreatIntelSource).
- Default field initialization on ThreatIntelResult.
- Timezone awareness enforcement on all timestamp fields.
- Confidence score boundaries (0.0 - 1.0).
- Detection ratio validation (detection_count <= total_engines).
- Expiration chronology validation (expires_at >= queried_at).
- Reputation score boundaries (0.0 - 1.0).
- Automatic secret credential sanitization in raw_metadata.
- Serialization and round-trip deserialization (model_dump / model_validate_json).
- Explicit decoupling of ThreatIntelStatus from IOCStatus.
"""

from datetime import datetime, timedelta, timezone
import os
import sys
import unittest

from pydantic import ValidationError

# ── Path setup ──────────────────────────────────────────────────────────────
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from app.models.ioc import IOCStatus, IOCType
from app.models.threat_intel import (
    ThreatIntelResult,
    ThreatIntelSource,
    ThreatIntelStatus,
    _sanitize_metadata,
)


def _make_ti_result(**overrides) -> ThreatIntelResult:
    """Helper to construct a valid ThreatIntelResult with sensible defaults."""
    now = datetime.now(timezone.utc)
    defaults = {
        "ioc_id": "ioc-test-12345",
        "ioc_type": IOCType.IPV4,
        "ioc_value": "198.51.100.1",
        "normalized_value": "198.51.100.1",
        "provider_name": "offline_mock",
        "status": ThreatIntelStatus.UNKNOWN,
        "confidence": 0.5,
        "source": ThreatIntelSource.OFFLINE_MOCK,
        "queried_at": now,
        "expires_at": now + timedelta(hours=1),
    }
    defaults.update(overrides)
    return ThreatIntelResult(**defaults)


class TestThreatIntelEnums(unittest.TestCase):
    """Test ThreatIntelStatus and ThreatIntelSource enums."""

    def test_threat_intel_status_values(self):
        expected_statuses = {"UNKNOWN", "CLEAN", "SUSPICIOUS", "MALICIOUS", "ERROR"}
        actual_statuses = {s.value for s in ThreatIntelStatus}
        self.assertEqual(expected_statuses, actual_statuses)

    def test_threat_intel_status_is_str_enum(self):
        self.assertEqual(ThreatIntelStatus.CLEAN, "CLEAN")
        self.assertEqual(ThreatIntelStatus.MALICIOUS, "MALICIOUS")
        self.assertEqual(ThreatIntelStatus.SUSPICIOUS, "SUSPICIOUS")
        self.assertEqual(ThreatIntelStatus.UNKNOWN, "UNKNOWN")
        self.assertEqual(ThreatIntelStatus.ERROR, "ERROR")

    def test_threat_intel_status_strictly_decoupled_from_ioc_status(self):
        """Verify ThreatIntelStatus values represent intel findings, distinct from analyst IOCStatus."""
        ioc_statuses = {s.value for s in IOCStatus}
        ti_statuses = {s.value for s in ThreatIntelStatus}
        # IOCStatus has EXTRACTED, UNDER_REVIEW, CONFIRMED, FALSE_POSITIVE
        # None of these should collide with ThreatIntelStatus
        self.assertTrue(ioc_statuses.isdisjoint(ti_statuses))

    def test_threat_intel_source_values(self):
        expected_sources = {
            "offline_mock",
            "virustotal",
            "abuseipdb",
            "urlhaus",
            "greynoise",
            "alienvault",
            "custom",
        }
        actual_sources = {s.value for s in ThreatIntelSource}
        self.assertEqual(expected_sources, actual_sources)


class TestThreatIntelResultDefaults(unittest.TestCase):
    """Test default values and generation for ThreatIntelResult."""

    def test_default_values(self):
        now = datetime.now(timezone.utc)
        result = ThreatIntelResult(
            ioc_id="ioc-abc-001",
            ioc_type=IOCType.DOMAIN,
            ioc_value="evil.example.com",
            normalized_value="evil.example.com",
            provider_name="offline_mock",
        )
        self.assertTrue(result.id.startswith("ti-"))
        self.assertEqual(result.ioc_id, "ioc-abc-001")
        self.assertEqual(result.ioc_type, IOCType.DOMAIN)
        self.assertEqual(result.status, ThreatIntelStatus.UNKNOWN)
        self.assertEqual(result.confidence, 0.0)
        self.assertEqual(result.source, ThreatIntelSource.OFFLINE_MOCK)
        self.assertEqual(result.provider_name, "offline_mock")
        self.assertEqual(result.provider_version, "1.0.0")
        self.assertEqual(result.categories, [])
        self.assertEqual(result.tags, [])
        self.assertIsNone(result.reputation_score)
        self.assertIsNone(result.detection_count)
        self.assertIsNone(result.total_engines)
        self.assertIsNone(result.lookup_latency_ms)
        self.assertIsNone(result.raw_metadata)
        # Dates should be timezone-aware UTC and chronologically ordered
        self.assertIsNotNone(result.queried_at.tzinfo)
        self.assertIsNotNone(result.expires_at.tzinfo)
        self.assertGreaterEqual(result.expires_at, result.queried_at)


class TestThreatIntelResultValidation(unittest.TestCase):
    """Test field and model validation invariants."""

    def test_timezone_awareness_required(self):
        """Naive datetimes must be rejected by validator."""
        naive_dt = datetime(2026, 11, 5, 12, 0, 0)  # No tzinfo
        utc_dt = datetime(2026, 11, 5, 12, 0, 0, tzinfo=timezone.utc)

        # Naive queried_at must fail
        with self.assertRaises(ValidationError):
            _make_ti_result(queried_at=naive_dt)

        # Naive expires_at must fail
        with self.assertRaises(ValidationError):
            _make_ti_result(expires_at=naive_dt)

        # Naive first_seen must fail
        with self.assertRaises(ValidationError):
            _make_ti_result(first_seen=naive_dt)

        # Naive last_seen must fail
        with self.assertRaises(ValidationError):
            _make_ti_result(last_seen=naive_dt)

        # Timezone-aware must succeed
        valid = _make_ti_result(
            queried_at=utc_dt,
            expires_at=utc_dt + timedelta(hours=1),
            first_seen=utc_dt - timedelta(days=30),
            last_seen=utc_dt,
        )
        self.assertEqual(valid.queried_at, utc_dt)

    def test_confidence_bounds(self):
        # 0.0 and 1.0 are valid bounds
        self.assertEqual(_make_ti_result(confidence=0.0).confidence, 0.0)
        self.assertEqual(_make_ti_result(confidence=1.0).confidence, 1.0)
        self.assertEqual(_make_ti_result(confidence=0.75).confidence, 0.75)

        # < 0.0 rejected
        with self.assertRaises(ValidationError):
            _make_ti_result(confidence=-0.01)

        # > 1.0 rejected
        with self.assertRaises(ValidationError):
            _make_ti_result(confidence=1.01)

    def test_reputation_score_bounds(self):
        # 0.0 and 1.0 are valid bounds
        self.assertEqual(_make_ti_result(reputation_score=0.0).reputation_score, 0.0)
        self.assertEqual(_make_ti_result(reputation_score=1.0).reputation_score, 1.0)

        # < 0.0 rejected
        with self.assertRaises(ValidationError):
            _make_ti_result(reputation_score=-0.1)

        # > 1.0 rejected
        with self.assertRaises(ValidationError):
            _make_ti_result(reputation_score=1.1)

    def test_detection_ratio_validation(self):
        # Valid: detection_count <= total_engines
        valid = _make_ti_result(detection_count=5, total_engines=70)
        self.assertEqual(valid.detection_count, 5)
        self.assertEqual(valid.total_engines, 70)

        # Valid: detection_count == total_engines
        equal = _make_ti_result(detection_count=70, total_engines=70)
        self.assertEqual(equal.detection_count, 70)

        # Invalid: detection_count > total_engines
        with self.assertRaises(ValidationError) as ctx:
            _make_ti_result(detection_count=71, total_engines=70)
        self.assertIn("cannot exceed total_engines", str(ctx.exception))

        # Invalid: negative detection count
        with self.assertRaises(ValidationError):
            _make_ti_result(detection_count=-1, total_engines=70)

        # Invalid: negative total_engines
        with self.assertRaises(ValidationError):
            _make_ti_result(detection_count=0, total_engines=-5)

    def test_expiration_chronology_validation(self):
        now = datetime.now(timezone.utc)
        # Valid: expires_at > queried_at
        valid = _make_ti_result(queried_at=now, expires_at=now + timedelta(minutes=5))
        self.assertGreater(valid.expires_at, valid.queried_at)

        # Valid: expires_at == queried_at
        equal = _make_ti_result(queried_at=now, expires_at=now)
        self.assertEqual(equal.expires_at, equal.queried_at)

        # Invalid: expires_at < queried_at
        with self.assertRaises(ValidationError) as ctx:
            _make_ti_result(queried_at=now, expires_at=now - timedelta(seconds=1))
        self.assertIn("cannot be before queried_at", str(ctx.exception))


class TestThreatIntelSanitization(unittest.TestCase):
    """Test recursive secret credential scrubbing in metadata."""

    def test_sanitize_metadata_helper(self):
        raw = {
            "api_key": "secret_key_12345",
            "API-Key": "bearer_abc",
            "safe_field": "hello world",
            "nested": {
                "password": "hunter2",
                "bearer_token": "token987",
                "engine_count": 42,
            },
        }
        sanitized = _sanitize_metadata(raw)
        self.assertEqual(sanitized["api_key"], "[REDACTED]")
        self.assertEqual(sanitized["API-Key"], "[REDACTED]")
        self.assertEqual(sanitized["safe_field"], "hello world")
        self.assertEqual(sanitized["nested"]["password"], "[REDACTED]")
        self.assertEqual(sanitized["nested"]["bearer_token"], "[REDACTED]")
        self.assertEqual(sanitized["nested"]["engine_count"], 42)

    def test_result_sanitizes_raw_metadata_automatically(self):
        result = _make_ti_result(
            raw_metadata={
                "provider_secret": "xyz_super_secret",
                "auth_header": "Bearer token",
                "clean_ip": "198.51.100.1",
            }
        )
        self.assertEqual(result.raw_metadata["provider_secret"], "[REDACTED]")
        self.assertEqual(result.raw_metadata["auth_header"], "[REDACTED]")
        self.assertEqual(result.raw_metadata["clean_ip"], "198.51.100.1")


class TestThreatIntelResultSerialization(unittest.TestCase):
    """Test serialization and deserialization of ThreatIntelResult."""

    def test_json_roundtrip(self):
        original = _make_ti_result(
            status=ThreatIntelStatus.MALICIOUS,
            confidence=0.99,
            reputation_score=0.95,
            detection_count=45,
            total_engines=70,
            categories=["ransomware", "trojan"],
            tags=["lockbit", "high_priority"],
            country="RU",
            asn="AS12345",
        )
        json_data = original.model_dump_json()
        reconstructed = ThreatIntelResult.model_validate_json(json_data)

        self.assertEqual(original.id, reconstructed.id)
        self.assertEqual(original.ioc_id, reconstructed.ioc_id)
        self.assertEqual(original.status, reconstructed.status)
        self.assertEqual(original.confidence, reconstructed.confidence)
        self.assertEqual(original.reputation_score, reconstructed.reputation_score)
        self.assertEqual(original.detection_count, reconstructed.detection_count)
        self.assertEqual(original.total_engines, reconstructed.total_engines)
        self.assertEqual(original.categories, reconstructed.categories)
        self.assertEqual(original.tags, reconstructed.tags)
        self.assertEqual(original.country, reconstructed.country)
        self.assertEqual(original.asn, reconstructed.asn)
        self.assertEqual(original.queried_at, reconstructed.queried_at)
        self.assertEqual(original.expires_at, reconstructed.expires_at)


if __name__ == "__main__":
    unittest.main()

