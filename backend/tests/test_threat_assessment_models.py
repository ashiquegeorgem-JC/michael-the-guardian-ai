"""
Phase 4.2B.2 — Threat Assessment & Scoring Data Model Tests

Tests all threat assessment models and enums for:
- Correct enum definitions and string representations (ThreatSeverity).
- ContributingSignal model field validation and boundaries.
- ThreatAssessment default fields and initialization.
- Timezone awareness validation on timestamps (assessed_at, expires_at).
- Threat score boundaries (0.0 - 100.0).
- Confidence boundaries (0.0 - 1.0).
- Expiration chronology validation (expires_at >= assessed_at).
- Secret scrubbing in raw_metadata.
- Serialization and JSON round-trip deserialization.
"""

from datetime import datetime, timedelta, timezone
import os
import sys
import unittest

from pydantic import ValidationError

# ── Path setup ──────────────────────────────────────────────────────────────
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from app.models.ioc import IOCType
from app.models.threat_intel import (
    ContributingSignal,
    ThreatAssessment,
    ThreatIntelStatus,
    ThreatSeverity,
)


def _make_assessment(**overrides) -> ThreatAssessment:
    """Helper to construct a valid ThreatAssessment with sensible defaults."""
    now = datetime.now(timezone.utc)
    defaults = {
        "ioc_id": "ioc-test-9999",
        "ioc_type": IOCType.IPV4,
        "ioc_value": "198.51.100.1",
        "normalized_value": "198.51.100.1",
        "threat_score": 45.0,
        "confidence": 0.85,
        "severity": ThreatSeverity.MEDIUM,
        "status": ThreatIntelStatus.SUSPICIOUS,
        "reasons": ["Test suspicious assessment reason."],
        "contributing_signals": [
            ContributingSignal(
                signal_name="provider_status",
                value="SUSPICIOUS",
                weight=0.35,
                contribution=17.5,
                explanation="Provider flagged suspicious activity",
                available=True,
            )
        ],
        "assessed_at": now,
        "expires_at": now + timedelta(hours=1),
    }
    defaults.update(overrides)
    return ThreatAssessment(**defaults)


class TestThreatSeverityEnum(unittest.TestCase):
    """Test ThreatSeverity enum definitions."""

    def test_severity_values(self):
        expected_severities = {"UNKNOWN", "LOW", "MEDIUM", "HIGH", "CRITICAL"}
        actual_severities = {s.value for s in ThreatSeverity}
        self.assertEqual(expected_severities, actual_severities)

    def test_severity_is_str_enum(self):
        self.assertEqual(ThreatSeverity.UNKNOWN, "UNKNOWN")
        self.assertEqual(ThreatSeverity.LOW, "LOW")
        self.assertEqual(ThreatSeverity.MEDIUM, "MEDIUM")
        self.assertEqual(ThreatSeverity.HIGH, "HIGH")
        self.assertEqual(ThreatSeverity.CRITICAL, "CRITICAL")


class TestContributingSignalModel(unittest.TestCase):
    """Test ContributingSignal model validation."""

    def test_valid_signal(self):
        signal = ContributingSignal(
            signal_name="detection_ratio",
            value=0.75,
            weight=0.30,
            contribution=22.5,
            explanation="54 of 72 engines detected malicious behavior",
            available=True,
        )
        self.assertEqual(signal.signal_name, "detection_ratio")
        self.assertEqual(signal.value, 0.75)
        self.assertEqual(signal.weight, 0.30)
        self.assertEqual(signal.contribution, 22.5)
        self.assertTrue(signal.available)

    def test_signal_weight_bounds(self):
        # 0.0 and 1.0 are valid
        self.assertEqual(ContributingSignal(signal_name="s", value=0, weight=0.0, contribution=0, explanation="").weight, 0.0)
        self.assertEqual(ContributingSignal(signal_name="s", value=0, weight=1.0, contribution=0, explanation="").weight, 1.0)

        # < 0.0 rejected
        with self.assertRaises(ValidationError):
            ContributingSignal(signal_name="s", value=0, weight=-0.01, contribution=0, explanation="")

        # > 1.0 rejected
        with self.assertRaises(ValidationError):
            ContributingSignal(signal_name="s", value=0, weight=1.01, contribution=0, explanation="")

    def test_signal_contribution_bounds(self):
        # 0.0 and 100.0 are valid
        self.assertEqual(ContributingSignal(signal_name="s", value=0, weight=0.5, contribution=0.0, explanation="").contribution, 0.0)
        self.assertEqual(ContributingSignal(signal_name="s", value=0, weight=0.5, contribution=100.0, explanation="").contribution, 100.0)

        # < 0.0 rejected
        with self.assertRaises(ValidationError):
            ContributingSignal(signal_name="s", value=0, weight=0.5, contribution=-1.0, explanation="")

        # > 100.0 rejected
        with self.assertRaises(ValidationError):
            ContributingSignal(signal_name="s", value=0, weight=0.5, contribution=100.5, explanation="")


class TestThreatAssessmentValidation(unittest.TestCase):
    """Test ThreatAssessment field boundaries and invariants."""

    def test_default_values(self):
        now = datetime.now(timezone.utc)
        assessment = ThreatAssessment(
            ioc_id="ioc-123",
            ioc_type=IOCType.DOMAIN,
            ioc_value="test.example",
            normalized_value="test.example",
        )
        self.assertTrue(assessment.assessment_id.startswith("ta-"))
        self.assertEqual(assessment.threat_score, 0.0)
        self.assertEqual(assessment.confidence, 0.0)
        self.assertEqual(assessment.severity, ThreatSeverity.UNKNOWN)
        self.assertEqual(assessment.status, ThreatIntelStatus.UNKNOWN)
        self.assertEqual(assessment.reasons, [])
        self.assertEqual(assessment.contributing_signals, [])
        self.assertEqual(assessment.engine_version, "1.0.0")
        self.assertIsNotNone(assessment.assessed_at.tzinfo)
        self.assertIsNotNone(assessment.expires_at.tzinfo)
        self.assertGreaterEqual(assessment.expires_at, assessment.assessed_at)

    def test_threat_score_bounds(self):
        # 0.0 and 100.0 are valid bounds
        self.assertEqual(_make_assessment(threat_score=0.0).threat_score, 0.0)
        self.assertEqual(_make_assessment(threat_score=100.0).threat_score, 100.0)
        self.assertEqual(_make_assessment(threat_score=67.5).threat_score, 67.5)

        # < 0.0 rejected
        with self.assertRaises(ValidationError):
            _make_assessment(threat_score=-0.1)

        # > 100.0 rejected
        with self.assertRaises(ValidationError):
            _make_assessment(threat_score=100.1)

    def test_confidence_bounds(self):
        # 0.0 and 1.0 are valid bounds
        self.assertEqual(_make_assessment(confidence=0.0).confidence, 0.0)
        self.assertEqual(_make_assessment(confidence=1.0).confidence, 1.0)
        self.assertEqual(_make_assessment(confidence=0.88).confidence, 0.88)

        # < 0.0 rejected
        with self.assertRaises(ValidationError):
            _make_assessment(confidence=-0.01)

        # > 1.0 rejected
        with self.assertRaises(ValidationError):
            _make_assessment(confidence=1.01)

    def test_timezone_awareness_required(self):
        naive_dt = datetime(2026, 11, 5, 12, 0, 0)
        utc_dt = datetime(2026, 11, 5, 12, 0, 0, tzinfo=timezone.utc)

        # Naive assessed_at rejected
        with self.assertRaises(ValidationError):
            _make_assessment(assessed_at=naive_dt)

        # Naive expires_at rejected
        with self.assertRaises(ValidationError):
            _make_assessment(expires_at=naive_dt)

        # Aware succeeds
        valid = _make_assessment(assessed_at=utc_dt, expires_at=utc_dt + timedelta(hours=1))
        self.assertEqual(valid.assessed_at, utc_dt)

    def test_expiration_chronology_validation(self):
        now = datetime.now(timezone.utc)
        # expires_at < assessed_at rejected
        with self.assertRaises(ValidationError) as ctx:
            _make_assessment(assessed_at=now, expires_at=now - timedelta(seconds=1))
        self.assertIn("cannot be before assessed_at", str(ctx.exception))

    def test_raw_metadata_secret_scrubbing(self):
        assessment = _make_assessment(
            raw_metadata={
                "api_key": "secret_abc_123",
                "normal_field": "safe",
                "nested": {"token": "secret_bearer_token"},
            }
        )
        self.assertEqual(assessment.raw_metadata["api_key"], "[REDACTED]")
        self.assertEqual(assessment.raw_metadata["normal_field"], "safe")
        self.assertEqual(assessment.raw_metadata["nested"]["token"], "[REDACTED]")

    def test_json_roundtrip(self):
        orig = _make_assessment()
        json_str = orig.model_dump_json()
        restored = ThreatAssessment.model_validate_json(json_str)

        self.assertEqual(orig.assessment_id, restored.assessment_id)
        self.assertEqual(orig.threat_score, restored.threat_score)
        self.assertEqual(orig.confidence, restored.confidence)
        self.assertEqual(orig.severity, restored.severity)
        self.assertEqual(orig.status, restored.status)
        self.assertEqual(len(orig.contributing_signals), len(restored.contributing_signals))
        self.assertEqual(orig.contributing_signals[0].signal_name, restored.contributing_signals[0].signal_name)


if __name__ == "__main__":
    unittest.main()

