"""
Unit tests for Threat Correlation data models.

Phase 4.2B.4 — Threat Correlation & Unified Intelligence Engine.
"""

from datetime import datetime, timedelta, timezone
import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from pydantic import ValidationError

from app.models.ioc import IOCStatus, IOCType
from app.models.threat_correlation import (
    CorrelationConfidence,
    CorrelationConfidenceLevel,
    ThreatCorrelation,
    ThreatCorrelationType,
    UnifiedThreatContext,
)
from app.models.threat_intel import (
    ThreatAssessment,
    ThreatIntelStatus,
    ThreatSeverity,
)


class TestThreatCorrelationModels(unittest.TestCase):
    """Test validation and invariants of Threat Correlation data models."""

    def test_correlation_type_enum(self):
        """Verify all mandatory correlation types exist."""
        expected = {
            "IOC_TO_ANOMALY",
            "IOC_TO_INCIDENT",
            "IOC_TO_ATTACK_CHAIN",
            "IOC_TO_EVENT",
            "THREAT_ASSESSMENT_TO_INCIDENT",
            "THREAT_ASSESSMENT_TO_ATTACK_CHAIN",
        }
        actual = {t.value for t in ThreatCorrelationType}
        self.assertEqual(expected, actual)

    def test_correlation_confidence_score_bounds(self):
        """Verify score is bounded between 0.0 and 1.0."""
        # Valid bounds
        c0 = CorrelationConfidence(score=0.0, correlation_method="test")
        self.assertEqual(c0.score, 0.0)
        self.assertEqual(c0.confidence_level, CorrelationConfidenceLevel.LOW)

        c1 = CorrelationConfidence(score=1.0, correlation_method="test")
        self.assertEqual(c1.score, 1.0)
        self.assertEqual(c1.confidence_level, CorrelationConfidenceLevel.HIGH)

        c_mid = CorrelationConfidence(score=0.55, correlation_method="test")
        self.assertEqual(c_mid.confidence_level, CorrelationConfidenceLevel.MEDIUM)

        # Invalid bounds
        with self.assertRaises(ValidationError):
            CorrelationConfidence(score=-0.01, correlation_method="test")

        with self.assertRaises(ValidationError):
            CorrelationConfidence(score=1.01, correlation_method="test")

    def test_correlation_confidence_invalid_evidence_count(self):
        """Verify negative evidence_count fails validation."""
        with self.assertRaises(ValidationError):
            CorrelationConfidence(score=0.5, evidence_count=-1, correlation_method="test")

        # Non-negative is valid
        c = CorrelationConfidence(score=0.5, evidence_count=0, correlation_method="test")
        self.assertEqual(c.evidence_count, 0)

    def test_correlation_confidence_timezone_awareness(self):
        """Ensure calculated_at / correlated_at must be timezone-aware."""
        naive_dt = datetime(2026, 1, 1, 12, 0, 0)
        with self.assertRaises(ValidationError):
            CorrelationConfidence(
                score=0.8,
                correlation_method="test",
                calculated_at=naive_dt,
            )

        utc_dt = datetime(2026, 1, 1, 12, 0, 0, tzinfo=timezone.utc)
        conf = CorrelationConfidence(
            score=0.8,
            correlation_method="test",
            calculated_at=utc_dt,
        )
        self.assertEqual(conf.calculated_at, utc_dt)
        self.assertEqual(conf.correlated_at, utc_dt)

    def test_threat_correlation_valid_instantiation(self):
        """Verify valid ThreatCorrelation construction with auto-generated ID."""
        now = datetime.now(timezone.utc)
        conf = CorrelationConfidence(
            score=0.85,
            evidence_count=2,
            correlation_method="shared_event",
        )
        corr = ThreatCorrelation(
            correlation_type=ThreatCorrelationType.IOC_TO_EVENT,
            source_id="ioc-12345",
            source_type="ioc",
            target_id="evt-67890",
            target_type="event",
            confidence=conf,
            evidence=["IOC appeared in event line 42"],
            correlation_method="shared_event",
            first_seen=now,
            last_seen=now,
            confirmed=True,
        )
        self.assertTrue(corr.correlation_id.startswith("tc-"))
        self.assertEqual(corr.correlation_type, ThreatCorrelationType.IOC_TO_EVENT)
        self.assertEqual(corr.source_id, "ioc-12345")
        self.assertEqual(corr.target_id, "evt-67890")
        self.assertTrue(corr.confirmed)

    def test_threat_correlation_empty_ids_invalid(self):
        """Verify empty source_id or target_id fails validation."""
        conf = CorrelationConfidence(score=0.5, correlation_method="test")

        with self.assertRaises(ValidationError):
            ThreatCorrelation(
                correlation_type=ThreatCorrelationType.IOC_TO_EVENT,
                source_id="",  # Invalid
                source_type="ioc",
                target_id="evt-1",
                target_type="event",
                confidence=conf,
                correlation_method="test",
            )

        with self.assertRaises(ValidationError):
            ThreatCorrelation(
                correlation_type=ThreatCorrelationType.IOC_TO_EVENT,
                source_id="ioc-1",
                source_type="ioc",
                target_id="",  # Invalid
                target_type="event",
                confidence=conf,
                correlation_method="test",
            )

    def test_threat_correlation_chronology_validation(self):
        """Verify first_seen <= last_seen invariant."""
        conf = CorrelationConfidence(score=0.7, correlation_method="test")
        t_early = datetime(2026, 1, 1, 10, 0, 0, tzinfo=timezone.utc)
        t_late = datetime(2026, 1, 1, 11, 0, 0, tzinfo=timezone.utc)

        # Valid chronology
        corr = ThreatCorrelation(
            correlation_type=ThreatCorrelationType.IOC_TO_ANOMALY,
            source_id="ioc-1",
            source_type="ioc",
            target_id="anom-1",
            target_type="anomaly",
            confidence=conf,
            correlation_method="test",
            first_seen=t_early,
            last_seen=t_late,
        )
        self.assertEqual(corr.first_seen, t_early)
        self.assertEqual(corr.last_seen, t_late)

        # Invalid chronology (first_seen > last_seen)
        with self.assertRaises(ValidationError):
            ThreatCorrelation(
                correlation_type=ThreatCorrelationType.IOC_TO_ANOMALY,
                source_id="ioc-1",
                source_type="ioc",
                target_id="anom-1",
                target_type="anomaly",
                confidence=conf,
                correlation_method="test",
                first_seen=t_late,
                last_seen=t_early,
            )

    def test_threat_correlation_timezone_awareness(self):
        """Verify first_seen, last_seen, and created_at must be timezone-aware."""
        conf = CorrelationConfidence(score=0.7, correlation_method="test")
        naive_dt = datetime(2026, 1, 1, 10, 0, 0)

        with self.assertRaises(ValidationError):
            ThreatCorrelation(
                correlation_type=ThreatCorrelationType.IOC_TO_INCIDENT,
                source_id="ioc-1",
                source_type="ioc",
                target_id="inc-1",
                target_type="incident",
                confidence=conf,
                correlation_method="test",
                first_seen=naive_dt,
            )

    def test_unified_threat_context_model(self):
        """Verify UnifiedThreatContext model instantiation and fields."""
        now = datetime.now(timezone.utc)
        assessment = ThreatAssessment(
            ioc_id="ioc-test",
            ioc_type=IOCType.IPV4,
            ioc_value="198.51.100.42",
            normalized_value="198.51.100.42",
            threat_score=85.0,
            confidence=0.9,
            severity=ThreatSeverity.CRITICAL,
            status=ThreatIntelStatus.MALICIOUS,
        )
        conf = CorrelationConfidence(score=0.95, correlation_method="direct")
        corr = ThreatCorrelation(
            correlation_type=ThreatCorrelationType.IOC_TO_INCIDENT,
            source_id="ioc-test",
            source_type="ioc",
            target_id="inc-99",
            target_type="incident",
            confidence=conf,
            correlation_method="direct",
        )

        ctx = UnifiedThreatContext(
            ioc_id="ioc-test",
            ioc_value="198.51.100.42",
            normalized_value="198.51.100.42",
            ioc_type=IOCType.IPV4,
            analyst_status=IOCStatus.UNDER_REVIEW,
            threat_assessment=assessment,
            related_incidents=[{"incident_id": "inc-99"}],
            correlations=[corr],
            overall_correlation_confidence=0.95,
            investigation_summary={"key_findings": ["Test"]},
            generated_at=now,
        )

        self.assertEqual(ctx.ioc_id, "ioc-test")
        self.assertEqual(ctx.analyst_status, IOCStatus.UNDER_REVIEW)
        self.assertEqual(ctx.threat_assessment.threat_score, 85.0)
        self.assertEqual(len(ctx.correlations), 1)
        self.assertEqual(ctx.overall_correlation_confidence, 0.95)


if __name__ == "__main__":
    unittest.main()
