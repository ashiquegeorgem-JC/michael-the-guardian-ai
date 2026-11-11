"""
Phase 4.2B.2 — Threat Reputation & Scoring Engine Tests

Tests the ThreatReputationEngine for:
- Deterministic scoring of CLEAN indicators (score < 25, severity LOW, high confidence).
- Deterministic scoring of SUSPICIOUS indicators (score 25-59, severity MEDIUM).
- Deterministic scoring of MALICIOUS indicators (score >= 85, severity CRITICAL).
- EICAR test hash evaluation (critical severity, high confidence).
- CRITICAL SECURITY INVARIANT: UNKNOWN must remain UNKNOWN (score 0.0, confidence 0.0, severity UNKNOWN).
- Error isolation: ERROR status results produce UNKNOWN severity and 0.0 confidence.
- Handling partial telemetry: gracefully scores indicators missing engines or reputation.
- Contributing signals auditability: signal contributions sum to total threat score.
- Explainability: human-readable reasons generated from actual signals.
- Non-mutation guarantee: assess_ioc leaves input IOC and IOCStatus untouched.
- Async assessment execution (assess_ioc_async).
"""

import asyncio
from datetime import datetime, timedelta, timezone
import math
import os
import sys
import unittest

# ── Path setup ──────────────────────────────────────────────────────────────
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from app.models.ioc import IOC, IOCStatus, IOCType
from app.models.threat_intel import (
    ThreatAssessment,
    ThreatIntelResult,
    ThreatIntelSource,
    ThreatIntelStatus,
    ThreatSeverity,
)
from app.services.threat_reputation_engine import (
    ThreatReputationEngine,
    threat_reputation_engine,
)


def _build_ioc(ioc_type: IOCType, value: str, status: IOCStatus = IOCStatus.EXTRACTED) -> IOC:
    """Helper to build an IOC for testing."""
    now = datetime.now(timezone.utc)
    return IOC(
        id=f"ioc-{ioc_type.value.lower()}-test",
        ioc_type=ioc_type,
        raw_value=value,
        normalized_value=value.lower(),
        status=status,
        first_seen=now,
        last_seen=now,
    )


class TestThreatReputationEngine(unittest.TestCase):
    """Test suite for deterministic ThreatReputationEngine."""

    def setUp(self):
        self.engine = ThreatReputationEngine()

    def test_singleton_engine_available(self):
        self.assertIsNotNone(threat_reputation_engine)
        self.assertEqual(threat_reputation_engine.ENGINE_VERSION, "1.0.0")

    def test_clean_indicator_scoring(self):
        """Known clean indicators should receive score < 25, LOW severity, and high confidence."""
        clean_result = ThreatIntelResult(
            ioc_id="ioc-clean-ip",
            ioc_type=IOCType.IPV4,
            ioc_value="8.8.8.8",
            normalized_value="8.8.8.8",
            status=ThreatIntelStatus.CLEAN,
            confidence=0.95,
            source=ThreatIntelSource.OFFLINE_MOCK,
            provider_name="offline_mock",
            detection_count=0,
            total_engines=72,
            reputation_score=0.02,
            categories=["dns_resolver", "anycast", "benign"],
            tags=["google_dns", "verified_clean"],
        )

        assessment = self.engine.assess(clean_result)

        self.assertEqual(assessment.status, ThreatIntelStatus.CLEAN)
        self.assertLess(assessment.threat_score, 25.0)
        self.assertEqual(assessment.severity, ThreatSeverity.LOW)
        self.assertGreaterEqual(assessment.confidence, 0.80)

        # Verify reasons mention clean verdict and 0 engines
        reasons_text = " ".join(assessment.reasons)
        self.assertIn("benign", reasons_text.lower())
        self.assertIn("0 of 72", reasons_text)

        # Verify signals sum up to threat_score
        available_signals = [s for s in assessment.contributing_signals if s.available]
        self.assertEqual(len(available_signals), 4)
        signal_sum = sum(s.contribution for s in available_signals)
        self.assertAlmostEqual(assessment.threat_score, signal_sum, delta=0.05)

    def test_suspicious_indicator_scoring(self):
        """Suspicious indicators should receive score in 25-59 range and MEDIUM severity."""
        susp_result = ThreatIntelResult(
            ioc_id="ioc-susp-ip",
            ioc_type=IOCType.IPV4,
            ioc_value="198.51.100.42",
            normalized_value="198.51.100.42",
            status=ThreatIntelStatus.SUSPICIOUS,
            confidence=0.70,
            source=ThreatIntelSource.OFFLINE_MOCK,
            provider_name="offline_mock",
            detection_count=6,
            total_engines=72,
            reputation_score=0.55,
            categories=["scanner", "port_probe", "anomalous_source"],
            tags=["reconnaissance", "unsolicited_traffic"],
        )

        assessment = self.engine.assess(susp_result)

        self.assertEqual(assessment.status, ThreatIntelStatus.SUSPICIOUS)
        self.assertGreaterEqual(assessment.threat_score, 25.0)
        self.assertLess(assessment.threat_score, 60.0)
        self.assertEqual(assessment.severity, ThreatSeverity.MEDIUM)
        self.assertGreaterEqual(assessment.confidence, 0.70)

        # Verify reasons mention suspicious classification and engine ratio
        reasons_text = " ".join(assessment.reasons)
        self.assertIn("suspicious", reasons_text.lower())
        self.assertIn("6 of 72", reasons_text)

    def test_malicious_indicator_scoring(self):
        """Known malicious indicators should receive score >= 85 and CRITICAL severity."""
        malicious_result = ThreatIntelResult(
            ioc_id="ioc-mal-ip",
            ioc_type=IOCType.IPV4,
            ioc_value="185.220.101.5",
            normalized_value="185.220.101.5",
            status=ThreatIntelStatus.MALICIOUS,
            confidence=0.95,
            source=ThreatIntelSource.OFFLINE_MOCK,
            provider_name="offline_mock",
            detection_count=54,
            total_engines=72,
            reputation_score=0.92,
            categories=["c2_server", "brute_force", "tor_exit"],
            tags=["active_threat", "botnet_node"],
        )

        assessment = self.engine.assess(malicious_result)

        self.assertEqual(assessment.status, ThreatIntelStatus.MALICIOUS)
        self.assertGreaterEqual(assessment.threat_score, 85.0)
        self.assertEqual(assessment.severity, ThreatSeverity.CRITICAL)
        self.assertGreaterEqual(assessment.confidence, 0.90)

        # Verify reasons mention malicious classification, C2 taxonomy, and high engine detections
        reasons_text = " ".join(assessment.reasons)
        self.assertIn("malicious", reasons_text.lower())
        self.assertIn("c2_server", reasons_text.lower())
        self.assertIn("54 of 72", reasons_text)

    def test_eicar_test_hash_scoring(self):
        """EICAR test signatures should be recognized as critical threats."""
        eicar_result = ThreatIntelResult(
            ioc_id="ioc-eicar-sha256",
            ioc_type=IOCType.SHA256,
            ioc_value="275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f",
            normalized_value="275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f",
            status=ThreatIntelStatus.MALICIOUS,
            confidence=1.0,
            source=ThreatIntelSource.OFFLINE_MOCK,
            provider_name="offline_mock",
            detection_count=68,
            total_engines=70,
            reputation_score=1.0,
            categories=["test_virus", "eicar_standard_av_test"],
            tags=["eicar", "av_test_file"],
        )

        assessment = self.engine.assess(eicar_result)

        self.assertEqual(assessment.status, ThreatIntelStatus.MALICIOUS)
        self.assertGreaterEqual(assessment.threat_score, 95.0)
        self.assertEqual(assessment.severity, ThreatSeverity.CRITICAL)
        self.assertAlmostEqual(assessment.confidence, 1.0, places=1)

    def test_critical_security_invariant_unknown_remains_unknown(self):
        """UNKNOWN indicators must NEVER resolve to CLEAN or receive false reassurance."""
        unknown_result = ThreatIntelResult(
            ioc_id="ioc-unmapped-ip",
            ioc_type=IOCType.IPV4,
            ioc_value="203.0.113.199",
            normalized_value="203.0.113.199",
            status=ThreatIntelStatus.UNKNOWN,
            confidence=0.0,
            source=ThreatIntelSource.OFFLINE_MOCK,
            provider_name="offline_mock",
            detection_count=0,
            total_engines=0,
            reputation_score=None,
            categories=[],
            tags=["unknown_indicator"],
        )

        assessment = self.engine.assess(unknown_result)

        self.assertEqual(assessment.status, ThreatIntelStatus.UNKNOWN)
        self.assertEqual(assessment.threat_score, 0.0)
        self.assertEqual(assessment.confidence, 0.0)
        self.assertEqual(assessment.severity, ThreatSeverity.UNKNOWN)

        # Verify reasons state unclassified status explicitly
        reasons_text = " ".join(assessment.reasons)
        self.assertIn("unclassified", reasons_text.lower())
        self.assertIn("rather than being treated as clean", reasons_text.lower())

        # Verify signals are marked unavailable
        for signal in assessment.contributing_signals:
            self.assertFalse(signal.available)
            self.assertEqual(signal.contribution, 0.0)

    def test_error_status_isolation(self):
        """ERROR status results must produce UNKNOWN severity and 0.0 confidence."""
        error_result = ThreatIntelResult(
            ioc_id="ioc-err-ip",
            ioc_type=IOCType.IPV4,
            ioc_value="10.0.0.1",
            normalized_value="10.0.0.1",
            status=ThreatIntelStatus.ERROR,
            confidence=0.0,
            source=ThreatIntelSource.CUSTOM,
            provider_name="failing_provider",
            raw_metadata={"error": "Connection timed out"},
        )

        assessment = self.engine.assess(error_result)

        self.assertEqual(assessment.status, ThreatIntelStatus.ERROR)
        self.assertEqual(assessment.threat_score, 0.0)
        self.assertEqual(assessment.confidence, 0.0)
        self.assertEqual(assessment.severity, ThreatSeverity.UNKNOWN)

    def test_partial_telemetry_scoring(self):
        """Indicators with missing engine counts or reputation should still be scored cleanly without errors."""
        partial_result = ThreatIntelResult(
            ioc_id="ioc-partial-ip",
            ioc_type=IOCType.IPV4,
            ioc_value="198.51.100.99",
            normalized_value="198.51.100.99",
            status=ThreatIntelStatus.MALICIOUS,
            confidence=0.60,
            source=ThreatIntelSource.OFFLINE_MOCK,
            provider_name="offline_mock",
            detection_count=None,
            total_engines=None,
            reputation_score=None,
            categories=[],
        )

        assessment = self.engine.assess(partial_result)

        self.assertEqual(assessment.status, ThreatIntelStatus.MALICIOUS)
        # Evaluated purely on provider_status (100 points)
        self.assertEqual(assessment.threat_score, 100.0)
        # Confidence is lower due to missing telemetry
        self.assertLess(assessment.confidence, 0.60)
        self.assertEqual(assessment.severity, ThreatSeverity.CRITICAL)

        # Check signals
        status_sig = next(s for s in assessment.contributing_signals if s.signal_name == "provider_status")
        engine_sig = next(s for s in assessment.contributing_signals if s.signal_name == "detection_ratio")
        self.assertTrue(status_sig.available)
        self.assertFalse(engine_sig.available)

    def test_assess_ioc_integration_and_non_mutation(self):
        """Verify assess_ioc coordinates through ThreatIntelService without mutating input IOC."""
        initial_status = IOCStatus.UNDER_REVIEW
        ioc = _build_ioc(IOCType.IPV4, "8.8.8.8", status=initial_status)

        assessment = self.engine.assess_ioc(ioc)

        # Assessment is CLEAN / LOW
        self.assertEqual(assessment.status, ThreatIntelStatus.CLEAN)
        self.assertEqual(assessment.severity, ThreatSeverity.LOW)
        self.assertLess(assessment.threat_score, 25.0)

        # Invariant check: IOC instance and IOCStatus remain completely unchanged
        self.assertEqual(ioc.status, IOCStatus.UNDER_REVIEW)
        self.assertEqual(ioc.raw_value, "8.8.8.8")
        self.assertEqual(ioc.normalized_value, "8.8.8.8")

    def test_assess_ioc_async(self):
        """Verify async assessment execution."""
        async def run_async():
            ioc = _build_ioc(IOCType.IPV4, "185.220.101.5")
            return await self.engine.assess_ioc_async(ioc)

        assessment = asyncio.run(run_async())
        self.assertIsInstance(assessment, ThreatAssessment)
        self.assertEqual(assessment.status, ThreatIntelStatus.MALICIOUS)
        self.assertEqual(assessment.severity, ThreatSeverity.CRITICAL)


if __name__ == "__main__":
    unittest.main()
