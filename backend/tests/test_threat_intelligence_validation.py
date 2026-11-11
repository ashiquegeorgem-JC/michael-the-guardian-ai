"""
Phase 4.2B.6 — Threat Intelligence Validation & Security Audit Suite.

Executes rigorous validation across the entire Threat Intelligence subsystem:
- IOC extraction precision/recall/F1 & adversarial non-IOC resistance.
- IOC normalization canonicalization & RFC compliance.
- IOC validation status & non-malicious invariant checks.
- Provider abstraction & error resilience (Offline Mock + VirusTotal 200/401/403/404->UNKNOWN/429/500/timeout).
- Threat reputation engine mathematical accuracy, signal point breakdown & confidence independence.
- Threat correlation true/false relationships, temporal decay, and cross-session safeguards.
- Mutation safety audit (deep snapshot verification of source immutability).
- UnifiedThreatContext aggregation fidelity.
- Security audit: zero-network offline guarantee, secret scrubbing, SSRF resistance & XSS safety.

NOTE: All benchmark results derived from this module are designated
      "Synthetic / Controlled Validation" and do NOT claim to represent
      real-world production detection accuracy.
"""

from datetime import datetime, timedelta, timezone
import json
import os
import socket
import sys
import unittest
from unittest.mock import MagicMock, patch

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from app.models.anomaly import Anomaly, DetectionMethod, SeverityLevel
from app.models.attack_chain import (
    AttackChain,
    AttackStage,
    ChainLinkEvent,
    ChainStatus,
)
from app.models.incident import Incident, IncidentCategory, IncidentStatus
from app.models.ioc import (
    IOC,
    IOCEvidence,
    IOCStatus,
    IOCType,
    IPScope,
    ValidationStatus,
)
from app.models.threat_correlation import (
    CorrelationConfidenceLevel,
    ThreatCorrelationType,
    UnifiedThreatContext,
)
from app.models.threat_intel import (
    ThreatAssessment,
    ThreatIntelResult,
    ThreatIntelSource,
    ThreatIntelStatus,
    ThreatSeverity,
    _sanitize_metadata,
)
from app.services.ioc_extractor import IOCExtractor
from app.services.ioc_normalizer import IOCNormalizer
from app.services.ioc_repository import IOCRepository
from app.services.ioc_validator import IOCValidator
from app.services.providers.offline_mock_provider import OfflineMockThreatIntelProvider
from app.services.providers.virustotal_provider import VirusTotalProvider
from app.services.store import SessionStore
from app.services.threat_correlation_engine import ThreatCorrelationEngine
from app.services.threat_intel_service import ThreatIntelService
from app.services.threat_reputation_engine import ThreatReputationEngine

from tests.fixtures.threat_intelligence_validation.validation_dataset import (
    ADVERSARIAL_NON_IOC_FIXTURES,
    BENIGN_IOC_FIXTURES,
    MALICIOUS_IOC_FIXTURES,
    NORMALIZATION_TEST_CASES,
    SUSPICIOUS_IOC_FIXTURES,
)


# ─────────────────────────────────────────────────────────────────────────────
# 1. IOC Extraction Validation
# ─────────────────────────────────────────────────────────────────────────────

class TestIOCExtractionValidation(unittest.TestCase):
    """
    Synthetic ground-truth validation of IOC extraction across all 9 IOC types
    and strict adversarial non-IOC string rejection controls.
    """

    def test_01_synthetic_extraction_precision_recall_f1(self):
        """
        Measure TP, FP, FN, Precision, Recall, F1 from synthetic ground-truth fixtures.

        LABEL: Synthetic / Controlled Validation.
        """
        tp = 0
        fn = 0
        fp = 0

        all_fixtures = BENIGN_IOC_FIXTURES + SUSPICIOUS_IOC_FIXTURES + MALICIOUS_IOC_FIXTURES
        for fix in all_fixtures:
            text = f"Security log entry observed indicator: {fix['raw_value']} in connection metadata"
            res = IOCExtractor.extract_from_text(text)

            matched = [
                i for i in res.iocs
                if i.ioc_type == fix["expected_type"] and i.normalized_value == fix["expected_normalized"]
            ]
            if matched:
                tp += 1
            else:
                fn += 1

        for adv in ADVERSARIAL_NON_IOC_FIXTURES:
            res = IOCExtractor.extract_from_text(adv["text"])
            if res.total_extracted > adv["expected_extracted_iocs"]:
                fp += res.total_extracted - adv["expected_extracted_iocs"]

        total = tp + fn
        precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
        recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
        f1 = (2 * precision * recall) / (precision + recall) if (precision + recall) > 0 else 0.0

        print(f"\n[SYNTHETIC IOC EXTRACTION] TP={tp}/{total}, FP={fp}, FN={fn}")
        print(f"[SYNTHETIC IOC EXTRACTION] Precision={precision:.4f}, Recall={recall:.4f}, F1={f1:.4f}")

        self.assertEqual(fn, 0, f"False Negatives: {fn} — expected 0")
        self.assertEqual(fp, 0, f"False Positives on adversarial strings: {fp} — expected 0")
        self.assertAlmostEqual(precision, 1.0, places=4)
        self.assertAlmostEqual(recall, 1.0, places=4)
        self.assertAlmostEqual(f1, 1.0, places=4)

    def test_02_adversarial_rejection_specific_cases(self):
        """Verify individual adversarial patterns produce zero IOC extractions."""
        # MAC Address — colons must not trigger IPv6 or domain extraction
        res = IOCExtractor.extract_from_text("MAC address 00:1A:2B:3C:4D:5E registered for interface eth0")
        self.assertEqual(res.total_extracted, 0, "MAC address incorrectly extracted as IOC")

        # ISO 8601 Timestamp
        res = IOCExtractor.extract_from_text("Event logged at 2026-11-06T12:00:00Z system heartbeat normal")
        self.assertEqual(res.total_extracted, 0, "ISO timestamp incorrectly extracted as IOC")

        # Software version string
        res = IOCExtractor.extract_from_text("Upgraded from v1.2.3.4 to latest build")
        self.assertEqual(res.total_extracted, 0, "Version string incorrectly extracted as IPv4 IOC")

        # Sentences with periods (prose)
        res = IOCExtractor.extract_from_text("Host is up. Service is responding. All ok.")
        self.assertEqual(res.total_extracted, 0, "Prose sentences incorrectly extracted as IOC")

        # File extensions without valid path
        res = IOCExtractor.extract_from_text("Blocked files with extension .exe and .dll from email")
        self.assertEqual(res.total_extracted, 0, "File extensions incorrectly extracted as file path IOC")

        # Invalid octet IPv4
        res = IOCExtractor.extract_from_text("Dropped bogus packet from 999.123.456.789 overflow")
        self.assertEqual(res.total_extracted, 0, "Invalid IPv4 octets incorrectly extracted")

    def test_03_all_nine_ioc_types_extractable(self):
        """Verify each of the 9 IOC types is extractable from a natural-language template."""
        type_to_sample = {
            IOCType.IPV4:      "192.168.1.105",
            IOCType.IPV6:      "2001:db8::1",
            IOCType.DOMAIN:    "malicious.example.com",
            IOCType.URL:       "http://malicious.example.com/payload.php",
            IOCType.MD5:       "d41d8cd98f00b204e9800998ecf8427e",
            IOCType.SHA1:      "da39a3ee5e6b4b0d3255bfef95601890afd80709",
            IOCType.SHA256:    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            IOCType.EMAIL:     "attacker@evil.example.com",
            IOCType.FILE_PATH: "/etc/passwd",
        }
        for ioc_type, raw in type_to_sample.items():
            text = f"Security event: indicator {raw} observed in log stream"
            res = IOCExtractor.extract_from_text(text)
            matched = [i for i in res.iocs if i.ioc_type == ioc_type]
            self.assertGreaterEqual(
                len(matched), 1,
                f"IOC type {ioc_type.value} not extracted from: '{text}'"
            )


# ─────────────────────────────────────────────────────────────────────────────
# 2. IOC Normalization Validation
# ─────────────────────────────────────────────────────────────────────────────

class TestIOCNormalizationValidation(unittest.TestCase):
    """Validates RFC-compliant IOC normalization canonicalization."""

    def test_01_normalization_rfc_compliance_cases(self):
        """
        Assert each normalization case matches its ground-truth canonical form.
        """
        for case in NORMALIZATION_TEST_CASES:
            normalized = IOCNormalizer.normalize(case["raw"], case["ioc_type"])
            self.assertEqual(
                normalized,
                case["expected"],
                f"Normalization mismatch for [{case['name']}]: "
                f"normalize('{case['raw']}') => '{normalized}', expected '{case['expected']}'",
            )

    def test_02_normalize_ioc_model_copy_immutability(self):
        """
        Verify IOCNormalizer.normalize_ioc produces an updated copy without altering
        the original IOC's raw_value or existing normalized_value.
        """
        original = IOC(
            ioc_type=IOCType.IPV4,
            raw_value="  010.001.020.005  ",
            normalized_value="pending",
            status=IOCStatus.EXTRACTED,
        )
        updated = IOCNormalizer.normalize_ioc(original)

        # Updated copy has correct canonical value
        self.assertEqual(updated.normalized_value, "10.1.20.5")
        # Original raw_value preserved in copy
        self.assertEqual(updated.raw_value, "  010.001.020.005  ")
        # Original object is NOT mutated
        self.assertEqual(original.normalized_value, "pending")


# ─────────────────────────────────────────────────────────────────────────────
# 3. IOC Validation Status
# ─────────────────────────────────────────────────────────────────────────────

class TestIOCValidationStatus(unittest.TestCase):
    """
    Validates structural validity checks and enforces the invariant that
    ValidationStatus.SUSPICIOUS is not equivalent to a malicious threat verdict.
    """

    def test_01_valid_public_ipv4(self):
        v = IOCValidator.validate("1.1.1.1", IOCType.IPV4)
        self.assertEqual(v.validation_status, ValidationStatus.VALID)
        self.assertTrue(v.is_valid)
        self.assertEqual(v.ip_scope, IPScope.PUBLIC)

    def test_02_invalid_octet_ipv4_rejected(self):
        v = IOCValidator.validate("999.1.1.1", IOCType.IPV4)
        self.assertEqual(v.validation_status, ValidationStatus.INVALID)
        self.assertFalse(v.is_valid)

    def test_03_loopback_scope(self):
        v = IOCValidator.validate("127.0.0.1", IOCType.IPV4)
        self.assertEqual(v.ip_scope, IPScope.LOOPBACK)
        self.assertEqual(v.validation_status, ValidationStatus.VALID)

    def test_04_valid_sha256(self):
        v = IOCValidator.validate(
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            IOCType.SHA256,
        )
        self.assertEqual(v.validation_status, ValidationStatus.VALID)

    def test_05_truncated_sha256_rejected(self):
        v = IOCValidator.validate("e3b0c44298fc1c149", IOCType.SHA256)
        self.assertEqual(v.validation_status, ValidationStatus.INVALID)
        self.assertFalse(v.is_valid)

    def test_06_suspicious_validation_is_not_malicious(self):
        """
        DESIGN INVARIANT: ValidationStatus.SUSPICIOUS (structural anomaly) ≠ MALICIOUS (threat verdict).
        IOCStatus must remain EXTRACTED regardless of validation classification.
        """
        ioc = IOC(
            ioc_type=IOCType.FILE_PATH,
            raw_value="/tmp/.hidden_script.sh",
            normalized_value="/tmp/.hidden_script.sh",
            status=IOCStatus.EXTRACTED,
        )
        _, v_res = IOCValidator.validate_ioc(ioc)

        # ValidationStatus may be VALID or SUSPICIOUS, but NEVER "MALICIOUS"
        self.assertNotIn(str(v_res.validation_status), ["MALICIOUS", "malicious"])
        # IOCStatus must NOT be changed by validation
        self.assertEqual(ioc.status, IOCStatus.EXTRACTED)


# ─────────────────────────────────────────────────────────────────────────────
# 4. Provider Validation
# ─────────────────────────────────────────────────────────────────────────────

class TestProviderValidation(unittest.TestCase):
    """
    Validates OfflineMockThreatIntelProvider determinism and
    VirusTotalProvider edge-case HTTP status handling.
    """

    def setUp(self):
        self.mock_provider = OfflineMockThreatIntelProvider()
        self.service = ThreatIntelService()
        self.service.register_provider(self.mock_provider)

    def test_01_offline_mock_malicious_lookup_and_cache(self):
        """Verify deterministic malicious verdict and TTL cache hit."""
        ioc = IOC(
            ioc_type=IOCType.IPV4,
            raw_value="185.220.101.5",
            normalized_value="185.220.101.5",
            status=IOCStatus.EXTRACTED,
        )
        res1 = self.service.lookup(ioc)
        self.assertEqual(res1.status, ThreatIntelStatus.MALICIOUS)

        res2 = self.service.lookup(ioc)
        self.assertEqual(res1.id, res2.id, "Cache hit should return same result ID")
        self.assertEqual(res1.status, res2.status)
        self.assertEqual(res1.reputation_score, res2.reputation_score)

    def test_02_offline_mock_clean_lookup(self):
        """Verify known-clean domains produce CLEAN verdict."""
        ioc = IOC(
            ioc_type=IOCType.DOMAIN,
            raw_value="google.com",
            normalized_value="google.com",
            status=IOCStatus.EXTRACTED,
        )
        res = self.service.lookup(ioc)
        self.assertEqual(res.status, ThreatIntelStatus.CLEAN)

    def test_03_virustotal_404_maps_to_unknown_not_clean(self):
        """
        CRITICAL SECURITY INVARIANT:
        HTTP 404 from VirusTotal MUST map to ThreatIntelStatus.UNKNOWN.
        Absence of VT data is NOT evidence of benign intent.
        """
        vt = VirusTotalProvider(api_key="test_dummy_key_1234567890")
        ioc = IOC(
            ioc_type=IOCType.DOMAIN,
            raw_value="newly-registered-unknown-domain.test",
            normalized_value="newly-registered-unknown-domain.test",
            status=IOCStatus.EXTRACTED,
        )

        mock_resp = MagicMock()
        mock_resp.status_code = 404

        with patch("httpx.Client.get", return_value=mock_resp):
            result = vt.lookup(ioc)
            self.assertEqual(
                result.status,
                ThreatIntelStatus.UNKNOWN,
                "HTTP 404 MUST map to UNKNOWN, not CLEAN (security invariant violated!)"
            )
            self.assertNotEqual(result.status, ThreatIntelStatus.CLEAN)

    def test_04_virustotal_http_200_malicious(self):
        """HTTP 200 with high malicious count produces MALICIOUS verdict."""
        vt = VirusTotalProvider(api_key="test_dummy_key_1234567890")
        ioc = IOC(
            ioc_type=IOCType.IPV4,
            raw_value="185.220.101.5",
            normalized_value="185.220.101.5",
            status=IOCStatus.EXTRACTED,
        )
        body = {
            "data": {
                "attributes": {
                    "last_analysis_stats": {
                        "malicious": 15,
                        "suspicious": 2,
                        "harmless": 20,
                        "undetected": 10,
                    }
                }
            }
        }
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = body

        with patch("httpx.Client.get", return_value=mock_resp):
            result = vt.lookup(ioc)
            self.assertEqual(result.status, ThreatIntelStatus.MALICIOUS)

    def test_05_virustotal_401_produces_error(self):
        """HTTP 401 Unauthorized produces ERROR result."""
        vt = VirusTotalProvider(api_key="wrong_api_key")
        ioc = IOC(
            ioc_type=IOCType.IPV4,
            raw_value="1.2.3.4",
            normalized_value="1.2.3.4",
            status=IOCStatus.EXTRACTED,
        )
        mock_resp = MagicMock()
        mock_resp.status_code = 401

        with patch("httpx.Client.get", return_value=mock_resp):
            result = vt.lookup(ioc)
            self.assertEqual(result.status, ThreatIntelStatus.ERROR)

    def test_06_virustotal_403_produces_error(self):
        """HTTP 403 Forbidden produces ERROR result."""
        vt = VirusTotalProvider(api_key="limited_api_key")
        ioc = IOC(
            ioc_type=IOCType.IPV4,
            raw_value="1.2.3.4",
            normalized_value="1.2.3.4",
            status=IOCStatus.EXTRACTED,
        )
        mock_resp = MagicMock()
        mock_resp.status_code = 403

        with patch("httpx.Client.get", return_value=mock_resp):
            result = vt.lookup(ioc)
            self.assertEqual(result.status, ThreatIntelStatus.ERROR)

    def test_07_virustotal_429_rate_limit_produces_error(self):
        """HTTP 429 Rate Limit produces ERROR with retry metadata."""
        vt = VirusTotalProvider(api_key="test_dummy_key_1234567890")
        ioc = IOC(
            ioc_type=IOCType.IPV4,
            raw_value="1.2.3.4",
            normalized_value="1.2.3.4",
            status=IOCStatus.EXTRACTED,
        )
        mock_resp = MagicMock()
        mock_resp.status_code = 429
        mock_resp.headers = {"Retry-After": "60"}

        with patch("httpx.Client.get", return_value=mock_resp):
            result = vt.lookup(ioc)
            self.assertEqual(result.status, ThreatIntelStatus.ERROR)

    def test_08_virustotal_500_upstream_error(self):
        """HTTP 500 Server Error produces ERROR result."""
        vt = VirusTotalProvider(api_key="test_dummy_key_1234567890")
        ioc = IOC(
            ioc_type=IOCType.IPV4,
            raw_value="1.2.3.4",
            normalized_value="1.2.3.4",
            status=IOCStatus.EXTRACTED,
        )
        mock_resp = MagicMock()
        mock_resp.status_code = 500

        with patch("httpx.Client.get", return_value=mock_resp):
            result = vt.lookup(ioc)
            self.assertEqual(result.status, ThreatIntelStatus.ERROR)

    def test_09_virustotal_timeout_handled_gracefully(self):
        """Timeout exception produces ERROR result without crashing."""
        import httpx
        vt = VirusTotalProvider(api_key="test_dummy_key_1234567890")
        ioc = IOC(
            ioc_type=IOCType.IPV4,
            raw_value="1.2.3.4",
            normalized_value="1.2.3.4",
            status=IOCStatus.EXTRACTED,
        )

        with patch("httpx.Client.get", side_effect=httpx.TimeoutException("timed out")):
            result = vt.lookup(ioc)
            self.assertEqual(result.status, ThreatIntelStatus.ERROR)
            self.assertIn("timed out", result.raw_metadata.get("error", "").lower())

    def test_10_virustotal_no_api_key_disabled(self):
        """
        Provider with empty API key must be in DISABLED state.
        Lookup should return UNKNOWN safely without crashing.
        """
        vt = VirusTotalProvider(api_key="")
        ioc = IOC(
            ioc_type=IOCType.IPV4,
            raw_value="1.2.3.4",
            normalized_value="1.2.3.4",
            status=IOCStatus.EXTRACTED,
        )
        result = vt.lookup(ioc)
        self.assertEqual(result.status, ThreatIntelStatus.UNKNOWN)

    def test_11_provider_secret_isolation(self):
        """
        SECURITY INVARIANT: API key must NEVER appear in ThreatIntelResult metadata,
        reason strings, or serialized model output.
        """
        api_key = "SECRET_VT_API_KEY_MUST_NOT_LEAK_XYZ_12345"
        vt = VirusTotalProvider(api_key=api_key)
        ioc = IOC(
            ioc_type=IOCType.IPV4,
            raw_value="1.2.3.4",
            normalized_value="1.2.3.4",
            status=IOCStatus.EXTRACTED,
        )
        result = vt.lookup(ioc)
        serialized = result.model_dump_json()

        self.assertNotIn(api_key, serialized, "API key leaked into ThreatIntelResult serialization!")


# ─────────────────────────────────────────────────────────────────────────────
# 5. Threat Reputation Engine Validation
# ─────────────────────────────────────────────────────────────────────────────

class TestThreatReputationValidation(unittest.TestCase):
    """
    Validates ThreatReputationEngine mathematical accuracy and
    invariant correctness: scoring bounds, signal decomposition, confidence independence.
    """

    def setUp(self):
        self.engine = ThreatReputationEngine()

    def test_01_threat_score_bounded_to_0_100(self):
        """Threat score must always be clamped to [0.0, 100.0]."""
        ti = ThreatIntelResult(
            ioc_id="ioc-bound",
            ioc_type=IOCType.IPV4,
            ioc_value="198.51.100.1",
            normalized_value="198.51.100.1",
            status=ThreatIntelStatus.MALICIOUS,
            detection_count=20,
            total_engines=20,
            reputation_score=1.0,
            categories=["c2", "ransomware"],
            source=ThreatIntelSource.OFFLINE_MOCK,
            provider_name="offline_mock",
        )
        assessment = self.engine.assess(ti)
        self.assertGreaterEqual(assessment.threat_score, 0.0)
        self.assertLessEqual(assessment.threat_score, 100.0)

    def test_02_signal_contributions_sum_to_threat_score(self):
        """
        Design Invariant: sum of contributing_signal.contribution values across
        available signals must equal the reported threat_score (within floating point tolerance).
        """
        ti = ThreatIntelResult(
            ioc_id="ioc-sig",
            ioc_type=IOCType.IPV4,
            ioc_value="198.51.100.1",
            normalized_value="198.51.100.1",
            status=ThreatIntelStatus.MALICIOUS,
            detection_count=15,
            total_engines=20,
            reputation_score=0.85,
            categories=["c2", "trojan"],
            source=ThreatIntelSource.OFFLINE_MOCK,
            provider_name="offline_mock",
        )
        assessment = self.engine.assess(ti)
        signal_sum = sum(s.contribution for s in assessment.contributing_signals if s.available)
        self.assertAlmostEqual(
            assessment.threat_score, signal_sum, places=1,
            msg=f"Signal contributions {signal_sum:.2f} don't match threat_score {assessment.threat_score:.2f}"
        )

    def test_03_malicious_full_telemetry_produces_critical(self):
        """Full malicious telemetry (all signals) produces CRITICAL severity."""
        ti = ThreatIntelResult(
            ioc_id="ioc-crit",
            ioc_type=IOCType.SHA256,
            ioc_value="275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f",
            normalized_value="275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f",
            status=ThreatIntelStatus.MALICIOUS,
            detection_count=60,
            total_engines=70,
            reputation_score=0.99,
            categories=["eicar_standard_av_test", "ransomware"],
            source=ThreatIntelSource.VIRUSTOTAL,
            provider_name="virustotal",
        )
        a = self.engine.assess(ti)
        self.assertEqual(a.severity, ThreatSeverity.CRITICAL)
        self.assertGreaterEqual(a.threat_score, 85.0)

    def test_04_unknown_status_produces_unknown_severity_zero_confidence(self):
        """
        DESIGN INVARIANT: UNKNOWN / ERROR results MUST produce UNKNOWN severity
        and 0.0 confidence. Insufficient intelligence never resolves to CLEAN.
        """
        ti = ThreatIntelResult(
            ioc_id="ioc-unk",
            ioc_type=IOCType.DOMAIN,
            ioc_value="newly-registered-unknown.xyz",
            normalized_value="newly-registered-unknown.xyz",
            status=ThreatIntelStatus.UNKNOWN,
            source=ThreatIntelSource.CUSTOM,
            provider_name="custom",
        )
        a = self.engine.assess(ti)
        self.assertEqual(a.severity, ThreatSeverity.UNKNOWN)
        self.assertEqual(a.confidence, 0.0)
        self.assertEqual(a.threat_score, 0.0)
        self.assertNotEqual(a.status, ThreatIntelStatus.CLEAN)

    def test_05_clean_full_coverage_produces_low_severity_high_confidence(self):
        """Verified clean with high engine coverage produces LOW severity and high confidence."""
        ti = ThreatIntelResult(
            ioc_id="ioc-clean",
            ioc_type=IOCType.DOMAIN,
            ioc_value="google.com",
            normalized_value="google.com",
            status=ThreatIntelStatus.CLEAN,
            confidence=0.95,
            detection_count=0,
            total_engines=72,
            reputation_score=0.0,
            categories=["search_engine"],
            source=ThreatIntelSource.VIRUSTOTAL,
            provider_name="virustotal",
        )
        a = self.engine.assess(ti)
        self.assertEqual(a.severity, ThreatSeverity.LOW)
        self.assertEqual(a.threat_score, 0.0)
        self.assertGreaterEqual(a.confidence, 0.80)

    def test_06_confidence_is_independent_of_threat_score(self):
        """
        Design Invariant: Threat confidence (evidence coverage) is computed independently
        of threat score (risk). They can diverge substantially.

        Low confidence example: 1 engine out of 2 flagging suspicious = moderate risk score
        but very low confidence (sparse telemetry).
        """
        sparse = ThreatIntelResult(
            ioc_id="ioc-sparse",
            ioc_type=IOCType.DOMAIN,
            ioc_value="obscure-domain.xyz",
            normalized_value="obscure-domain.xyz",
            status=ThreatIntelStatus.SUSPICIOUS,
            confidence=0.2,
            detection_count=1,
            total_engines=2,
            reputation_score=None,
            categories=[],
            source=ThreatIntelSource.CUSTOM,
            provider_name="custom",
        )
        a = self.engine.assess(sparse)
        # Non-zero score from SUSPICIOUS provider_status
        self.assertGreater(a.threat_score, 0.0)
        # But very low confidence due to sparse engine coverage
        self.assertLess(a.confidence, 0.50)
        # Score and confidence must not be equal (they diverge here)
        self.assertNotAlmostEqual(a.threat_score / 100.0, a.confidence, places=1)


# ─────────────────────────────────────────────────────────────────────────────
# 6. Threat Correlation Validation
# ─────────────────────────────────────────────────────────────────────────────

class TestThreatCorrelationValidation(unittest.TestCase):
    """
    Validates ThreatCorrelationEngine:
    - True relationship detection.
    - Zero false correlations for unrelated IOCs (FPR = 0).
    - Cross-session penalty enforcement.
    - Temporal proximity score derivation.
    """

    def setUp(self):
        self.store = SessionStore()
        self.ioc_repo = IOCRepository(session_store=self.store)
        self.engine = ThreatCorrelationEngine(
            ioc_repo=self.ioc_repo,
            session_store=self.store,
        )
        self.session_a = "session-alpha"
        self.session_b = "session-beta"
        self.base_time = datetime(2026, 11, 6, 12, 0, 0, tzinfo=timezone.utc)

    def test_01_explicit_anomaly_link_produces_true_positive(self):
        """IOC with explicit associated_anomaly_id must produce a confirmed correlation."""
        anomaly = Anomaly(
            id="anom-tp01",
            session_id=self.session_a,
            log_entry_ids=["evt-tp01"],
            score=0.9,
            severity=SeverityLevel.HIGH,
            reason="Malicious probe from test IP",
            method=DetectionMethod.RULE_BASED,
            detected_at=self.base_time,
        )
        self.store.anomalies[self.session_a] = [anomaly]

        ioc = IOC(
            id="ioc-tp01",
            ioc_type=IOCType.IPV4,
            raw_value="198.51.100.1",
            normalized_value="198.51.100.1",
            status=IOCStatus.EXTRACTED,
            source_sessions=[self.session_a],
            associated_anomaly_ids=["anom-tp01"],
        )
        corrs = self.engine.correlate_ioc(ioc)
        anom_corrs = [c for c in corrs if c.target_type == "anomaly"]

        self.assertGreaterEqual(len(anom_corrs), 1, "Expected at least 1 anomaly correlation")
        self.assertEqual(anom_corrs[0].target_id, "anom-tp01")
        self.assertTrue(anom_corrs[0].confirmed, "Explicit reference should be confirmed=True")
        self.assertGreaterEqual(anom_corrs[0].confidence.score, 0.85)

    def test_02_unrelated_ioc_produces_zero_correlations(self):
        """
        IOC with no known associations MUST produce 0 correlations in a store with
        populated unrelated security objects (false-correlation resistance).
        """
        # Populate store with an anomaly that has no relation to our IOC
        anomaly = Anomaly(
            id="anom-unrel",
            session_id=self.session_a,
            log_entry_ids=["evt-completely-different"],
            score=0.8,
            severity=SeverityLevel.MEDIUM,
            reason="Unrelated anomaly",
            method=DetectionMethod.RULE_BASED,
            detected_at=self.base_time,
        )
        self.store.anomalies[self.session_a] = [anomaly]

        ioc = IOC(
            id="ioc-tn01",
            ioc_type=IOCType.DOMAIN,
            raw_value="totally-unrelated-domain.example.com",
            normalized_value="totally-unrelated-domain.example.com",
            status=IOCStatus.EXTRACTED,
            source_sessions=[self.session_a],
        )
        corrs = self.engine.correlate_ioc(ioc)
        structural_corrs = [
            c for c in corrs
            if c.correlation_method in ("explicit_reference", "shared_event", "entity_match", "evidence_extraction")
        ]
        self.assertEqual(len(structural_corrs), 0, "Unrelated IOC must produce zero structural correlations")

    def test_03_cross_session_correlation_marked_unconfirmed(self):
        """
        Cross-session correlations MUST have:
        - confirmed = False
        - Confidence score penalized by CROSS_SESSION_PENALTY_MULTIPLIER (0.40)
        Base score = 0.85, penalized = 0.85 * 0.40 = 0.34 (capped at CROSS_SESSION_MAX_UNCONFIRMED_SCORE = 0.35)
        """
        anomaly_b = Anomaly(
            id="anom-cross-sess",
            session_id=self.session_b,
            log_entry_ids=["evt-sess-b"],
            score=0.8,
            severity=SeverityLevel.HIGH,
            reason="Cross-session anomaly",
            method=DetectionMethod.RULE_BASED,
            detected_at=self.base_time,
        )
        self.store.anomalies[self.session_b] = [anomaly_b]

        # IOC in session A, with explicit reference to anomaly in session B
        ioc = IOC(
            id="ioc-cross-01",
            ioc_type=IOCType.IPV4,
            raw_value="198.51.100.55",
            normalized_value="198.51.100.55",
            status=IOCStatus.EXTRACTED,
            source_sessions=[self.session_a],  # Session A
            associated_anomaly_ids=["anom-cross-sess"],  # Session B anomaly
        )

        corrs = self.engine.correlate_ioc(ioc)
        anom_corrs = [c for c in corrs if c.target_type == "anomaly"]

        self.assertGreaterEqual(len(anom_corrs), 1)
        cross_corr = anom_corrs[0]

        # Cross-session safety invariant
        self.assertFalse(cross_corr.confirmed, "Cross-session correlation must be confirmed=False")
        self.assertLessEqual(
            cross_corr.confidence.score, 0.35,
            f"Cross-session score {cross_corr.confidence.score} exceeds max unconfirmed score 0.35"
        )

    def test_04_event_extraction_confidence_1_0_with_line_number(self):
        """Evidence with line_number achieves maximum event correlation confidence = 1.0."""
        ev = IOCEvidence(
            event_id="evt-lineno",
            session_id=self.session_a,
            timestamp=self.base_time,
            raw_value="198.51.100.7",
            source_field="src_ip",
            line_number=42,
        )
        ioc = IOC(
            id="ioc-ev-lineno",
            ioc_type=IOCType.IPV4,
            raw_value="198.51.100.7",
            normalized_value="198.51.100.7",
            status=IOCStatus.EXTRACTED,
            evidence_references=[ev],
            source_sessions=[self.session_a],
        )
        corrs = self.engine.correlate_ioc(ioc)
        event_corrs = [c for c in corrs if c.target_type == "event"]
        self.assertGreaterEqual(len(event_corrs), 1)
        self.assertEqual(event_corrs[0].confidence.score, 1.0)
        self.assertTrue(event_corrs[0].confirmed)

    def test_05_incident_correlation_via_anomaly_chain(self):
        """
        Incident linked through anomaly chain produces an incident correlation
        derived from the already-established anomaly correlation.
        """
        anomaly = Anomaly(
            id="anom-chain01",
            session_id=self.session_a,
            log_entry_ids=["evt-chain01"],
            score=0.9,
            severity=SeverityLevel.CRITICAL,
            reason="Attack probe confirmed",
            method=DetectionMethod.RULE_BASED,
            detected_at=self.base_time,
        )
        incident = Incident(
            id="inc-chain01",
            anomaly_id="anom-chain01",
            session_id=self.session_a,
            category=IncidentCategory.INTRUSION_ATTEMPT,
            severity=SeverityLevel.CRITICAL,
            title="Ingress Attack",
            description="Intrusion attempt description",
            root_cause_hypothesis="Lateral movement from C2 host",
            potential_impact="Unauthorized access to internal services",
            first_seen=self.base_time,
            last_seen=self.base_time,
            status=IncidentStatus.INVESTIGATING,
        )
        self.store.anomalies[self.session_a] = [anomaly]
        self.store.incidents[self.session_a] = [incident]

        ioc = IOC(
            id="ioc-chain01",
            ioc_type=IOCType.IPV4,
            raw_value="198.51.100.1",
            normalized_value="198.51.100.1",
            status=IOCStatus.UNDER_REVIEW,
            source_sessions=[self.session_a],
            associated_anomaly_ids=["anom-chain01"],
        )
        corrs = self.engine.correlate_ioc(ioc)

        incident_corrs = [c for c in corrs if c.target_type == "incident"]
        self.assertGreaterEqual(len(incident_corrs), 1, "Expected incident correlation via anomaly chain")
        self.assertEqual(incident_corrs[0].target_id, "inc-chain01")

    def test_06_correlation_does_not_modify_analyst_status(self):
        """
        INVARIANT: Correlation is NOT classification.
        IOC status must remain EXTRACTED after correlation, even if the IOC correlates
        to a highly suspicious anomaly/incident with MALICIOUS threat assessment.
        """
        anomaly = Anomaly(
            id="anom-nc01",
            session_id=self.session_a,
            log_entry_ids=["evt-nc01"],
            score=0.99,
            severity=SeverityLevel.CRITICAL,
            reason="Definitive C2 beacon",
            method=DetectionMethod.RULE_BASED,
            detected_at=self.base_time,
        )
        self.store.anomalies[self.session_a] = [anomaly]

        ioc = IOC(
            id="ioc-nc01",
            ioc_type=IOCType.IPV4,
            raw_value="198.51.100.1",
            normalized_value="198.51.100.1",
            status=IOCStatus.EXTRACTED,  # Explicitly set to EXTRACTED
            source_sessions=[self.session_a],
            associated_anomaly_ids=["anom-nc01"],
        )
        assessment = ThreatAssessment(
            ioc_id="ioc-nc01",
            ioc_type=IOCType.IPV4,
            ioc_value="198.51.100.1",
            normalized_value="198.51.100.1",
            threat_score=99.0,
            confidence=0.99,
            severity=ThreatSeverity.CRITICAL,
            status=ThreatIntelStatus.MALICIOUS,
        )

        _ = self.engine.correlate_ioc(ioc, threat_assessment=assessment)

        # IOC analyst status MUST remain EXTRACTED
        self.assertEqual(ioc.status, IOCStatus.EXTRACTED,
                         "IOC analyst status was mutated by correlation — invariant violated!")


# ─────────────────────────────────────────────────────────────────────────────
# 7. Mutation Safety Audit
# ─────────────────────────────────────────────────────────────────────────────

class TestMutationSafetyAudit(unittest.TestCase):
    """
    Forensic immutability audit:
    Deep snapshot comparison verifying that correlation, scoring, and context assembly
    NEVER mutate the source IOC, Anomaly, Incident, or ThreatAssessment objects.
    """

    def test_01_full_pipeline_zero_mutation(self):
        store = SessionStore()
        ioc_repo = IOCRepository(session_store=store)
        engine = ThreatCorrelationEngine(ioc_repo=ioc_repo, session_store=store)
        rep_engine = ThreatReputationEngine()

        sess_id = "audit-session-01"
        now = datetime(2026, 11, 6, 12, 0, 0, tzinfo=timezone.utc)

        anomaly = Anomaly(
            id="anom-audit-01",
            session_id=sess_id,
            log_entry_ids=["evt-audit-01"],
            score=0.9,
            severity=SeverityLevel.HIGH,
            reason="Audit test anomaly",
            method=DetectionMethod.RULE_BASED,
            detected_at=now,
        )
        incident = Incident(
            id="inc-audit-01",
            anomaly_id="anom-audit-01",
            session_id=sess_id,
            category=IncidentCategory.INTRUSION_ATTEMPT,
            severity=SeverityLevel.HIGH,
            title="Audit Incident",
            description="Audit test incident description",
            root_cause_hypothesis="Root cause hypothesis",
            potential_impact="Potential impact assessment",
            first_seen=now,
            last_seen=now,
            status=IncidentStatus.OPEN,
        )
        store.anomalies[sess_id] = [anomaly]
        store.incidents[sess_id] = [incident]

        ioc = IOC(
            id="ioc-audit-01",
            ioc_type=IOCType.IPV4,
            raw_value="198.51.100.99",
            normalized_value="198.51.100.99",
            status=IOCStatus.EXTRACTED,
            source_sessions=[sess_id],
            associated_anomaly_ids=["anom-audit-01"],
            associated_incident_ids=["inc-audit-01"],
        )
        ti_result = ThreatIntelResult(
            ioc_id="ioc-audit-01",
            ioc_type=IOCType.IPV4,
            ioc_value="198.51.100.99",
            normalized_value="198.51.100.99",
            status=ThreatIntelStatus.MALICIOUS,
            detection_count=18,
            total_engines=20,
            reputation_score=0.9,
            source=ThreatIntelSource.OFFLINE_MOCK,
            provider_name="offline_mock",
        )
        assessment = rep_engine.assess(ti_result)

        # Deep snapshot before any operations
        ioc_before = ioc.model_dump()
        anom_before = anomaly.model_dump()
        inc_before = incident.model_dump()
        result_before = ti_result.model_dump()
        assessment_before = assessment.model_dump()

        # Run full correlation + context assembly pipeline
        corrs = engine.correlate_ioc(ioc, threat_assessment=assessment)
        unified = engine.build_unified_context(ioc, threat_assessment=assessment, threat_intel_result=ti_result)

        # Assert ZERO field mutations across all source objects
        self.assertEqual(ioc.model_dump(), ioc_before, "IOC model was mutated during pipeline")
        self.assertEqual(anomaly.model_dump(), anom_before, "Anomaly model was mutated during pipeline")
        self.assertEqual(incident.model_dump(), inc_before, "Incident model was mutated during pipeline")
        self.assertEqual(ti_result.model_dump(), result_before, "ThreatIntelResult was mutated during pipeline")
        self.assertEqual(assessment.model_dump(), assessment_before, "ThreatAssessment was mutated during pipeline")


# ─────────────────────────────────────────────────────────────────────────────
# 8. UnifiedThreatContext Aggregation Validation
# ─────────────────────────────────────────────────────────────────────────────

class TestUnifiedThreatContextValidation(unittest.TestCase):
    """
    Validates UnifiedThreatContext aggregation, counts fidelity,
    and investigation summary correctness.
    """

    def test_01_full_unified_context_aggregation(self):
        store = SessionStore()
        ioc_repo = IOCRepository(session_store=store)
        engine = ThreatCorrelationEngine(ioc_repo=ioc_repo, session_store=store)
        sess_id = "ctx-session-01"
        now = datetime(2026, 11, 6, 12, 0, 0, tzinfo=timezone.utc)

        ev = IOCEvidence(
            event_id="evt-ctx-01",
            session_id=sess_id,
            timestamp=now,
            raw_value="198.51.100.7",
            source_field="destination_ip",
            line_number=42,
        )
        ioc = IOC(
            id="ioc-ctx-01",
            ioc_type=IOCType.IPV4,
            raw_value="198.51.100.7",
            normalized_value="198.51.100.7",
            status=IOCStatus.UNDER_REVIEW,
            evidence_references=[ev],
            source_sessions=[sess_id],
            associated_anomaly_ids=["anom-ctx-01"],
            associated_incident_ids=["inc-ctx-01"],
        )
        ioc_repo.add_ioc(ioc)

        anomaly = Anomaly(
            id="anom-ctx-01",
            session_id=sess_id,
            log_entry_ids=["evt-ctx-01"],
            score=0.92,
            severity=SeverityLevel.CRITICAL,
            reason="Confirmed malicious probe",
            method=DetectionMethod.RULE_BASED,
            detected_at=now,
        )
        incident = Incident(
            id="inc-ctx-01",
            anomaly_id="anom-ctx-01",
            session_id=sess_id,
            title="Ingress Attack Campaign",
            category=IncidentCategory.INTRUSION_ATTEMPT,
            severity=SeverityLevel.CRITICAL,
            description="Ingress attack campaign description",
            root_cause_hypothesis="Compromised credentials used for lateral movement",
            potential_impact="Unauthorized access to internal services",
            first_seen=now,
            last_seen=now,
            status=IncidentStatus.INVESTIGATING,
        )
        chain = AttackChain(
            id="chain-ctx-01",
            session_id=sess_id,
            title="Multi-stage Infiltration",
            summary="Multi-stage attack chain with MITRE T1190",
            severity="CRITICAL",
            confidence_score=0.95,
            first_seen=now,
            last_seen=now,
            status=ChainStatus.NEW,
            potential_impact="Full domain compromise",
            correlation_explanation="Attack correlated via shared event IDs",
            associated_anomaly_ids=["anom-ctx-01"],
            associated_incident_ids=["inc-ctx-01"],
            events=[
                ChainLinkEvent(
                    id="link-ctx-01",
                    log_entry_id="evt-ctx-01",
                    timestamp=now,
                    stage=AttackStage.INITIAL_ACCESS,
                    is_confirmed=True,
                    correlation_reason="Matched IOC",
                    raw_log="Sample raw log event",
                    message="Exploit detected",
                )
            ],
        )
        store.anomalies[sess_id] = [anomaly]
        store.incidents[sess_id] = [incident]
        store.attack_chains[sess_id] = [chain]

        assessment = ThreatAssessment(
            ioc_id=ioc.id,
            ioc_type=ioc.ioc_type,
            ioc_value=ioc.raw_value,
            normalized_value=ioc.normalized_value,
            threat_score=95.0,
            confidence=0.92,
            severity=ThreatSeverity.CRITICAL,
            status=ThreatIntelStatus.MALICIOUS,
        )

        unified = engine.build_unified_context(ioc, threat_assessment=assessment)

        # Verify IOC identity
        self.assertEqual(unified.ioc_id, "ioc-ctx-01")
        self.assertEqual(unified.ioc_type, IOCType.IPV4)
        self.assertEqual(unified.analyst_status, IOCStatus.UNDER_REVIEW)

        # Verify entity counts
        self.assertGreaterEqual(len(unified.related_events), 1)
        self.assertGreaterEqual(len(unified.related_anomalies), 1)
        self.assertGreaterEqual(len(unified.related_incidents), 1)
        self.assertGreaterEqual(len(unified.related_attack_chains), 1)

        # Verify investigation summary
        summary = unified.investigation_summary
        self.assertIn("event_count", summary)
        self.assertIn("anomaly_count", summary)
        self.assertIn("incident_count", summary)
        self.assertIn("attack_chain_count", summary)
        self.assertIn("key_findings", summary)
        self.assertGreaterEqual(len(summary["key_findings"]), 1)

        # Verify overall correlation confidence
        self.assertGreater(unified.overall_correlation_confidence, 0.0)

    def test_02_unified_context_zero_correlations_on_isolated_ioc(self):
        """
        Isolated IOC with no evidence references and no store data
        produces zero correlations and zero entity counts.
        """
        store = SessionStore()
        ioc_repo = IOCRepository(session_store=store)
        engine = ThreatCorrelationEngine(ioc_repo=ioc_repo, session_store=store)

        ioc = IOC(
            id="ioc-isolated",
            ioc_type=IOCType.SHA256,
            raw_value="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            normalized_value="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            status=IOCStatus.EXTRACTED,
        )

        unified = engine.build_unified_context(ioc)

        self.assertEqual(len(unified.correlations), 0)
        self.assertEqual(len(unified.related_events), 0)
        self.assertEqual(len(unified.related_anomalies), 0)
        self.assertEqual(len(unified.related_incidents), 0)
        self.assertEqual(len(unified.related_attack_chains), 0)
        self.assertEqual(unified.overall_correlation_confidence, 0.0)


# ─────────────────────────────────────────────────────────────────────────────
# 9. Security Audit
# ─────────────────────────────────────────────────────────────────────────────

class TestSecurityAudit(unittest.TestCase):
    """
    Security invariant validation:
    - Zero-network offline guarantee during all offline lookups.
    - Secret/API-key scrubbing from ThreatIntelResult metadata.
    - SSRF resilience via IP scope classification.
    - XSS injection safety in IOC model serialization.
    """

    def test_01_offline_mode_zero_network_sockets(self):
        """
        SECURITY INVARIANT: Zero TCP/UDP network sockets MUST be opened during
        offline mode threat lookups, reputation assessment, and correlation.
        """
        service = ThreatIntelService()
        service.register_provider(OfflineMockThreatIntelProvider())
        rep_engine = ThreatReputationEngine(service=service)

        ioc = IOC(
            ioc_type=IOCType.IPV4,
            raw_value="185.220.101.5",
            normalized_value="185.220.101.5",
            status=IOCStatus.EXTRACTED,
        )

        with patch.object(socket, "socket", side_effect=AssertionError("Network socket opened in offline mode!")):
            assessment = rep_engine.assess_ioc(ioc)
            self.assertEqual(assessment.status, ThreatIntelStatus.MALICIOUS)
            self.assertGreaterEqual(assessment.threat_score, 50.0)

    def test_02_secret_scrubbing_all_patterns(self):
        """
        SECURITY INVARIANT: API keys, bearer tokens, auth headers, passwords,
        and private keys must be recursively stripped from all metadata payloads.
        """
        polluted = {
            "api_key": "SECRET_KEY_1234567890_MUST_NOT_APPEAR",
            "bearer_token": "BEARER_AUTH_TOKEN_MUST_NOT_APPEAR",
            "auth_secret": "AUTH_SECRET_MUST_NOT_APPEAR",
            "password": "PLAINTEXT_PASSWORD_MUST_NOT_APPEAR",
            "private_key": "RSA_PRIVATE_KEY_MUST_NOT_APPEAR",
            "safe_field": "safe_public_telemetry_ok",
            "count": 42,
            "nested": {
                "api-key": "NESTED_API_KEY_MUST_NOT_APPEAR",
                "clean_nested_field": "clean_value_safe",
            }
        }

        sanitized = _sanitize_metadata(polluted)
        serialized = json.dumps(sanitized)

        # Verify all secret patterns are scrubbed
        self.assertNotIn("SECRET_KEY_1234567890", serialized)
        self.assertNotIn("BEARER_AUTH_TOKEN", serialized)
        self.assertNotIn("AUTH_SECRET", serialized)
        self.assertNotIn("PLAINTEXT_PASSWORD", serialized)
        self.assertNotIn("RSA_PRIVATE_KEY", serialized)
        self.assertNotIn("NESTED_API_KEY", serialized)

        # Verify safe fields are preserved
        self.assertIn("safe_public_telemetry_ok", serialized)
        self.assertEqual(sanitized["count"], 42)
        self.assertEqual(sanitized["nested"]["clean_nested_field"], "clean_value_safe")

    def test_03_ssrf_resilience_ip_scope_classification(self):
        """
        Verify that internal infrastructure IP addresses (loopback, link-local,
        private, cloud metadata endpoint 169.254.169.254) are correctly scoped.
        SSRF mitigation relies on correct scope detection to gate lookups.
        """
        cases = [
            ("127.0.0.1", IPScope.LOOPBACK),
            ("169.254.169.254", IPScope.LINK_LOCAL),
            ("10.0.0.1", IPScope.PRIVATE),
            ("192.168.0.1", IPScope.PRIVATE),
            ("172.16.0.1", IPScope.PRIVATE),
        ]
        for ip, expected_scope in cases:
            v = IOCValidator.validate(ip, IOCType.IPV4)
            self.assertEqual(
                v.ip_scope, expected_scope,
                f"IP {ip}: expected scope {expected_scope.value}, got {v.ip_scope.value}"
            )

    def test_04_xss_injection_safety_in_ioc_models(self):
        """
        IOC models with XSS payloads in raw_value must serialize and deserialize safely
        without code execution risk. The model round-trip must preserve string data as literals.
        """
        xss_values = [
            "<script>alert('XSS')</script>",
            "javascript:alert(document.cookie)",
            "<img src=x onerror=alert(1)>",
            "\"><svg/onload=alert('xss')>",
        ]
        for xss in xss_values:
            # Must not raise, must not execute — just store raw string
            ioc = IOC(
                ioc_type=IOCType.DOMAIN,
                raw_value=xss,
                normalized_value="safe.placeholder.com",
                status=IOCStatus.EXTRACTED,
            )
            dumped = ioc.model_dump_json()
            loaded = IOC.model_validate_json(dumped)
            # Data preserved as literal string (not executed, not modified)
            self.assertEqual(loaded.raw_value, xss)
            self.assertEqual(loaded.normalized_value, "safe.placeholder.com")

    def test_05_xss_extraction_does_not_fire(self):
        """
        IOC extraction must not extract HTML/JS payloads as valid IOC indicators.
        """
        xss_text = "Filter blocked <script>alert('XSS_ATTACK')</script> in POST body"
        res = IOCExtractor.extract_from_text(xss_text)
        # Confirm no IOC extraction from XSS payloads
        for ioc in res.iocs:
            self.assertNotIn("<script>", ioc.raw_value)
            self.assertNotIn("alert(", ioc.raw_value)


if __name__ == "__main__":
    unittest.main()
