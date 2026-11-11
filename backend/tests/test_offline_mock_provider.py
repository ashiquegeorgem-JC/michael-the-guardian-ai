"""
Phase 4.2B.1 — Offline Mock Threat Intelligence Provider Tests

Tests the OfflineMockThreatIntelProvider for:
- Supported indicator types (IPs, domains, URLs, hashes, emails, file paths).
- Capability filtering when instantiated with restricted types.
- Deterministic fixture matching for CLEAN indicators (e.g., 8.8.8.8, google.com).
- Deterministic fixture matching for SUSPICIOUS indicators (e.g., 198.51.100.42).
- Deterministic fixture matching for MALICIOUS indicators (e.g., 185.220.101.5, EICAR hashes).
- Graceful fallback to UNKNOWN for unmapped indicators.
- Graceful handling of unsupported indicator types via capability restriction.
- Custom test fixture registration (register_fixture).
- Metadata simulation flags (is_simulated, offline).
- Absolute non-mutation of input IOC instances.
"""

from datetime import datetime, timezone
import os
import sys
import unittest

# ── Path setup ──────────────────────────────────────────────────────────────
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from app.models.ioc import IOC, IOCStatus, IOCType
from app.models.threat_intel import ThreatIntelSource, ThreatIntelStatus
from app.services.providers.offline_mock_provider import OfflineMockThreatIntelProvider


def _build_ioc(ioc_type: IOCType, value: str) -> IOC:
    """Helper to build an IOC for testing."""
    now = datetime.now(timezone.utc)
    return IOC(
        id=f"ioc-{ioc_type.value.lower()}-test",
        ioc_type=ioc_type,
        raw_value=value,
        normalized_value=value.lower(),
        status=IOCStatus.EXTRACTED,
        first_seen=now,
        last_seen=now,
    )


class TestOfflineMockThreatIntelProvider(unittest.TestCase):
    """Test suite for deterministic OfflineMockThreatIntelProvider."""

    def setUp(self):
        self.provider = OfflineMockThreatIntelProvider()

    def test_provider_properties(self):
        self.assertEqual(self.provider.provider_name, "offline_mock")
        self.assertEqual(self.provider.provider_version, "1.0.0")
        self.assertEqual(self.provider.source_type, ThreatIntelSource.OFFLINE_MOCK)
        self.assertIn(IOCType.IPV4, self.provider.supported_ioc_types)
        self.assertIn(IOCType.IPV6, self.provider.supported_ioc_types)
        self.assertIn(IOCType.DOMAIN, self.provider.supported_ioc_types)
        self.assertIn(IOCType.URL, self.provider.supported_ioc_types)
        self.assertIn(IOCType.MD5, self.provider.supported_ioc_types)
        self.assertIn(IOCType.SHA1, self.provider.supported_ioc_types)
        self.assertIn(IOCType.SHA256, self.provider.supported_ioc_types)
        self.assertIn(IOCType.EMAIL, self.provider.supported_ioc_types)
        self.assertIn(IOCType.FILE_PATH, self.provider.supported_ioc_types)

    def test_clean_indicator_lookups(self):
        # 8.8.8.8
        ip_ioc = _build_ioc(IOCType.IPV4, "8.8.8.8")
        res = self.provider.lookup(ip_ioc)
        self.assertEqual(res.status, ThreatIntelStatus.CLEAN)
        self.assertGreaterEqual(res.confidence, 0.9)
        self.assertEqual(res.detection_count, 0)
        self.assertEqual(res.country, "US")
        self.assertEqual(res.asn, "AS15169")
        self.assertIn("verified_clean", res.tags)

        # google.com
        domain_ioc = _build_ioc(IOCType.DOMAIN, "google.com")
        res = self.provider.lookup(domain_ioc)
        self.assertEqual(res.status, ThreatIntelStatus.CLEAN)
        self.assertEqual(res.detection_count, 0)

        # 2001:4860:4860::8888 (IPv6)
        ipv6_ioc = _build_ioc(IOCType.IPV6, "2001:4860:4860::8888")
        res = self.provider.lookup(ipv6_ioc)
        self.assertEqual(res.status, ThreatIntelStatus.CLEAN)

    def test_suspicious_indicator_lookups(self):
        # 198.51.100.42
        susp_ip = _build_ioc(IOCType.IPV4, "198.51.100.42")
        res = self.provider.lookup(susp_ip)
        self.assertEqual(res.status, ThreatIntelStatus.SUSPICIOUS)
        self.assertGreater(res.reputation_score, 0.5)
        self.assertGreater(res.detection_count, 0)
        self.assertIn("reconnaissance", res.tags)

        # suspicious-domain.test
        susp_domain = _build_ioc(IOCType.DOMAIN, "suspicious-domain.test")
        res = self.provider.lookup(susp_domain)
        self.assertEqual(res.status, ThreatIntelStatus.SUSPICIOUS)
        self.assertIn("low_reputation", res.tags)

    def test_malicious_indicator_lookups(self):
        # Known Tor / scanner IP 185.220.101.5
        c2_ip = _build_ioc(IOCType.IPV4, "185.220.101.5")
        res = self.provider.lookup(c2_ip)
        self.assertEqual(res.status, ThreatIntelStatus.MALICIOUS)
        self.assertGreaterEqual(res.confidence, 0.95)
        self.assertGreaterEqual(res.reputation_score, 0.85)
        self.assertGreater(res.detection_count, 30)
        self.assertIn("c2_server", res.categories)

        # EICAR SHA256 hash
        eicar_sha256 = _build_ioc(
            IOCType.SHA256,
            "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f",
        )
        res = self.provider.lookup(eicar_sha256)
        self.assertEqual(res.status, ThreatIntelStatus.MALICIOUS)
        self.assertEqual(res.detection_count, 68)
        self.assertEqual(res.total_engines, 70)
        self.assertIn("eicar", res.tags)

        # EICAR MD5 hash
        eicar_md5 = _build_ioc(
            IOCType.MD5,
            "44d88612fea8a8f36de82e1278abb02f",
        )
        res = self.provider.lookup(eicar_md5)
        self.assertEqual(res.status, ThreatIntelStatus.MALICIOUS)
        self.assertEqual(res.detection_count, 68)

    def test_unmapped_indicator_returns_unknown(self):
        unmapped_ip = _build_ioc(IOCType.IPV4, "203.0.113.199")
        res = self.provider.lookup(unmapped_ip)
        self.assertEqual(res.status, ThreatIntelStatus.UNKNOWN)
        self.assertEqual(res.confidence, 0.0)
        self.assertEqual(res.detection_count, 0)
        self.assertEqual(res.total_engines, 0)
        self.assertIn("unknown_indicator", res.tags)

    def test_unsupported_indicator_type(self):
        restricted_provider = OfflineMockThreatIntelProvider(
            supported_types={IOCType.IPV4, IOCType.DOMAIN}
        )
        file_path_ioc = _build_ioc(IOCType.FILE_PATH, "C:\\Windows\\System32\\cmd.exe")
        res = restricted_provider.lookup(file_path_ioc)
        self.assertEqual(res.status, ThreatIntelStatus.UNKNOWN)
        self.assertIn("unsupported_type", res.tags)

    def test_custom_fixture_registration(self):
        custom_domain = _build_ioc(IOCType.DOMAIN, "custom-test-threat.xyz")
        # Before registration -> UNKNOWN
        res_before = self.provider.lookup(custom_domain)
        self.assertEqual(res_before.status, ThreatIntelStatus.UNKNOWN)

        # Register fixture
        self.provider.register_fixture(
            "custom-test-threat.xyz",
            {
                "status": ThreatIntelStatus.MALICIOUS,
                "confidence": 0.99,
                "reputation_score": 0.98,
                "detection_count": 55,
                "total_engines": 60,
                "categories": ["apt", "c2"],
                "tags": ["custom_test"],
                "country": "DE",
                "asn": "AS9999",
            },
        )

        # After registration -> MALICIOUS
        res_after = self.provider.lookup(custom_domain)
        self.assertEqual(res_after.status, ThreatIntelStatus.MALICIOUS)
        self.assertEqual(res_after.confidence, 0.99)
        self.assertEqual(res_after.reputation_score, 0.98)
        self.assertEqual(res_after.detection_count, 55)
        self.assertEqual(res_after.total_engines, 60)
        self.assertEqual(res_after.categories, ["apt", "c2"])
        self.assertIn("custom_test", res_after.tags)
        self.assertEqual(res_after.country, "DE")
        self.assertEqual(res_after.asn, "AS9999")

    def test_metadata_attribution_flags(self):
        ip_ioc = _build_ioc(IOCType.IPV4, "8.8.8.8")
        res = self.provider.lookup(ip_ioc)
        self.assertIsNotNone(res.raw_metadata)
        self.assertTrue(res.raw_metadata.get("is_simulated"))
        self.assertTrue(res.raw_metadata.get("offline"))

    def test_input_ioc_remains_unmutated(self):
        initial_status = IOCStatus.EXTRACTED
        ioc = _build_ioc(IOCType.IPV4, "185.220.101.5")
        ioc.status = initial_status

        res = self.provider.lookup(ioc)
        # Even though result is MALICIOUS, input IOC status must remain unchanged
        self.assertEqual(res.status, ThreatIntelStatus.MALICIOUS)
        self.assertEqual(ioc.status, IOCStatus.EXTRACTED)


if __name__ == "__main__":
    unittest.main()
