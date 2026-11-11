"""
Phase 4.2B.3 — VirusTotal Provider Tests

All tests use mocked HTTP responses via unittest.mock.
No real VirusTotal API requests are made during the test suite.

Covers:
- Authentication: key present, key absent, invalid key (401/403)
- IOC type support: IPv4, IPv6, domain, URL, MD5, SHA1, SHA256, unsupported EMAIL/FILE_PATH
- Response normalization: malicious, suspicious, clean, unknown (404), missing fields
- HTTP errors: timeout, connection error, 400, 401, 403, 404, 429, 500, malformed JSON
- Cache integration via ThreatIntelService: hit, miss, force refresh
- Security: API key never appears in result, raw_metadata, or tags
- Integration pipeline: IOC → ThreatIntelService → VirusTotalProvider → ThreatIntelResult
  → ThreatReputationEngine → ThreatAssessment
- Provider availability/status reporting
"""

from datetime import datetime, timezone
import os
import sys
from typing import Dict, Any
import unittest
from unittest.mock import MagicMock, patch, PropertyMock

# ── Path setup ──────────────────────────────────────────────────────────────
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import httpx

from app.models.ioc import IOC, IOCStatus, IOCType
from app.models.threat_intel import ThreatIntelStatus, ThreatIntelSource, ThreatSeverity
from app.services.providers.virustotal_provider import VirusTotalProvider
from app.services.threat_intel_service import ThreatIntelCache, ThreatIntelService
from app.services.threat_reputation_engine import ThreatReputationEngine


# ─────────────────────────────────────────────────────────────────────────────
# Test Fixtures & Helpers
# ─────────────────────────────────────────────────────────────────────────────

FAKE_API_KEY = "vt_test_api_key_1234567890abcdef"


def _build_ioc(ioc_type: IOCType, value: str) -> IOC:
    now = datetime.now(timezone.utc)
    return IOC(
        id=f"ioc-{ioc_type.value}-test",
        ioc_type=ioc_type,
        raw_value=value,
        normalized_value=value.lower(),
        status=IOCStatus.EXTRACTED,
        first_seen=now,
        last_seen=now,
    )


def _mock_vt_ip_response(
    malicious: int = 0,
    suspicious: int = 0,
    harmless: int = 70,
    undetected: int = 2,
    reputation: int = 0,
    country: str = "US",
    asn: int = 15169,
) -> Dict[str, Any]:
    """Build a realistic VirusTotal v3 IP address response payload."""
    return {
        "data": {
            "id": "8.8.8.8",
            "type": "ip_address",
            "attributes": {
                "last_analysis_stats": {
                    "malicious": malicious,
                    "suspicious": suspicious,
                    "harmless": harmless,
                    "undetected": undetected,
                },
                "last_analysis_date": 1762300000,
                "first_submission_date": 1700000000,
                "reputation": reputation,
                "country": country,
                "asn": asn,
                "as_owner": "GOOGLE",
                "tags": ["google", "dns"],
                "categories": {"Cloudmersive": "content server"},
            },
        }
    }


def _mock_response(status_code: int, json_data: Any = None, headers: Dict = None) -> httpx.Response:
    """Build a mock httpx.Response with controlled status and JSON body."""
    mock = MagicMock(spec=httpx.Response)
    mock.status_code = status_code
    mock.headers = headers or {}
    if json_data is not None:
        mock.json.return_value = json_data
    else:
        mock.json.side_effect = ValueError("No JSON body")
    return mock


# ─────────────────────────────────────────────────────────────────────────────
# Authentication Tests
# ─────────────────────────────────────────────────────────────────────────────

class TestVirusTotalAuthentication(unittest.TestCase):

    def test_provider_enabled_when_api_key_set(self):
        p = VirusTotalProvider(api_key=FAKE_API_KEY)
        self.assertTrue(p.is_available)
        self.assertEqual(p.availability_status, "AVAILABLE")

    def test_provider_disabled_when_no_api_key(self):
        p = VirusTotalProvider(api_key="")
        self.assertFalse(p.is_available)
        self.assertEqual(p.availability_status, "DISABLED")

    def test_lookup_returns_unknown_when_disabled(self):
        p = VirusTotalProvider(api_key="")
        ioc = _build_ioc(IOCType.IPV4, "8.8.8.8")
        result = p.lookup(ioc)
        self.assertEqual(result.status, ThreatIntelStatus.UNKNOWN)
        self.assertIn("missing_api_key", result.tags)
        self.assertIn("provider_disabled", result.tags)
        self.assertEqual(result.confidence, 0.0)
        # API key must NOT appear in result
        self.assertNotIn(FAKE_API_KEY, str(result.raw_metadata))

    def test_lookup_returns_error_on_401_invalid_key(self):
        mock_resp = _mock_response(401)
        client = MagicMock(spec=httpx.Client)
        client.get.return_value = mock_resp
        p = VirusTotalProvider(api_key=FAKE_API_KEY, client=client)
        ioc = _build_ioc(IOCType.IPV4, "1.2.3.4")
        result = p.lookup(ioc)
        self.assertEqual(result.status, ThreatIntelStatus.ERROR)
        self.assertIn("auth_error", result.tags)

    def test_lookup_returns_error_on_403_forbidden(self):
        mock_resp = _mock_response(403)
        client = MagicMock(spec=httpx.Client)
        client.get.return_value = mock_resp
        p = VirusTotalProvider(api_key=FAKE_API_KEY, client=client)
        ioc = _build_ioc(IOCType.DOMAIN, "test.com")
        result = p.lookup(ioc)
        self.assertEqual(result.status, ThreatIntelStatus.ERROR)
        self.assertIn("auth_error", result.tags)


# ─────────────────────────────────────────────────────────────────────────────
# IOC Type Support Tests
# ─────────────────────────────────────────────────────────────────────────────

class TestVirusTotalIOCTypeSupport(unittest.TestCase):

    def setUp(self):
        self.provider = VirusTotalProvider(api_key=FAKE_API_KEY)

    def test_supported_types_declared(self):
        for t in [IOCType.IPV4, IOCType.IPV6, IOCType.DOMAIN, IOCType.URL,
                  IOCType.MD5, IOCType.SHA1, IOCType.SHA256]:
            self.assertTrue(self.provider.supports(t), f"Should support {t.value}")

    def test_unsupported_email_returns_unknown(self):
        self.assertFalse(self.provider.supports(IOCType.EMAIL))
        email_ioc = _build_ioc(IOCType.EMAIL, "test@example.com")
        result = self.provider.lookup(email_ioc)
        self.assertEqual(result.status, ThreatIntelStatus.UNKNOWN)
        self.assertIn("unsupported_type", result.tags)

    def test_unsupported_file_path_returns_unknown(self):
        self.assertFalse(self.provider.supports(IOCType.FILE_PATH))
        fp_ioc = _build_ioc(IOCType.FILE_PATH, "C:\\Windows\\System32\\calc.exe")
        result = self.provider.lookup(fp_ioc)
        self.assertEqual(result.status, ThreatIntelStatus.UNKNOWN)
        self.assertIn("unsupported_type", result.tags)

    def test_ipv4_uses_correct_endpoint(self):
        path, gui = self.provider._resolve_endpoint_and_gui(_build_ioc(IOCType.IPV4, "8.8.8.8"))
        self.assertIn("/ip_addresses/", path)

    def test_ipv6_uses_ip_endpoint(self):
        path, gui = self.provider._resolve_endpoint_and_gui(
            _build_ioc(IOCType.IPV6, "2001:4860:4860::8888")
        )
        self.assertIn("/ip_addresses/", path)

    def test_domain_uses_domains_endpoint(self):
        path, gui = self.provider._resolve_endpoint_and_gui(_build_ioc(IOCType.DOMAIN, "google.com"))
        self.assertIn("/domains/", path)

    def test_hash_uses_files_endpoint(self):
        for t in [IOCType.MD5, IOCType.SHA1, IOCType.SHA256]:
            path, gui = self.provider._resolve_endpoint_and_gui(_build_ioc(t, "aabbcc"))
            self.assertIn("/files/", path)

    def test_url_uses_base64_encoded_endpoint(self):
        import base64
        url_ioc = _build_ioc(IOCType.URL, "http://malicious-c2.example/beacon")
        path, gui = self.provider._resolve_endpoint_and_gui(url_ioc)
        expected_id = base64.urlsafe_b64encode(url_ioc.raw_value.encode()).decode().rstrip("=")
        self.assertIn(f"/urls/{expected_id}", path)


# ─────────────────────────────────────────────────────────────────────────────
# Response Normalization Tests
# ─────────────────────────────────────────────────────────────────────────────

class TestVirusTotalResponseNormalization(unittest.TestCase):

    def _make_provider_with_response(self, response: httpx.Response) -> VirusTotalProvider:
        client = MagicMock(spec=httpx.Client)
        client.get.return_value = response
        return VirusTotalProvider(api_key=FAKE_API_KEY, client=client)

    def test_malicious_response_normalization(self):
        resp = _mock_response(200, _mock_vt_ip_response(
            malicious=48, suspicious=5, harmless=18, undetected=1, reputation=-90
        ))
        p = self._make_provider_with_response(resp)
        result = p.lookup(_build_ioc(IOCType.IPV4, "185.220.101.5"))

        self.assertEqual(result.status, ThreatIntelStatus.MALICIOUS)
        self.assertEqual(result.detection_count, 53)   # malicious + suspicious
        self.assertGreaterEqual(result.total_engines, 70)
        self.assertGreaterEqual(result.confidence, 0.85)
        self.assertGreaterEqual(result.reputation_score, 0.90)  # -90 rep → high risk
        self.assertIn("virustotal", result.tags)

    def test_suspicious_response_normalization(self):
        resp = _mock_response(200, _mock_vt_ip_response(
            malicious=1, suspicious=4, harmless=65, undetected=2, reputation=-20
        ))
        p = self._make_provider_with_response(resp)
        result = p.lookup(_build_ioc(IOCType.IPV4, "198.51.100.42"))

        self.assertEqual(result.status, ThreatIntelStatus.SUSPICIOUS)
        self.assertEqual(result.detection_count, 5)
        self.assertIn("virustotal", result.tags)

    def test_clean_response_normalization(self):
        resp = _mock_response(200, _mock_vt_ip_response(
            malicious=0, suspicious=0, harmless=72, undetected=0, reputation=100, country="US", asn=15169
        ))
        p = self._make_provider_with_response(resp)
        result = p.lookup(_build_ioc(IOCType.IPV4, "8.8.8.8"))

        self.assertEqual(result.status, ThreatIntelStatus.CLEAN)
        self.assertEqual(result.detection_count, 0)
        self.assertEqual(result.country, "US")
        self.assertEqual(result.asn, "AS15169")

    def test_unknown_no_engines_normalization(self):
        resp = _mock_response(200, {
            "data": {
                "id": "new-ip",
                "type": "ip_address",
                "attributes": {
                    "last_analysis_stats": {
                        "malicious": 0, "suspicious": 0, "harmless": 0, "undetected": 0,
                    },
                },
            }
        })
        p = self._make_provider_with_response(resp)
        result = p.lookup(_build_ioc(IOCType.IPV4, "192.0.2.1"))

        self.assertEqual(result.status, ThreatIntelStatus.UNKNOWN)
        self.assertEqual(result.confidence, 0.0)
        self.assertEqual(result.total_engines, 0)

    def test_404_normalization_is_unknown_not_clean(self):
        """Critical security invariant: 404 Not Found must be UNKNOWN, never CLEAN."""
        resp = _mock_response(404)
        p = self._make_provider_with_response(resp)
        result = p.lookup(_build_ioc(IOCType.IPV4, "192.0.2.100"))

        self.assertEqual(result.status, ThreatIntelStatus.UNKNOWN)
        self.assertIn("not_found_in_virustotal", result.tags)
        self.assertEqual(result.confidence, 0.0)

    def test_missing_optional_fields_produce_safe_fallbacks(self):
        resp = _mock_response(200, {
            "data": {
                "id": "partial",
                "type": "ip_address",
                "attributes": {
                    "last_analysis_stats": {"malicious": 5, "suspicious": 2, "harmless": 60, "undetected": 5},
                },
            }
        })
        p = self._make_provider_with_response(resp)
        result = p.lookup(_build_ioc(IOCType.IPV4, "1.2.3.4"))

        # Must not crash on missing optional fields
        self.assertIsNotNone(result)
        self.assertIsNone(result.country)
        self.assertIsNone(result.asn)
        self.assertIsNone(result.first_seen)

    def test_malformed_json_returns_error(self):
        mock = MagicMock(spec=httpx.Response)
        mock.status_code = 200
        mock.headers = {}
        mock.json.side_effect = ValueError("not json")
        p = VirusTotalProvider(api_key=FAKE_API_KEY, client=MagicMock(spec=httpx.Client, **{"get.return_value": mock}))
        result = p.lookup(_build_ioc(IOCType.IPV4, "9.9.9.9"))
        self.assertEqual(result.status, ThreatIntelStatus.ERROR)
        self.assertIn("parse_error", result.tags)

    def test_reputation_score_normalized_from_vt_integer(self):
        # VT rep of -100 (most malicious) should map to 1.0 in MICHAEL
        # VT rep of +100 (most benign) should map to 0.0 in MICHAEL
        resp = _mock_response(200, _mock_vt_ip_response(
            malicious=0, suspicious=0, harmless=70, undetected=2, reputation=100
        ))
        p = self._make_provider_with_response(resp)
        result = p.lookup(_build_ioc(IOCType.IPV4, "1.1.1.1"))
        self.assertAlmostEqual(result.reputation_score, 0.0, places=1)

        resp2 = _mock_response(200, _mock_vt_ip_response(
            malicious=50, suspicious=5, harmless=0, undetected=5, reputation=-100
        ))
        client2 = MagicMock(spec=httpx.Client)
        client2.get.return_value = resp2
        p2 = VirusTotalProvider(api_key=FAKE_API_KEY, client=client2)
        result2 = p2.lookup(_build_ioc(IOCType.IPV4, "185.220.101.5"))
        self.assertAlmostEqual(result2.reputation_score, 1.0, places=1)


# ─────────────────────────────────────────────────────────────────────────────
# Error Handling Tests
# ─────────────────────────────────────────────────────────────────────────────

class TestVirusTotalErrorHandling(unittest.TestCase):

    def _make_provider_with_response(self, response: httpx.Response) -> VirusTotalProvider:
        client = MagicMock(spec=httpx.Client)
        client.get.return_value = response
        return VirusTotalProvider(api_key=FAKE_API_KEY, client=client)

    def _make_provider_with_exception(self, exc: Exception) -> VirusTotalProvider:
        client = MagicMock(spec=httpx.Client)
        client.get.side_effect = exc
        return VirusTotalProvider(api_key=FAKE_API_KEY, client=client)

    def test_timeout_returns_error(self):
        p = self._make_provider_with_exception(httpx.TimeoutException("timed out"))
        result = p.lookup(_build_ioc(IOCType.IPV4, "1.2.3.4"))
        self.assertEqual(result.status, ThreatIntelStatus.ERROR)
        self.assertIn("lookup_error", result.tags)

    def test_connection_error_returns_error(self):
        p = self._make_provider_with_exception(httpx.ConnectError("connection failed"))
        result = p.lookup(_build_ioc(IOCType.DOMAIN, "malicious.example"))
        self.assertEqual(result.status, ThreatIntelStatus.ERROR)

    def test_http_400_returns_error(self):
        result = self._make_provider_with_response(_mock_response(400)).lookup(
            _build_ioc(IOCType.IPV4, "not.valid")
        )
        self.assertEqual(result.status, ThreatIntelStatus.ERROR)

    def test_http_401_returns_error(self):
        result = self._make_provider_with_response(_mock_response(401)).lookup(
            _build_ioc(IOCType.IPV4, "1.2.3.4")
        )
        self.assertEqual(result.status, ThreatIntelStatus.ERROR)
        self.assertIn("auth_error", result.tags)

    def test_http_403_returns_error(self):
        result = self._make_provider_with_response(_mock_response(403)).lookup(
            _build_ioc(IOCType.IPV4, "1.2.3.4")
        )
        self.assertEqual(result.status, ThreatIntelStatus.ERROR)
        self.assertIn("auth_error", result.tags)

    def test_http_404_returns_unknown_not_error(self):
        result = self._make_provider_with_response(_mock_response(404)).lookup(
            _build_ioc(IOCType.IPV4, "192.0.2.200")
        )
        self.assertEqual(result.status, ThreatIntelStatus.UNKNOWN)

    def test_http_429_rate_limit_returns_error(self):
        resp = _mock_response(429, headers={"Retry-After": "60"})
        result = self._make_provider_with_response(resp).lookup(_build_ioc(IOCType.IPV4, "1.2.3.4"))
        self.assertEqual(result.status, ThreatIntelStatus.ERROR)
        self.assertIn("rate_limited", result.tags)
        self.assertEqual(result.raw_metadata.get("rate_limited"), True)
        self.assertEqual(result.raw_metadata.get("retry_after"), "60")

    def test_http_500_returns_error(self):
        result = self._make_provider_with_response(_mock_response(500)).lookup(
            _build_ioc(IOCType.IPV4, "1.2.3.4")
        )
        self.assertEqual(result.status, ThreatIntelStatus.ERROR)
        self.assertIn("upstream_error", result.tags)

    def test_no_crash_on_any_error_type(self):
        """Provider exceptions must never propagate uncaught."""
        p = self._make_provider_with_exception(RuntimeError("unexpected crash"))
        ioc = _build_ioc(IOCType.IPV4, "1.2.3.4")
        # Must not raise
        result = p.lookup(ioc)
        self.assertIsNotNone(result)
        self.assertIn(result.status, (ThreatIntelStatus.ERROR, ThreatIntelStatus.UNKNOWN))


# ─────────────────────────────────────────────────────────────────────────────
# Security Tests — API Key / Secret Leakage
# ─────────────────────────────────────────────────────────────────────────────

class TestVirusTotalSecurityInvariants(unittest.TestCase):

    def _get_all_result_strings(self, result) -> str:
        """Flatten all string fields in a ThreatIntelResult for secret scanning."""
        parts = [
            result.ioc_id, result.ioc_value, result.normalized_value,
            result.provider_name, result.provider_version,
            str(result.tags), str(result.categories),
            str(result.raw_metadata), str(result.source_reference),
        ]
        return " ".join(str(p) for p in parts if p)

    def test_api_key_never_appears_in_result_on_success(self):
        resp_data = _mock_vt_ip_response(malicious=0, suspicious=0, harmless=72, undetected=0, reputation=100)
        client = MagicMock(spec=httpx.Client)
        client.get.return_value = _mock_response(200, resp_data)
        p = VirusTotalProvider(api_key=FAKE_API_KEY, client=client)
        result = p.lookup(_build_ioc(IOCType.IPV4, "8.8.8.8"))

        all_text = self._get_all_result_strings(result)
        self.assertNotIn(FAKE_API_KEY, all_text)

    def test_api_key_never_appears_in_error_result(self):
        client = MagicMock(spec=httpx.Client)
        client.get.return_value = _mock_response(401)
        p = VirusTotalProvider(api_key=FAKE_API_KEY, client=client)
        result = p.lookup(_build_ioc(IOCType.IPV4, "1.2.3.4"))

        all_text = self._get_all_result_strings(result)
        self.assertNotIn(FAKE_API_KEY, all_text)

    def test_api_key_never_appears_in_timeout_result(self):
        client = MagicMock(spec=httpx.Client)
        client.get.side_effect = httpx.TimeoutException("timeout")
        p = VirusTotalProvider(api_key=FAKE_API_KEY, client=client)
        result = p.lookup(_build_ioc(IOCType.DOMAIN, "test.com"))

        all_text = self._get_all_result_strings(result)
        self.assertNotIn(FAKE_API_KEY, all_text)

    def test_authorization_header_not_in_result_metadata(self):
        resp_data = _mock_vt_ip_response()
        client = MagicMock(spec=httpx.Client)
        client.get.return_value = _mock_response(200, resp_data)
        p = VirusTotalProvider(api_key=FAKE_API_KEY, client=client)
        result = p.lookup(_build_ioc(IOCType.IPV4, "8.8.8.8"))

        meta_str = str(result.raw_metadata)
        self.assertNotIn("x-apikey", meta_str.lower())
        self.assertNotIn("authorization", meta_str.lower())
        self.assertNotIn(FAKE_API_KEY, meta_str)

    def test_disabled_provider_result_contains_no_key(self):
        p = VirusTotalProvider(api_key="")
        result = p.lookup(_build_ioc(IOCType.IPV4, "1.1.1.1"))
        all_text = self._get_all_result_strings(result)
        self.assertNotIn(FAKE_API_KEY, all_text)
        # Confirm the disabled_result flag is present but no credentials
        self.assertTrue(result.raw_metadata.get("disabled"))


# ─────────────────────────────────────────────────────────────────────────────
# Cache Integration Tests
# ─────────────────────────────────────────────────────────────────────────────

class TestVirusTotalCacheIntegration(unittest.TestCase):

    def test_service_cache_hit_prevents_external_call(self):
        """When a valid cached result exists, no HTTP request should be made."""
        client = MagicMock(spec=httpx.Client)
        client.get.return_value = _mock_response(200, _mock_vt_ip_response())

        vt_provider = VirusTotalProvider(api_key=FAKE_API_KEY, client=client)
        cache = ThreatIntelCache(default_ttl_seconds=3600)
        service = ThreatIntelService(cache=cache)
        service.register_provider(vt_provider)
        service.default_provider_name = "virustotal"

        ioc = _build_ioc(IOCType.IPV4, "8.8.8.8")

        # First call: populates cache (1 HTTP request)
        service.lookup(ioc)
        first_call_count = client.get.call_count
        self.assertEqual(first_call_count, 1)

        # Second call: cache hit, no HTTP request
        service.lookup(ioc)
        self.assertEqual(client.get.call_count, 1)

    def test_force_refresh_bypasses_cache(self):
        """force_refresh=True must bypass cache and invoke a fresh HTTP request."""
        client = MagicMock(spec=httpx.Client)
        client.get.return_value = _mock_response(200, _mock_vt_ip_response())

        vt_provider = VirusTotalProvider(api_key=FAKE_API_KEY, client=client)
        cache = ThreatIntelCache(default_ttl_seconds=3600)
        service = ThreatIntelService(cache=cache)
        service.register_provider(vt_provider)
        service.default_provider_name = "virustotal"

        ioc = _build_ioc(IOCType.IPV4, "8.8.8.8")

        # Populate cache
        service.lookup(ioc)
        self.assertEqual(client.get.call_count, 1)

        # Force refresh
        service.lookup(ioc, force_refresh=True)
        self.assertEqual(client.get.call_count, 2)

    def test_no_external_call_when_key_absent(self):
        """VirusTotal provider must never issue HTTP requests when disabled."""
        client = MagicMock(spec=httpx.Client)
        p = VirusTotalProvider(api_key="", client=client)
        ioc = _build_ioc(IOCType.IPV4, "1.2.3.4")

        p.lookup(ioc)
        client.get.assert_not_called()


# ─────────────────────────────────────────────────────────────────────────────
# Provider Status Tests
# ─────────────────────────────────────────────────────────────────────────────

class TestVirusTotalProviderStatus(unittest.TestCase):

    def test_provider_status_reported_in_service(self):
        vt = VirusTotalProvider(api_key=FAKE_API_KEY)
        service = ThreatIntelService()
        service.register_provider(vt)

        statuses = service.get_provider_status()
        vt_status = next(s for s in statuses if s["provider_name"] == "virustotal")

        self.assertEqual(vt_status["status"], "AVAILABLE")
        self.assertIn("ipv4", vt_status["supported_ioc_types"])

    def test_disabled_provider_reported_in_service(self):
        vt = VirusTotalProvider(api_key="")
        service = ThreatIntelService()
        service.register_provider(vt)

        statuses = service.get_provider_status()
        vt_status = next(s for s in statuses if s["provider_name"] == "virustotal")
        self.assertEqual(vt_status["status"], "DISABLED")

    def test_provider_attributes(self):
        p = VirusTotalProvider(api_key=FAKE_API_KEY)
        self.assertEqual(p.provider_name, "virustotal")
        self.assertEqual(p.source_type, ThreatIntelSource.VIRUSTOTAL)
        self.assertEqual(p.provider_version, "1.0.0")


# ─────────────────────────────────────────────────────────────────────────────
# Full Pipeline Integration Test
# ─────────────────────────────────────────────────────────────────────────────

class TestVirusTotalFullPipelineIntegration(unittest.TestCase):
    """
    End-to-end: IOC → ThreatIntelService → VirusTotalProvider → ThreatIntelResult
              → ThreatReputationEngine → ThreatAssessment
    Uses mocked HTTP responses; no real network calls.
    """

    def test_malicious_ioc_full_pipeline(self):
        """A malicious IP should produce a CRITICAL assessment through the full pipeline."""
        resp_data = _mock_vt_ip_response(
            malicious=48, suspicious=5, harmless=18, undetected=1, reputation=-90
        )
        client = MagicMock(spec=httpx.Client)
        client.get.return_value = _mock_response(200, resp_data)

        vt_provider = VirusTotalProvider(api_key=FAKE_API_KEY, client=client)
        cache = ThreatIntelCache()
        service = ThreatIntelService(cache=cache)
        service.register_provider(vt_provider)
        service.default_provider_name = "virustotal"

        engine = ThreatReputationEngine(service=service)
        ioc = _build_ioc(IOCType.IPV4, "185.220.101.5")
        ioc.status = IOCStatus.EXTRACTED

        assessment = engine.assess_ioc(ioc, provider_name="virustotal")

        self.assertEqual(assessment.status, ThreatIntelStatus.MALICIOUS)
        self.assertGreaterEqual(assessment.threat_score, 75.0)
        self.assertIn(assessment.severity, (ThreatSeverity.HIGH, ThreatSeverity.CRITICAL))
        self.assertGreaterEqual(assessment.confidence, 0.80)
        self.assertGreater(len(assessment.reasons), 0)
        self.assertGreater(len(assessment.contributing_signals), 0)

        # IOC immutability guaranteed
        self.assertEqual(ioc.status, IOCStatus.EXTRACTED)

    def test_clean_ioc_full_pipeline(self):
        """A clean well-known IP should produce a LOW assessment."""
        resp_data = _mock_vt_ip_response(
            malicious=0, suspicious=0, harmless=72, undetected=0, reputation=100
        )
        client = MagicMock(spec=httpx.Client)
        client.get.return_value = _mock_response(200, resp_data)

        vt_provider = VirusTotalProvider(api_key=FAKE_API_KEY, client=client)
        service = ThreatIntelService()
        service.register_provider(vt_provider)
        service.default_provider_name = "virustotal"

        engine = ThreatReputationEngine(service=service)
        ioc = _build_ioc(IOCType.IPV4, "8.8.8.8")
        assessment = engine.assess_ioc(ioc, provider_name="virustotal")

        self.assertEqual(assessment.status, ThreatIntelStatus.CLEAN)
        self.assertLess(assessment.threat_score, 25.0)
        self.assertEqual(assessment.severity, ThreatSeverity.LOW)

    def test_provider_disabled_pipeline_returns_unknown_severity(self):
        """When API key absent, pipeline should safely return UNKNOWN severity."""
        vt_provider = VirusTotalProvider(api_key="")
        service = ThreatIntelService()
        service.register_provider(vt_provider)
        service.default_provider_name = "virustotal"

        engine = ThreatReputationEngine(service=service)
        ioc = _build_ioc(IOCType.IPV4, "8.8.8.8")
        assessment = engine.assess_ioc(ioc, provider_name="virustotal")

        self.assertEqual(assessment.severity, ThreatSeverity.UNKNOWN)
        self.assertEqual(assessment.threat_score, 0.0)
        self.assertEqual(assessment.confidence, 0.0)
        self.assertEqual(ioc.status, IOCStatus.EXTRACTED)


if __name__ == "__main__":
    unittest.main()
