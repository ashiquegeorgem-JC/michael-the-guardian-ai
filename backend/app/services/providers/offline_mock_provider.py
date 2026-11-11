"""
Offline Mock Threat Intelligence Provider for MICHAEL – THE GUARDIAN AI.

Phase 4.2B.1 — Threat Intelligence Data Model & Provider Interface.

Provides a deterministic, strictly offline provider using hardcoded test fixtures.
Never makes external network calls, DNS requests, or API queries.
Used exclusively for unit testing, integration tests, UI scaffolding, and demonstration.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
import time
from typing import Any, Dict, List, Optional, Set

from app.models.ioc import IOC, IOCType
from app.models.threat_intel import (
    ThreatIntelResult,
    ThreatIntelSource,
    ThreatIntelStatus,
)
from app.services.threat_intel_provider import BaseThreatIntelProvider


# ─────────────────────────────────────────────────────────────────────────────
# Deterministic Fixture Records
# ─────────────────────────────────────────────────────────────────────────────

_DEFAULT_FIXTURES: Dict[str, Dict[str, Any]] = {
    # ── Known Clean Indicators ───────────────────────────────────────────────
    "8.8.8.8": {
        "status": ThreatIntelStatus.CLEAN,
        "confidence": 0.95,
        "reputation_score": 0.02,
        "detection_count": 0,
        "total_engines": 72,
        "categories": ["dns_resolver", "anycast", "benign"],
        "tags": ["google_dns", "verified_clean"],
        "country": "US",
        "asn": "AS15169",
    },
    "1.1.1.1": {
        "status": ThreatIntelStatus.CLEAN,
        "confidence": 0.95,
        "reputation_score": 0.01,
        "detection_count": 0,
        "total_engines": 72,
        "categories": ["dns_resolver", "anycast", "benign"],
        "tags": ["cloudflare_dns", "verified_clean"],
        "country": "US",
        "asn": "AS13335",
    },
    "google.com": {
        "status": ThreatIntelStatus.CLEAN,
        "confidence": 0.98,
        "reputation_score": 0.01,
        "detection_count": 0,
        "total_engines": 84,
        "categories": ["search_engine", "web_services"],
        "tags": ["google", "top_domain"],
        "country": "US",
    },
    "microsoft.com": {
        "status": ThreatIntelStatus.CLEAN,
        "confidence": 0.98,
        "reputation_score": 0.01,
        "detection_count": 0,
        "total_engines": 84,
        "categories": ["enterprise_services", "software"],
        "tags": ["microsoft", "top_domain"],
        "country": "US",
    },
    "https://www.google.com": {
        "status": ThreatIntelStatus.CLEAN,
        "confidence": 0.95,
        "reputation_score": 0.01,
        "detection_count": 0,
        "total_engines": 70,
        "categories": ["search"],
        "tags": ["https", "verified_clean"],
    },
    "2001:4860:4860::8888": {
        "status": ThreatIntelStatus.CLEAN,
        "confidence": 0.95,
        "reputation_score": 0.02,
        "detection_count": 0,
        "total_engines": 65,
        "categories": ["ipv6_dns", "anycast"],
        "tags": ["google_ipv6"],
        "country": "US",
    },
    "support@google.com": {
        "status": ThreatIntelStatus.CLEAN,
        "confidence": 0.90,
        "reputation_score": 0.05,
        "detection_count": 0,
        "total_engines": 30,
        "categories": ["corporate_support"],
        "tags": ["legitimate_email"],
    },
    "c:\\windows\\system32\\calc.exe": {
        "status": ThreatIntelStatus.CLEAN,
        "confidence": 0.90,
        "reputation_score": 0.01,
        "detection_count": 0,
        "total_engines": 50,
        "categories": ["system_binary"],
        "tags": ["windows_utility"],
    },

    # ── Known Suspicious Indicators ──────────────────────────────────────────
    "198.51.100.42": {
        "status": ThreatIntelStatus.SUSPICIOUS,
        "confidence": 0.70,
        "reputation_score": 0.55,
        "detection_count": 6,
        "total_engines": 72,
        "categories": ["scanner", "port_probe", "anomalous_source"],
        "tags": ["reconnaissance", "unsolicited_traffic"],
        "country": "NL",
        "asn": "AS64496",
    },
    "suspicious-domain.test": {
        "status": ThreatIntelStatus.SUSPICIOUS,
        "confidence": 0.75,
        "reputation_score": 0.65,
        "detection_count": 8,
        "total_engines": 80,
        "categories": ["suspicious_registration", "potential_phish"],
        "tags": ["low_reputation", "dynamic_dns"],
    },
    "http://suspicious-test.example/login": {
        "status": ThreatIntelStatus.SUSPICIOUS,
        "confidence": 0.80,
        "reputation_score": 0.70,
        "detection_count": 12,
        "total_engines": 75,
        "categories": ["credential_harvesting", "untrusted_url"],
        "tags": ["suspicious_login_page"],
    },
    "admin@suspicious-phish.test": {
        "status": ThreatIntelStatus.SUSPICIOUS,
        "confidence": 0.75,
        "reputation_score": 0.65,
        "detection_count": 4,
        "total_engines": 35,
        "categories": ["spoofed_sender", "suspicious_mail"],
        "tags": ["phishing_campaign"],
    },

    # ── Known Malicious Indicators ───────────────────────────────────────────
    "185.220.101.5": {
        "status": ThreatIntelStatus.MALICIOUS,
        "confidence": 0.95,
        "reputation_score": 0.92,
        "detection_count": 54,
        "total_engines": 72,
        "categories": ["c2_server", "brute_force", "tor_exit"],
        "tags": ["active_threat", "botnet_node"],
        "country": "DE",
        "asn": "AS208294",
    },
    "c2-malicious.xyz": {
        "status": ThreatIntelStatus.MALICIOUS,
        "confidence": 0.98,
        "reputation_score": 0.96,
        "detection_count": 64,
        "total_engines": 82,
        "categories": ["command_and_control", "cobalt_strike", "malware_host"],
        "tags": ["c2", "apt_infra"],
    },
    "http://malicious-c2.example/beacon": {
        "status": ThreatIntelStatus.MALICIOUS,
        "confidence": 0.98,
        "reputation_score": 0.98,
        "detection_count": 62,
        "total_engines": 75,
        "categories": ["malware_download", "c2_beacon"],
        "tags": ["c2_endpoint", "active_campaign"],
    },
    # Standard EICAR Test String Hashes (Widely Recognized Malicious Signatures)
    "44d88612fea8a8f36de82e1278abb02f": {
        "status": ThreatIntelStatus.MALICIOUS,
        "confidence": 1.0,
        "reputation_score": 1.0,
        "detection_count": 68,
        "total_engines": 70,
        "categories": ["test_virus", "eicar_standard_av_test"],
        "tags": ["eicar", "av_test_file"],
    },
    "3395856ce81f2b7382dee72602f798b642f14140": {
        "status": ThreatIntelStatus.MALICIOUS,
        "confidence": 1.0,
        "reputation_score": 1.0,
        "detection_count": 68,
        "total_engines": 70,
        "categories": ["test_virus", "eicar_standard_av_test"],
        "tags": ["eicar", "av_test_file"],
    },
    "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f": {
        "status": ThreatIntelStatus.MALICIOUS,
        "confidence": 1.0,
        "reputation_score": 1.0,
        "detection_count": 68,
        "total_engines": 70,
        "categories": ["test_virus", "eicar_standard_av_test"],
        "tags": ["eicar", "av_test_file"],
    },
}


class OfflineMockThreatIntelProvider(BaseThreatIntelProvider):
    """
    Deterministic offline mock threat intelligence provider.

    Returns static predefined test fixtures based on normalized indicator values.
    Operates strictly in-memory without making external network or DNS requests.
    """

    def __init__(
        self,
        supported_types: Optional[Set[IOCType]] = None,
        custom_fixtures: Optional[Dict[str, Dict[str, Any]]] = None,
        default_ttl_seconds: int = 3600,
    ) -> None:
        self._supported_types: Set[IOCType] = (
            supported_types
            if supported_types is not None
            else {
                IOCType.IPV4,
                IOCType.IPV6,
                IOCType.DOMAIN,
                IOCType.URL,
                IOCType.MD5,
                IOCType.SHA1,
                IOCType.SHA256,
                IOCType.EMAIL,
                IOCType.FILE_PATH,
            }
        )
        self._fixtures: Dict[str, Dict[str, Any]] = dict(_DEFAULT_FIXTURES)
        if custom_fixtures:
            self._fixtures.update(custom_fixtures)
        self.default_ttl_seconds = default_ttl_seconds

    @property
    def provider_name(self) -> str:
        return "offline_mock"

    @property
    def provider_version(self) -> str:
        return "1.0.0"

    @property
    def source_type(self) -> ThreatIntelSource:
        return ThreatIntelSource.OFFLINE_MOCK

    @property
    def supported_ioc_types(self) -> Set[IOCType]:
        return self._supported_types

    def register_fixture(self, key: str, fixture_data: Dict[str, Any]) -> None:
        """Register or override a deterministic fixture mapping for testing."""
        self._fixtures[key.strip().lower()] = fixture_data

    def clear_custom_fixtures(self) -> None:
        """Reset fixtures back to the default fixture baseline."""
        self._fixtures = dict(_DEFAULT_FIXTURES)

    def lookup(self, ioc: IOC) -> ThreatIntelResult:
        """
        Execute deterministic offline mock lookup for an indicator.
        Guarantees zero network calls and immutability of the input IOC.
        """
        start_time = time.perf_counter()

        # Capability validation
        if not self.supports(ioc.ioc_type):
            return self.create_unsupported_result(ioc)

        lookup_key = ioc.normalized_value.strip().lower()
        fixture = self._fixtures.get(lookup_key)

        now = datetime.now(timezone.utc)
        expires_at = now + timedelta(seconds=self.default_ttl_seconds)
        latency_ms = round((time.perf_counter() - start_time) * 1000.0, 3)

        if fixture is not None:
            return ThreatIntelResult(
                ioc_id=ioc.id,
                ioc_type=ioc.ioc_type,
                ioc_value=ioc.raw_value,
                normalized_value=ioc.normalized_value,
                status=fixture.get("status", ThreatIntelStatus.UNKNOWN),
                confidence=fixture.get("confidence", 0.5),
                source=self.source_type,
                provider_name=self.provider_name,
                provider_version=self.provider_version,
                queried_at=now,
                expires_at=expires_at,
                lookup_latency_ms=latency_ms,
                source_reference="offline_mock://fixture_db/v1",
                detection_count=fixture.get("detection_count"),
                total_engines=fixture.get("total_engines"),
                reputation_score=fixture.get("reputation_score"),
                categories=list(fixture.get("categories", [])),
                tags=list(fixture.get("tags", [])) + ["offline_simulated"],
                country=fixture.get("country"),
                asn=fixture.get("asn"),
                first_seen=fixture.get("first_seen", now - timedelta(days=30)),
                last_seen=fixture.get("last_seen", now),
                raw_metadata={
                    "is_simulated": True,
                    "offline": True,
                    "lookup_mode": "fixture_match",
                    "fixture_key": lookup_key,
                },
            )

        # Indicator not found in deterministic fixtures -> UNKNOWN outcome
        return ThreatIntelResult(
            ioc_id=ioc.id,
            ioc_type=ioc.ioc_type,
            ioc_value=ioc.raw_value,
            normalized_value=ioc.normalized_value,
            status=ThreatIntelStatus.UNKNOWN,
            confidence=0.0,
            source=self.source_type,
            provider_name=self.provider_name,
            provider_version=self.provider_version,
            queried_at=now,
            expires_at=expires_at,
            lookup_latency_ms=latency_ms,
            source_reference=None,
            detection_count=0,
            total_engines=0,
            reputation_score=None,
            categories=[],
            tags=["offline_simulated", "unknown_indicator"],
            country=None,
            asn=None,
            first_seen=None,
            last_seen=None,
            raw_metadata={
                "is_simulated": True,
                "offline": True,
                "lookup_mode": "not_in_fixtures",
            },
        )

