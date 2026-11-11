"""
Phase 4.2B.1 — Threat Intelligence Service Tests

Tests the ThreatIntelService and ThreatIntelCache for:
- Thread-safe TTL cache operations (hit, miss, expiration, invalidation, clear).
- Provider registration, unregistration, and discovery.
- Compatible provider filtering by IOC type (get_compatible_providers).
- Cache-first lookup flow and cache bypass via force_refresh.
- Graceful handling of unregistered provider names.
- Graceful handling of provider exceptions (defensive error isolation).
- Provider capability validation and graceful fallback.
- Async lookup execution (lookup_async).
- Strict non-mutation guarantee: input IOC and analyst IOCStatus remain untouched.
"""

import asyncio
from datetime import datetime, timedelta, timezone
import os
import sys
import threading
from typing import Set
import unittest

# ── Path setup ──────────────────────────────────────────────────────────────
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from app.models.ioc import IOC, IOCStatus, IOCType
from app.models.threat_intel import (
    ThreatIntelResult,
    ThreatIntelSource,
    ThreatIntelStatus,
)
from app.services.providers.offline_mock_provider import OfflineMockThreatIntelProvider
from app.services.threat_intel_provider import BaseThreatIntelProvider
from app.services.threat_intel_service import (
    ThreatIntelCache,
    ThreatIntelService,
    threat_intel_service,
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


class FaultyTestProvider(BaseThreatIntelProvider):
    """Provider that raises an unhandled exception to test defensive error handling."""

    @property
    def provider_name(self) -> str:
        return "faulty_provider"

    @property
    def source_type(self) -> ThreatIntelSource:
        return ThreatIntelSource.CUSTOM

    @property
    def supported_ioc_types(self) -> Set[IOCType]:
        return {IOCType.IPV4}

    def lookup(self, ioc: IOC) -> ThreatIntelResult:
        raise RuntimeError("Simulated unexpected network socket crash")


class TestThreatIntelCache(unittest.TestCase):
    """Unit tests for ThreatIntelCache thread-safe TTL operations."""

    def setUp(self):
        self.cache = ThreatIntelCache(default_ttl_seconds=10)

    def test_cache_miss_and_hit(self):
        # Initial miss
        self.assertIsNone(self.cache.get("mock", IOCType.IPV4, "8.8.8.8"))

        now = datetime.now(timezone.utc)
        result = ThreatIntelResult(
            ioc_id="ioc-1",
            ioc_type=IOCType.IPV4,
            ioc_value="8.8.8.8",
            normalized_value="8.8.8.8",
            status=ThreatIntelStatus.CLEAN,
            confidence=0.9,
            source=ThreatIntelSource.OFFLINE_MOCK,
            provider_name="mock",
            queried_at=now,
            expires_at=now + timedelta(seconds=10),
        )

        # Store in cache
        self.cache.set(result)

        # Cache hit
        cached = self.cache.get("mock", IOCType.IPV4, "8.8.8.8")
        self.assertIsNotNone(cached)
        self.assertEqual(cached.ioc_id, "ioc-1")
        self.assertEqual(self.cache.size(), 1)

    def test_cache_expiration(self):
        now = datetime.now(timezone.utc)
        result = ThreatIntelResult(
            ioc_id="ioc-expired",
            ioc_type=IOCType.DOMAIN,
            ioc_value="expired.test",
            normalized_value="expired.test",
            status=ThreatIntelStatus.UNKNOWN,
            provider_name="mock",
            queried_at=now,
        )

        # Set with negative TTL so it is immediately expired
        self.cache.set(result, ttl_seconds=-5)

        # Should detect expiration, evict entry, and return None
        self.assertIsNone(self.cache.get("mock", IOCType.DOMAIN, "expired.test"))
        self.assertEqual(self.cache.size(), 0)

    def test_cache_invalidation_and_clear(self):
        now = datetime.now(timezone.utc)
        res1 = ThreatIntelResult(
            ioc_id="ioc-1",
            ioc_type=IOCType.IPV4,
            ioc_value="1.1.1.1",
            normalized_value="1.1.1.1",
            provider_name="mock",
            queried_at=now,
            expires_at=now + timedelta(hours=1),
        )
        res2 = ThreatIntelResult(
            ioc_id="ioc-2",
            ioc_type=IOCType.IPV4,
            ioc_value="8.8.8.8",
            normalized_value="8.8.8.8",
            provider_name="mock",
            queried_at=now,
            expires_at=now + timedelta(hours=1),
        )

        self.cache.set(res1)
        self.cache.set(res2)
        self.assertEqual(self.cache.size(), 2)

        # Invalidate 1.1.1.1
        self.assertTrue(self.cache.invalidate("mock", IOCType.IPV4, "1.1.1.1"))
        self.assertIsNone(self.cache.get("mock", IOCType.IPV4, "1.1.1.1"))
        self.assertEqual(self.cache.size(), 1)

        # Clear remaining
        self.cache.clear()
        self.assertEqual(self.cache.size(), 0)

    def test_cache_thread_safety(self):
        """Verify concurrent cache access from multiple threads does not deadlock or crash."""
        cache = ThreatIntelCache(default_ttl_seconds=60)
        errors = []

        def worker(thread_id: int):
            try:
                for i in range(50):
                    val = f"192.168.1.{thread_id % 10}"
                    res = ThreatIntelResult(
                        ioc_id=f"ioc-{thread_id}-{i}",
                        ioc_type=IOCType.IPV4,
                        ioc_value=val,
                        normalized_value=val,
                        provider_name="thread_test",
                    )
                    cache.set(res)
                    _ = cache.get("thread_test", IOCType.IPV4, val)
            except Exception as e:
                errors.append(e)

        threads = [threading.Thread(target=worker, args=(t,)) for t in range(5)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        self.assertEqual(errors, [])


class TestThreatIntelService(unittest.TestCase):
    """Unit tests for ThreatIntelService orchestration and invariants."""

    def setUp(self):
        self.cache = ThreatIntelCache(default_ttl_seconds=3600)
        self.service = ThreatIntelService(cache=self.cache)
        self.mock_provider = OfflineMockThreatIntelProvider()
        self.service.register_provider(self.mock_provider)

    def test_singleton_instance_available(self):
        self.assertIsNotNone(threat_intel_service)
        self.assertIsNotNone(threat_intel_service.get_provider("offline_mock"))

    def test_provider_registration_and_lookup(self):
        provider = self.service.get_provider("offline_mock")
        self.assertIsNotNone(provider)
        self.assertEqual(provider.provider_name, "offline_mock")

        all_providers = self.service.get_providers()
        self.assertEqual(len(all_providers), 1)

        # Unregister
        self.assertTrue(self.service.unregister_provider("offline_mock"))
        self.assertIsNone(self.service.get_provider("offline_mock"))
        self.assertEqual(len(self.service.get_providers()), 0)

    def test_get_compatible_providers(self):
        # Default mock supports all types except when restricted
        compatible = self.service.get_compatible_providers(IOCType.IPV4)
        self.assertEqual(len(compatible), 1)

        # Add provider that only supports SHA256
        class ShaOnlyProvider(BaseThreatIntelProvider):
            @property
            def provider_name(self) -> str:
                return "sha_only"

            @property
            def source_type(self) -> ThreatIntelSource:
                return ThreatIntelSource.CUSTOM

            @property
            def supported_ioc_types(self) -> Set[IOCType]:
                return {IOCType.SHA256}

            def lookup(self, ioc: IOC) -> ThreatIntelResult:
                return self.create_unsupported_result(ioc)

        self.service.register_provider(ShaOnlyProvider())

        # SHA256 should have both providers
        sha_compatible = self.service.get_compatible_providers(IOCType.SHA256)
        self.assertEqual(len(sha_compatible), 2)

        # IPV4 should only have offline_mock
        ip_compatible = self.service.get_compatible_providers(IOCType.IPV4)
        self.assertEqual(len(ip_compatible), 1)
        self.assertEqual(ip_compatible[0].provider_name, "offline_mock")

    def test_service_lookup_caching(self):
        ioc = _build_ioc(IOCType.IPV4, "8.8.8.8")

        # Initial lookup: should hit provider and populate cache
        self.assertEqual(self.cache.size(), 0)
        res1 = self.service.lookup(ioc)
        self.assertEqual(res1.status, ThreatIntelStatus.CLEAN)
        self.assertEqual(self.cache.size(), 1)

        # Second lookup: should hit cache directly
        res2 = self.service.lookup(ioc)
        self.assertEqual(res1.id, res2.id)
        self.assertEqual(res2.status, ThreatIntelStatus.CLEAN)

        # Force refresh: should bypass cache and generate new query
        res3 = self.service.lookup(ioc, force_refresh=True)
        self.assertEqual(res3.status, ThreatIntelStatus.CLEAN)
        self.assertNotEqual(res1.id, res3.id)

    def test_lookup_unregistered_provider(self):
        ioc = _build_ioc(IOCType.IPV4, "8.8.8.8")
        res = self.service.lookup(ioc, provider_name="nonexistent_provider")

        self.assertEqual(res.status, ThreatIntelStatus.ERROR)
        self.assertEqual(res.provider_name, "nonexistent_provider")
        self.assertIn("provider_not_found", res.tags)

    def test_lookup_unsupported_type_graceful_handling(self):
        # Register a provider with restricted types
        class OnlyEmailProvider(BaseThreatIntelProvider):
            @property
            def provider_name(self) -> str:
                return "only_email"

            @property
            def source_type(self) -> ThreatIntelSource:
                return ThreatIntelSource.CUSTOM

            @property
            def supported_ioc_types(self) -> Set[IOCType]:
                return {IOCType.EMAIL}

            def lookup(self, ioc: IOC) -> ThreatIntelResult:
                return self.create_unsupported_result(ioc)

        self.service.register_provider(OnlyEmailProvider())
        ioc_ip = _build_ioc(IOCType.IPV4, "1.1.1.1")

        # Query provider for unsupported IP
        res = self.service.lookup(ioc_ip, provider_name="only_email")
        self.assertEqual(res.status, ThreatIntelStatus.UNKNOWN)
        self.assertIn("unsupported_type", res.tags)

    def test_provider_exception_defensive_isolation(self):
        """Verify provider runtime exceptions are caught defensively and returned as ERROR results."""
        self.service.register_provider(FaultyTestProvider())
        ioc = _build_ioc(IOCType.IPV4, "192.168.1.50")

        # Must not raise RuntimeError
        res = self.service.lookup(ioc, provider_name="faulty_provider")
        self.assertEqual(res.status, ThreatIntelStatus.ERROR)
        self.assertEqual(res.provider_name, "faulty_provider")
        self.assertIn("Simulated unexpected network socket crash", res.raw_metadata.get("error", ""))
        self.assertIn("lookup_error", res.tags)

    def test_strict_ioc_immutability(self):
        """Threat intelligence lookup must NEVER modify the input IOC or its IOCStatus."""
        initial_status = IOCStatus.UNDER_REVIEW
        ioc = _build_ioc(IOCType.IPV4, "185.220.101.5", status=initial_status)

        res = self.service.lookup(ioc)
        self.assertEqual(res.status, ThreatIntelStatus.MALICIOUS)

        # Verify IOC object itself was NOT altered
        self.assertEqual(ioc.status, IOCStatus.UNDER_REVIEW)
        self.assertEqual(ioc.raw_value, "185.220.101.5")
        self.assertEqual(ioc.normalized_value, "185.220.101.5")

    def test_service_lookup_async(self):
        async def run_lookup():
            ioc = _build_ioc(IOCType.IPV4, "8.8.8.8")
            return await self.service.lookup_async(ioc)

        res = asyncio.run(run_lookup())
        self.assertIsInstance(res, ThreatIntelResult)
        self.assertEqual(res.status, ThreatIntelStatus.CLEAN)


if __name__ == "__main__":
    unittest.main()
