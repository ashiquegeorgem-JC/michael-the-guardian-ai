"""
Phase 4.2B.1 — Threat Intelligence Provider Interface Tests

Tests the BaseThreatIntelProvider contract and default behaviors:
- Enforces abstract method requirements (provider_name, source_type, supported_ioc_types, lookup).
- Verifies default provider_version behavior.
- Verifies capability matching (supports).
- Verifies create_unsupported_result() fallback construction.
- Verifies create_error_result() fallback construction.
- Verifies lookup_async() execution.
- Verifies zero mutation of the target IOC.
"""

import asyncio
from datetime import datetime, timezone
import os
import sys
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
from app.services.threat_intel_provider import BaseThreatIntelProvider


class DummyConcreteProvider(BaseThreatIntelProvider):
    """Minimal concrete provider for testing the ABC base behaviors."""

    @property
    def provider_name(self) -> str:
        return "dummy_test_provider"

    @property
    def source_type(self) -> ThreatIntelSource:
        return ThreatIntelSource.CUSTOM

    @property
    def supported_ioc_types(self) -> Set[IOCType]:
        return {IOCType.IPV4, IOCType.DOMAIN}

    def lookup(self, ioc: IOC) -> ThreatIntelResult:
        if not self.supports(ioc.ioc_type):
            return self.create_unsupported_result(ioc)
        now = datetime.now(timezone.utc)
        return ThreatIntelResult(
            ioc_id=ioc.id,
            ioc_type=ioc.ioc_type,
            ioc_value=ioc.raw_value,
            normalized_value=ioc.normalized_value,
            status=ThreatIntelStatus.CLEAN,
            confidence=0.85,
            source=self.source_type,
            provider_name=self.provider_name,
            queried_at=now,
        )


class TestThreatIntelProviderInterface(unittest.TestCase):
    """Test BaseThreatIntelProvider abstract class and concrete contract."""

    def setUp(self):
        self.provider = DummyConcreteProvider()
        self.sample_ip_ioc = IOC(
            id="ioc-ip-001",
            ioc_type=IOCType.IPV4,
            raw_value="192.168.1.1",
            normalized_value="192.168.1.1",
            status=IOCStatus.EXTRACTED,
            first_seen=datetime.now(timezone.utc),
            last_seen=datetime.now(timezone.utc),
        )
        self.sample_hash_ioc = IOC(
            id="ioc-hash-001",
            ioc_type=IOCType.SHA256,
            raw_value="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            normalized_value="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            status=IOCStatus.EXTRACTED,
            first_seen=datetime.now(timezone.utc),
            last_seen=datetime.now(timezone.utc),
        )

    def test_cannot_instantiate_base_class_directly(self):
        """BaseThreatIntelProvider has abstract methods and cannot be directly instantiated."""
        with self.assertRaises(TypeError):
            BaseThreatIntelProvider()  # type: ignore

    def test_provider_attributes(self):
        self.assertEqual(self.provider.provider_name, "dummy_test_provider")
        self.assertEqual(self.provider.provider_version, "1.0.0")
        self.assertEqual(self.provider.source_type, ThreatIntelSource.CUSTOM)
        self.assertEqual(self.provider.supported_ioc_types, {IOCType.IPV4, IOCType.DOMAIN})

    def test_supports_method(self):
        self.assertTrue(self.provider.supports(IOCType.IPV4))
        self.assertTrue(self.provider.supports(IOCType.DOMAIN))
        self.assertFalse(self.provider.supports(IOCType.SHA256))
        self.assertFalse(self.provider.supports(IOCType.EMAIL))
        self.assertFalse(self.provider.supports(IOCType.URL))

    def test_create_unsupported_result(self):
        res = self.provider.create_unsupported_result(self.sample_hash_ioc)
        self.assertEqual(res.ioc_id, self.sample_hash_ioc.id)
        self.assertEqual(res.ioc_type, IOCType.SHA256)
        self.assertEqual(res.status, ThreatIntelStatus.UNKNOWN)
        self.assertEqual(res.confidence, 0.0)
        self.assertEqual(res.provider_name, "dummy_test_provider")
        self.assertIn("unsupported_type", res.tags)

    def test_create_error_result(self):
        res = self.provider.create_error_result(
            self.sample_ip_ioc,
            error_message="Simulated connection timeout",
            latency_ms=12.5,
        )
        self.assertEqual(res.ioc_id, self.sample_ip_ioc.id)
        self.assertEqual(res.status, ThreatIntelStatus.ERROR)
        self.assertEqual(res.confidence, 0.0)
        self.assertEqual(res.lookup_latency_ms, 12.5)
        self.assertEqual(res.provider_name, "dummy_test_provider")
        self.assertIn("lookup_error", res.tags)
        self.assertIsNotNone(res.raw_metadata)
        self.assertEqual(res.raw_metadata["error"], "Simulated connection timeout")

    def test_lookup_preserves_ioc_immutability(self):
        initial_status = self.sample_ip_ioc.status
        initial_raw = self.sample_ip_ioc.raw_value

        res = self.provider.lookup(self.sample_ip_ioc)
        self.assertEqual(res.status, ThreatIntelStatus.CLEAN)

        # Confirm IOC instance was not modified
        self.assertEqual(self.sample_ip_ioc.status, initial_status)
        self.assertEqual(self.sample_ip_ioc.raw_value, initial_raw)

    def test_lookup_async(self):
        """Async lookup should complete successfully in event loop."""
        async def run_async():
            return await self.provider.lookup_async(self.sample_ip_ioc)

        res = asyncio.run(run_async())
        self.assertIsInstance(res, ThreatIntelResult)
        self.assertEqual(res.status, ThreatIntelStatus.CLEAN)


if __name__ == "__main__":
    unittest.main()
