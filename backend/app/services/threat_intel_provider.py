"""
Threat Intelligence Provider Interface for MICHAEL – THE GUARDIAN AI.

Phase 4.2B.1 — Threat Intelligence Data Model & Provider Interface.

Defines the abstract interface for threat intelligence providers.
Enforces provider capability declarations (supported IOC types) and normalized
result contracts.

DESIGN INVARIANTS:
==================
1. Threat intelligence providers must declare their supported IOCType set.
2. The core subsystem depends ONLY on this interface, never on concrete provider details.
3. Providers return a normalized ThreatIntelResult; they NEVER mutate the input IOC.
4. Unsupported IOC types must be handled gracefully without throwing unhandled exceptions.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
import asyncio
from datetime import datetime, timezone
import time
from typing import Optional, Set

from app.models.ioc import IOC, IOCType
from app.models.threat_intel import (
    ThreatIntelResult,
    ThreatIntelSource,
    ThreatIntelStatus,
)


class BaseThreatIntelProvider(ABC):
    """
    Abstract Base Class for Threat Intelligence Providers.

    All threat intelligence integrations (offline mock, future VirusTotal,
    future AbuseIPDB, etc.) must implement this contract.
    """

    @property
    @abstractmethod
    def provider_name(self) -> str:
        """Unique machine identifier for the provider (e.g. 'offline_mock', 'virustotal')."""
        pass

    @property
    def provider_version(self) -> str:
        """Version string of the provider implementation."""
        return "1.0.0"

    @property
    def is_available(self) -> bool:
        """Indicate whether the provider is configured and available for lookups."""
        return True

    @property
    def availability_status(self) -> str:
        """Return provider availability state ('AVAILABLE', 'DISABLED', 'ERROR')."""
        return "AVAILABLE" if self.is_available else "DISABLED"

    @property
    @abstractmethod
    def source_type(self) -> ThreatIntelSource:
        """ThreatIntelSource classification for this provider."""
        pass

    @property
    @abstractmethod
    def supported_ioc_types(self) -> Set[IOCType]:
        """Set of IOCType categories supported by this provider."""
        pass

    def supports(self, ioc_type: IOCType) -> bool:
        """Check whether this provider supports looking up the given IOC type."""
        return ioc_type in self.supported_ioc_types

    @abstractmethod
    def lookup(self, ioc: IOC) -> ThreatIntelResult:
        """
        Execute synchronous threat intelligence lookup for an IOC.

        Must return a valid, normalized ThreatIntelResult without mutating the input IOC.
        If the indicator type is unsupported, must return an UNKNOWN or gracefully handled result.
        """
        pass

    async def lookup_async(self, ioc: IOC) -> ThreatIntelResult:
        """
        Execute asynchronous threat intelligence lookup for an IOC.
        Default implementation offloads the synchronous lookup to the default event loop executor.
        Concrete network providers can override this with native async I/O.
        """
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(None, self.lookup, ioc)

    def create_unsupported_result(self, ioc: IOC, reason: Optional[str] = None) -> ThreatIntelResult:
        """
        Construct a clean, non-malicious ThreatIntelResult when an indicator type
        is not supported by this provider.
        """
        now = datetime.now(timezone.utc)
        expl = reason or f"Provider '{self.provider_name}' does not support indicator type '{ioc.ioc_type.value}'"
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
            expires_at=now,
            lookup_latency_ms=0.0,
            detection_count=0,
            total_engines=0,
            reputation_score=None,
            categories=[],
            tags=["unsupported_type"],
            raw_metadata={"skipped": True, "reason": expl},
        )

    def create_error_result(self, ioc: IOC, error_message: str, latency_ms: float = 0.0) -> ThreatIntelResult:
        """
        Construct a normalized ThreatIntelResult representing a provider lookup failure.
        """
        now = datetime.now(timezone.utc)
        return ThreatIntelResult(
            ioc_id=ioc.id,
            ioc_type=ioc.ioc_type,
            ioc_value=ioc.raw_value,
            normalized_value=ioc.normalized_value,
            status=ThreatIntelStatus.ERROR,
            confidence=0.0,
            source=self.source_type,
            provider_name=self.provider_name,
            provider_version=self.provider_version,
            queried_at=now,
            expires_at=now,
            lookup_latency_ms=max(0.0, latency_ms),
            detection_count=None,
            total_engines=None,
            reputation_score=None,
            categories=[],
            tags=["lookup_error"],
            raw_metadata={"error": error_message},
        )

