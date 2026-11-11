"""
Threat Intelligence Service for MICHAEL – THE GUARDIAN AI.

Phase 4.2B.1 — Threat Intelligence Data Model & Provider Interface.
Phase 4.2B.3 — External Threat Intelligence Provider Integration.

Coordinates threat intelligence lookups across registered providers, enforces
capability checks, maintains an in-memory TTL cache, and guarantees zero mutation
of input IOC entities or analyst review states (IOCStatus).

DESIGN INVARIANTS:
==================
1. ThreatIntelService never modifies the input IOC or its IOCStatus.
2. Provider capability checks prevent unsupported IOC lookups from throwing exceptions.
3. Thread-safe in-memory caching respects result TTLs, avoiding redundant lookups.
4. Multiple providers can be registered dynamically via dependency injection.
5. Provider availability is surfaced without crashing the application.
6. The default provider is controlled by THREAT_INTEL_PROVIDER environment setting.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
import logging
import threading
from typing import Dict, List, Optional, Set, Tuple

from app.models.ioc import IOC, IOCType
from app.models.threat_intel import (
    ThreatIntelResult,
    ThreatIntelSource,
    ThreatIntelStatus,
)
from app.services.threat_intel_provider import BaseThreatIntelProvider

logger = logging.getLogger("michael.threat_intel")


# ─────────────────────────────────────────────────────────────────────────────
# In-Memory Thread-Safe TTL Cache
# ─────────────────────────────────────────────────────────────────────────────

class ThreatIntelCache:
    """
    In-memory thread-safe cache for ThreatIntelResult instances.

    Keyed by: (provider_name, ioc_type, normalized_value).
    Evicts stale entries on lookup when current time > expires_at.
    """

    def __init__(self, default_ttl_seconds: int = 3600) -> None:
        self._lock = threading.RLock()
        self._entries: Dict[Tuple[str, IOCType, str], ThreatIntelResult] = {}
        self.default_ttl_seconds = default_ttl_seconds

    def _make_key(self, provider_name: str, ioc_type: IOCType, normalized_value: str) -> Tuple[str, IOCType, str]:
        return (provider_name.strip().lower(), ioc_type, normalized_value.strip().lower())

    def get(
        self,
        provider_name: str,
        ioc_type: IOCType,
        normalized_value: str,
    ) -> Optional[ThreatIntelResult]:
        """
        Retrieve a cached result if present and not expired.
        Evicts expired entry and returns None if stale.
        """
        with self._lock:
            key = self._make_key(provider_name, ioc_type, normalized_value)
            entry = self._entries.get(key)
            if entry is None:
                return None

            now = datetime.now(timezone.utc)
            if now > entry.expires_at:
                # Entry expired -> evict
                del self._entries[key]
                return None

            return entry

    def set(
        self,
        result: ThreatIntelResult,
        ttl_seconds: Optional[int] = None,
    ) -> None:
        """
        Store a ThreatIntelResult in the cache.
        If ttl_seconds is provided, updates result.expires_at accordingly.
        """
        with self._lock:
            now = datetime.now(timezone.utc)
            ttl = ttl_seconds if ttl_seconds is not None else self.default_ttl_seconds
            expires_at = now + timedelta(seconds=ttl)

            if result.expires_at != expires_at:
                cached_result = result.model_copy(update={"expires_at": expires_at})
            else:
                cached_result = result

            key = self._make_key(
                cached_result.provider_name,
                cached_result.ioc_type,
                cached_result.normalized_value,
            )
            self._entries[key] = cached_result

    def invalidate(
        self,
        provider_name: str,
        ioc_type: IOCType,
        normalized_value: str,
    ) -> bool:
        """Manually invalidate a single cached indicator entry."""
        with self._lock:
            key = self._make_key(provider_name, ioc_type, normalized_value)
            if key in self._entries:
                del self._entries[key]
                return True
            return False

    def clear(self) -> None:
        """Clear all cached entries."""
        with self._lock:
            self._entries.clear()

    def size(self) -> int:
        """Return total number of unexpired entries currently in cache."""
        with self._lock:
            now = datetime.now(timezone.utc)
            # Filter out expired items
            valid_keys = [k for k, v in self._entries.items() if v.expires_at >= now]
            return len(valid_keys)


# ─────────────────────────────────────────────────────────────────────────────
# Core Threat Intelligence Service
# ─────────────────────────────────────────────────────────────────────────────

class ThreatIntelService:
    """
    Orchestration service for threat intelligence enrichment.

    Coordinates multi-provider lookups, capability detection, caching, and
    result aggregation while strictly maintaining IOC entity immutability.
    """

    def __init__(
        self,
        cache: Optional[ThreatIntelCache] = None,
        default_provider_name: str = "offline_mock",
    ) -> None:
        self._lock = threading.RLock()
        self._cache = cache if cache is not None else ThreatIntelCache()
        self._providers: Dict[str, BaseThreatIntelProvider] = {}
        self.default_provider_name = default_provider_name

    # ── Provider Management ──────────────────────────────────────────────────

    def register_provider(self, provider: BaseThreatIntelProvider) -> None:
        """Register a new threat intelligence provider."""
        with self._lock:
            name = provider.provider_name.strip().lower()
            self._providers[name] = provider
            logger.info("Registered ThreatIntel provider: %s (v%s)", name, provider.provider_version)

    def unregister_provider(self, provider_name: str) -> bool:
        """Remove a registered provider by name."""
        with self._lock:
            name = provider_name.strip().lower()
            if name in self._providers:
                del self._providers[name]
                logger.info("Unregistered ThreatIntel provider: %s", name)
                return True
            return False

    def get_provider(self, provider_name: str) -> Optional[BaseThreatIntelProvider]:
        """Retrieve a registered provider by name."""
        with self._lock:
            return self._providers.get(provider_name.strip().lower())

    def get_providers(self) -> List[BaseThreatIntelProvider]:
        """Return all registered provider instances."""
        with self._lock:
            return list(self._providers.values())

    def get_compatible_providers(self, ioc_type: IOCType) -> List[BaseThreatIntelProvider]:
        """Return all registered providers that declare support for the specified IOC type."""
        with self._lock:
            return [p for p in self._providers.values() if p.supports(ioc_type)]

    # ── Lookup Operations ────────────────────────────────────────────────────

    def lookup(
        self,
        ioc: IOC,
        provider_name: Optional[str] = None,
        force_refresh: bool = False,
    ) -> ThreatIntelResult:
        """
        Execute a threat intelligence lookup for an IOC.

        Workflow:
        1. Select target provider (specific name or default compatible provider).
        2. Check cache (unless force_refresh is True).
        3. Perform provider capability check.
        4. Execute provider lookup if supported; handle errors gracefully.
        5. Populate cache and return normalized ThreatIntelResult.
        6. Guarantees: Input IOC and its IOCStatus are NEVER modified.
        """
        # Resolve target provider
        target_name = (provider_name or self.default_provider_name).strip().lower()
        provider = self.get_provider(target_name)

        if provider is None:
            logger.warning("Threat intel provider '%s' not found.", target_name)
            now = datetime.now(timezone.utc)
            return ThreatIntelResult(
                ioc_id=ioc.id,
                ioc_type=ioc.ioc_type,
                ioc_value=ioc.raw_value,
                normalized_value=ioc.normalized_value,
                status=ThreatIntelStatus.ERROR,
                confidence=0.0,
                source=ThreatIntelSource.CUSTOM,
                provider_name=target_name,
                queried_at=now,
                expires_at=now,
                tags=["provider_not_found"],
                raw_metadata={"error": f"Provider '{target_name}' is not registered"},
            )

        # Cache check
        if not force_refresh:
            cached = self._cache.get(provider.provider_name, ioc.ioc_type, ioc.normalized_value)
            if cached is not None:
                logger.debug("Threat intel cache HIT: (%s, %s)", provider.provider_name, ioc.normalized_value)
                return cached

        # Capability validation
        if not provider.supports(ioc.ioc_type):
            logger.info(
                "Provider '%s' does not support IOC type '%s'. Skipping lookup.",
                provider.provider_name,
                ioc.ioc_type.value,
            )
            return provider.create_unsupported_result(ioc)

        # Provider execution with defensive error handling
        start_time = datetime.now(timezone.utc)
        try:
            result = provider.lookup(ioc)
        except Exception as exc:
            logger.exception("Unexpected error in threat intel provider '%s': %s", provider.provider_name, exc)
            return provider.create_error_result(ioc, str(exc))

        # Cache storage
        self._cache.set(result)
        return result

    async def lookup_async(
        self,
        ioc: IOC,
        provider_name: Optional[str] = None,
        force_refresh: bool = False,
    ) -> ThreatIntelResult:
        """
        Asynchronously execute a threat intelligence lookup for an IOC.
        """
        target_name = (provider_name or self.default_provider_name).strip().lower()
        provider = self.get_provider(target_name)

        if provider is None:
            return self.lookup(ioc, provider_name, force_refresh)

        if not force_refresh:
            cached = self._cache.get(provider.provider_name, ioc.ioc_type, ioc.normalized_value)
            if cached is not None:
                return cached

        if not provider.supports(ioc.ioc_type):
            return provider.create_unsupported_result(ioc)

        try:
            result = await provider.lookup_async(ioc)
        except Exception as exc:
            logger.exception("Async error in threat intel provider '%s': %s", provider.provider_name, exc)
            return provider.create_error_result(ioc, str(exc))

        self._cache.set(result)
        return result

    def clear_cache(self) -> None:
        """Clear all cached threat intelligence entries."""
        self._cache.clear()

    def get_provider_status(self) -> List[Dict]:
        """
        Return availability status for all registered providers.
        Useful for health checks and diagnostics.
        """
        with self._lock:
            statuses = []
            for name, provider in self._providers.items():
                statuses.append({
                    "provider_name": name,
                    "version": provider.provider_version,
                    "status": provider.availability_status,
                    "supported_ioc_types": [t.value for t in provider.supported_ioc_types],
                })
            return statuses


# ─────────────────────────────────────────────────────────────────────────────
# Global Service Singleton — Supports offline_mock and optional virustotal
# ─────────────────────────────────────────────────────────────────────────────

def _create_default_service() -> ThreatIntelService:
    """
    Create the default ThreatIntelService.

    Provider selection is controlled by THREAT_INTEL_PROVIDER env var:
      - "offline_mock" (default): Deterministic offline mode, no credentials required.
      - "virustotal": Requires VIRUSTOTAL_API_KEY; falls back to offline_mock if absent.
      - "both": Registers both providers.

    The application starts and operates safely regardless of credentials presence.
    """
    import os
    from app.services.providers.offline_mock_provider import OfflineMockThreatIntelProvider
    from app.services.providers.virustotal_provider import VirusTotalProvider

    provider_setting = os.environ.get("THREAT_INTEL_PROVIDER", "offline_mock").strip().lower()
    service = ThreatIntelService()

    # Offline mock is always registered (never removed by configuration)
    mock_provider = OfflineMockThreatIntelProvider()
    service.register_provider(mock_provider)

    # VirusTotal is registered when explicitly configured
    if provider_setting in ("virustotal", "both"):
        vt_provider = VirusTotalProvider()
        service.register_provider(vt_provider)
        if vt_provider.is_available:
            service.default_provider_name = "virustotal"
            logger.info("VirusTotal provider registered as default (key configured)")
        else:
            logger.warning(
                "VirusTotal provider registered but DISABLED: VIRUSTOTAL_API_KEY is absent. "
                "Falling back to offline_mock as default."
            )
            service.default_provider_name = "offline_mock"
    else:
        logger.info("Threat intelligence running in offline_mock mode (THREAT_INTEL_PROVIDER=%s)", provider_setting)

    return service


threat_intel_service = _create_default_service()

