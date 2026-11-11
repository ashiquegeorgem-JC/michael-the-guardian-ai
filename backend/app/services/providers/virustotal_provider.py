"""
VirusTotal Threat Intelligence Provider for MICHAEL – THE GUARDIAN AI.

Phase 4.2B.3 — External Threat Intelligence Provider Integration.

Integrates with the VirusTotal v3 REST API to provide real-world indicator enrichment.
Implements the BaseThreatIntelProvider contract to ensure full provider abstraction.

DESIGN INVARIANTS:
==================
1. Provider-Agnostic Abstraction: Implements BaseThreatIntelProvider without altering core models.
2. Zero Secret Leakage: API keys are strictly sourced from environment variables / config,
   never logged, never placed in exceptions, and never stored in ThreatIntelResult or metadata.
3. Safe Failure & Offline Fallback: If VIRUSTOTAL_API_KEY is absent, the provider transitions to
   DISABLED status and returns a safe UNKNOWN result without crashing or failing startup.
4. Robust Error Isolation: Network timeouts, 404s, 429 rate limits, and 500s are caught and
   normalized into structured ThreatIntelResult records (ERROR or UNKNOWN); never uncaught.
5. Invariant: 404 Not Found is normalized to UNKNOWN (not CLEAN).
6. Non-Mutation: Input IOC objects are strictly read-only.
"""

from __future__ import annotations

import base64
from datetime import datetime, timedelta, timezone
import logging
import os
import time
from typing import Any, Dict, List, Optional, Set, Tuple

import httpx

from app.models.ioc import IOC, IOCType
from app.models.threat_intel import (
    ThreatIntelResult,
    ThreatIntelSource,
    ThreatIntelStatus,
    _sanitize_metadata,
)
from app.services.threat_intel_provider import BaseThreatIntelProvider

logger = logging.getLogger("michael.threat_intel.virustotal")

_SUPPORTED_IOC_TYPES: Set[IOCType] = {
    IOCType.IPV4,
    IOCType.IPV6,
    IOCType.DOMAIN,
    IOCType.URL,
    IOCType.MD5,
    IOCType.SHA1,
    IOCType.SHA256,
}


class VirusTotalProvider(BaseThreatIntelProvider):
    """
    Threat intelligence provider integrating the VirusTotal v3 API.

    Supports IPv4, IPv6, Domain, URL, MD5, SHA1, and SHA256 indicator lookups.
    Safely degrades to DISABLED when no API key is provided.
    """

    API_BASE_URL: str = "https://www.virustotal.com/api/v3"
    DEFAULT_TIMEOUT_SECONDS: float = 15.0
    DEFAULT_TTL_SECONDS: int = 86400  # 24 hours caching for external VT lookups

    def __init__(
        self,
        api_key: Optional[str] = None,
        client: Optional[httpx.Client] = None,
        async_client: Optional[httpx.AsyncClient] = None,
        timeout: float = DEFAULT_TIMEOUT_SECONDS,
        default_ttl_seconds: int = DEFAULT_TTL_SECONDS,
    ) -> None:
        raw_key = api_key if api_key is not None else os.environ.get("VIRUSTOTAL_API_KEY", "")
        self._api_key: str = (raw_key or "").strip()
        self._timeout: float = timeout
        self._default_ttl_seconds: int = default_ttl_seconds
        self._client: Optional[httpx.Client] = client
        self._async_client: Optional[httpx.AsyncClient] = async_client

    # ── Base Properties ──────────────────────────────────────────────────────

    @property
    def provider_name(self) -> str:
        return "virustotal"

    @property
    def provider_version(self) -> str:
        return "1.0.0"

    @property
    def source_type(self) -> ThreatIntelSource:
        return ThreatIntelSource.VIRUSTOTAL

    @property
    def supported_ioc_types(self) -> Set[IOCType]:
        return _SUPPORTED_IOC_TYPES

    @property
    def is_available(self) -> bool:
        """VirusTotal provider is available if an API key is configured."""
        return bool(self._api_key)

    @property
    def availability_status(self) -> str:
        return "AVAILABLE" if self.is_available else "DISABLED"

    # ── Lookup Execution (Synchronous) ───────────────────────────────────────

    def lookup(self, ioc: IOC) -> ThreatIntelResult:
        """
        Execute synchronous VirusTotal lookup for an indicator.
        Guarantees zero mutation of the input IOC and comprehensive error handling.
        """
        start_time = time.perf_counter()

        # Capability Check
        if not self.supports(ioc.ioc_type):
            return self.create_unsupported_result(ioc)

        # Availability Check
        if not self.is_available:
            return self._build_disabled_result(ioc)

        endpoint_path, gui_url = self._resolve_endpoint_and_gui(ioc)
        url = f"{self.API_BASE_URL}{endpoint_path}"
        headers = self._get_request_headers()

        client = self._client or httpx.Client(
            timeout=httpx.Timeout(self._timeout, connect=5.0),
            headers=headers,
        )
        should_close = self._client is None

        try:
            resp = client.get(url)
            latency_ms = round((time.perf_counter() - start_time) * 1000.0, 2)
            return self._handle_http_response(ioc, resp, latency_ms, gui_url)
        except httpx.TimeoutException:
            latency_ms = round((time.perf_counter() - start_time) * 1000.0, 2)
            logger.warning("VirusTotal lookup timed out for IOC %s", ioc.normalized_value)
            return self.create_error_result(
                ioc,
                error_message="VirusTotal request timed out",
                latency_ms=latency_ms,
            )
        except httpx.RequestError as exc:
            latency_ms = round((time.perf_counter() - start_time) * 1000.0, 2)
            logger.warning("VirusTotal transport error for IOC %s: %s", ioc.normalized_value, type(exc).__name__)
            return self.create_error_result(
                ioc,
                error_message=f"VirusTotal network transport error: {type(exc).__name__}",
                latency_ms=latency_ms,
            )
        except Exception as exc:
            latency_ms = round((time.perf_counter() - start_time) * 1000.0, 2)
            logger.exception("Unexpected error during VirusTotal lookup for IOC %s: %s", ioc.normalized_value, exc)
            return self.create_error_result(
                ioc,
                error_message=f"VirusTotal lookup error: {type(exc).__name__}",
                latency_ms=latency_ms,
            )
        finally:
            if should_close:
                client.close()

    # ── Lookup Execution (Asynchronous) ──────────────────────────────────────

    async def lookup_async(self, ioc: IOC) -> ThreatIntelResult:
        """
        Execute asynchronous VirusTotal lookup for an indicator using httpx.AsyncClient.
        """
        start_time = time.perf_counter()

        if not self.supports(ioc.ioc_type):
            return self.create_unsupported_result(ioc)

        if not self.is_available:
            return self._build_disabled_result(ioc)

        endpoint_path, gui_url = self._resolve_endpoint_and_gui(ioc)
        url = f"{self.API_BASE_URL}{endpoint_path}"
        headers = self._get_request_headers()

        async_client = self._async_client or httpx.AsyncClient(
            timeout=httpx.Timeout(self._timeout, connect=5.0),
            headers=headers,
        )
        should_close = self._async_client is None

        try:
            resp = await async_client.get(url)
            latency_ms = round((time.perf_counter() - start_time) * 1000.0, 2)
            return self._handle_http_response(ioc, resp, latency_ms, gui_url)
        except httpx.TimeoutException:
            latency_ms = round((time.perf_counter() - start_time) * 1000.0, 2)
            logger.warning("Async VirusTotal lookup timed out for IOC %s", ioc.normalized_value)
            return self.create_error_result(
                ioc,
                error_message="VirusTotal request timed out",
                latency_ms=latency_ms,
            )
        except httpx.RequestError as exc:
            latency_ms = round((time.perf_counter() - start_time) * 1000.0, 2)
            logger.warning("Async VirusTotal transport error for IOC %s: %s", ioc.normalized_value, type(exc).__name__)
            return self.create_error_result(
                ioc,
                error_message=f"VirusTotal network transport error: {type(exc).__name__}",
                latency_ms=latency_ms,
            )
        except Exception as exc:
            latency_ms = round((time.perf_counter() - start_time) * 1000.0, 2)
            logger.exception("Unexpected error during async VirusTotal lookup for IOC %s: %s", ioc.normalized_value, exc)
            return self.create_error_result(
                ioc,
                error_message=f"VirusTotal lookup error: {type(exc).__name__}",
                latency_ms=latency_ms,
            )
        finally:
            if should_close:
                await async_client.aclose()

    # ── Endpoint & Headers Resolution ────────────────────────────────────────

    def _resolve_endpoint_and_gui(self, ioc: IOC) -> Tuple[str, str]:
        """Resolve the appropriate VirusTotal v3 API endpoint path and GUI permalink."""
        val = ioc.normalized_value

        if ioc.ioc_type in (IOCType.IPV4, IOCType.IPV6):
            return f"/ip_addresses/{val}", f"https://www.virustotal.com/gui/ip-address/{val}"
        elif ioc.ioc_type == IOCType.DOMAIN:
            return f"/domains/{val}", f"https://www.virustotal.com/gui/domain/{val}"
        elif ioc.ioc_type in (IOCType.MD5, IOCType.SHA1, IOCType.SHA256):
            return f"/files/{val}", f"https://www.virustotal.com/gui/file/{val}"
        elif ioc.ioc_type == IOCType.URL:
            # VirusTotal v3 requires base64-url encoding of URL string without padding '='
            raw_url = ioc.raw_value
            url_id = base64.urlsafe_b64encode(raw_url.encode("utf-8")).decode("ascii").rstrip("=")
            return f"/urls/{url_id}", f"https://www.virustotal.com/gui/url/{url_id}"
        else:
            return f"/search?query={val}", f"https://www.virustotal.com/gui/search/{val}"

    def _get_request_headers(self) -> Dict[str, str]:
        """Build request headers without exposing keys in external loggers."""
        return {
            "x-apikey": self._api_key,
            "Accept": "application/json",
            "User-Agent": "MICHAEL-Guardian-AI/1.0",
        }

    # ── HTTP Response Handling & Normalization ───────────────────────────────

    def _handle_http_response(
        self,
        ioc: IOC,
        resp: httpx.Response,
        latency_ms: float,
        gui_url: str,
    ) -> ThreatIntelResult:
        """
        Map VirusTotal HTTP status codes and payloads to normalized ThreatIntelResult.
        """
        now = datetime.now(timezone.utc)
        expires_at = now + timedelta(seconds=self._default_ttl_seconds)

        # 200 OK -> Normalization
        if resp.status_code == 200:
            try:
                data = resp.json()
                return self._normalize_vt_payload(ioc, data, latency_ms, gui_url, now, expires_at)
            except Exception as parse_err:
                logger.error("Failed to parse VirusTotal JSON response for %s: %s", ioc.normalized_value, parse_err)
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
                    lookup_latency_ms=latency_ms,
                    tags=["virustotal", "parse_error"],
                    raw_metadata={"http_status": 200, "error": "Malformed JSON payload from VirusTotal"},
                )

        # 404 Not Found -> UNKNOWN outcome (Critical Security Invariant: 404 != CLEAN)
        if resp.status_code == 404:
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
                source_reference=gui_url,
                detection_count=0,
                total_engines=0,
                reputation_score=None,
                categories=[],
                tags=["virustotal", "not_found_in_virustotal"],
                raw_metadata={
                    "http_status": 404,
                    "message": "Indicator was not found in the VirusTotal database",
                },
            )

        # 401 Unauthorized / 403 Forbidden
        if resp.status_code in (401, 403):
            logger.warning("VirusTotal authentication failure (HTTP %d)", resp.status_code)
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
                lookup_latency_ms=latency_ms,
                tags=["virustotal", "auth_error"],
                raw_metadata={
                    "http_status": resp.status_code,
                    "error": "VirusTotal API authorization or quota validation failed",
                },
            )

        # 429 Rate Limit
        if resp.status_code == 429:
            retry_after = resp.headers.get("Retry-After")
            logger.warning("VirusTotal API rate limit reached (HTTP 429). Retry-After: %s", retry_after)
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
                lookup_latency_ms=latency_ms,
                tags=["virustotal", "rate_limited"],
                raw_metadata={
                    "http_status": 429,
                    "rate_limited": True,
                    "retry_after": retry_after,
                    "error": "VirusTotal request rate limit exceeded",
                },
            )

        # 500+ Upstream Errors
        logger.warning("VirusTotal upstream server error (HTTP %d)", resp.status_code)
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
            lookup_latency_ms=latency_ms,
            tags=["virustotal", "upstream_error"],
            raw_metadata={
                "http_status": resp.status_code,
                "error": f"VirusTotal upstream server error (HTTP {resp.status_code})",
            },
        )

    # ── Payload Normalization ────────────────────────────────────────────────

    def _normalize_vt_payload(
        self,
        ioc: IOC,
        payload: Dict[str, Any],
        latency_ms: float,
        gui_url: str,
        now: datetime,
        expires_at: datetime,
    ) -> ThreatIntelResult:
        """
        Transform raw VirusTotal v3 data attributes into normalized ThreatIntelResult.
        """
        data = payload.get("data", {})
        attributes = data.get("attributes", {})

        stats = attributes.get("last_analysis_stats", {})
        malicious = max(0, int(stats.get("malicious", 0)))
        suspicious = max(0, int(stats.get("suspicious", 0)))
        harmless = max(0, int(stats.get("harmless", 0)))
        undetected = max(0, int(stats.get("undetected", 0)))

        total_engines = malicious + suspicious + harmless + undetected
        detection_count = malicious + suspicious

        # Status Verdict Normalization
        if total_engines == 0:
            status = ThreatIntelStatus.UNKNOWN
        elif malicious >= 3 or (total_engines > 0 and (malicious / total_engines) >= 0.05):
            status = ThreatIntelStatus.MALICIOUS
        elif malicious > 0 or suspicious >= 2:
            status = ThreatIntelStatus.SUSPICIOUS
        elif harmless > 0 or undetected > 0:
            status = ThreatIntelStatus.CLEAN
        else:
            status = ThreatIntelStatus.UNKNOWN

        # Confidence Normalization
        if total_engines >= 50:
            confidence = 0.95
        elif total_engines >= 20:
            confidence = 0.85
        elif total_engines >= 5:
            confidence = 0.70
        elif total_engines > 0:
            confidence = 0.50
        else:
            confidence = 0.0

        # Reputation Score Normalization
        # VirusTotal reputation is an integer [-100 (malicious) to +100 (benign)]
        # MICHAEL reputation_score is normalized [0.0 (benign) to 1.0 (malicious)]
        raw_reputation = attributes.get("reputation")
        if raw_reputation is not None and isinstance(raw_reputation, (int, float)):
            clamped_rep = max(-100.0, min(100.0, float(raw_reputation)))
            reputation_score = round((100.0 - clamped_rep) / 200.0, 4)
        elif total_engines > 0:
            reputation_score = round(detection_count / total_engines, 4)
        else:
            reputation_score = None

        # Threat Categories Extraction
        categories_dict = attributes.get("categories", {})
        categories_set = set()
        if isinstance(categories_dict, dict):
            for cat in categories_dict.values():
                if isinstance(cat, str) and cat.strip():
                    categories_set.add(cat.strip().lower())
        categories = sorted(list(categories_set))

        # Tags Extraction
        raw_tags = attributes.get("tags", [])
        tags = [t.strip().lower() for t in raw_tags if isinstance(t, str) and t.strip()]
        if "virustotal" not in tags:
            tags.append("virustotal")

        # Geo & ASN Context
        country = attributes.get("country")
        raw_asn = attributes.get("asn")
        asn = f"AS{raw_asn}" if raw_asn is not None else None

        # Timestamps
        first_seen = self._parse_unix_timestamp(attributes.get("first_submission_date"))
        last_seen = self._parse_unix_timestamp(attributes.get("last_analysis_date"))

        # Raw Metadata Sanitization (Guarantees zero credentials)
        raw_meta = _sanitize_metadata({
            "http_status": 200,
            "vt_id": data.get("id"),
            "malicious": malicious,
            "suspicious": suspicious,
            "harmless": harmless,
            "undetected": undetected,
            "raw_reputation": raw_reputation,
            "as_owner": attributes.get("as_owner"),
        })

        return ThreatIntelResult(
            ioc_id=ioc.id,
            ioc_type=ioc.ioc_type,
            ioc_value=ioc.raw_value,
            normalized_value=ioc.normalized_value,
            status=status,
            confidence=confidence,
            source=self.source_type,
            provider_name=self.provider_name,
            provider_version=self.provider_version,
            queried_at=now,
            expires_at=expires_at,
            lookup_latency_ms=latency_ms,
            source_reference=gui_url,
            detection_count=detection_count,
            total_engines=total_engines,
            reputation_score=reputation_score,
            categories=categories,
            tags=tags,
            country=country,
            asn=asn,
            first_seen=first_seen,
            last_seen=last_seen,
            raw_metadata=raw_meta,
        )

    def _parse_unix_timestamp(self, ts: Any) -> Optional[datetime]:
        """Convert a Unix epoch seconds timestamp into a timezone-aware UTC datetime."""
        if ts is not None and isinstance(ts, (int, float)) and ts > 0:
            try:
                return datetime.fromtimestamp(ts, tz=timezone.utc)
            except (ValueError, OSError, OverflowError):
                return None
        return None

    def _build_disabled_result(self, ioc: IOC) -> ThreatIntelResult:
        """Construct a safe UNKNOWN result when VirusTotal is disabled (API key missing)."""
        now = datetime.now(timezone.utc)
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
            detection_count=None,
            total_engines=None,
            reputation_score=None,
            categories=[],
            tags=["virustotal", "provider_disabled", "missing_api_key"],
            raw_metadata={
                "error": "VirusTotal provider is disabled because VIRUSTOTAL_API_KEY is not configured",
                "disabled": True,
            },
        )

