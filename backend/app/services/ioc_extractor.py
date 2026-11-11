"""
IOC Extraction Engine for MICHAEL – THE GUARDIAN AI.

Phase 4.2A.2 — IOC Extraction Engine.

Discovers potential Indicators of Compromise (IOCs) from raw log text
and structured LogEntry events. Supports 9 indicator types:
- IPv4 addresses (validated via standard library ipaddress)
- IPv6 addresses (validated via standard library ipaddress)
- Domains and subdomains (with TLD validation and prose/extension exclusion)
- Full URLs (HTTP/HTTPS with trailing punctuation handling)
- MD5 hashes (32 hex characters)
- SHA1 hashes (40 hex characters)
- SHA256 hashes (64 hex characters)
- Email addresses
- File paths (Unix and Windows absolute / qualified paths)

DESIGN & SAFETY RULES
=====================
- Extraction only: does NOT label indicators as malicious or assign reputation.
- Defaults all new indicators to IOCStatus.EXTRACTED.
- Preserves raw values exactly as seen, keeping normalized values separate.
- Preserves complete evidence traceability (event_id, session_id, line_number,
  timestamp, source_field, surrounding_context).
- Never modifies the original LogEntry objects.
- Uses span-based exclusion to prevent URLs/Emails from being fragmented into
  duplicate standalone domains or file paths.
- Applies SHA256 before SHA1 and MD5 with exact hex boundary lookarounds to
  prevent overlapping classifications.
"""

from __future__ import annotations

from datetime import datetime
import ipaddress
import re
from typing import Any, Dict, List, Optional, Set, Tuple
from urllib.parse import urlparse

from app.models.ioc import (
    IOC,
    IOCEvidence,
    IOCExtractionResult,
    IOCStatus,
    IOCType,
)
from app.models.log_entry import LogEntry


# ─────────────────────────────────────────────────────────────────────────────
# Compiled Regular Expressions & Constants
# ─────────────────────────────────────────────────────────────────────────────

# URL: http/https followed by non-whitespace/bracket chars
_URL_REGEX = re.compile(r'https?://[^\s\'"<>]+', re.IGNORECASE)

# Email: conventional user@domain.tld
_EMAIL_REGEX = re.compile(r'\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b')

# IPv4: 4 octets candidate (validity checked via ipaddress.IPv4Address)
_IPV4_CANDIDATE_REGEX = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')

# IPv6: Enclosed in brackets or delimited by colons
_IPV6_BRACKET_REGEX = re.compile(r'\[([0-9a-fA-F:.]+)\]')
_IPV6_CANDIDATE_REGEX = re.compile(
    r'(?<![0-9a-zA-Z:])(?:[0-9a-fA-F]{1,4}:){1,7}:?(?:[0-9a-fA-F]{1,4})?(?![0-9a-zA-Z:])|'
    r'(?<![0-9a-zA-Z:])::(?:[0-9a-fA-F]{1,4}:){0,6}[0-9a-fA-F]{1,4}(?![0-9a-zA-Z:])|'
    r'(?<![0-9a-zA-Z:])(?:[0-9a-fA-F]{1,4}:){1,6}::(?:[0-9a-fA-F]{1,4}:){0,5}[0-9a-fA-F]{1,4}(?![0-9a-zA-Z:])'
)

# Hashes: Strict negative lookarounds on hex characters ensure exact length matching
_SHA256_REGEX = re.compile(r'(?<![0-9a-fA-F])[0-9a-fA-F]{64}(?![0-9a-fA-F])')
_SHA1_REGEX   = re.compile(r'(?<![0-9a-fA-F])[0-9a-fA-F]{40}(?![0-9a-fA-F])')
_MD5_REGEX    = re.compile(r'(?<![0-9a-fA-F])[0-9a-fA-F]{32}(?![0-9a-fA-F])')

# Domain: Subdomain segments + domain + valid TLD
_DOMAIN_REGEX = re.compile(
    r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,63}\b'
)

# File Paths
_WIN_PATH_REGEX = re.compile(
    r'\b[a-zA-Z]:\\(?:[^\\/:*?"<>|\r\n\s]+\\)*[^\\/:*?"<>|\r\n\s]+'
)
_UNC_PATH_REGEX = re.compile(
    r'\\\\[a-zA-Z0-9_.-]+\\(?:[^\\/:*?"<>|\r\n\s]+\\)*[^\\/:*?"<>|\r\n\s]+'
)
_UNIX_PATH_REGEX = re.compile(
    r'(?<![0-9a-zA-Z_])/(?:[a-zA-Z0-9_.-]+/)*[a-zA-Z0-9_.-]+'
)

# Known Unix system tree roots for high-confidence path matching
_UNIX_KNOWN_ROOTS: Tuple[str, ...] = (
    "/etc", "/var", "/tmp", "/usr", "/bin", "/sbin", "/opt",
    "/home", "/root", "/sys", "/dev", "/proc", "/boot", "/run",
    "/lib", "/lib64", "/mnt", "/media", "/srv",
)

# Common non-domain file/daemon extensions that should not be extracted as domains
_NON_DOMAIN_EXTENSIONS: Set[str] = {
    "log", "txt", "py", "sh", "exe", "dll", "csv", "json", "xml", "gz", "tar",
    "zip", "png", "jpg", "jpeg", "gif", "service", "conf", "cfg", "ini", "so",
    "bin", "md", "html", "css", "js", "ts", "tsx", "jsx", "java", "cpp", "c",
    "h", "go", "rs", "rb", "php", "bak", "tmp", "lock", "yaml", "yml", "env",
    "socket", "target", "mount", "slice", "device", "scope",
}

# Standard TLDs (generic and ccTLDs) for domain validation
_COMMON_TLDS: Set[str] = {
    # Generic
    "com", "org", "net", "edu", "gov", "mil", "int", "arpa", "info", "biz",
    "pro", "name", "mobi", "co", "io", "ai", "app", "dev", "tech", "cloud",
    "site", "online", "store", "live", "club", "space", "security", "top",
    "xyz", "vip", "work", "icu", "click", "link", "guru", "network", "agency",
    "media", "world", "today", "zone", "host", "press", "news", "tv", "me",
    "cc", "ws", "onion", "local", "internal",
    # Common Country Codes
    "ac", "ae", "ar", "at", "au", "be", "br", "ca", "ch", "cl", "cn", "co",
    "cz", "de", "dk", "es", "eu", "fi", "fr", "gr", "hk", "id", "ie", "il",
    "in", "it", "jp", "kr", "mx", "my", "nl", "no", "nz", "pl", "pt", "ro",
    "ru", "se", "sg", "th", "tr", "tw", "ua", "uk", "us", "vn", "za",
}


# ─────────────────────────────────────────────────────────────────────────────
# Helper extraction models & span management
# ─────────────────────────────────────────────────────────────────────────────

class _RawCandidate:
    """Internal container for an un-merged indicator candidate with its span."""
    __slots__ = (
        "ioc_type", "raw_value", "normalized_value", "start", "end",
        "event_id", "session_id", "timestamp", "line_number",
        "source_field", "surrounding_context", "extraction_method",
    )

    def __init__(
        self,
        ioc_type: IOCType,
        raw_value: str,
        normalized_value: str,
        start: int,
        end: int,
        event_id: str,
        session_id: str,
        timestamp: Optional[datetime],
        line_number: Optional[int],
        source_field: str,
        surrounding_context: str,
        extraction_method: str,
    ):
        self.ioc_type = ioc_type
        self.raw_value = raw_value
        self.normalized_value = normalized_value
        self.start = start
        self.end = end
        self.event_id = event_id
        self.session_id = session_id
        self.timestamp = timestamp
        self.line_number = line_number
        self.source_field = source_field
        self.surrounding_context = surrounding_context
        self.extraction_method = extraction_method


def _get_context(text: str, start: int, end: int, window: int = 50) -> str:
    """Extract up to 120 chars of surrounding context centred on match."""
    left = max(0, start - window)
    right = min(len(text), end + window)
    return text[left:right].replace("\r", " ").replace("\n", " ").strip()


def _is_contained(span: Tuple[int, int], excluded_spans: List[Tuple[int, int]]) -> bool:
    """True if span (start, end) falls inside any span in excluded_spans."""
    s, e = span
    return any(ex_s <= s and e <= ex_e for ex_s, ex_e in excluded_spans)


# ─────────────────────────────────────────────────────────────────────────────
# IOCExtractor Service
# ─────────────────────────────────────────────────────────────────────────────

class IOCExtractor:
    """
    Centralized discovery service for Indicators of Compromise (IOCs).

    Scans text and LogEntry events using multi-pattern extraction with
    span exclusion to prevent fragmented sub-component duplicates.
    """

    @classmethod
    def extract_from_text(
        cls,
        text: str,
        session_id: str = "manual",
        event_id: str = "raw-text",
        timestamp: Optional[datetime] = None,
        line_number: Optional[int] = None,
        source_field: str = "text",
    ) -> IOCExtractionResult:
        """
        Extract all candidate IOCs from a single text string.

        Returns an IOCExtractionResult with deduplicated IOC objects and
        complete evidence linkages.
        """
        if not text or not isinstance(text, str) or not text.strip():
            return IOCExtractionResult(
                total_extracted=0,
                unique_iocs=0,
                duplicate_count=0,
                iocs=[],
                extraction_errors=[],
            )

        candidates, errors = cls._extract_candidates_from_string(
            text=text,
            session_id=session_id,
            event_id=event_id,
            timestamp=timestamp,
            line_number=line_number,
            source_field=source_field,
        )

        return cls._aggregate_candidates(candidates, errors)

    @classmethod
    def extract_from_event(
        cls,
        event: LogEntry,
    ) -> IOCExtractionResult:
        """
        Extract all candidate IOCs from a single LogEntry.

        Inspects event.raw_line (falling back to event.message if empty).
        """
        return cls.extract_from_events([event])

    @classmethod
    def extract_from_events(
        cls,
        events: List[LogEntry],
    ) -> IOCExtractionResult:
        """
        Extract and deduplicate candidate IOCs across a batch of LogEntry objects.

        Preserves all evidence references across multiple occurrences.
        """
        if not events:
            return IOCExtractionResult(
                total_extracted=0,
                unique_iocs=0,
                duplicate_count=0,
                iocs=[],
                extraction_errors=[],
            )

        all_candidates: List[_RawCandidate] = []
        all_errors: List[str] = []

        for ev in events:
            text = ev.raw_line if (ev.raw_line and ev.raw_line.strip()) else ev.message
            source_field = "raw_line" if (ev.raw_line and ev.raw_line.strip()) else "message"

            if not text or not text.strip():
                continue

            candidates, errors = cls._extract_candidates_from_string(
                text=text,
                session_id=ev.session_id,
                event_id=ev.id,
                timestamp=ev.timestamp,
                line_number=ev.line_number,
                source_field=source_field,
            )
            all_candidates.extend(candidates)
            all_errors.extend(errors)

        return cls._aggregate_candidates(all_candidates, all_errors)

    # ─────────────────────────────────────────────────────────────────────────
    # Private String Extractor
    # ─────────────────────────────────────────────────────────────────────────

    @classmethod
    def _extract_candidates_from_string(
        cls,
        text: str,
        session_id: str,
        event_id: str,
        timestamp: Optional[datetime],
        line_number: Optional[int],
        source_field: str,
    ) -> Tuple[List[_RawCandidate], List[str]]:
        candidates: List[_RawCandidate] = []
        errors: List[str] = []
        excluded_spans: List[Tuple[int, int]] = []
        hash_spans: List[Tuple[int, int]] = []

        # 1. URLs
        for m in _URL_REGEX.finditer(text):
            raw = m.group()
            cleaned = raw.rstrip('.,;:)\'\"`>]}')
            if not cleaned:
                continue
            try:
                parsed = urlparse(cleaned)
                if parsed.scheme.lower() in ("http", "https") and parsed.netloc:
                    start = m.start()
                    end = start + len(cleaned)
                    span = (start, end)
                    excluded_spans.append(span)

                    ctx = _get_context(text, start, end)
                    candidates.append(_RawCandidate(
                        ioc_type=IOCType.URL,
                        raw_value=cleaned,
                        normalized_value=cleaned.strip(),
                        start=start,
                        end=end,
                        event_id=event_id,
                        session_id=session_id,
                        timestamp=timestamp,
                        line_number=line_number,
                        source_field=source_field,
                        surrounding_context=ctx,
                        extraction_method="regex_url",
                    ))
            except Exception as e:
                errors.append(f"Error parsing URL '{cleaned}': {e}")

        # 2. Email Addresses
        for m in _EMAIL_REGEX.finditer(text):
            raw = m.group()
            cleaned = raw.rstrip('.,;:)\'\"`>]}')
            start = m.start()
            end = start + len(cleaned)
            span = (start, end)

            # Avoid emails inside URLs
            if _is_contained(span, excluded_spans):
                continue

            if "@" in cleaned and "." in cleaned.split("@")[-1]:
                excluded_spans.append(span)
                ctx = _get_context(text, start, end)
                candidates.append(_RawCandidate(
                    ioc_type=IOCType.EMAIL,
                    raw_value=cleaned,
                    normalized_value=cleaned.lower(),
                    start=start,
                    end=end,
                    event_id=event_id,
                    session_id=session_id,
                    timestamp=timestamp,
                    line_number=line_number,
                    source_field=source_field,
                    surrounding_context=ctx,
                    extraction_method="regex_email",
                ))

        # 3. IPv6 Addresses
        # Check bracketed [ipv6] first
        for m in _IPV6_BRACKET_REGEX.finditer(text):
            raw_bracketed = m.group()
            inner = m.group(1)
            span = (m.start(), m.end())
            if _is_contained(span, excluded_spans):
                continue
            try:
                ip = ipaddress.IPv6Address(inner)
                excluded_spans.append(span)
                ctx = _get_context(text, m.start(), m.end())
                candidates.append(_RawCandidate(
                    ioc_type=IOCType.IPV6,
                    raw_value=inner,
                    normalized_value=str(ip).lower(),
                    start=m.start(1),
                    end=m.end(1),
                    event_id=event_id,
                    session_id=session_id,
                    timestamp=timestamp,
                    line_number=line_number,
                    source_field=source_field,
                    surrounding_context=ctx,
                    extraction_method="regex_ipv6",
                ))
            except ValueError:
                pass

        # Check bare IPv6
        for m in _IPV6_CANDIDATE_REGEX.finditer(text):
            raw = m.group()
            cleaned = raw.rstrip('.,;:)\'\"`>]}')
            start = m.start()
            end = start + len(cleaned)
            span = (start, end)
            if _is_contained(span, excluded_spans):
                continue
            if ":" in cleaned:
                try:
                    ip = ipaddress.IPv6Address(cleaned)
                    excluded_spans.append(span)
                    ctx = _get_context(text, start, end)
                    candidates.append(_RawCandidate(
                        ioc_type=IOCType.IPV6,
                        raw_value=cleaned,
                        normalized_value=str(ip).lower(),
                        start=start,
                        end=end,
                        event_id=event_id,
                        session_id=session_id,
                        timestamp=timestamp,
                        line_number=line_number,
                        source_field=source_field,
                        surrounding_context=ctx,
                        extraction_method="regex_ipv6",
                    ))
                except ValueError:
                    # Not a valid IPv6 address (e.g. MAC address, timestamp)
                    pass

        # 4. IPv4 Addresses
        for m in _IPV4_CANDIDATE_REGEX.finditer(text):
            raw = m.group()
            start = m.start()
            end = m.end()
            span = (start, end)
            if _is_contained(span, excluded_spans):
                continue

            try:
                parts = raw.split(".")
                # Check for standard 4 octets
                if len(parts) == 4:
                    # Strip leading zeroes for validation so 192.168.01.1 is parsed cleanly
                    cleaned_octets = [str(int(p)) for p in parts]
                    test_ip_str = ".".join(cleaned_octets)
                    ip = ipaddress.IPv4Address(test_ip_str)

                    excluded_spans.append(span)
                    ctx = _get_context(text, start, end)
                    candidates.append(_RawCandidate(
                        ioc_type=IOCType.IPV4,
                        raw_value=raw,
                        normalized_value=str(ip),
                        start=start,
                        end=end,
                        event_id=event_id,
                        session_id=session_id,
                        timestamp=timestamp,
                        line_number=line_number,
                        source_field=source_field,
                        surrounding_context=ctx,
                        extraction_method="regex_ipv4",
                    ))
            except ValueError:
                errors.append(f"Rejected invalid IPv4 candidate '{raw}' in line")

        # 5. Hashes: Apply SHA256 -> SHA1 -> MD5 strictly
        # 5a. SHA256 (64 hex)
        for m in _SHA256_REGEX.finditer(text):
            raw = m.group()
            span = (m.start(), m.end())
            if _is_contained(span, excluded_spans):
                continue
            # Avoid single repeated character dummy strings (e.g. 64 zeroes)
            if len(set(raw.lower())) > 1:
                hash_spans.append(span)
                excluded_spans.append(span)
                ctx = _get_context(text, m.start(), m.end())
                candidates.append(_RawCandidate(
                    ioc_type=IOCType.SHA256,
                    raw_value=raw,
                    normalized_value=raw.lower(),
                    start=m.start(),
                    end=m.end(),
                    event_id=event_id,
                    session_id=session_id,
                    timestamp=timestamp,
                    line_number=line_number,
                    source_field=source_field,
                    surrounding_context=ctx,
                    extraction_method="regex_sha256",
                ))

        # 5b. SHA1 (40 hex)
        for m in _SHA1_REGEX.finditer(text):
            raw = m.group()
            span = (m.start(), m.end())
            if _is_contained(span, hash_spans) or _is_contained(span, excluded_spans):
                continue
            if len(set(raw.lower())) > 1:
                hash_spans.append(span)
                excluded_spans.append(span)
                ctx = _get_context(text, m.start(), m.end())
                candidates.append(_RawCandidate(
                    ioc_type=IOCType.SHA1,
                    raw_value=raw,
                    normalized_value=raw.lower(),
                    start=m.start(),
                    end=m.end(),
                    event_id=event_id,
                    session_id=session_id,
                    timestamp=timestamp,
                    line_number=line_number,
                    source_field=source_field,
                    surrounding_context=ctx,
                    extraction_method="regex_sha1",
                ))

        # 5c. MD5 (32 hex)
        for m in _MD5_REGEX.finditer(text):
            raw = m.group()
            span = (m.start(), m.end())
            if _is_contained(span, hash_spans) or _is_contained(span, excluded_spans):
                continue
            if len(set(raw.lower())) > 1:
                hash_spans.append(span)
                excluded_spans.append(span)
                ctx = _get_context(text, m.start(), m.end())
                candidates.append(_RawCandidate(
                    ioc_type=IOCType.MD5,
                    raw_value=raw,
                    normalized_value=raw.lower(),
                    start=m.start(),
                    end=m.end(),
                    event_id=event_id,
                    session_id=session_id,
                    timestamp=timestamp,
                    line_number=line_number,
                    source_field=source_field,
                    surrounding_context=ctx,
                    extraction_method="regex_md5",
                ))

        # 6. Domains & Subdomains
        for m in _DOMAIN_REGEX.finditer(text):
            raw = m.group()
            cleaned = raw.rstrip('.,;:)\'\"`>]}')
            start = m.start()
            end = start + len(cleaned)
            span = (start, end)

            # Avoid domains inside URLs, emails, or hashes
            if _is_contained(span, excluded_spans):
                continue

            # Verify domain structure
            parts = cleaned.split(".")
            tld = parts[-1].lower()

            # Skip common file extensions and daemons
            if tld in _NON_DOMAIN_EXTENSIONS:
                continue

            # Skip prose abbreviations (e.g. i.e, e.g)
            if cleaned.lower() in ("e.g", "i.e", "a.k.a", "etc"):
                continue

            # Skip if it is an IP address
            try:
                ipaddress.ip_address(cleaned)
                continue
            except ValueError:
                pass

            # Require standard TLD or multi-part internet domain
            if tld in _COMMON_TLDS or (len(parts) >= 3 and len(tld) >= 2 and tld.isalpha()):
                excluded_spans.append(span)
                ctx = _get_context(text, start, end)
                candidates.append(_RawCandidate(
                    ioc_type=IOCType.DOMAIN,
                    raw_value=cleaned,
                    normalized_value=cleaned.lower(),
                    start=start,
                    end=end,
                    event_id=event_id,
                    session_id=session_id,
                    timestamp=timestamp,
                    line_number=line_number,
                    source_field=source_field,
                    surrounding_context=ctx,
                    extraction_method="regex_domain",
                ))

        # 7. File Paths (Windows and Unix)
        # 7a. Windows paths (drive letter or UNC)
        for rx in (_WIN_PATH_REGEX, _UNC_PATH_REGEX):
            for m in rx.finditer(text):
                raw = m.group()
                cleaned = raw.rstrip('.,;:)\'\"`>]}')
                start = m.start()
                end = start + len(cleaned)
                span = (start, end)

                if _is_contained(span, excluded_spans):
                    continue

                excluded_spans.append(span)
                ctx = _get_context(text, start, end)
                candidates.append(_RawCandidate(
                    ioc_type=IOCType.FILE_PATH,
                    raw_value=cleaned,
                    normalized_value=cleaned.replace("\\", "/").rstrip("/"),
                    start=start,
                    end=end,
                    event_id=event_id,
                    session_id=session_id,
                    timestamp=timestamp,
                    line_number=line_number,
                    source_field=source_field,
                    surrounding_context=ctx,
                    extraction_method="regex_win_path",
                ))

        # 7b. Unix paths
        for m in _UNIX_PATH_REGEX.finditer(text):
            raw = m.group()
            cleaned = raw.rstrip('.,;:)\'\"`>]}')
            start = m.start()
            end = start + len(cleaned)
            span = (start, end)

            if _is_contained(span, excluded_spans):
                continue

            # Validate Unix path structure:
            # Must either start with a known system tree root OR have >= 2 segments with a file extension
            is_valid_path = False
            if any(cleaned.startswith(root) for root in _UNIX_KNOWN_ROOTS):
                is_valid_path = True
            elif cleaned.count("/") >= 2 and "." in cleaned.split("/")[-1]:
                is_valid_path = True

            if is_valid_path and len(cleaned) > 1:
                excluded_spans.append(span)
                ctx = _get_context(text, start, end)
                candidates.append(_RawCandidate(
                    ioc_type=IOCType.FILE_PATH,
                    raw_value=cleaned,
                    normalized_value=cleaned.rstrip("/"),
                    start=start,
                    end=end,
                    event_id=event_id,
                    session_id=session_id,
                    timestamp=timestamp,
                    line_number=line_number,
                    source_field=source_field,
                    surrounding_context=ctx,
                    extraction_method="regex_unix_path",
                ))

        return candidates, errors

    # ─────────────────────────────────────────────────────────────────────────
    # Candidate Aggregation & Deduplication
    # ─────────────────────────────────────────────────────────────────────────

    @classmethod
    def _aggregate_candidates(
        cls,
        candidates: List[_RawCandidate],
        errors: List[str],
    ) -> IOCExtractionResult:
        """
        Merge candidate matches into deduplicated IOC records while preserving
        all IOCEvidence entries.
        """
        seen: Dict[Tuple[IOCType, str], IOC] = {}
        ordered_iocs: List[IOC] = []
        duplicate_count = 0

        for cand in candidates:
            evidence = IOCEvidence(
                event_id=cand.event_id,
                session_id=cand.session_id,
                timestamp=cand.timestamp,
                raw_value=cand.raw_value,
                source_field=cand.source_field,
                line_number=cand.line_number,
                surrounding_context=cand.surrounding_context,
            )

            key = (cand.ioc_type, cand.normalized_value)

            if key in seen:
                # Merge into existing IOC record
                existing = seen[key]
                existing.occurrence_count += 1
                existing.evidence_references.append(evidence)

                if cand.session_id and cand.session_id not in existing.source_sessions:
                    existing.source_sessions.append(cand.session_id)

                if cand.extraction_method and cand.extraction_method not in existing.extraction_methods:
                    existing.extraction_methods.append(cand.extraction_method)

                if cand.timestamp:
                    if existing.first_seen is None or cand.timestamp < existing.first_seen:
                        existing.first_seen = cand.timestamp
                    if existing.last_seen is None or cand.timestamp > existing.last_seen:
                        existing.last_seen = cand.timestamp

                duplicate_count += 1
            else:
                # Create brand new IOC record
                new_ioc = IOC(
                    ioc_type=cand.ioc_type,
                    raw_value=cand.raw_value,
                    normalized_value=cand.normalized_value,
                    status=IOCStatus.EXTRACTED,
                    confidence=0.5,
                    first_seen=cand.timestamp,
                    last_seen=cand.timestamp,
                    occurrence_count=1,
                    evidence_references=[evidence],
                    source_sessions=[cand.session_id] if cand.session_id else [],
                    extraction_methods=[cand.extraction_method],
                )
                seen[key] = new_ioc
                ordered_iocs.append(new_ioc)

        total_extracted = len(candidates)
        unique_iocs = len(ordered_iocs)

        return IOCExtractionResult(
            total_extracted=total_extracted,
            unique_iocs=unique_iocs,
            duplicate_count=duplicate_count,
            iocs=ordered_iocs,
            extraction_errors=errors,
        )
