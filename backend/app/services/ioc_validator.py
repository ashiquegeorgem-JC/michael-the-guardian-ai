"""
IOC Validator for MICHAEL – THE GUARDIAN AI.

Phase 4.2A.3 — IOC Normalization & Validation.

Provides deterministic, offline validation for each IOCType.
Distinguishes three statuses:
- VALID: Syntactically sound, conforming to all RFC and formatting rules.
- INVALID: Malformed, impossible value, or violating syntax constraints.
- SUSPICIOUS: Syntactically valid but exhibiting anomalous patterns (e.g. directory traversal,
             punycode, credentials in URL, trivial null hash masks).
             "Suspicious" does NOT indicate confirmed maliciousness.

Never queries external networks or performs DNS resolution.
Classifies IP indicators into network scopes: public, private, loopback, link-local, multicast, reserved, unspecified.
"""

from __future__ import annotations

import ipaddress
import re
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse

from app.models.ioc import (
    IOC,
    IOCExtractionResult,
    IOCStatus,
    IOCType,
    IOCValidationResult,
    IPScope,
    ValidationStatus,
)
from app.services.ioc_normalizer import IOCNormalizer


# ─────────────────────────────────────────────────────────────────────────────
# Syntax Constraints & Constants
# ─────────────────────────────────────────────────────────────────────────────

_HEX_CHAR_SET = set("0123456789abcdefABCDEF")

# Allowed characters in email local-part per RFC 5322
_EMAIL_LOCAL_PART_REGEX = re.compile(r"^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+$")

# Domain label regex: 1 to 63 alphanumeric or hyphen characters, no leading/trailing hyphen
_DOMAIN_LABEL_REGEX = re.compile(r"^[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$")

# Forbidden characters in Windows path components
_WIN_FORBIDDEN_CHARS = set('*?"<>|')


class IOCValidator:
    """
    Deterministic syntax and format validator for Indicators of Compromise.
    Operates strictly offline without external reputation lookups or DNS requests.
    """

    @classmethod
    def validate(
        cls,
        raw_value: str,
        ioc_type: IOCType,
        normalized_value: Optional[str] = None,
    ) -> IOCValidationResult:
        """
        Validate an indicator candidate.
        If normalized_value is not provided, normalizes raw_value via IOCNormalizer first.
        """
        if not raw_value or not isinstance(raw_value, str) or not raw_value.strip():
            return IOCValidationResult(
                is_valid=False,
                normalized_value="",
                original_value=raw_value or "",
                ioc_type=ioc_type,
                validation_status=ValidationStatus.INVALID,
                validation_reason="Empty or whitespace indicator string",
                ip_scope=None,
            )

        norm = IOCNormalizer.normalize(normalized_value if normalized_value is not None else raw_value, ioc_type)

        if ioc_type == IOCType.IPV4:
            return cls._validate_ipv4(raw_value, norm)
        elif ioc_type == IOCType.IPV6:
            return cls._validate_ipv6(raw_value, norm)
        elif ioc_type == IOCType.DOMAIN:
            return cls._validate_domain(raw_value, norm)
        elif ioc_type == IOCType.URL:
            return cls._validate_url(raw_value, norm)
        elif ioc_type in (IOCType.MD5, IOCType.SHA1, IOCType.SHA256):
            return cls._validate_hash(raw_value, norm, ioc_type)
        elif ioc_type == IOCType.EMAIL:
            return cls._validate_email(raw_value, norm)
        elif ioc_type == IOCType.FILE_PATH:
            return cls._validate_file_path(raw_value, norm)
        else:
            return IOCValidationResult(
                is_valid=True,
                normalized_value=norm,
                original_value=raw_value,
                ioc_type=ioc_type,
                validation_status=ValidationStatus.VALID,
                validation_reason="Unconstrained indicator type",
            )

    @classmethod
    def validate_ioc(cls, ioc: IOC) -> Tuple[IOC, IOCValidationResult]:
        """
        Validate an existing IOC instance.
        Returns a tuple of (updated_ioc, validation_result).
        The updated_ioc preserves raw_value and evidence references while
        refreshing normalized_value with the canonical form.
        """
        v_res = cls.validate(ioc.raw_value, ioc.ioc_type)
        updated_ioc = ioc.model_copy(update={
            "normalized_value": v_res.normalized_value,
        })
        return updated_ioc, v_res

    @classmethod
    def validate_iocs(cls, iocs: List[IOC]) -> List[Tuple[IOC, IOCValidationResult]]:
        """
        Batch validation across a list of IOC objects.
        """
        return [cls.validate_ioc(ioc) for ioc in iocs]

    @classmethod
    def validate_extraction_result(
        cls,
        result: IOCExtractionResult,
    ) -> Tuple[IOCExtractionResult, List[IOCValidationResult]]:
        """
        Validate all IOCs within an IOCExtractionResult.
        Returns (new_result_with_canonical_iocs, list_of_validation_results).
        Does not mutate the original IOCExtractionResult.
        """
        validated_iocs: List[IOC] = []
        validation_results: List[IOCValidationResult] = []

        for ioc in result.iocs:
            v_ioc, v_res = cls.validate_ioc(ioc)
            validated_iocs.append(v_ioc)
            validation_results.append(v_res)

        new_result = result.model_copy(update={
            "iocs": validated_iocs,
        })
        return new_result, validation_results

    # ─────────────────────────────────────────────────────────────────────────
    # IP Scope Classifier
    # ─────────────────────────────────────────────────────────────────────────

    @classmethod
    def classify_ip_scope(
        cls,
        ip: ipaddress.IPv4Address | ipaddress.IPv6Address,
    ) -> IPScope:
        """
        Classify an IPv4 or IPv6 object into standard RFC scopes:
        public, private, loopback, link-local, multicast, reserved, unspecified.
        """
        if ip.is_unspecified:
            return IPScope.UNSPECIFIED
        elif ip.is_loopback:
            return IPScope.LOOPBACK
        elif ip.is_link_local:
            return IPScope.LINK_LOCAL
        elif ip.is_multicast:
            return IPScope.MULTICAST
        elif ip.is_reserved:
            return IPScope.RESERVED
        elif ip.is_private:
            return IPScope.PRIVATE
        else:
            return IPScope.PUBLIC

    # ─────────────────────────────────────────────────────────────────────────
    # Type-Specific Validation Internals
    # ─────────────────────────────────────────────────────────────────────────

    @classmethod
    def _validate_ipv4(cls, raw: str, norm: str) -> IOCValidationResult:
        """
        Validate IPv4 candidate using ipaddress.IPv4Address.
        Rejects impossible octets, malformed addresses, and non-numeric strings.
        """
        clean = raw.strip().strip("'\"`")
        parts = clean.split(".")

        if len(parts) != 4:
            return IOCValidationResult(
                is_valid=False,
                normalized_value=norm,
                original_value=raw,
                ioc_type=IOCType.IPV4,
                validation_status=ValidationStatus.INVALID,
                validation_reason=f"IPv4 address must contain exactly 4 octets, got {len(parts)}",
                ip_scope=None,
            )

        for p in parts:
            if not p.isdigit():
                return IOCValidationResult(
                    is_valid=False,
                    normalized_value=norm,
                    original_value=raw,
                    ioc_type=IOCType.IPV4,
                    validation_status=ValidationStatus.INVALID,
                    validation_reason=f"Octet '{p}' is not a numeric integer",
                    ip_scope=None,
                )
            num = int(p)
            if num < 0 or num > 255:
                return IOCValidationResult(
                    is_valid=False,
                    normalized_value=norm,
                    original_value=raw,
                    ioc_type=IOCType.IPV4,
                    validation_status=ValidationStatus.INVALID,
                    validation_reason=f"Octet value {num} exceeds valid range (0-255)",
                    ip_scope=None,
                )

        try:
            ip = ipaddress.IPv4Address(norm)
            scope = cls.classify_ip_scope(ip)

            # Check if raw had leading zeroes (suspicious octal/decimal ambiguity)
            has_leading_zero = any(len(p) > 1 and p.startswith("0") for p in parts)
            status = ValidationStatus.SUSPICIOUS if has_leading_zero else ValidationStatus.VALID
            reason = "Octets contain leading zeros (normalized)" if has_leading_zero else None

            return IOCValidationResult(
                is_valid=True,
                normalized_value=str(ip),
                original_value=raw,
                ioc_type=IOCType.IPV4,
                validation_status=status,
                validation_reason=reason,
                ip_scope=scope,
            )
        except Exception as e:
            return IOCValidationResult(
                is_valid=False,
                normalized_value=norm,
                original_value=raw,
                ioc_type=IOCType.IPV4,
                validation_status=ValidationStatus.INVALID,
                validation_reason=f"IPv4 parse error: {e}",
                ip_scope=None,
            )

    @classmethod
    def _validate_ipv6(cls, raw: str, norm: str) -> IOCValidationResult:
        """
        Validate IPv6 candidate using ipaddress.IPv6Address.
        Rejects timestamps, MAC addresses, and malformed hex strings.
        """
        clean = raw.strip().strip("'\"`")
        if clean.startswith("[") and clean.endswith("]"):
            clean = clean[1:-1].strip()

        # Rejection: MAC addresses (contains exactly 5 colons and 6 pairs of hex)
        mac_match = re.match(r"^([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}$", clean)
        if mac_match:
            return IOCValidationResult(
                is_valid=False,
                normalized_value=norm,
                original_value=raw,
                ioc_type=IOCType.IPV6,
                validation_status=ValidationStatus.INVALID,
                validation_reason="String is a hardware MAC address, not an IPv6 address",
                ip_scope=None,
            )

        # Rejection: Timestamps (e.g. 12:30:45)
        if re.match(r"^\d{1,2}:\d{2}(?::\d{2})?$", clean):
            return IOCValidationResult(
                is_valid=False,
                normalized_value=norm,
                original_value=raw,
                ioc_type=IOCType.IPV6,
                validation_status=ValidationStatus.INVALID,
                validation_reason="String represents a clock timestamp, not an IPv6 address",
                ip_scope=None,
            )

        try:
            ip = ipaddress.IPv6Address(clean)
            scope = cls.classify_ip_scope(ip)
            return IOCValidationResult(
                is_valid=True,
                normalized_value=str(ip).lower(),
                original_value=raw,
                ioc_type=IOCType.IPV6,
                validation_status=ValidationStatus.VALID,
                validation_reason=None,
                ip_scope=scope,
            )
        except Exception as e:
            return IOCValidationResult(
                is_valid=False,
                normalized_value=norm,
                original_value=raw,
                ioc_type=IOCType.IPV6,
                validation_status=ValidationStatus.INVALID,
                validation_reason=f"IPv6 parse error: {e}",
                ip_scope=None,
            )

    @classmethod
    def _validate_domain(cls, raw: str, norm: str) -> IOCValidationResult:
        """
        Validate domain syntax based on RFC 1035 / RFC 1123 hostname rules.
        Validates total length, labels, allowed characters, hyphen placement, and TLD.
        Does not reject unknown TLDs if syntactically conforming.
        """
        domain = norm.rstrip(".")

        if not domain:
            return IOCValidationResult(
                is_valid=False,
                normalized_value=norm,
                original_value=raw,
                ioc_type=IOCType.DOMAIN,
                validation_status=ValidationStatus.INVALID,
                validation_reason="Domain string is empty",
            )

        if len(domain) > 253:
            return IOCValidationResult(
                is_valid=False,
                normalized_value=norm,
                original_value=raw,
                ioc_type=IOCType.DOMAIN,
                validation_status=ValidationStatus.INVALID,
                validation_reason=f"Domain total length ({len(domain)}) exceeds RFC 1035 limit (253 chars)",
            )

        labels = domain.split(".")
        if len(labels) < 2:
            return IOCValidationResult(
                is_valid=False,
                normalized_value=norm,
                original_value=raw,
                ioc_type=IOCType.DOMAIN,
                validation_status=ValidationStatus.INVALID,
                validation_reason="Domain must contain at least a domain name and a TLD",
            )

        has_underscore = False
        has_punycode = False

        for i, label in enumerate(labels):
            if not label:
                return IOCValidationResult(
                    is_valid=False,
                    normalized_value=norm,
                    original_value=raw,
                    ioc_type=IOCType.DOMAIN,
                    validation_status=ValidationStatus.INVALID,
                    validation_reason=f"Empty label found at position {i} (consecutive dots)",
                )

            if len(label) > 63:
                return IOCValidationResult(
                    is_valid=False,
                    normalized_value=norm,
                    original_value=raw,
                    ioc_type=IOCType.DOMAIN,
                    validation_status=ValidationStatus.INVALID,
                    validation_reason=f"Label '{label[:15]}...' exceeds maximum 63 characters",
                )

            if label.startswith("-") or label.endswith("-"):
                return IOCValidationResult(
                    is_valid=False,
                    normalized_value=norm,
                    original_value=raw,
                    ioc_type=IOCType.DOMAIN,
                    validation_status=ValidationStatus.INVALID,
                    validation_reason=f"Label '{label}' cannot begin or end with a hyphen",
                )

            if label.startswith("xn--"):
                has_punycode = True

            if "_" in label:
                has_underscore = True
                # Check characters outside underscore
                if not re.match(r"^[a-zA-Z0-9_-]+$", label):
                    return IOCValidationResult(
                        is_valid=False,
                        normalized_value=norm,
                        original_value=raw,
                        ioc_type=IOCType.DOMAIN,
                        validation_status=ValidationStatus.INVALID,
                        validation_reason=f"Label '{label}' contains illegal characters",
                    )
            else:
                if not _DOMAIN_LABEL_REGEX.match(label):
                    return IOCValidationResult(
                        is_valid=False,
                        normalized_value=norm,
                        original_value=raw,
                        ioc_type=IOCType.DOMAIN,
                        validation_status=ValidationStatus.INVALID,
                        validation_reason=f"Label '{label}' contains illegal characters",
                    )

        # TLD check: last label must NOT be purely numeric (RFC 1123 sec 2.1)
        tld = labels[-1]
        if tld.isdigit():
            return IOCValidationResult(
                is_valid=False,
                normalized_value=norm,
                original_value=raw,
                ioc_type=IOCType.DOMAIN,
                validation_status=ValidationStatus.INVALID,
                validation_reason=f"Top-level domain '{tld}' cannot be purely numeric",
            )

        if len(tld) < 2:
            return IOCValidationResult(
                is_valid=False,
                normalized_value=norm,
                original_value=raw,
                ioc_type=IOCType.DOMAIN,
                validation_status=ValidationStatus.INVALID,
                validation_reason=f"Top-level domain '{tld}' must be at least 2 characters",
            )

        # Suspicious conditions
        if has_punycode:
            return IOCValidationResult(
                is_valid=True,
                normalized_value=norm,
                original_value=raw,
                ioc_type=IOCType.DOMAIN,
                validation_status=ValidationStatus.SUSPICIOUS,
                validation_reason="Contains Punycode (IDN internationalized domain) label",
            )
        elif has_underscore:
            return IOCValidationResult(
                is_valid=True,
                normalized_value=norm,
                original_value=raw,
                ioc_type=IOCType.DOMAIN,
                validation_status=ValidationStatus.SUSPICIOUS,
                validation_reason="Domain contains underscores (common in DNS service records, but non-standard for web hostnames)",
            )
        elif len(labels) > 6:
            return IOCValidationResult(
                is_valid=True,
                normalized_value=norm,
                original_value=raw,
                ioc_type=IOCType.DOMAIN,
                validation_status=ValidationStatus.SUSPICIOUS,
                validation_reason=f"Unusually deep subdomain hierarchy ({len(labels)} labels)",
            )

        return IOCValidationResult(
            is_valid=True,
            normalized_value=norm,
            original_value=raw,
            ioc_type=IOCType.DOMAIN,
            validation_status=ValidationStatus.VALID,
            validation_reason=None,
        )

    @classmethod
    def _validate_url(cls, raw: str, norm: str) -> IOCValidationResult:
        """
        Validate HTTP/HTTPS URL structure.
        Checks scheme, host structure (domain, IPv4, or IPv6), and port boundaries.
        """
        try:
            parsed = urlparse(norm)
            scheme = parsed.scheme.lower()

            if scheme not in ("http", "https"):
                return IOCValidationResult(
                    is_valid=False,
                    normalized_value=norm,
                    original_value=raw,
                    ioc_type=IOCType.URL,
                    validation_status=ValidationStatus.INVALID,
                    validation_reason=f"Unsupported URL scheme '{scheme}' (must be http or https)",
                )

            if not parsed.netloc:
                return IOCValidationResult(
                    is_valid=False,
                    normalized_value=norm,
                    original_value=raw,
                    ioc_type=IOCType.URL,
                    validation_status=ValidationStatus.INVALID,
                    validation_reason="URL is missing a network host authority (netloc)",
                )

            netloc = parsed.netloc
            has_credentials = "@" in netloc

            if has_credentials:
                _, hostport = netloc.split("@", 1)
            else:
                hostport = netloc

            # Parse host and port
            if hostport.startswith("[") and "]" in hostport:
                bracket_end = hostport.find("]")
                v6_str = hostport[1:bracket_end]
                port_str = hostport[bracket_end + 1:].lstrip(":")
                try:
                    ipaddress.IPv6Address(v6_str)
                except Exception:
                    return IOCValidationResult(
                        is_valid=False,
                        normalized_value=norm,
                        original_value=raw,
                        ioc_type=IOCType.URL,
                        validation_status=ValidationStatus.INVALID,
                        validation_reason=f"Invalid IPv6 host literal in URL: '{v6_str}'",
                    )
            elif ":" in hostport:
                host, port_str = hostport.rsplit(":", 1)
            else:
                host = hostport
                port_str = ""

            # Validate port
            if port_str:
                if not port_str.isdigit():
                    return IOCValidationResult(
                        is_valid=False,
                        normalized_value=norm,
                        original_value=raw,
                        ioc_type=IOCType.URL,
                        validation_status=ValidationStatus.INVALID,
                        validation_reason=f"URL port '{port_str}' is not a numeric integer",
                    )
                port_num = int(port_str)
                if port_num < 1 or port_num > 65535:
                    return IOCValidationResult(
                        is_valid=False,
                        normalized_value=norm,
                        original_value=raw,
                        ioc_type=IOCType.URL,
                        validation_status=ValidationStatus.INVALID,
                        validation_reason=f"URL port {port_num} outside valid TCP range (1-65535)",
                    )

            # Suspicious conditions
            if has_credentials:
                return IOCValidationResult(
                    is_valid=True,
                    normalized_value=norm,
                    original_value=raw,
                    ioc_type=IOCType.URL,
                    validation_status=ValidationStatus.SUSPICIOUS,
                    validation_reason="Embedded user credentials detected in URL netloc",
                )

            return IOCValidationResult(
                is_valid=True,
                normalized_value=norm,
                original_value=raw,
                ioc_type=IOCType.URL,
                validation_status=ValidationStatus.VALID,
                validation_reason=None,
            )
        except Exception as e:
            return IOCValidationResult(
                is_valid=False,
                normalized_value=norm,
                original_value=raw,
                ioc_type=IOCType.URL,
                validation_status=ValidationStatus.INVALID,
                validation_reason=f"URL parse failure: {e}",
            )

    @classmethod
    def _validate_email(cls, raw: str, norm: str) -> IOCValidationResult:
        """
        Validate email address syntax based on RFC 5322 structure.
        Requires single @ separator, valid local-part, and valid domain structure.
        """
        if norm.count("@") != 1:
            return IOCValidationResult(
                is_valid=False,
                normalized_value=norm,
                original_value=raw,
                ioc_type=IOCType.EMAIL,
                validation_status=ValidationStatus.INVALID,
                validation_reason="Email address must contain exactly one '@' character",
            )

        if len(norm) > 254:
            return IOCValidationResult(
                is_valid=False,
                normalized_value=norm,
                original_value=raw,
                ioc_type=IOCType.EMAIL,
                validation_status=ValidationStatus.INVALID,
                validation_reason=f"Total email length ({len(norm)}) exceeds maximum 254 characters",
            )

        local_part, domain_part = norm.split("@", 1)

        if not local_part or len(local_part) > 64:
            return IOCValidationResult(
                is_valid=False,
                normalized_value=norm,
                original_value=raw,
                ioc_type=IOCType.EMAIL,
                validation_status=ValidationStatus.INVALID,
                validation_reason=f"Local-part length ({len(local_part)}) must be between 1 and 64 characters",
            )

        if local_part.startswith(".") or local_part.endswith("."):
            return IOCValidationResult(
                is_valid=False,
                normalized_value=norm,
                original_value=raw,
                ioc_type=IOCType.EMAIL,
                validation_status=ValidationStatus.INVALID,
                validation_reason="Local-part cannot start or end with a dot",
            )

        if ".." in local_part:
            return IOCValidationResult(
                is_valid=False,
                normalized_value=norm,
                original_value=raw,
                ioc_type=IOCType.EMAIL,
                validation_status=ValidationStatus.INVALID,
                validation_reason="Local-part cannot contain consecutive dots",
            )

        if not _EMAIL_LOCAL_PART_REGEX.match(local_part):
            return IOCValidationResult(
                is_valid=False,
                normalized_value=norm,
                original_value=raw,
                ioc_type=IOCType.EMAIL,
                validation_status=ValidationStatus.INVALID,
                validation_reason="Local-part contains characters disallowed by RFC 5322",
            )

        # Validate domain part
        if not domain_part or "." not in domain_part:
            return IOCValidationResult(
                is_valid=False,
                normalized_value=norm,
                original_value=raw,
                ioc_type=IOCType.EMAIL,
                validation_status=ValidationStatus.INVALID,
                validation_reason="Email domain part is missing or lacks a top-level domain",
            )

        dom_res = cls._validate_domain(domain_part, domain_part)
        if not dom_res.is_valid:
            return IOCValidationResult(
                is_valid=False,
                normalized_value=norm,
                original_value=raw,
                ioc_type=IOCType.EMAIL,
                validation_status=ValidationStatus.INVALID,
                validation_reason=f"Invalid email domain structure: {dom_res.validation_reason}",
            )

        return IOCValidationResult(
            is_valid=True,
            normalized_value=norm,
            original_value=raw,
            ioc_type=IOCType.EMAIL,
            validation_status=ValidationStatus.VALID,
            validation_reason=None,
        )

    @classmethod
    def _validate_hash(cls, raw: str, norm: str, ioc_type: IOCType) -> IOCValidationResult:
        """
        Validate cryptographic hash by exact hex length:
        MD5 = 32, SHA1 = 40, SHA256 = 64.
        Detects non-hex characters and trivial null-mask patterns.
        """
        expected_lengths = {
            IOCType.MD5: 32,
            IOCType.SHA1: 40,
            IOCType.SHA256: 64,
        }
        exp_len = expected_lengths.get(ioc_type, 32)

        if len(norm) != exp_len:
            return IOCValidationResult(
                is_valid=False,
                normalized_value=norm,
                original_value=raw,
                ioc_type=ioc_type,
                validation_status=ValidationStatus.INVALID,
                validation_reason=f"Hash length is {len(norm)}, expected exactly {exp_len} hex characters for {ioc_type.value.upper()}",
            )

        # Check hex character set
        if not all(c in _HEX_CHAR_SET for c in norm):
            return IOCValidationResult(
                is_valid=False,
                normalized_value=norm,
                original_value=raw,
                ioc_type=ioc_type,
                validation_status=ValidationStatus.INVALID,
                validation_reason=f"Hash contains non-hexadecimal characters",
            )

        # Check for dummy mask (all identical characters, e.g. 00000000000000000000000000000000)
        if len(set(norm)) == 1:
            return IOCValidationResult(
                is_valid=True,
                normalized_value=norm,
                original_value=raw,
                ioc_type=ioc_type,
                validation_status=ValidationStatus.SUSPICIOUS,
                validation_reason="Trivial null / placeholder hash mask detected (all identical characters)",
            )

        return IOCValidationResult(
            is_valid=True,
            normalized_value=norm,
            original_value=raw,
            ioc_type=ioc_type,
            validation_status=ValidationStatus.VALID,
            validation_reason=None,
        )

    @classmethod
    def _validate_file_path(cls, raw: str, norm: str) -> IOCValidationResult:
        """
        Validate file path structure:
        - Windows drive paths (C:\\Windows\\...)
        - Windows UNC paths (\\\\server\\share\\...)
        - Unix absolute paths (/etc/...)
        - Relative qualified paths (./... or ../...)
        Rejects ordinary prose.
        Flags directory traversal sequences as SUSPICIOUS.
        """
        clean = norm.strip()

        if not clean:
            return IOCValidationResult(
                is_valid=False,
                normalized_value=norm,
                original_value=raw,
                ioc_type=IOCType.FILE_PATH,
                validation_status=ValidationStatus.INVALID,
                validation_reason="Empty file path",
            )

        # Check for directory traversal sequences
        has_traversal = "../" in clean or "..\\" in clean or clean == ".." or clean.endswith("/..") or clean.endswith("\\..")

        # Windows UNC Path: \\server\share\...
        if clean.startswith(r"\\"):
            unc_body = clean[2:]
            parts = [p for p in unc_body.split("\\") if p]
            if len(parts) < 2:
                return IOCValidationResult(
                    is_valid=False,
                    normalized_value=norm,
                    original_value=raw,
                    ioc_type=IOCType.FILE_PATH,
                    validation_status=ValidationStatus.INVALID,
                    validation_reason="Windows UNC path must contain at least \\\\host\\share",
                )
            if any(any(c in _WIN_FORBIDDEN_CHARS for c in p) for p in parts):
                return IOCValidationResult(
                    is_valid=False,
                    normalized_value=norm,
                    original_value=raw,
                    ioc_type=IOCType.FILE_PATH,
                    validation_status=ValidationStatus.INVALID,
                    validation_reason="UNC path contains forbidden Windows filename characters (* ? \" < > |)",
                )
            status = ValidationStatus.SUSPICIOUS if has_traversal else ValidationStatus.VALID
            reason = "Directory traversal sequence detected in UNC path" if has_traversal else None
            return IOCValidationResult(
                is_valid=True,
                normalized_value=norm,
                original_value=raw,
                ioc_type=IOCType.FILE_PATH,
                validation_status=status,
                validation_reason=reason,
            )

        # Windows Drive Path: C:\...
        if re.match(r"^[a-zA-Z]:\\", clean):
            body = clean[3:]
            parts = [p for p in body.split("\\") if p]
            if any(any(c in _WIN_FORBIDDEN_CHARS for c in p) for p in parts):
                return IOCValidationResult(
                    is_valid=False,
                    normalized_value=norm,
                    original_value=raw,
                    ioc_type=IOCType.FILE_PATH,
                    validation_status=ValidationStatus.INVALID,
                    validation_reason="Windows path contains forbidden characters (* ? \" < > |)",
                )
            status = ValidationStatus.SUSPICIOUS if has_traversal else ValidationStatus.VALID
            reason = "Directory traversal sequence detected in path" if has_traversal else None
            return IOCValidationResult(
                is_valid=True,
                normalized_value=norm,
                original_value=raw,
                ioc_type=IOCType.FILE_PATH,
                validation_status=status,
                validation_reason=reason,
            )

        # Unix Absolute Path: /...
        if clean.startswith("/"):
            if "\0" in clean:
                return IOCValidationResult(
                    is_valid=False,
                    normalized_value=norm,
                    original_value=raw,
                    ioc_type=IOCType.FILE_PATH,
                    validation_status=ValidationStatus.INVALID,
                    validation_reason="Unix path contains null byte",
                )
            status = ValidationStatus.SUSPICIOUS if has_traversal else ValidationStatus.VALID
            reason = "Directory traversal sequence detected in path" if has_traversal else None
            return IOCValidationResult(
                is_valid=True,
                normalized_value=norm,
                original_value=raw,
                ioc_type=IOCType.FILE_PATH,
                validation_status=status,
                validation_reason=reason,
            )

        # Relative paths: ./... or ../...
        if clean.startswith("./") or clean.startswith("../"):
            return IOCValidationResult(
                is_valid=True,
                normalized_value=norm,
                original_value=raw,
                ioc_type=IOCType.FILE_PATH,
                validation_status=ValidationStatus.SUSPICIOUS if has_traversal else ValidationStatus.VALID,
                validation_reason="Relative path with traversal sequence" if has_traversal else "Relative file path",
            )

        # Disallow plain prose
        return IOCValidationResult(
            is_valid=False,
            normalized_value=norm,
            original_value=raw,
            ioc_type=IOCType.FILE_PATH,
            validation_status=ValidationStatus.INVALID,
            validation_reason="Not a recognized absolute, UNC, or qualified relative file path",
        )
