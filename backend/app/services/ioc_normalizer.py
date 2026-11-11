"""
IOC Normalizer for MICHAEL – THE GUARDIAN AI.

Phase 4.2A.3 — IOC Normalization & Validation.

Provides deterministic canonicalization for Indicators of Compromise:
- IPv4: Canonical dotted-quad via ipaddress, strips leading octet zeroes (10.001.020.005 -> 10.1.20.5).
- IPv6: Canonical compressed lowercase representation (RFC 5952, e.g. 2001:0DB8::0001 -> 2001:db8::1).
- Domains: Lowercased, stripped of trailing dots and punctuation (WWW.Example.COM. -> www.example.com).
- URLs: Canonical scheme and host (lowercased), default port removal (:80 for http, :443 for https),
        trailing punctuation stripped, path and query parameters preserved.
- Emails: Standardized lowercase address.
- Hashes: Lowercase hexadecimal, whitespace stripped.
- File paths: Normalizes duplicate separators and trailing slashes while preserving drive/UNC identity.
"""

from __future__ import annotations

import ipaddress
import re
from typing import Optional
from urllib.parse import urlparse, urlunparse

from app.models.ioc import IOC, IOCType


class IOCNormalizer:
    """
    Deterministic canonicalization service for extracted indicator candidates.
    Never alters raw evidence strings.
    """

    @classmethod
    def normalize(cls, value: str, ioc_type: IOCType) -> str:
        """
        Normalize an indicator string according to its IOCType.
        Returns the canonical normalized string representation.
        """
        if not value or not isinstance(value, str):
            return ""

        val = value.strip()

        if ioc_type == IOCType.IPV4:
            return cls.normalize_ipv4(val)
        elif ioc_type == IOCType.IPV6:
            return cls.normalize_ipv6(val)
        elif ioc_type == IOCType.DOMAIN:
            return cls.normalize_domain(val)
        elif ioc_type == IOCType.URL:
            return cls.normalize_url(val)
        elif ioc_type in (IOCType.MD5, IOCType.SHA1, IOCType.SHA256):
            return cls.normalize_hash(val)
        elif ioc_type == IOCType.EMAIL:
            return cls.normalize_email(val)
        elif ioc_type == IOCType.FILE_PATH:
            return cls.normalize_file_path(val)
        else:
            return val

    @classmethod
    def normalize_ioc(cls, ioc: IOC) -> IOC:
        """
        Produce a copy of an IOC with its normalized_value refreshed via canonicalization rules.
        Preserves original raw_value, evidence_references, and ID.
        """
        canonical = cls.normalize(ioc.raw_value, ioc.ioc_type)
        return ioc.model_copy(update={"normalized_value": canonical})

    # ─────────────────────────────────────────────────────────────────────────
    # Type-Specific Normalization Handlers
    # ─────────────────────────────────────────────────────────────────────────

    @classmethod
    def normalize_ipv4(cls, value: str) -> str:
        """
        Canonicalize IPv4 address.
        Strips leading zeroes from octets (10.001.020.005 -> 10.1.20.5)
        and formats via standard library ipaddress.IPv4Address.
        """
        clean = value.strip().strip("'\"`")
        try:
            parts = clean.split(".")
            if len(parts) == 4:
                # Strip leading zeroes from each octet
                stripped_octets = [str(int(p)) for p in parts]
                candidate = ".".join(stripped_octets)
                ip = ipaddress.IPv4Address(candidate)
                return str(ip)
            ip = ipaddress.IPv4Address(clean)
            return str(ip)
        except Exception:
            return clean

    @classmethod
    def normalize_ipv6(cls, value: str) -> str:
        """
        Canonicalize IPv6 address to RFC 5952 lowercase compressed format.
        Handles bracketed values ([2001:db8::1] -> 2001:db8::1).
        """
        clean = value.strip().strip("'\"`")
        # Remove surrounding brackets if present
        if clean.startswith("[") and clean.endswith("]"):
            clean = clean[1:-1].strip()

        try:
            ip = ipaddress.IPv6Address(clean)
            return str(ip).lower()
        except Exception:
            return clean.lower()

    @classmethod
    def normalize_domain(cls, value: str) -> str:
        """
        Normalize domain name.
        Lowercases, strips surrounding whitespace, quotes, brackets, and trailing dots.
        Preserves domain structure without converting to an IP.
        """
        clean = value.strip().strip("'\"`()[]<>")
        # Strip trailing dot (FQDN representation: example.com. -> example.com)
        clean = clean.rstrip(".")
        return clean.lower()

    @classmethod
    def normalize_url(cls, value: str) -> str:
        """
        Normalize HTTP/HTTPS URLs.
        - Lowercases scheme and netloc/hostname.
        - Strips default port numbers (:80 for http, :443 for https).
        - Strips trailing sentence punctuation (.,;:)'">).
        - Preserves path, query parameters, and fragments.
        """
        clean = value.strip().strip("'\"`<>")
        # Strip trailing sentence punctuation often attached in log prose
        clean = clean.rstrip(".,;:)'\"`>]}")

        try:
            parsed = urlparse(clean)
            scheme = parsed.scheme.lower()
            netloc = parsed.netloc

            # Normalize netloc: hostname to lowercase, remove default ports
            if "@" in netloc:
                userinfo, hostport = netloc.split("@", 1)
            else:
                userinfo = ""
                hostport = netloc

            # Handle IPv6 host in netloc: e.g. [2001:db8::1]:8080
            if hostport.startswith("[") and "]" in hostport:
                bracket_end = hostport.find("]")
                v6_host = hostport[:bracket_end + 1]
                port_part = hostport[bracket_end + 1:]
                # Canonicalize IPv6 inside bracket
                try:
                    v6_ip = ipaddress.IPv6Address(v6_host[1:-1])
                    v6_host = f"[{str(v6_ip).lower()}]"
                except Exception:
                    pass
                normalized_host = v6_host
            else:
                if ":" in hostport:
                    host, port_str = hostport.rsplit(":", 1)
                    port_part = f":{port_str}"
                else:
                    host = hostport
                    port_part = ""
                normalized_host = host.lower()

            # Strip default ports
            if scheme == "http" and port_part == ":80":
                port_part = ""
            elif scheme == "https" and port_part == ":443":
                port_part = ""

            rebuilt_netloc = f"{userinfo}@{normalized_host}{port_part}" if userinfo else f"{normalized_host}{port_part}"

            # Preserve path, query, and fragment as-is
            normalized = urlunparse((
                scheme,
                rebuilt_netloc,
                parsed.path,
                parsed.params,
                parsed.query,
                parsed.fragment,
            ))
            return normalized
        except Exception:
            return clean

    @classmethod
    def normalize_email(cls, value: str) -> str:
        """
        Normalize email address.
        Strips surrounding quotes/whitespace and lowercases consistently.
        """
        clean = value.strip().strip("'\"`<>")
        clean = clean.rstrip(".,;:)'\"`>]}")
        return clean.lower()

    @classmethod
    def normalize_hash(cls, value: str) -> str:
        """
        Normalize cryptographic hash (MD5, SHA1, SHA256).
        Strips whitespace and converts hex to lowercase without modifying value.
        """
        clean = value.strip().strip("'\"`")
        return clean.lower()

    @classmethod
    def normalize_file_path(cls, value: str) -> str:
        """
        Normalize file paths.
        - Standardizes duplicate slashes.
        - Preserves Windows drive letters (e.g. C:\\path\\to\\file).
        - Preserves Windows UNC paths (e.g. \\\\server\\share\\file).
        - Strips trailing slashes unless root directory.
        """
        clean = value.strip().strip("'\"`")
        clean = clean.rstrip(".,;:)'\"`>]}")

        # Windows UNC path: \\server\share\...
        if clean.startswith(r"\\"):
            unc_body = clean[2:].replace("/", "\\")
            parts = [p for p in unc_body.split("\\") if p]
            return r"\\" + "\\".join(parts)

        # Windows drive path: C:\... or C:/...
        if re.match(r'^[a-zA-Z]:[\\/]', clean):
            drive = clean[:2].upper()
            rest = clean[2:].replace("/", "\\")
            parts = [p for p in rest.split("\\") if p]
            return drive + "\\" + "\\".join(parts)

        # Unix absolute path: /...
        if clean.startswith("/"):
            parts = [p for p in clean.split("/") if p]
            if not parts:
                return "/"
            return "/" + "/".join(parts)

        # Relative paths: ./... or ../...
        if clean.startswith("./") or clean.startswith("../"):
            prefix = "../" if clean.startswith("../") else "./"
            body = clean[len(prefix):]
            parts = [p for p in body.split("/") if p]
            return prefix + "/".join(parts)

        return clean

