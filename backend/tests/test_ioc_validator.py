"""
Phase 4.2A.3 — IOC Normalization & Validation Tests

Tests IOCNormalizer and IOCValidator for:
- IPv4: public, private, invalid octets, malformed addresses, leading zeroes.
- IPv6: compressed, full notation, uppercase, invalid addresses, bracketed addresses, timestamps/MAC rejection.
- Domains: normal, uppercase, subdomains, trailing dot, invalid label, malformed domains, punycode.
- URLs: HTTP, HTTPS, default port stripping, custom ports, query strings, IPv4 hosts, IPv6 hosts, malformed URLs.
- Hashes: valid MD5, SHA1, SHA256, wrong lengths, non-hex characters, trivial null masks.
- Email: valid, uppercase, malformed, missing domain, consecutive dots.
- File paths: Unix paths, Windows drive paths, UNC paths, relative traversal, prose rejection.
- IP Scope Classification: public, private, loopback, link-local, multicast, reserved.
- Pipeline & Round-Trip: raw value -> normalized value -> validation -> canonical IOC without losing evidence.
- Batch processing: single IOC, list of IOCs, IOCExtractionResult.

Total tests: 35+ focused tests.
"""

from datetime import datetime
import os
import sys
import unittest

# Path setup
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from app.models.ioc import (
    IOC,
    IOCEvidence,
    IOCExtractionResult,
    IOCStatus,
    IOCType,
    IOCValidationResult,
    IPScope,
    ValidationStatus,
)
from app.services.ioc_normalizer import IOCNormalizer
from app.services.ioc_validator import IOCValidator


class TestIOCNormalizationAndValidation(unittest.TestCase):

    # ─────────────────────────────────────────────────────────────────────────
    # 1. IPv4 Normalization & Validation
    # ─────────────────────────────────────────────────────────────────────────

    def test_01_ipv4_valid_public(self):
        """Valid public IPv4 produces canonical dotted-quad and IPScope.PUBLIC."""
        raw = " 8.8.8.8 "
        norm = IOCNormalizer.normalize(raw, IOCType.IPV4)
        self.assertEqual(norm, "8.8.8.8")

        res = IOCValidator.validate(raw, IOCType.IPV4)
        self.assertTrue(res.is_valid)
        self.assertEqual(res.validation_status, ValidationStatus.VALID)
        self.assertEqual(res.normalized_value, "8.8.8.8")
        self.assertEqual(res.ip_scope, IPScope.PUBLIC)

    def test_02_ipv4_valid_private(self):
        """Private RFC 1918 address produces IPScope.PRIVATE."""
        raw = "192.168.1.100"
        norm = IOCNormalizer.normalize(raw, IOCType.IPV4)
        self.assertEqual(norm, "192.168.1.100")

        res = IOCValidator.validate(raw, IOCType.IPV4)
        self.assertTrue(res.is_valid)
        self.assertEqual(res.validation_status, ValidationStatus.VALID)
        self.assertEqual(res.ip_scope, IPScope.PRIVATE)

    def test_03_ipv4_leading_zeroes_normalization(self):
        """Leading zeroes in octets are stripped cleanly (10.001.020.005 -> 10.1.20.5)."""
        raw = "10.001.020.005"
        norm = IOCNormalizer.normalize(raw, IOCType.IPV4)
        self.assertEqual(norm, "10.1.20.5")

        res = IOCValidator.validate(raw, IOCType.IPV4)
        self.assertTrue(res.is_valid)
        self.assertEqual(res.normalized_value, "10.1.20.5")
        self.assertEqual(res.ip_scope, IPScope.PRIVATE)

    def test_04_ipv4_invalid_octets(self):
        """Octet > 255 (e.g. 999.1.2.3) is flagged INVALID."""
        raw = "999.1.2.3"
        res = IOCValidator.validate(raw, IOCType.IPV4)
        self.assertFalse(res.is_valid)
        self.assertEqual(res.validation_status, ValidationStatus.INVALID)
        self.assertIn("exceeds valid range", res.validation_reason)

    def test_05_ipv4_malformed_structure(self):
        """Address with too few or too many octets is flagged INVALID."""
        for malformed in ("192.168.1", "192.168.1.1.1", "192.168.1.abc"):
            with self.subTest(val=malformed):
                res = IOCValidator.validate(malformed, IOCType.IPV4)
                self.assertFalse(res.is_valid)
                self.assertEqual(res.validation_status, ValidationStatus.INVALID)

    # ─────────────────────────────────────────────────────────────────────────
    # 2. IPv6 Normalization & Validation
    # ─────────────────────────────────────────────────────────────────────────

    def test_06_ipv6_compressed_and_full(self):
        """Full notation normalizes to compressed lowercase RFC 5952 representation."""
        full_raw = "2001:0DB8:0000:0000:0000:0000:0000:0001"
        norm = IOCNormalizer.normalize(full_raw, IOCType.IPV6)
        self.assertEqual(norm, "2001:db8::1")

        res = IOCValidator.validate(full_raw, IOCType.IPV6)
        self.assertTrue(res.is_valid)
        self.assertEqual(res.validation_status, ValidationStatus.VALID)
        self.assertEqual(res.normalized_value, "2001:db8::1")

    def test_07_ipv6_bracketed(self):
        """Bracketed IPv6 [2001:db8::1] normalizes and validates cleanly."""
        bracketed = "[2001:db8::1]"
        norm = IOCNormalizer.normalize(bracketed, IOCType.IPV6)
        self.assertEqual(norm, "2001:db8::1")

        res = IOCValidator.validate(bracketed, IOCType.IPV6)
        self.assertTrue(res.is_valid)
        self.assertEqual(res.normalized_value, "2001:db8::1")

    def test_08_ipv6_mac_and_timestamp_rejection(self):
        """MAC addresses and clock timestamps are rejected as INVALID IPv6."""
        for bad_v6 in ("00:11:22:33:44:55", "12:30:45", "12:30"):
            with self.subTest(val=bad_v6):
                res = IOCValidator.validate(bad_v6, IOCType.IPV6)
                self.assertFalse(res.is_valid)
                self.assertEqual(res.validation_status, ValidationStatus.INVALID)

    def test_09_ipv6_scope_classification(self):
        """IPv6 scopes (loopback ::1, link-local fe80::1, private fc00::1) are classified accurately."""
        scopes = [
            ("::1", IPScope.LOOPBACK),
            ("fe80::1", IPScope.LINK_LOCAL),
            ("fc00::1", IPScope.PRIVATE),
            ("2607:f8b0:4005:805::200e", IPScope.PUBLIC),
        ]
        for ip_str, expected_scope in scopes:
            with self.subTest(ip=ip_str):
                res = IOCValidator.validate(ip_str, IOCType.IPV6)
                self.assertTrue(res.is_valid)
                self.assertEqual(res.ip_scope, expected_scope)

    # ─────────────────────────────────────────────────────────────────────────
    # 3. Domain Normalization & Validation
    # ─────────────────────────────────────────────────────────────────────────

    def test_10_domain_normal_and_subdomain(self):
        """Subdomains and standard domains are validated cleanly."""
        raw = "c2.beacon.malicious-threat.org"
        norm = IOCNormalizer.normalize(raw, IOCType.DOMAIN)
        self.assertEqual(norm, "c2.beacon.malicious-threat.org")

        res = IOCValidator.validate(raw, IOCType.DOMAIN)
        self.assertTrue(res.is_valid)
        self.assertEqual(res.validation_status, ValidationStatus.VALID)

    def test_11_domain_uppercase_and_trailing_dot(self):
        """Uppercase domain with trailing dot (WWW.Example.COM.) normalizes to lowercase without dot."""
        raw = "WWW.Example.COM."
        norm = IOCNormalizer.normalize(raw, IOCType.DOMAIN)
        self.assertEqual(norm, "www.example.com")

        res = IOCValidator.validate(raw, IOCType.DOMAIN)
        self.assertTrue(res.is_valid)
        self.assertEqual(res.normalized_value, "www.example.com")

    def test_12_domain_invalid_labels(self):
        """Labels starting/ending with hyphen or containing illegal chars are INVALID."""
        invalids = ["-bad-domain.com", "bad-domain-.com", "bad..com", "domain_with!chars.com"]
        for bad_dom in invalids:
            with self.subTest(dom=bad_dom):
                res = IOCValidator.validate(bad_dom, IOCType.DOMAIN)
                self.assertFalse(res.is_valid)
                self.assertEqual(res.validation_status, ValidationStatus.INVALID)

    def test_13_domain_label_and_total_length_boundaries(self):
        """Labels > 63 chars or total domain > 253 chars are INVALID."""
        long_label = "a" * 64 + ".com"
        res = IOCValidator.validate(long_label, IOCType.DOMAIN)
        self.assertFalse(res.is_valid)
        self.assertEqual(res.validation_status, ValidationStatus.INVALID)

        long_domain = ("subdomain." * 30) + "com"  # > 253 chars (303 chars)
        res_total = IOCValidator.validate(long_domain, IOCType.DOMAIN)
        self.assertFalse(res_total.is_valid)
        self.assertEqual(res_total.validation_status, ValidationStatus.INVALID)

    def test_14_domain_punycode_suspicious(self):
        """Punycode IDN domains (xn--...) are syntactically valid but flagged SUSPICIOUS."""
        puny = "xn--bcher-kva.example"
        res = IOCValidator.validate(puny, IOCType.DOMAIN)
        self.assertTrue(res.is_valid)
        self.assertEqual(res.validation_status, ValidationStatus.SUSPICIOUS)
        self.assertIn("Punycode", res.validation_reason)

    # ─────────────────────────────────────────────────────────────────────────
    # 4. URL Normalization & Validation
    # ─────────────────────────────────────────────────────────────────────────

    def test_15_url_http_and_https_canonicalization(self):
        """URLs lowercase scheme/host and strip default ports (:80 for http, :443 for https)."""
        url1 = "HTTP://Example.COM:80/path/to/page?query=1#frag"
        norm1 = IOCNormalizer.normalize(url1, IOCType.URL)
        self.assertEqual(norm1, "http://example.com/path/to/page?query=1#frag")

        res1 = IOCValidator.validate(url1, IOCType.URL)
        self.assertTrue(res1.is_valid)
        self.assertEqual(res1.normalized_value, norm1)

        url2 = "HTTPS://Evil.COM:443/drop/payload.exe"
        norm2 = IOCNormalizer.normalize(url2, IOCType.URL)
        self.assertEqual(norm2, "https://evil.com/drop/payload.exe")

    def test_16_url_custom_port_and_query_preserved(self):
        """Non-default ports and complex query parameters are preserved."""
        url = "https://c2.badactor.net:8443/api/v2/beacon?id=xyz&token=123"
        norm = IOCNormalizer.normalize(url, IOCType.URL)
        self.assertEqual(norm, url)

        res = IOCValidator.validate(url, IOCType.URL)
        self.assertTrue(res.is_valid)
        self.assertEqual(res.validation_status, ValidationStatus.VALID)

    def test_17_url_ipv4_and_ipv6_hosts(self):
        """URLs with literal IPv4 or IPv6 hosts validate cleanly."""
        url_v4 = "http://192.168.1.1:8080/admin"
        res_v4 = IOCValidator.validate(url_v4, IOCType.URL)
        self.assertTrue(res_v4.is_valid)

        url_v6 = "http://[2001:db8::1]:8080/status"
        res_v6 = IOCValidator.validate(url_v6, IOCType.URL)
        self.assertTrue(res_v6.is_valid)

    def test_18_url_credentials_flagged_suspicious(self):
        """URLs with embedded user credentials (user:pass@host) are flagged SUSPICIOUS."""
        url = "http://admin:secret123@internal.corp/admin"
        res = IOCValidator.validate(url, IOCType.URL)
        self.assertTrue(res.is_valid)
        self.assertEqual(res.validation_status, ValidationStatus.SUSPICIOUS)
        self.assertIn("credentials", res.validation_reason)

    def test_19_url_malformed_and_unsupported_schemes(self):
        """Unsupported schemes (ftp://, file://) and missing hosts are INVALID."""
        invalids = ["ftp://example.com/file", "http:///path/without/host", "https://example.com:99999/"]
        for bad_url in invalids:
            with self.subTest(url=bad_url):
                res = IOCValidator.validate(bad_url, IOCType.URL)
                self.assertFalse(res.is_valid)
                self.assertEqual(res.validation_status, ValidationStatus.INVALID)

    # ─────────────────────────────────────────────────────────────────────────
    # 5. Hashes (MD5, SHA1, SHA256) Normalization & Validation
    # ─────────────────────────────────────────────────────────────────────────

    def test_20_hashes_valid(self):
        """MD5 (32 hex), SHA1 (40 hex), SHA256 (64 hex) normalize to lowercase and validate as VALID."""
        md5_raw = "5D41402ABC4B2A76B9719D911017C592"
        self.assertEqual(IOCNormalizer.normalize(md5_raw, IOCType.MD5), "5d41402abc4b2a76b9719d911017c592")
        res_md5 = IOCValidator.validate(md5_raw, IOCType.MD5)
        self.assertTrue(res_md5.is_valid)
        self.assertEqual(res_md5.validation_status, ValidationStatus.VALID)

        sha1_raw = "2FD4E1C67A2D28FCED849EE1BB76E7391B93EB12"
        res_sha1 = IOCValidator.validate(sha1_raw, IOCType.SHA1)
        self.assertTrue(res_sha1.is_valid)

        sha256_raw = "2C26B46B68FFC68FF99B453C1D30413413422D706483BFA0F98A5E886266E7AE"
        res_sha256 = IOCValidator.validate(sha256_raw, IOCType.SHA256)
        self.assertTrue(res_sha256.is_valid)

    def test_21_hashes_wrong_length_rejected(self):
        """Hashes of incorrect lengths are flagged INVALID."""
        res = IOCValidator.validate("5d41402abc4b2a76", IOCType.MD5)  # 16 chars instead of 32
        self.assertFalse(res.is_valid)
        self.assertEqual(res.validation_status, ValidationStatus.INVALID)
        self.assertIn("Hash length", res.validation_reason)

    def test_22_hashes_non_hex_rejected(self):
        """Hashes containing non-hexadecimal characters (g-z) are flagged INVALID."""
        bad_hash = "5d41402abc4b2a76b9719d911017c59g"  # ends with 'g'
        res = IOCValidator.validate(bad_hash, IOCType.MD5)
        self.assertFalse(res.is_valid)
        self.assertEqual(res.validation_status, ValidationStatus.INVALID)
        self.assertIn("non-hexadecimal", res.validation_reason)

    def test_23_hashes_trivial_null_mask_suspicious(self):
        """All-zero null masks (e.g. 32 zeroes) are flagged SUSPICIOUS."""
        null_md5 = "0" * 32
        res = IOCValidator.validate(null_md5, IOCType.MD5)
        self.assertTrue(res.is_valid)
        self.assertEqual(res.validation_status, ValidationStatus.SUSPICIOUS)
        self.assertIn("null / placeholder", res.validation_reason)

    # ─────────────────────────────────────────────────────────────────────────
    # 6. Email Normalization & Validation
    # ─────────────────────────────────────────────────────────────────────────

    def test_24_email_valid_and_casing(self):
        """Valid email addresses normalize to lowercase and validate cleanly."""
        raw = " Attacker@Evil-Corp.COM "
        norm = IOCNormalizer.normalize(raw, IOCType.EMAIL)
        self.assertEqual(norm, "attacker@evil-corp.com")

        res = IOCValidator.validate(raw, IOCType.EMAIL)
        self.assertTrue(res.is_valid)
        self.assertEqual(res.validation_status, ValidationStatus.VALID)
        self.assertEqual(res.normalized_value, "attacker@evil-corp.com")

    def test_25_email_malformed_rejected(self):
        """Malformed emails (missing @, missing domain, consecutive dots in local part) are INVALID."""
        invalids = ["user@@domain.com", "plainaddress", "user@.com", "user..name@domain.com", ".user@domain.com"]
        for bad_email in invalids:
            with self.subTest(email=bad_email):
                res = IOCValidator.validate(bad_email, IOCType.EMAIL)
                self.assertFalse(res.is_valid)
                self.assertEqual(res.validation_status, ValidationStatus.INVALID)

    # ─────────────────────────────────────────────────────────────────────────
    # 7. File Paths Normalization & Validation
    # ─────────────────────────────────────────────────────────────────────────

    def test_26_file_path_unix_and_windows(self):
        """Standard Unix and Windows drive paths normalize and validate cleanly."""
        unix_raw = "/etc//shadow"
        norm_unix = IOCNormalizer.normalize(unix_raw, IOCType.FILE_PATH)
        self.assertEqual(norm_unix, "/etc/shadow")
        res_unix = IOCValidator.validate(unix_raw, IOCType.FILE_PATH)
        self.assertTrue(res_unix.is_valid)
        self.assertEqual(res_unix.validation_status, ValidationStatus.VALID)

        win_raw = r"C:\Windows\System32\cmd.exe"
        norm_win = IOCNormalizer.normalize(win_raw, IOCType.FILE_PATH)
        self.assertEqual(norm_win, r"C:\Windows\System32\cmd.exe")
        res_win = IOCValidator.validate(win_raw, IOCType.FILE_PATH)
        self.assertTrue(res_win.is_valid)

    def test_27_file_path_unc(self):
        """Windows UNC paths normalize duplicate slashes and validate cleanly."""
        unc_raw = r"\\fileserver\shared\deploy.bat"
        norm_unc = IOCNormalizer.normalize(unc_raw, IOCType.FILE_PATH)
        self.assertEqual(norm_unc, unc_raw)

        res_unc = IOCValidator.validate(unc_raw, IOCType.FILE_PATH)
        self.assertTrue(res_unc.is_valid)
        self.assertEqual(res_unc.validation_status, ValidationStatus.VALID)

    def test_28_file_path_directory_traversal_suspicious(self):
        """File paths containing directory traversal sequences (../ or ..\\) are flagged SUSPICIOUS."""
        traversal = "/var/log/../../etc/shadow"
        res = IOCValidator.validate(traversal, IOCType.FILE_PATH)
        self.assertTrue(res.is_valid)
        self.assertEqual(res.validation_status, ValidationStatus.SUSPICIOUS)
        self.assertIn("traversal", res.validation_reason)

    def test_29_file_path_prose_rejected(self):
        """Ordinary prose slashes like and/or, true/false, read/write are flagged INVALID."""
        prose_samples = ["and/or", "true/false", "read/write", "this is a random sentence"]
        for prose in prose_samples:
            with self.subTest(p=prose):
                res = IOCValidator.validate(prose, IOCType.FILE_PATH)
                self.assertFalse(res.is_valid)
                self.assertEqual(res.validation_status, ValidationStatus.INVALID)

    # ─────────────────────────────────────────────────────────────────────────
    # 8. IP Scope Classification Granularity
    # ─────────────────────────────────────────────────────────────────────────

    def test_30_ip_scope_classification_granularity(self):
        """Verifies all IP scopes: public, private, loopback, link-local, multicast, reserved, unspecified."""
        cases = [
            ("1.1.1.1", IPScope.PUBLIC),
            ("10.0.0.1", IPScope.PRIVATE),
            ("172.16.5.1", IPScope.PRIVATE),
            ("192.168.0.1", IPScope.PRIVATE),
            ("127.0.0.1", IPScope.LOOPBACK),
            ("169.254.1.1", IPScope.LINK_LOCAL),
            ("224.0.0.1", IPScope.MULTICAST),
            ("0.0.0.0", IPScope.UNSPECIFIED),
            ("240.0.0.1", IPScope.RESERVED),
        ]
        for ip_str, expected in cases:
            with self.subTest(ip=ip_str):
                res = IOCValidator.validate(ip_str, IOCType.IPV4)
                self.assertEqual(res.ip_scope, expected)

    # ─────────────────────────────────────────────────────────────────────────
    # 9. Pipeline & Round-Trip Traceability
    # ─────────────────────────────────────────────────────────────────────────

    def test_31_round_trip_preserves_evidence(self):
        """
        Flow: Raw extracted IOC -> IOCNormalizer -> IOCValidator -> Canonical IOC.
        Original raw_value and evidence_references must remain 100% intact.
        """
        raw_val = "10.001.020.005"
        ev = IOCEvidence(
            event_id="ev-123",
            session_id="sess-abc",
            raw_value=raw_val,
            line_number=42,
            surrounding_context="failed auth from 10.001.020.005",
        )
        ioc = IOC(
            ioc_type=IOCType.IPV4,
            raw_value=raw_val,
            normalized_value=raw_val,
            evidence_references=[ev],
        )

        updated_ioc, val_res = IOCValidator.validate_ioc(ioc)

        # Verification: normalized_value is updated
        self.assertEqual(updated_ioc.normalized_value, "10.1.20.5")
        # Raw value remains untouched
        self.assertEqual(updated_ioc.raw_value, "10.001.020.005")
        # Evidence references preserved
        self.assertEqual(len(updated_ioc.evidence_references), 1)
        self.assertEqual(updated_ioc.evidence_references[0].raw_value, "10.001.020.005")
        self.assertEqual(updated_ioc.evidence_references[0].line_number, 42)
        # Validation result matches
        self.assertTrue(val_res.is_valid)
        self.assertEqual(val_res.ip_scope, IPScope.PRIVATE)

    # ─────────────────────────────────────────────────────────────────────────
    # 10. Batch Validation
    # ─────────────────────────────────────────────────────────────────────────

    def test_32_validate_iocs_batch(self):
        """Batch validation of a list of IOC objects returns corresponding results."""
        ioc1 = IOC(ioc_type=IOCType.IPV4, raw_value="8.8.8.8", normalized_value="8.8.8.8")
        ioc2 = IOC(ioc_type=IOCType.DOMAIN, raw_value="WWW.Example.COM.", normalized_value="WWW.Example.COM.")
        ioc3 = IOC(ioc_type=IOCType.MD5, raw_value="5D41402ABC4B2A76B9719D911017C592", normalized_value="5d41402abc4b2a76b9719d911017c592")

        batch = [ioc1, ioc2, ioc3]
        results = IOCValidator.validate_iocs(batch)

        self.assertEqual(len(results), 3)
        self.assertEqual(results[0][0].normalized_value, "8.8.8.8")
        self.assertEqual(results[1][0].normalized_value, "www.example.com")
        self.assertEqual(results[2][0].normalized_value, "5d41402abc4b2a76b9719d911017c592")

    def test_33_validate_extraction_result_non_mutating(self):
        """Validating an IOCExtractionResult returns a new result without mutating the original."""
        ioc = IOC(ioc_type=IOCType.DOMAIN, raw_value="Bad.Actor.NET.", normalized_value="Bad.Actor.NET.")
        orig_result = IOCExtractionResult(
            total_extracted=1,
            unique_iocs=1,
            iocs=[ioc],
        )

        new_result, val_list = IOCValidator.validate_extraction_result(orig_result)

        # Original is not mutated
        self.assertEqual(orig_result.iocs[0].normalized_value, "Bad.Actor.NET.")
        # New result has canonical value
        self.assertEqual(new_result.iocs[0].normalized_value, "bad.actor.net")
        self.assertEqual(len(val_list), 1)
        self.assertTrue(val_list[0].is_valid)

    # ─────────────────────────────────────────────────────────────────────────
    # 11. Edge Cases & Safety
    # ─────────────────────────────────────────────────────────────────────────

    def test_34_empty_and_whitespace_validation(self):
        """Empty or whitespace values return INVALID validation results gracefully."""
        res = IOCValidator.validate("   ", IOCType.IPV4)
        self.assertFalse(res.is_valid)
        self.assertEqual(res.validation_status, ValidationStatus.INVALID)

    def test_35_domain_not_converted_to_ip(self):
        """Validating a domain does not convert it into an IP address."""
        res = IOCValidator.validate("example.com", IOCType.DOMAIN)
        self.assertEqual(res.normalized_value, "example.com")
        self.assertIsNone(res.ip_scope)


if __name__ == "__main__":
    unittest.main(verbosity=2)
