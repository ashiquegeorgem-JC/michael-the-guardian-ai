"""
Phase 4.2A.2 — IOC Extraction Engine Tests

Tests IOCExtractor for:
- All nine IOC types (IPv4, IPv6, Domain, URL, MD5, SHA1, SHA256, Email, File Path).
- Multiple indicators in a single log line.
- Multiple events in a batch.
- IPv4 validation and rejection of invalid octets (e.g. 999.0.0.1).
- IPv6 extraction (bracketed and bare) and rejection of timestamps/MAC addresses.
- Hash classification order (SHA256 -> SHA1 -> MD5) with zero overlap.
- URL punctuation stripping (quotes, trailing periods, parens).
- Domain extraction with subdomain support, prose exclusion, and file extension filtering.
- Email extraction and malformed address rejection.
- Unix and Windows file path extraction with prose slash resistance.
- Duplicate indicator detection and occurrence aggregation.
- Evidence reference preservation across multiple log lines.
- Empty, whitespace, malformed, and Unicode log input handling.
- Default status enforcement (IOCStatus.EXTRACTED).
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
)
from app.models.log_entry import LogEntry, LogLevel
from app.services.ioc_extractor import IOCExtractor


class TestIOCExtractor(unittest.TestCase):

    # ── 01: IPv4 Extraction ──────────────────────────────────────────────────

    def test_01_ipv4_extraction(self):
        """Extracts standard IPv4 addresses and verifies normalized format."""
        text = "Failed password for root from 192.168.1.105 port 22 ssh2"
        res = IOCExtractor.extract_from_text(text)
        self.assertEqual(res.total_extracted, 1)
        self.assertEqual(res.unique_iocs, 1)
        ioc = res.iocs[0]
        self.assertEqual(ioc.ioc_type, IOCType.IPV4)
        self.assertEqual(ioc.raw_value, "192.168.1.105")
        self.assertEqual(ioc.normalized_value, "192.168.1.105")
        self.assertEqual(ioc.status, IOCStatus.EXTRACTED)

    def test_01b_ipv4_leading_zeroes_normalization(self):
        """IPv4 with leading zeroes is normalized cleanly."""
        text = "Inbound connection from 10.001.020.005 accepted"
        res = IOCExtractor.extract_from_text(text)
        self.assertEqual(res.unique_iocs, 1)
        ioc = res.iocs[0]
        self.assertEqual(ioc.ioc_type, IOCType.IPV4)
        self.assertEqual(ioc.raw_value, "10.001.020.005")
        self.assertEqual(ioc.normalized_value, "10.1.20.5")

    def test_01c_ipv4_invalid_octets_rejected(self):
        """Invalid IP addresses (e.g. octets > 255) must not be extracted as valid IOCs."""
        text = "Faulty packet header contains 999.123.456.789 which is bogus"
        res = IOCExtractor.extract_from_text(text)
        # Should not produce a valid IPv4 IOC
        ipv4_iocs = [i for i in res.iocs if i.ioc_type == IOCType.IPV4]
        self.assertEqual(len(ipv4_iocs), 0)
        self.assertTrue(len(res.extraction_errors) > 0)
        self.assertIn("999.123.456.789", res.extraction_errors[0])

    # ── 02: IPv6 Extraction ──────────────────────────────────────────────────

    def test_02_ipv6_bracketed(self):
        """Extracts bracketed IPv6 addresses often seen in web/SSH logs."""
        text = "Connection from [2001:db8:85a3::8a2e:370:7334]:8080 established"
        res = IOCExtractor.extract_from_text(text)
        ipv6_iocs = [i for i in res.iocs if i.ioc_type == IOCType.IPV6]
        self.assertEqual(len(ipv6_iocs), 1)
        self.assertEqual(ipv6_iocs[0].raw_value, "2001:db8:85a3::8a2e:370:7334")
        self.assertEqual(ipv6_iocs[0].normalized_value, "2001:db8:85a3::8a2e:370:7334")

    def test_02b_ipv6_bare_compressed(self):
        """Extracts bare compressed IPv6 like ::1."""
        text = "Local proxy connected to ::1 on port 5432"
        res = IOCExtractor.extract_from_text(text)
        ipv6_iocs = [i for i in res.iocs if i.ioc_type == IOCType.IPV6]
        self.assertEqual(len(ipv6_iocs), 1)
        self.assertEqual(ipv6_iocs[0].normalized_value, "::1")

    def test_02c_timestamps_and_macs_not_ipv6(self):
        """Timestamps (12:30:45) and MAC addresses (00:11:22:33:44:55) are not extracted as IPv6."""
        text = "Nov 04 12:30:45 kernel: [  123.45] eth0: MAC 00:11:22:33:44:55 link up"
        res = IOCExtractor.extract_from_text(text)
        ipv6_iocs = [i for i in res.iocs if i.ioc_type == IOCType.IPV6]
        self.assertEqual(len(ipv6_iocs), 0)

    # ── 03: Domain and Subdomain Extraction ──────────────────────────────────

    def test_03_domain_with_subdomain(self):
        """Extracts multi-level domain names."""
        text = "DNS query to c2.beacon.malicious-threat.org recorded"
        res = IOCExtractor.extract_from_text(text)
        domains = [i for i in res.iocs if i.ioc_type == IOCType.DOMAIN]
        self.assertEqual(len(domains), 1)
        self.assertEqual(domains[0].raw_value, "c2.beacon.malicious-threat.org")
        self.assertEqual(domains[0].normalized_value, "c2.beacon.malicious-threat.org")

    def test_03b_domain_punctuation_handling(self):
        """Handles trailing periods, quotes, and commas on domains."""
        text = 'Contacted server at "bad-actor.xyz", then reported back.'
        res = IOCExtractor.extract_from_text(text)
        domains = [i for i in res.iocs if i.ioc_type == IOCType.DOMAIN]
        self.assertEqual(len(domains), 1)
        self.assertEqual(domains[0].raw_value, "bad-actor.xyz")

    def test_03c_file_extensions_not_extracted_as_domains(self):
        """Filenames like audit.csv, script.py, or sshd.service are not treated as domains."""
        text = "Loaded sshd.service and processed audit.csv using runner.py"
        res = IOCExtractor.extract_from_text(text)
        domains = [i for i in res.iocs if i.ioc_type == IOCType.DOMAIN]
        self.assertEqual(len(domains), 0)

    # ── 04: Full URLs ────────────────────────────────────────────────────────

    def test_04_url_extraction(self):
        """Extracts complete HTTP/HTTPS URLs with paths and query strings."""
        text = "Download initiated: https://evil-c2.net:8443/payloads/stage1.bin?auth=xyz&id=12"
        res = IOCExtractor.extract_from_text(text)
        urls = [i for i in res.iocs if i.ioc_type == IOCType.URL]
        self.assertEqual(len(urls), 1)
        self.assertEqual(urls[0].raw_value, "https://evil-c2.net:8443/payloads/stage1.bin?auth=xyz&id=12")

    def test_04b_url_trailing_punctuation(self):
        """Trailing punctuation around URLs (e.g. closing parens, commas) is stripped."""
        text = "Check this URL (https://evil.com/drop/loader.exe)."
        res = IOCExtractor.extract_from_text(text)
        urls = [i for i in res.iocs if i.ioc_type == IOCType.URL]
        self.assertEqual(len(urls), 1)
        self.assertEqual(urls[0].raw_value, "https://evil.com/drop/loader.exe")

    def test_04c_url_components_not_duplicated(self):
        """
        The domain and path inside an extracted URL should not be re-extracted
        as duplicate standalone domain or file path indicators.
        """
        text = "Fetched https://phishing.example.com/login/auth.php successfully"
        res = IOCExtractor.extract_from_text(text)
        types = [i.ioc_type for i in res.iocs]
        self.assertEqual(types, [IOCType.URL])

    # ── 05: Hashes (MD5, SHA1, SHA256) ───────────────────────────────────────

    def test_05_sha256_hash(self):
        """64-hex string is correctly classified as SHA256."""
        text = "File hash sha256: 2c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e886266e7ae"
        res = IOCExtractor.extract_from_text(text)
        self.assertEqual(res.unique_iocs, 1)
        ioc = res.iocs[0]
        self.assertEqual(ioc.ioc_type, IOCType.SHA256)
        self.assertEqual(ioc.raw_value, "2c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e886266e7ae")

    def test_05b_sha1_hash(self):
        """40-hex string is correctly classified as SHA1."""
        text = "SHA1 checksum: 2fd4e1c67a2d28fced849ee1bb76e7391b93eb12 verified"
        res = IOCExtractor.extract_from_text(text)
        self.assertEqual(res.unique_iocs, 1)
        ioc = res.iocs[0]
        self.assertEqual(ioc.ioc_type, IOCType.SHA1)
        self.assertEqual(ioc.raw_value, "2fd4e1c67a2d28fced849ee1bb76e7391b93eb12")

    def test_05c_md5_hash(self):
        """32-hex string is correctly classified as MD5."""
        text = "MD5: 5d41402abc4b2a76b9719d911017c592 match"
        res = IOCExtractor.extract_from_text(text)
        self.assertEqual(res.unique_iocs, 1)
        ioc = res.iocs[0]
        self.assertEqual(ioc.ioc_type, IOCType.MD5)
        self.assertEqual(ioc.raw_value, "5d41402abc4b2a76b9719d911017c592")

    def test_05d_no_overlapping_hash_classification(self):
        """A 64-hex SHA256 must NOT produce duplicate SHA1 or MD5 indicators."""
        text = "Binary sha256=e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        res = IOCExtractor.extract_from_text(text)
        self.assertEqual(res.unique_iocs, 1)
        self.assertEqual(res.iocs[0].ioc_type, IOCType.SHA256)

    def test_05e_preserve_case_in_raw_value(self):
        """Uppercase hash preserves original case in raw_value and lowercases in normalized."""
        text = "MD5: 5D41402ABC4B2A76B9719D911017C592"
        res = IOCExtractor.extract_from_text(text)
        ioc = res.iocs[0]
        self.assertEqual(ioc.raw_value, "5D41402ABC4B2A76B9719D911017C592")
        self.assertEqual(ioc.normalized_value, "5d41402abc4b2a76b9719d911017c592")

    # ── 06: Email Addresses ──────────────────────────────────────────────────

    def test_06_email_extraction(self):
        """Extracts conventional email addresses."""
        text = "Phishing campaign from attacker@evil-corp.com sent to victim"
        res = IOCExtractor.extract_from_text(text)
        emails = [i for i in res.iocs if i.ioc_type == IOCType.EMAIL]
        self.assertEqual(len(emails), 1)
        self.assertEqual(emails[0].raw_value, "attacker@evil-corp.com")
        self.assertEqual(emails[0].normalized_value, "attacker@evil-corp.com")

    def test_06b_email_does_not_duplicate_domain(self):
        """The domain part of an email is not extracted as a duplicate standalone domain."""
        text = "Sender is phish@malware-domain.xyz"
        res = IOCExtractor.extract_from_text(text)
        types = [i.ioc_type for i in res.iocs]
        self.assertEqual(types, [IOCType.EMAIL])

    # ── 07: File Paths ───────────────────────────────────────────────────────

    def test_07_unix_path_known_root(self):
        """Extracts Unix system paths like /etc/shadow or /tmp/malware.sh."""
        text = "Unauthorized access attempt to /etc/shadow by user 1000"
        res = IOCExtractor.extract_from_text(text)
        paths = [i for i in res.iocs if i.ioc_type == IOCType.FILE_PATH]
        self.assertEqual(len(paths), 1)
        self.assertEqual(paths[0].raw_value, "/etc/shadow")

    def test_07b_windows_drive_path(self):
        """Extracts Windows absolute paths."""
        text = r"Execution of C:\Windows\System32\cmd.exe detected"
        res = IOCExtractor.extract_from_text(text)
        paths = [i for i in res.iocs if i.ioc_type == IOCType.FILE_PATH]
        self.assertEqual(len(paths), 1)
        self.assertEqual(paths[0].raw_value, r"C:\Windows\System32\cmd.exe")

    def test_07c_windows_unc_path(self):
        """Extracts Windows UNC network paths."""
        text = r"Mounting network share \\fileserver\shared\deploy.bat"
        res = IOCExtractor.extract_from_text(text)
        paths = [i for i in res.iocs if i.ioc_type == IOCType.FILE_PATH]
        self.assertEqual(len(paths), 1)
        self.assertEqual(paths[0].raw_value, r"\\fileserver\shared\deploy.bat")

    def test_07d_prose_slashes_not_extracted_as_paths(self):
        """Ordinary prose slashes like and/or, true/false, read/write are ignored."""
        text = "The system is in read/write mode and/or standby true/false"
        res = IOCExtractor.extract_from_text(text)
        paths = [i for i in res.iocs if i.ioc_type == IOCType.FILE_PATH]
        self.assertEqual(len(paths), 0)

    # ── 08: Multi-Indicator Single Line ──────────────────────────────────────

    def test_08_multi_indicator_single_line(self):
        """Extracts IP, domain, URL, and hash from a single complex security log line."""
        text = (
            "Host 10.0.0.1 queried c2.badactor.net and downloaded "
            "https://c2.badactor.net/payload.exe (MD5: 5d41402abc4b2a76b9719d911017c592)"
        )
        res = IOCExtractor.extract_from_text(text)
        self.assertEqual(res.unique_iocs, 4)
        found_types = {i.ioc_type for i in res.iocs}
        self.assertIn(IOCType.IPV4, found_types)
        self.assertIn(IOCType.DOMAIN, found_types)
        self.assertIn(IOCType.URL, found_types)
        self.assertIn(IOCType.MD5, found_types)

    # ── 09: Duplicate Handling & Evidence Traceability ───────────────────────

    def test_09_duplicate_occurrences_aggregated(self):
        """
        When the same IOC appears multiple times in a text or across events,
        it merges into a single IOC record with occurrence_count incremented
        and each occurrence recorded in evidence_references.
        """
        text = "Connection from 192.168.1.50 accepted; then 192.168.1.50 disconnected"
        res = IOCExtractor.extract_from_text(text, session_id="test-sess", event_id="ev-1", line_number=42)
        self.assertEqual(res.total_extracted, 2)
        self.assertEqual(res.unique_iocs, 1)
        self.assertEqual(res.duplicate_count, 1)

        ioc = res.iocs[0]
        self.assertEqual(ioc.occurrence_count, 2)
        self.assertEqual(len(ioc.evidence_references), 2)
        # Check evidence references
        self.assertEqual(ioc.evidence_references[0].event_id, "ev-1")
        self.assertEqual(ioc.evidence_references[0].line_number, 42)
        self.assertEqual(ioc.evidence_references[1].event_id, "ev-1")
        self.assertIn("192.168.1.50", ioc.evidence_references[0].surrounding_context)

    # ── 10: Batch Extraction from LogEntry Events ────────────────────────────

    def test_10_extract_from_events(self):
        """Extracts across multiple LogEntry objects with session and timestamp preservation."""
        t1 = datetime(2024, 1, 1, 12, 0, 0)
        t2 = datetime(2024, 1, 1, 12, 5, 0)

        events = [
            LogEntry(
                session_id="sess-A",
                raw_line="Attack from 10.10.10.1",
                message="Attack from 10.10.10.1",
                line_number=1,
                timestamp=t1,
            ),
            LogEntry(
                session_id="sess-B",
                raw_line="Second attempt from 10.10.10.1 and file /etc/passwd",
                message="Second attempt from 10.10.10.1 and file /etc/passwd",
                line_number=2,
                timestamp=t2,
            ),
        ]

        res = IOCExtractor.extract_from_events(events)
        self.assertEqual(res.total_extracted, 3)  # 2 IPs + 1 path
        self.assertEqual(res.unique_iocs, 2)
        self.assertEqual(res.duplicate_count, 1)

        ip_ioc = next(i for i in res.iocs if i.ioc_type == IOCType.IPV4)
        self.assertEqual(ip_ioc.occurrence_count, 2)
        self.assertEqual(len(ip_ioc.evidence_references), 2)
        self.assertIn("sess-A", ip_ioc.source_sessions)
        self.assertIn("sess-B", ip_ioc.source_sessions)
        self.assertEqual(ip_ioc.first_seen, t1)
        self.assertEqual(ip_ioc.last_seen, t2)

    # ── 11: Edge Cases (Empty, Whitespace, Malformed, Unicode) ────────────────

    def test_11_empty_and_whitespace_input(self):
        """Empty or whitespace inputs return zero IOCs without raising errors."""
        res1 = IOCExtractor.extract_from_text("")
        self.assertEqual(res1.total_extracted, 0)
        self.assertEqual(res1.unique_iocs, 0)

        res2 = IOCExtractor.extract_from_text("   \t\n  ")
        self.assertEqual(res2.total_extracted, 0)

        res3 = IOCExtractor.extract_from_events([])
        self.assertEqual(res3.total_extracted, 0)

    def test_11b_unicode_input(self):
        """Unicode log content extracts indicators cleanly."""
        text = "⚡ [CRITICAL] 攻撃開始: payload from 192.168.1.50 into /tmp/drop.sh"
        res = IOCExtractor.extract_from_text(text)
        self.assertEqual(res.unique_iocs, 2)
        types = {i.ioc_type for i in res.iocs}
        self.assertIn(IOCType.IPV4, types)
        self.assertIn(IOCType.FILE_PATH, types)

    def test_11c_plain_prose_no_false_positives(self):
        """Ordinary text without indicators yields 0 extracted IOCs."""
        text = "System rebooted successfully at noon. All services started normally."
        res = IOCExtractor.extract_from_text(text)
        self.assertEqual(res.total_extracted, 0)
        self.assertEqual(len(res.iocs), 0)


if __name__ == "__main__":
    unittest.main(verbosity=2)
