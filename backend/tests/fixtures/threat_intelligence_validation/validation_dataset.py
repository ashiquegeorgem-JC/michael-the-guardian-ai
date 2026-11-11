"""
Synthetic Ground-Truth Validation Dataset for Threat Intelligence.

Phase 4.2B.6 — Final Threat Intelligence Validation, Benchmarking & Security Audit.

NOTE: All metrics derived from this dataset are designated as
"Synthetic / Controlled Validation". This dataset provides strict,
deterministic ground truth across all 9 IOC types, negative controls,
reputation scoring, provider error resilience, and cross-session correlation.
"""

from typing import Any, Dict, List
from app.models.ioc import IOCType, ValidationStatus, IPScope
from app.models.threat_intel import ThreatIntelStatus, ThreatSeverity

# ─────────────────────────────────────────────────────────────────────────────
# 1. Benign IOC Fixtures (All 9 IOC Types)
# ─────────────────────────────────────────────────────────────────────────────
BENIGN_IOC_FIXTURES: List[Dict[str, Any]] = [
    {
        "id": "benign-ipv4-01",
        "raw_value": "  192.168.1.1  ",
        "expected_type": IOCType.IPV4,
        "expected_normalized": "192.168.1.1",
        "expected_validation": ValidationStatus.VALID,
        "expected_ip_scope": IPScope.PRIVATE,
        "expected_threat_status": ThreatIntelStatus.CLEAN,
        "expected_severity": ThreatSeverity.LOW,
        "expected_score_max": 24.9,
    },
    {
        "id": "benign-ipv4-02",
        "raw_value": "8.8.8.8",
        "expected_type": IOCType.IPV4,
        "expected_normalized": "8.8.8.8",
        "expected_validation": ValidationStatus.VALID,
        "expected_ip_scope": IPScope.PUBLIC,
        "expected_threat_status": ThreatIntelStatus.CLEAN,
        "expected_severity": ThreatSeverity.LOW,
        "expected_score_max": 24.9,
    },
    {
        "id": "benign-ipv6-01",
        "raw_value": "::1",
        "expected_type": IOCType.IPV6,
        "expected_normalized": "::1",
        "expected_validation": ValidationStatus.VALID,
        "expected_ip_scope": IPScope.LOOPBACK,
        "expected_threat_status": ThreatIntelStatus.CLEAN,
        "expected_severity": ThreatSeverity.LOW,
        "expected_score_max": 24.9,
    },
    {
        "id": "benign-ipv6-02",
        "raw_value": "2001:4860:4860:0000:0000:0000:0000:8888",
        "expected_type": IOCType.IPV6,
        "expected_normalized": "2001:4860:4860::8888",
        "expected_validation": ValidationStatus.VALID,
        "expected_ip_scope": IPScope.PUBLIC,
        "expected_threat_status": ThreatIntelStatus.CLEAN,
        "expected_severity": ThreatSeverity.LOW,
        "expected_score_max": 24.9,
    },
    {
        "id": "benign-domain-01",
        "raw_value": "GOOGLE.COM.",
        "expected_type": IOCType.DOMAIN,
        "expected_normalized": "google.com",
        "expected_validation": ValidationStatus.VALID,
        "expected_threat_status": ThreatIntelStatus.CLEAN,
        "expected_severity": ThreatSeverity.LOW,
        "expected_score_max": 24.9,
    },
    {
        "id": "benign-domain-02",
        "raw_value": "api.github.com",
        "expected_type": IOCType.DOMAIN,
        "expected_normalized": "api.github.com",
        "expected_validation": ValidationStatus.VALID,
        "expected_threat_status": ThreatIntelStatus.CLEAN,
        "expected_severity": ThreatSeverity.LOW,
        "expected_score_max": 24.9,
    },
    {
        "id": "benign-url-01",
        "raw_value": "http://example.com/index.html",
        "expected_type": IOCType.URL,
        "expected_normalized": "http://example.com/index.html",
        "expected_validation": ValidationStatus.VALID,
        "expected_threat_status": ThreatIntelStatus.CLEAN,
        "expected_severity": ThreatSeverity.LOW,
        "expected_score_max": 24.9,
    },
    {
        "id": "benign-md5-01",
        "raw_value": "D41D8CD98F00B204E9800998ECF8427E",
        "expected_type": IOCType.MD5,
        "expected_normalized": "d41d8cd98f00b204e9800998ecf8427e",
        "expected_validation": ValidationStatus.VALID,
        "expected_threat_status": ThreatIntelStatus.CLEAN,
        "expected_severity": ThreatSeverity.LOW,
        "expected_score_max": 24.9,
    },
    {
        "id": "benign-sha1-01",
        "raw_value": "DA39A3EE5E6B4B0D3255BFEF95601890AFD80709",
        "expected_type": IOCType.SHA1,
        "expected_normalized": "da39a3ee5e6b4b0d3255bfef95601890afd80709",
        "expected_validation": ValidationStatus.VALID,
        "expected_threat_status": ThreatIntelStatus.CLEAN,
        "expected_severity": ThreatSeverity.LOW,
        "expected_score_max": 24.9,
    },
    {
        "id": "benign-sha256-01",
        "raw_value": "E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855",
        "expected_type": IOCType.SHA256,
        "expected_normalized": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        "expected_validation": ValidationStatus.VALID,
        "expected_threat_status": ThreatIntelStatus.CLEAN,
        "expected_severity": ThreatSeverity.LOW,
        "expected_score_max": 24.9,
    },
    {
        "id": "benign-email-01",
        "raw_value": "Security.Analyst@Corp.Internal",
        "expected_type": IOCType.EMAIL,
        "expected_normalized": "security.analyst@corp.internal",
        "expected_validation": ValidationStatus.VALID,
        "expected_threat_status": ThreatIntelStatus.CLEAN,
        "expected_severity": ThreatSeverity.LOW,
        "expected_score_max": 24.9,
    },
    {
        "id": "benign-path-01",
        "raw_value": "/usr/local/bin/python3",
        "expected_type": IOCType.FILE_PATH,
        "expected_normalized": "/usr/local/bin/python3",
        "expected_validation": ValidationStatus.VALID,
        "expected_threat_status": ThreatIntelStatus.CLEAN,
        "expected_severity": ThreatSeverity.LOW,
        "expected_score_max": 24.9,
    },
]

# ─────────────────────────────────────────────────────────────────────────────
# 2. Suspicious IOC Fixtures
# ─────────────────────────────────────────────────────────────────────────────
SUSPICIOUS_IOC_FIXTURES: List[Dict[str, Any]] = [
    {
        "id": "susp-ipv4-01",
        "raw_value": "198.51.100.23",
        "expected_type": IOCType.IPV4,
        "expected_normalized": "198.51.100.23",
        "expected_validation": ValidationStatus.VALID,
        "expected_ip_scope": IPScope.RESERVED,
        "expected_threat_status": ThreatIntelStatus.SUSPICIOUS,
        "expected_severity": ThreatSeverity.MEDIUM,
        "expected_score_min": 25.0,
        "expected_score_max": 59.9,
    },
    {
        "id": "susp-domain-01",
        "raw_value": "dynamic-dns-updater.hopto.org",
        "expected_type": IOCType.DOMAIN,
        "expected_normalized": "dynamic-dns-updater.hopto.org",
        "expected_validation": ValidationStatus.VALID,
        "expected_threat_status": ThreatIntelStatus.SUSPICIOUS,
        "expected_severity": ThreatSeverity.MEDIUM,
        "expected_score_min": 25.0,
        "expected_score_max": 59.9,
    },
    {
        "id": "susp-url-01",
        "raw_value": "http://198.51.100.23:8080/setup.php",
        "expected_type": IOCType.URL,
        "expected_normalized": "http://198.51.100.23:8080/setup.php",
        "expected_validation": ValidationStatus.VALID,
        "expected_threat_status": ThreatIntelStatus.SUSPICIOUS,
        "expected_severity": ThreatSeverity.MEDIUM,
        "expected_score_min": 25.0,
        "expected_score_max": 59.9,
    },
    {
        "id": "susp-email-01",
        "raw_value": "invoice-urgent@external-temp-mail.xyz",
        "expected_type": IOCType.EMAIL,
        "expected_normalized": "invoice-urgent@external-temp-mail.xyz",
        "expected_validation": ValidationStatus.VALID,
        "expected_threat_status": ThreatIntelStatus.SUSPICIOUS,
        "expected_severity": ThreatSeverity.MEDIUM,
        "expected_score_min": 25.0,
        "expected_score_max": 59.9,
    },
    {
        "id": "susp-path-01",
        "raw_value": "/tmp/.hidden_script.sh",
        "expected_type": IOCType.FILE_PATH,
        "expected_normalized": "/tmp/.hidden_script.sh",
        "expected_validation": ValidationStatus.VALID,
        "expected_threat_status": ThreatIntelStatus.SUSPICIOUS,
        "expected_severity": ThreatSeverity.MEDIUM,
        "expected_score_min": 25.0,
        "expected_score_max": 59.9,
    },
]

# ─────────────────────────────────────────────────────────────────────────────
# 3. Malicious IOC Fixtures
# ─────────────────────────────────────────────────────────────────────────────
MALICIOUS_IOC_FIXTURES: List[Dict[str, Any]] = [
    {
        "id": "mal-ipv4-01",
        "raw_value": "198.51.100.1",
        "expected_type": IOCType.IPV4,
        "expected_normalized": "198.51.100.1",
        "expected_validation": ValidationStatus.VALID,
        "expected_ip_scope": IPScope.RESERVED,
        "expected_threat_status": ThreatIntelStatus.MALICIOUS,
        "expected_severity": ThreatSeverity.CRITICAL,
        "expected_score_min": 85.0,
    },
    {
        "id": "mal-domain-01",
        "raw_value": "c2-malware-beacon.evil.com",
        "expected_type": IOCType.DOMAIN,
        "expected_normalized": "c2-malware-beacon.evil.com",
        "expected_validation": ValidationStatus.VALID,
        "expected_threat_status": ThreatIntelStatus.MALICIOUS,
        "expected_severity": ThreatSeverity.CRITICAL,
        "expected_score_min": 85.0,
    },
    {
        "id": "mal-url-01",
        "raw_value": "http://c2-malware-beacon.evil.com/payload.bin",
        "expected_type": IOCType.URL,
        "expected_normalized": "http://c2-malware-beacon.evil.com/payload.bin",
        "expected_validation": ValidationStatus.VALID,
        "expected_threat_status": ThreatIntelStatus.MALICIOUS,
        "expected_severity": ThreatSeverity.CRITICAL,
        "expected_score_min": 85.0,
    },
    {
        "id": "mal-md5-01",
        "raw_value": "44D88612FEA8A8F36DE82E1278ABB02F",
        "expected_type": IOCType.MD5,
        "expected_normalized": "44d88612fea8a8f36de82e1278abb02f",
        "expected_validation": ValidationStatus.VALID,
        "expected_threat_status": ThreatIntelStatus.MALICIOUS,
        "expected_severity": ThreatSeverity.CRITICAL,
        "expected_score_min": 85.0,
    },
    {
        "id": "mal-sha256-01",
        "raw_value": "275A021BBFB6489E54D471899F7DB9D1663FC695EC2FE2A2C4538AABF651FD0F",
        "expected_type": IOCType.SHA256,
        "expected_normalized": "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f",
        "expected_validation": ValidationStatus.VALID,
        "expected_threat_status": ThreatIntelStatus.MALICIOUS,
        "expected_severity": ThreatSeverity.CRITICAL,
        "expected_score_min": 85.0,
    },
    {
        "id": "mal-path-01",
        "raw_value": "/etc/shadow",
        "expected_type": IOCType.FILE_PATH,
        "expected_normalized": "/etc/shadow",
        "expected_validation": ValidationStatus.VALID,
        "expected_threat_status": ThreatIntelStatus.MALICIOUS,
        "expected_severity": ThreatSeverity.HIGH,
        "expected_score_min": 60.0,
    },
]

# ─────────────────────────────────────────────────────────────────────────────
# 4. Adversarial Non-IOC Samples (Negative Extraction Controls)
# ─────────────────────────────────────────────────────────────────────────────
ADVERSARIAL_NON_IOC_FIXTURES: List[Dict[str, Any]] = [
    {
        "category": "mac_address",
        "text": "Device interface eth0 MAC 00:1A:2B:3C:4D:5E registered link",
        "expected_extracted_iocs": 0,
    },
    {
        "category": "timestamp_iso",
        "text": "Log emitted at 2026-11-06T12:00:00.000Z system alive",
        "expected_extracted_iocs": 0,
    },
    {
        "category": "software_version",
        "text": "Application upgrade to version v1.2.3.4 was successful",
        "expected_extracted_iocs": 0,
    },
    {
        "category": "floating_point",
        "text": "Telemetry ratio calculation resulted in value 3.14159265",
        "expected_extracted_iocs": 0,
    },
    {
        "category": "prose_periods",
        "text": "The host experienced latency. Service was restarted. Operations normal.",
        "expected_extracted_iocs": 0,
    },
    {
        "category": "file_extension_only",
        "text": "Attachment filter matched extensions .exe and .tar.gz and .dll safely",
        "expected_extracted_iocs": 0,
    },
    {
        "category": "invalid_octets_ipv4",
        "text": "Corrupted packet dropped from IP 999.123.456.789 buffer overflow",
        "expected_extracted_iocs": 0,
    },
    {
        "category": "malformed_email",
        "text": "Bad recipient string user@@internal_invalid rejected by parser",
        "expected_extracted_iocs": 0,
    },
    {
        "category": "empty_url_protocol",
        "text": "Bogus url string http:// encountered in text stream",
        "expected_extracted_iocs": 0,
    },
]

# ─────────────────────────────────────────────────────────────────────────────
# 5. Normalization Boundary Samples (RFC Compliance)
# ─────────────────────────────────────────────────────────────────────────────
NORMALIZATION_TEST_CASES: List[Dict[str, Any]] = [
    {
        "name": "ipv4_leading_zeros",
        "raw": "010.001.020.005",
        "ioc_type": IOCType.IPV4,
        "expected": "10.1.20.5",
    },
    {
        "name": "ipv6_rfc5952_compression",
        "raw": "2001:0DB8:0000:0000:0000:0000:0000:0001",
        "ioc_type": IOCType.IPV6,
        "expected": "2001:db8::1",
    },
    {
        "name": "domain_lowercase_trailing_dot",
        "raw": "EVIL-C2-DOMAIN.COM.",
        "ioc_type": IOCType.DOMAIN,
        "expected": "evil-c2-domain.com",
    },
    {
        "name": "url_default_port_stripping",
        "raw": "HTTP://Victim.COM:80/Path/To/Resource?id=1",
        "ioc_type": IOCType.URL,
        "expected": "http://victim.com/Path/To/Resource?id=1",
    },
    {
        "name": "url_default_https_port_stripping",
        "raw": "HTTPS://Victim.COM:443/login",
        "ioc_type": IOCType.URL,
        "expected": "https://victim.com/login",
    },
    {
        "name": "email_lowercase",
        "raw": "PHISHING.TARGET@Example.COM",
        "ioc_type": IOCType.EMAIL,
        "expected": "phishing.target@example.com",
    },
    {
        "name": "hash_lowercase_hex",
        "raw": "E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855",
        "ioc_type": IOCType.SHA256,
        "expected": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    },
    {
        "name": "file_path_redundant_slashes",
        "raw": "/etc//default///nginx",
        "ioc_type": IOCType.FILE_PATH,
        "expected": "/etc/default/nginx",
    },
]

