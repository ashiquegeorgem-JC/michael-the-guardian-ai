"""
Incident Investigation Service.
Converts detected anomalies into structured incidents with
evidence grounding and AI-generated hypotheses (clearly labelled).
"""

import re
import uuid
import logging
from datetime import datetime
from typing import List, Optional
from collections import Counter

from app.models.anomaly import Anomaly, SeverityLevel
from app.models.incident import Incident, IncidentCategory, IncidentStatus
from app.models.log_entry import LogEntry

logger = logging.getLogger("michael.incidents")

# ──────────────────────────────────────────────────────────────────────────────
# Category mapping by anomaly reason keywords
# ──────────────────────────────────────────────────────────────────────────────
CATEGORY_KEYWORDS = [
    (re.compile(r"auth|login|password|credential|ssh|ldap", re.I), IncidentCategory.AUTHENTICATION_FAILURE),
    (re.compile(r"injection|xss|sql|union.*select|script", re.I), IncidentCategory.INTRUSION_ATTEMPT),
    (re.compile(r"segfault|kernel.panic|crash|core.dump", re.I), IncidentCategory.SYSTEM_CRASH),
    (re.compile(r"memory|disk.full|oom|resource|exhaust", re.I), IncidentCategory.RESOURCE_EXHAUSTION),
    (re.compile(r"database|mysql|postgres|mongo|redis|query", re.I), IncidentCategory.DATABASE_ANOMALY),
    (re.compile(r"network|port|scan|connection|tcp|udp|firewall", re.I), IncidentCategory.NETWORK_ANOMALY),
    (re.compile(r"privilege|escalat|sudo|root|permission", re.I), IncidentCategory.PRIVILEGE_ESCALATION),
    (re.compile(r"malware|ransomware|virus|trojan|exploit|backdoor", re.I), IncidentCategory.MALWARE_INDICATOR),
    (re.compile(r"exfil|data.transfer|upload.*large|sensitive", re.I), IncidentCategory.DATA_EXFILTRATION),
    (re.compile(r"config|setting|change|modify|update.*config", re.I), IncidentCategory.CONFIGURATION_CHANGE),
]

# Root cause hypotheses templates (AI-generated — labelled accordingly)
ROOT_CAUSE_TEMPLATES = {
    IncidentCategory.AUTHENTICATION_FAILURE: (
        "[AI HYPOTHESIS] Multiple authentication failures suggest either a brute-force attack, "
        "misconfigured service credentials, or a compromised account. The pattern of failures "
        "from sequential IP addresses is consistent with automated credential stuffing."
    ),
    IncidentCategory.INTRUSION_ATTEMPT: (
        "[AI HYPOTHESIS] Detected input containing SQL/XSS injection patterns. This may indicate "
        "an active web application attack targeting vulnerable input endpoints. The attacker "
        "may be probing for injection vulnerabilities using automated tools."
    ),
    IncidentCategory.SYSTEM_CRASH: (
        "[AI HYPOTHESIS] System crash indicators (segfault/kernel panic) suggest possible memory "
        "corruption, hardware failure, or a software bug triggered by unusual input. "
        "Kernel panic may also result from driver incompatibility or resource exhaustion."
    ),
    IncidentCategory.RESOURCE_EXHAUSTION: (
        "[AI HYPOTHESIS] Resource exhaustion patterns indicate either a runaway process, "
        "memory leak, a deliberate DoS attack, or insufficient capacity for the current workload. "
        "OOM kills suggest the process consumed memory faster than expected."
    ),
    IncidentCategory.DATABASE_ANOMALY: (
        "[AI HYPOTHESIS] Unusual database activity may indicate a slow query bottleneck, "
        "unauthorized data access, schema modification, or database corruption. "
        "High query latency patterns are consistent with table lock contention."
    ),
    IncidentCategory.NETWORK_ANOMALY: (
        "[AI HYPOTHESIS] Network anomalies suggest possible port scanning, DDoS activity, "
        "or misconfigured network services. Repeated connection resets may indicate "
        "a SYN flood attack or firewall rule changes."
    ),
    IncidentCategory.PRIVILEGE_ESCALATION: (
        "[AI HYPOTHESIS] Privilege escalation attempts suggest a potentially compromised "
        "user account attempting to gain root access. This is consistent with post-exploitation "
        "activity following an initial compromise vector."
    ),
    IncidentCategory.MALWARE_INDICATOR: (
        "[AI HYPOTHESIS] Malware indicators detected in log entries. Patterns are consistent "
        "with known attack frameworks. Immediate system isolation and forensic investigation "
        "is recommended to prevent lateral movement."
    ),
    IncidentCategory.DATA_EXFILTRATION: (
        "[AI HYPOTHESIS] Unusual outbound data transfer patterns may indicate data exfiltration. "
        "The volume and frequency of transfers is inconsistent with normal operational baselines."
    ),
    IncidentCategory.APPLICATION_ERROR: (
        "[AI HYPOTHESIS] Elevated application error rates suggest a software defect, "
        "configuration error, or unexpected input causing service degradation. "
        "Stack trace patterns indicate the error originates in the request handling layer."
    ),
    IncidentCategory.CONFIGURATION_CHANGE: (
        "[AI HYPOTHESIS] Configuration changes detected outside normal change windows "
        "may indicate unauthorized modification or a misconfigured deployment pipeline."
    ),
    IncidentCategory.UNKNOWN: (
        "[AI HYPOTHESIS] The anomaly pattern does not match known incident signatures. "
        "Further investigation is required to determine the root cause."
    ),
}

REMEDIATION_TEMPLATES = {
    IncidentCategory.AUTHENTICATION_FAILURE: [
        "Immediately block the source IP addresses generating failed login attempts",
        "Enable multi-factor authentication (MFA) on all affected accounts",
        "Review and rotate credentials for potentially compromised accounts",
        "Implement account lockout policies after N failed attempts",
        "Enable alerting for repeated authentication failures from the same source",
    ],
    IncidentCategory.INTRUSION_ATTEMPT: [
        "Review and sanitize all user inputs using parameterized queries",
        "Deploy or update Web Application Firewall (WAF) rules",
        "Immediately patch vulnerable application endpoints",
        "Conduct a full penetration test of exposed web services",
        "Review access logs for successful exploitation indicators",
    ],
    IncidentCategory.SYSTEM_CRASH: [
        "Collect and analyze core dump files for root cause determination",
        "Review system memory usage trends leading up to the crash",
        "Check hardware health (ECC errors, disk S.M.A.R.T. status)",
        "Apply pending OS and kernel updates",
        "Implement process supervisors (systemd, PM2) for automatic restart",
    ],
    IncidentCategory.RESOURCE_EXHAUSTION: [
        "Identify the process consuming excessive resources and investigate",
        "Implement resource limits (cgroups, ulimit) per process",
        "Scale infrastructure horizontally if under legitimate high load",
        "Set up proactive alerting at 80% memory/CPU/disk thresholds",
        "Review application code for memory leaks or inefficient algorithms",
    ],
    IncidentCategory.DATABASE_ANOMALY: [
        "Run EXPLAIN on slow queries and add appropriate indexes",
        "Review database access logs for unauthorized query patterns",
        "Check for table locks and long-running transactions",
        "Ensure least-privilege access controls on database users",
        "Enable database audit logging for all privileged operations",
    ],
    IncidentCategory.NETWORK_ANOMALY: [
        "Block scanning source IPs at the firewall level",
        "Review firewall rules for unauthorized changes",
        "Enable rate limiting on exposed network services",
        "Conduct network traffic analysis using packet capture tools",
        "Verify integrity of network device configurations",
    ],
    IncidentCategory.PRIVILEGE_ESCALATION: [
        "Immediately lock the implicated user account",
        "Review sudo/sudoers configuration for overly permissive rules",
        "Audit all recent privileged command executions",
        "Isolate the affected system for forensic investigation",
        "Reset all privileged credentials system-wide as a precaution",
    ],
    IncidentCategory.MALWARE_INDICATOR: [
        "Immediately isolate the affected system from the network",
        "Run a full antimalware scan with updated signatures",
        "Preserve forensic evidence before remediation",
        "Identify and terminate malicious processes",
        "Rebuild the affected system from a known-good baseline",
    ],
    IncidentCategory.DATA_EXFILTRATION: [
        "Block identified exfiltration channels at the firewall",
        "Identify and classify the data potentially exfiltrated",
        "Notify relevant stakeholders per incident response plan",
        "Engage legal/compliance teams if regulated data is involved",
        "Implement DLP (Data Loss Prevention) controls",
    ],
    IncidentCategory.UNKNOWN: [
        "Collect all related log evidence for manual investigation",
        "Escalate to the security operations team for review",
        "Implement additional monitoring on the affected system",
        "Document findings for threat intelligence purposes",
    ],
}


def classify_category(reason: str) -> IncidentCategory:
    """Classify an incident category based on anomaly reason."""
    for pattern, category in CATEGORY_KEYWORDS:
        if pattern.search(reason):
            return category
    return IncidentCategory.APPLICATION_ERROR


def extract_ips(texts: List[str]) -> List[str]:
    """Extract unique IP addresses from log lines."""
    ip_pattern = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
    ips = []
    for t in texts:
        ips.extend(ip_pattern.findall(t))
    return list(set(ips))[:10]  # Top 10 unique IPs


def generate_incident_title(category: IncidentCategory, severity: str, source: Optional[str] = None) -> str:
    """Generate a descriptive incident title."""
    titles = {
        IncidentCategory.AUTHENTICATION_FAILURE: "Authentication Failure Cluster Detected",
        IncidentCategory.INTRUSION_ATTEMPT: "Web Application Intrusion Attempt",
        IncidentCategory.SYSTEM_CRASH: "Critical System Crash Event",
        IncidentCategory.RESOURCE_EXHAUSTION: "System Resource Exhaustion",
        IncidentCategory.DATABASE_ANOMALY: "Database Anomaly Detected",
        IncidentCategory.NETWORK_ANOMALY: "Suspicious Network Activity",
        IncidentCategory.PRIVILEGE_ESCALATION: "Privilege Escalation Attempt",
        IncidentCategory.MALWARE_INDICATOR: "Malware Indicator Identified",
        IncidentCategory.DATA_EXFILTRATION: "Potential Data Exfiltration",
        IncidentCategory.CONFIGURATION_CHANGE: "Unauthorized Configuration Change",
        IncidentCategory.APPLICATION_ERROR: "Application Error Spike",
        IncidentCategory.UNKNOWN: "Unknown Anomaly Pattern",
    }
    title = titles.get(category, "Security Anomaly")
    if source:
        title += f" [{source}]"
    return f"[{severity}] {title}"


def create_incident_from_anomaly(
    anomaly: Anomaly,
    all_entries: List[LogEntry],
) -> Incident:
    """Convert an Anomaly into a structured Incident."""
    # Collect evidence from matching log entries
    entry_map = {e.id: e for e in all_entries}
    evidence_entries = [entry_map[eid] for eid in anomaly.log_entry_ids if eid in entry_map]
    evidence_lines = anomaly.supporting_logs

    # Ground evidence in actual log data
    evidence = []
    if evidence_entries:
        for e in evidence_entries[:5]:  # Up to 5 evidence entries
            ts = e.timestamp.isoformat() if e.timestamp else "unknown time"
            evidence.append(f"[{ts}] [{e.level.value}] {e.message or e.raw_line}")

    # Classify category
    category = classify_category(anomaly.reason)

    # Extract IPs and sources
    affected_ips = extract_ips(evidence_lines + [e.raw_line for e in evidence_entries])
    sources = list(set(
        e.source for e in evidence_entries if e.source
    ))

    # Timestamps
    timestamps = [e.timestamp for e in evidence_entries if e.timestamp]
    first_seen = min(timestamps) if timestamps else anomaly.detected_at
    last_seen = max(timestamps) if timestamps else anomaly.detected_at

    return Incident(
        anomaly_id=anomaly.id,
        session_id=anomaly.session_id,
        category=category,
        severity=anomaly.severity.value,
        title=generate_incident_title(category, anomaly.severity.value, sources[0] if sources else None),
        description=(
            f"Detected via {anomaly.method.value} analysis. "
            f"Anomaly score: {anomaly.score:.3f}. {anomaly.reason}"
        ),
        evidence=evidence,
        evidence_log_lines=evidence_lines[:10],
        root_cause_hypothesis=ROOT_CAUSE_TEMPLATES.get(category, ROOT_CAUSE_TEMPLATES[IncidentCategory.UNKNOWN]),
        potential_impact=_impact_for_category(category, anomaly.severity),
        remediation_steps=REMEDIATION_TEMPLATES.get(category, REMEDIATION_TEMPLATES[IncidentCategory.UNKNOWN]),
        first_seen=first_seen,
        last_seen=last_seen,
        affected_sources=sources,
        affected_ips=affected_ips,
    )


def _impact_for_category(category: IncidentCategory, severity: SeverityLevel) -> str:
    impacts = {
        IncidentCategory.AUTHENTICATION_FAILURE: "Potential unauthorized access to user accounts and sensitive data",
        IncidentCategory.INTRUSION_ATTEMPT: "Risk of data breach, application compromise, or remote code execution",
        IncidentCategory.SYSTEM_CRASH: "Service downtime, data loss, and degraded user experience",
        IncidentCategory.RESOURCE_EXHAUSTION: "Service degradation or complete outage due to resource starvation",
        IncidentCategory.DATABASE_ANOMALY: "Data integrity risk, performance degradation, or unauthorized data access",
        IncidentCategory.NETWORK_ANOMALY: "Potential for DDoS, service disruption, or network infiltration",
        IncidentCategory.PRIVILEGE_ESCALATION: "Full system compromise risk if attacker gains root access",
        IncidentCategory.MALWARE_INDICATOR: "Data theft, system damage, lateral movement, and ransomware risk",
        IncidentCategory.DATA_EXFILTRATION: "Loss of sensitive/proprietary data; regulatory compliance violation",
        IncidentCategory.CONFIGURATION_CHANGE: "Service misconfiguration, security policy bypass",
        IncidentCategory.APPLICATION_ERROR: "Degraded application performance and user-facing errors",
        IncidentCategory.UNKNOWN: "Unknown impact — further investigation required",
    }
    base = impacts.get(category, "Potential system impact — investigation required")
    if severity == SeverityLevel.CRITICAL:
        return f"CRITICAL: {base}. Immediate action required."
    return base


def generate_all_incidents(
    anomalies: List[Anomaly],
    entries: List[LogEntry],
) -> List[Incident]:
    """Generate incidents for all detected anomalies."""
    incidents = []
    for anomaly in anomalies:
        try:
            incident = create_incident_from_anomaly(anomaly, entries)
            incidents.append(incident)
        except Exception as e:
            logger.error(f"Failed to create incident for anomaly {anomaly.id}: {e}")
    logger.info(f"Generated {len(incidents)} incidents from {len(anomalies)} anomalies")
    return incidents
