# DEMONSTRATION DATASET INVENTORY

**Project:** MICHAEL – THE GUARDIAN AI  
**Academic Title:** Intelligent Log Analysis and Anomaly Detection Using Artificial Intelligence  
**Directory:** `backend/tests/fixtures/demo/`  

---

This directory contains deterministic, synthetic log datasets engineered for live demonstration, academic defense, and technical evaluation. All data is synthetic and contains zero real credentials, personal information, or proprietary production logs.

## Scenario Catalog

### 1. `scenario_a_normal.log` (Normal Enterprise Baseline)
- **Demonstration Goal:** Demonstrates standard operational health and low false-positive baseline.
- **Log Events:** Routine HTTP 200 GET requests, CSS assets, internal health probes, logrotate service, scheduled backup jobs.
- **Expected System Response:**
  - Anomaly count: 0
  - Incidents: 0
  - Executive Dashboard: Operational / Normal
  - IOC Extraction: Internal RFC 1918 IPs tagged as internal scope.

### 2. `scenario_b_brute_force.log` (SSH Authentication Burst)
- **Demonstration Goal:** Demonstrates point-based heuristic rule matching, temporal burst detection, and incident creation.
- **Log Events:** 8 failed password attempts within 15 seconds targeting various usernames (`admin`, `root`, `deploy`, `postgres`) from source IP `198.51.100.45`.
- **Expected System Response:**
  - Anomaly Detection: Flagged as `CRITICAL` via Rule Engine (`AUTH_BRUTE_FORCE`) and Temporal Intelligence ($Z_{10\text{s}} \ge 3.0$).
  - Incident Created: `AUTHENTICATION_FAILURE` with remediation playbook (IP block).
  - IOC Extracted: IPv4 `198.51.100.45` linked to exact source line numbers.

### 3. `scenario_c_c2_outbound.log` (Command & Control Outbound Activity)
- **Demonstration Goal:** Demonstrates DNS resolution correlation, external C2 connection tracking, and high-threat reputation scoring.
- **Log Events:** Outbound SYN to `203.0.113.15:4444`, DNS lookup for `evil-command-control.org`, base64 payload execution.
- **Expected System Response:**
  - Threat Assessment: High threat score ($\ge 85.0$) from Offline Mock provider for known Cobalt Strike / C2 IP.
  - Incident: `OUTBOUND_C2` with MITRE ATT&CK C2 stage.
  - IOC Extracted: Domain `evil-command-control.org` and IPv4 `203.0.113.15`.

### 4. `scenario_d_multi_stage_attack.log` (Multi-Stage Intrusion Progression)
- **Demonstration Goal:** Demonstrates the complete end-to-end pipeline from SQL injection and path traversal to privilege escalation, dropper execution, and attack-chain graph reconstruction.
- **Log Events:**
  1. SQL injection probe (`admin' OR 1=1--`) via sqlmap.
  2. Path traversal (`../../../../etc/passwd`).
  3. SSH credential compromise (`deploy` user).
  4. Sudo escalation executing dropper script.
  5. Outbound data exfiltration to `203.0.113.77:8080`.
  6. Dropper SHA-256 hash logging.
- **Expected System Response:**
  - Full attack chain reconstructed across MITRE stages: Initial Access $\to$ Execution $\to$ Privilege Escalation $\to$ C2 $\to$ Exfiltration.
  - Interactive attack graph rendered in SOC dashboard (`/attack-chains`).
  - IOCs extracted: IPv4, Domain, URL, SHA256.

### 5. `scenario_e_unknown_threat_intel.log` (Telemetry Deficit & UNKNOWN Safeguard)
- **Demonstration Goal:** Explicitly proves the core academic invariant: **`UNKNOWN != CLEAN`**.
- **Log Events:** Unrecognized public IP `192.0.2.254` probing unlisted ports with unknown protocol signatures.
- **Expected System Response:**
  - Threat Intelligence query returns 404 (Not Found).
  - System strictly assigns `ThreatIntelStatus.UNKNOWN`.
  - Threat Score: $0.0$, Confidence: $0.0$, Severity: `UNKNOWN`.
  - Crucial proof: The system does **NOT** classify this unlisted IP as benign or clean.

