# FINAL DEMONSTRATION RUNBOOK

**Project:** MICHAEL – THE GUARDIAN AI  
**Academic Title:** Intelligent Log Analysis and Anomaly Detection Using Artificial Intelligence  
**Target Audience:** Capstone Defense Examiners, Technical Auditors, SOC Evaluators  
**Estimated Run Time:** 12–15 Minutes  

---

## 1. Pre-Flight Preparation & Service Launch

### Step 01: Launch Backend API Server
Open Terminal 1 (or PowerShell):
```bash
cd "backend"
# Activate virtual environment if configured:
# .\venv\Scripts\Activate.ps1
uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
```
- **Expected Terminal Output:**  
  `INFO: Application startup complete.`  
  `INFO: Uvicorn running on http://0.0.0.0:8000`

### Step 02: Launch Frontend SOC Dashboard
Open Terminal 2 (or PowerShell):
```bash
cd "frontend"
npm run dev
# Or for production server: npm run start
```
- **Expected Terminal Output:**  
  `▲ Next.js 16.4.4`  
  `- Local: http://localhost:3000`

### Step 03: Verify Operational Readiness Probes
Open Terminal 3:
```bash
curl http://localhost:8000/api/health
curl http://localhost:8000/api/ready
```
- **Expected Output:**
  ```json
  {"status":"operational","version":"1.0.0", ...}
  {"status":"ready","persistence_backend":"memory","db_status":"connected", ...}
  ```
- **Presenter Note:** Point out that `/api/health` (process vitality) and `/api/ready` (dependency readiness) are decoupled, preventing cascade container restart storms in production orchestrators.

---

## 2. Demonstration Flow: Step-by-Step

### Step 04: Open SOC Dashboard
- **Action:** Open browser to `http://localhost:3000`.
- **Expected View:** The Executive Dashboard (`/dashboard`) renders with clean threat gauges, system status indicators, and operational metrics.
- **Presenter Note:** Introduce MICHAEL as an evidence-driven, explainable cybersecurity log analysis platform designed to eliminate SOC alert fatigue.

### Step 05: Ingest Baseline Normal Activity (Scenario A)
- **Action:** Navigate to **Logs** (`/logs`) $\to$ Click **Upload Log File** $\to$ Select `backend/tests/fixtures/demo/scenario_a_normal.log`.
- **Expected Observation:**
  - File upload succeeds with 10 log entries parsed.
  - Ingestion status displays `ready`.
  - Anomaly queue remains empty ($0$ critical alarms).
- **Presenter Note:** Emphasize that the unsupervised models correctly establish the baseline: routine crons, web GET requests, and systemd actions generate zero false alarms.

### Step 06: Demonstrate Brute-Force & Temporal Burst (Scenario B)
- **Action:** Navigate to **Logs** (`/logs`) $\to$ Click **Upload Log File** $\to$ Select `backend/tests/fixtures/demo/scenario_b_brute_force.log`.
- **Expected Observation:**
  - 10 entries ingested covering failed authentications from `198.51.100.45`.
  - Navigate to **Anomalies** (`/anomalies`): High-severity anomaly flagged via Rule Engine (`AUTH_BRUTE_FORCE`) and Temporal Intelligence ($Z_{10\text{s}} \ge 3.0$).
  - Click on the anomaly card to reveal the drawer showing contributing feature weights.
- **Presenter Note:** Explain that point inspection catches the password failure, but the Temporal Engine's 10-second sliding window catches the high rate of change.

### Step 07: Inspect Incident Triage & Automated Playbook
- **Action:** Navigate to **Incidents** (`/incidents`).
- **Expected Observation:**
  - Incident `AUTHENTICATION_FAILURE` is listed.
  - Click on the incident: View Title, Severity (`HIGH`/`CRITICAL`), Root-Cause Hypothesis ("Credential brute-force burst from IP 198.51.100.45"), and prescriptive remediation steps ("Add IP to firewall drop list").
- **Presenter Note:** Highlight that individual anomalies were automatically synthesized into an actionable incident, reducing alert noise.

### Step 08: Ingest Multi-Stage Intrusion Campaign (Scenario D)
- **Action:** Navigate to **Logs** (`/logs`) $\to$ Click **Upload Log File** $\to$ Select `backend/tests/fixtures/demo/scenario_d_multi_stage_attack.log`.
- **Expected Observation:**
  - Ingests 8 events covering SQL injection, directory traversal, credential access, dropper execution, and data exfiltration.
- **Presenter Note:** Explain that an attacker is attempting a full intrusion lifecycle.

### Step 09: Reconstruct Attack Chain & Graph Visualization
- **Action:** Navigate to **Attack Chains** (`/attack-chains`).
- **Expected Observation:**
  - Reconstructed attack progression chain displayed.
  - Interactive attack graph shows interconnected nodes progressing chronologically through MITRE ATT&CK stages:
    $\text{Initial Access} \to \text{Execution} \to \text{Privilege Escalation} \to \text{Command and Control} \to \text{Exfiltration}$.
  - Click on a node to view the exact supporting log evidence lines.
- **Presenter Note:** Point out that analysts see the entire campaign narrative on a single canvas rather than piecing together disjointed alerts.

### Step 10: Investigate Canonical IOC & Evidence Mapping
- **Action:** Navigate to **IOCs** (`/iocs`).
- **Expected Observation:**
  - Clean table showing extracted indicators: `198.51.100.88`, `203.0.113.77`, `malicious-delivery.com`, and SHA-256 hash `e3b0c44...`.
  - Click on `198.51.100.88` $\to$ Evidence tab displays exact source lines and event IDs.
- **Presenter Note:** Emphasize that all IOCs undergo RFC normalization (IPv4 zero-stripping, domain case-folding) and maintain append-only evidence pointers back to raw log line numbers.

### Step 11: Demonstrate Threat Reputation & Explainable Signals
- **Action:** Navigate to **Threat Intelligence** (`/threat-intelligence`) $\to$ Select IP `203.0.113.77` or `203.0.113.15`.
- **Expected Observation:**
  - Threat Assessment card displays Threat Score (e.g., $85.0/100$) and Threat Confidence (e.g., $0.90$).
  - Severity badge shows `CRITICAL` or `HIGH`.
  - Contributing Signals panel decomposes the score into discrete signal points (e.g., Cobalt Strike C2 classification: $+50$ pts; Malicious verdict: $+35$ pts).
- **Presenter Note:** Show that the score is not an opaque number; every point is mathematically explainable.

### Step 12: Ingest Unknown Indicator to Prove `UNKNOWN != CLEAN` (Scenario E)
- **Action:** Navigate to **Logs** (`/logs`) $\to$ Click **Upload Log File** $\to$ Select `backend/tests/fixtures/demo/scenario_e_unknown_threat_intel.log`.
- **Expected Observation:**
  - Indicator `192.0.2.254` is extracted.
  - Navigate to `/threat-intelligence` and inspect `192.0.2.254`.
  - External lookup returns 404 (Not Found).
  - Status is displayed as `UNKNOWN` with Threat Score $0.0$, Confidence $0.0$, and Severity `UNKNOWN`.
  - **CRUCIAL POINT:** The system does **NOT** label this unlisted IP as benign or clean.
- **Presenter Note:** "Notice this vital security invariant: an absence of threat intelligence is NOT proof of innocence. The system never manufactures a false-safe conclusion."

### Step 13: Examine Unified Threat Context & Non-Destructive Correlation
- **Action:** In `/threat-intelligence`, click **Correlations** tab for `198.51.100.88` or `203.0.113.77`.
- **Expected Observation:**
  - View directional relationships linking the IOC to events, anomalies, incidents, and attack chains.
  - Highlight that the human analyst triage status (`IOCStatus`) remains `EXTRACTED` or `UNDER_REVIEW`.
- **Presenter Note:** "Our cardinal rule: **Correlation is NOT Classification**. Automated correlation adds relational evidence, but it never modifies the human analyst's workflow status without their explicit action."

### Step 14: Generate Forensic PDF Audit Report
- **Action:** Navigate to **Reports** (`/reports`) $\to$ Select active session $\to$ Click **Generate Executive Incident Report**.
- **Expected Observation:**
  - System generates a formatted PDF document within 2 seconds.
  - Click **Download PDF** $\to$ Open downloaded file in browser.
  - View executive incident summary, anomaly table, MITRE ATT&CK progression chart, and forensic line references.
- **Presenter Note:** Show that the report is audit-ready for compliance (NIST CSF / ISO 27001).

### Step 15: Conclude Presentation
- Conclude by summarizing the three core pillars:
  1. **Hybrid AI Detection** (precision on known threats, recall on zero-days).
  2. **Forensic Integrity** (unbroken line-number evidence links, immutability, `UNKNOWN != CLEAN`).
  3. **Analyst Sovereignty** (explainable signals, non-destructive correlation).
- Invite examiner questions.

