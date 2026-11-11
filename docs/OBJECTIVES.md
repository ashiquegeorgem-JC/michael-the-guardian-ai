# PROJECT OBJECTIVES

**Project:** MICHAEL – THE GUARDIAN AI  
**Academic Title:** Intelligent Log Analysis and Anomaly Detection Using Artificial Intelligence  

---

## 1. Primary Objective

The overarching objective of **MICHAEL – THE GUARDIAN AI** is to design, develop, validate, and document a robust, production-ready, intelligent log analysis and threat correlation platform capable of autonomous anomaly detection, incident derivation, attack chain reconstruction, and threat intelligence synthesis.

---

## 2. Specific Technical & Engineering Objectives

### Objective 1: Multi-Format Log Ingestion & Normalization
- Ingest unstructured log files across heterogeneous enterprise formats (Syslog, SSHD, Nginx, Linux Kernel, Firewall, and CSV/TXT).
- Parse timestamps, log levels, sources, messages, and raw lines into structured `LogEntry` entities.
- Track session boundaries, total lines, and file metadata via `LogSession`.

### Objective 2: Hybrid AI/ML Anomaly Detection
- Implement an unsupervised **Isolation Forest** tree ensemble to detect structural and statistical outliers based on message entropy, token density, and length.
- Implement a **TF-IDF Semantic Dispersion** model to quantify rare vocabulary and exploit syntax.
- Implement **Statistical Z-Score** detection for volumetric and metric anomalies.
- Implement deterministic **Heuristic Rules** for recognized signatures (e.g., SQL injection, path traversal, auth brute-force).
- Synthesize detections into an explainable hybrid ensemble producing normalized scores ($0.0–1.0$) and categorical severity tiers (`LOW`, `MEDIUM`, `HIGH`, `CRITICAL`).

### Objective 3: Temporal Behaviour Intelligence
- Implement rolling multi-scale sliding windows ($10\text{s}$, $30\text{s}$, $60\text{s}$, $300\text{s}$).
- Compute rolling mean, rolling standard deviation, Exponential Moving Average (EMA), and rolling Z-scores.
- Detect burst traffic, rapid authentication failures, and outbound beaconing that evade static point-based inspection.

### Objective 4: Incident Triage & Attack Chain Reconstruction
- Group related anomalies by affected entities, source IPs, and time windows into `Incident` objects.
- Synthesize multi-stage chronological progressions into `AttackChain` graphs mapped to MITRE ATT&CK tactics (Reconnaissance, Initial Access, Execution, Persistence, Command and Control).

### Objective 5: Forensic IOC Intelligence & RFC Normalization
- Extract candidate indicators across 9 types: IPv4, IPv6, Domain, URL, MD5, SHA1, SHA256, Email, File Path.
- Apply strict RFC normalization (IPv4 zero-stripping, IPv6 RFC 5952 compression, domain case-folding, URL default port stripping).
- Enforce strict validation states (`VALID`, `INVALID`, `SUSPICIOUS`) without altering analyst triage statuses (`EXTRACTED`, `UNDER_REVIEW`, `CONFIRMED`, `FALSE_POSITIVE`).
- Maintain append-only forensic evidence links (`IOCEvidence`) referencing exact event IDs, session IDs, and line numbers.

### Objective 6: Deterministic Threat Intelligence & Provider Integration
- Design a pluggable provider interface supporting offline and online telemetry sources.
- Implement the `OfflineMockThreatIntelProvider` for deterministic, zero-network air-gapped operations.
- Implement the `VirusTotalProvider` with HTTP status code mapping (200, 401, 403, 404, 429, 500), rate-limiting, and error handling.
- Enforce the **Telemetry Deficit Invariant**: missing records (404) map strictly to `UNKNOWN`, never `CLEAN`.
- Enforce the **Decoupled Scoring Invariant**: Threat Score ($0–100$) and Threat Confidence ($0–1$) are calculated independently.

### Objective 7: Threat Correlation & Unified Context Engine
- Establish directional relationships between IOCs, raw events, anomalies, incidents, and attack chains.
- Compute evidence-based correlation confidence based on explicit links, shared events, and calibrated temporal proximity windows ($\le 30\text{s}$, $30\text{s}–5\text{m}$, $5\text{m}–15\text{m}$, $>15\text{m}$).
- Enforce cross-session safety constraints ($0.40$ penalty multiplier and `confirmed=False`).
- Assemble the consolidated `UnifiedThreatContext` for single-pane-of-glass investigation.

### Objective 8: Enterprise Persistence & Process Restart Resilience
- Design an abstract repository pattern decoupling domain logic from physical storage.
- Implement a 12-table relational schema supporting in-memory, SQLite, and PostgreSQL modes.
- Verify zero data loss across process termination and cold reload.

### Objective 9: Production-Grade SOC Web Interface & REST APIs
- Expose a modular FastAPI backend with input validation, error leakage protection, and `/api/health` and `/api/ready` endpoints.
- Build a responsive 15-route Next.js 16 / React / TypeScript dashboard tailored for SOC operations.
- Implement automated forensic PDF audit report generation.

### Objective 10: Rigorous Verification, Auditing, and Academic Documentation
- Maintain a 100% passing backend regression suite ($\ge 400$ tests).
- Execute a 12-vector security audit verifying secret scrubbing, SSRF immunity, XSS prevention, and CORS boundaries.
- Produce comprehensive academic and engineering documentation detailing the architecture, ML methodology, empirical benchmarks, and operational limitations.

