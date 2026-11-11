# MODULE SPECIFICATIONS

**Project:** MICHAEL – THE GUARDIAN AI  
**Academic Title:** Intelligent Log Analysis and Anomaly Detection Using Artificial Intelligence  

---

This document provides detailed technical specifications for each of the 12 functional modules comprising the **MICHAEL – THE GUARDIAN AI** platform.

---

## Module 1: Log Ingestion & Parsing

- **Purpose:** Ingests raw, heterogeneous log data from diverse infrastructure components, extracts structured metadata, normalizes timestamps into UTC, and establishes session boundaries.
- **Inputs:** Raw log files or streams (`.log`, `.txt`, `.csv`, syslog text).
- **Processing:**
  1. Identifies file structure and delimiter formatting.
  2. Applies format-specific regular expressions (Syslog RFC 3164/5424, Nginx Combined, SSH, Linux Kernel, generic key-value).
  3. Parses timestamps into explicit timezone-aware UTC datetime objects.
  4. Classifies log severity levels (`DEBUG`, `INFO`, `WARNING`, `ERROR`, `CRITICAL`, `UNKNOWN`).
  5. Preserves exact line numbers and unparsed raw text for forensic auditing.
- **Outputs:** `Tuple[List[LogEntry], LogSession]`.
- **Technologies:** Python 3.12+, Python `re`, `datetime`, `uuid`.
- **Safety Constraints:** Ingestion is append-only and strictly read-only with respect to the source log file; raw lines are immutable.

---

## Module 2: AI Anomaly Detection

- **Purpose:** Identifies statistical, syntactic, and structural outliers in log streams without requiring labeled historical training data.
- **Inputs:** `List[LogEntry]`.
- **Processing:**
  1. **Isolation Forest:** Builds an ensemble of isolation trees on numeric feature vectors (message length, numerical density, character entropy).
  2. **TF-IDF Semantic Dispersion:** Computes term frequency-inverse document frequency over word n-grams, identifying rare vocabulary and code injection syntax.
  3. **Statistical Outlier Detection:** Computes Z-scores on feature distributions to identify extreme quantitative deviations.
  4. **Heuristic Rule Engine:** Applies deterministic pattern matching for verified attack signatures (SQLi, Directory Traversal, Brute Force).
  5. **Score Fusion:** Normalizes and fuses model outputs into an explainable anomaly score ($0.0–1.0$).
- **Outputs:** `List[Anomaly]`, `ModelMetrics`.
- **Technologies:** Scikit-learn (`IsolationForest`, `TfidfVectorizer`), NumPy.
- **Safety Constraints:** Unsupervised models must maintain deterministic random seeds (`random_state=42`) to guarantee reproducible audit outcomes.

---

## Module 3: Temporal Behaviour Intelligence

- **Purpose:** Detects burst attacks, rate-of-change surges, and stealthy anomalous patterns across contiguous temporal horizons.
- **Inputs:** `List[LogEntry]`, chronological event timestamps.
- **Processing:**
  1. Partitions log streams into four rolling sliding windows: $10\text{s}$, $30\text{s}$, $60\text{s}$, and $300\text{s}$.
  2. Computes rolling statistical indicators: Rolling Mean ($\mu_t$), Rolling Standard Deviation ($\sigma_t$), Exponential Moving Average ($\text{EMA}_t$), and Rolling Z-Score ($Z_t = \frac{x_t - \mu_t}{\sigma_t}$).
  3. Evaluates first-order rate-of-change ($\frac{\Delta x}{\Delta t}$) to identify sudden traffic volume inflection points.
  4. Flags temporal bursts (rapid authentication failures, HTTP 5xx error waves, port sweeps, C2 beaconing pulses).
- **Outputs:** `List[Anomaly]` (with `method = DetectionMethod.TEMPORAL`), temporal metrics dictionary.
- **Technologies:** Python `datetime`, NumPy, statistical moving-window algorithms.
- **Safety Constraints:** Causal forward-pass processing only; future lookahead is prohibited to prevent data leakage.

---

## Module 4: Incident Triage

- **Purpose:** Consolidates isolated anomalies into actionable, contextual security incident cases to reduce SOC alert fatigue.
- **Inputs:** `List[Anomaly]`, `List[LogEntry]`, `session_id`.
- **Processing:**
  1. Clusters concurrent anomalies sharing common attributes (source IP, targeted user, destination host, service).
  2. Classifies incident category (`AUTHENTICATION_FAILURE`, `PRIVILEGE_ESCALATION`, `COMMAND_INJECTION`, `OUTBOUND_C2`, `DATA_EXFILTRATION`, `DENIAL_OF_SERVICE`).
  3. Determines aggregated severity based on peak anomaly score and event density.
  4. Generates an explainable title, operational description, root-cause hypothesis, and prescriptive remediation steps.
- **Outputs:** `List[Incident]`.
- **Technologies:** Python domain logic, rule-based incident aggregation heuristics.
- **Safety Constraints:** Incident creation preserves all contributing anomaly IDs; automated triage never deletes underlying anomaly records.

---

## Module 5: Attack Chain Reconstruction

- **Purpose:** Reconstructs multi-stage attack narratives by correlating incidents chronologically across the MITRE ATT&CK matrix.
- **Inputs:** `List[LogEntry]`, `List[Anomaly]`, `List[Incident]`, `session_id`.
- **Processing:**
  1. Maps individual incidents to MITRE ATT&CK tactics (Reconnaissance, Initial Access, Execution, Persistence, Privilege Escalation, Command and Control, Exfiltration).
  2. Evaluates inter-incident causal links using shared IP addresses, entity overlap, and temporal progression rules.
  3. Synthesizes a directed attack progression graph with nodes (incidents/events) and edges (transitions).
  4. Computes chain severity and confidence metrics based on path length and corroborating evidence.
- **Outputs:** `List[AttackChain]`, graph visualization structures.
- **Technologies:** Python network algorithms, MITRE ATT&CK taxonomy mapping.
- **Safety Constraints:** Chronological causality invariant: an event occurring at $T_2$ cannot serve as a prerequisite cause for an event at $T_1 < T_2$.

---

## Module 6: IOC Intelligence

- **Purpose:** Extracts, normalizes, validates, and manages Indicators of Compromise (IOCs) while maintaining append-only forensic evidence links.
- **Inputs:** `List[LogEntry]`, `List[Anomaly]`, `List[Incident]`, `List[AttackChain]`.
- **Processing:**
  1. **Extraction:** Applies specialized regex patterns across 9 IOC categories: IPv4, IPv6, Domain, URL, MD5, SHA1, SHA256, Email, File Path.
  2. **Deduplication:** Groups multiple observations by canonical identity `(ioc_type, normalized_value)`.
  3. **RFC Normalization:** Strips leading zeros in IPv4 octets, applies RFC 5952 compression on IPv6, case-folds domains, strips default HTTP/HTTPS ports.
  4. **Validation:** Assigns structural validation statuses (`VALID`, `INVALID`, `SUSPICIOUS`).
  5. **Evidence Mapping:** Generates `IOCEvidence` records containing exact `event_id`, `session_id`, `timestamp`, and `line_number`.
- **Outputs:** `List[IOC]`, updated `IOCRepository`.
- **Technologies:** Python `ipaddress`, `urllib.parse`, Pydantic v2.
- **Safety Constraints:** Separation of concerns: structural validation status (`ValidationStatus`) is decoupled from analyst workflow status (`IOCStatus`), which can only be modified by authorized human operators.

---

## Module 7: Threat Intelligence

- **Purpose:** Queries external and offline threat reputation providers to enrich indicators with global intelligence telemetry.
- **Inputs:** `IOC`, optional `provider_name`, `force_refresh` flag.
- **Processing:**
  1. Interrogates thread-safe deterministic in-memory TTL cache (`ThreatIntelService`).
  2. Dispatches lookup to registered providers:
     - `OfflineMockThreatIntelProvider`: In-memory deterministic threat database for air-gapped environments.
     - `VirusTotalProvider`: Authenticated HTTP REST client querying the VirusTotal v3 API.
  3. Enforces rate-limiting backoff and quota headers (`Retry-After` on HTTP 429).
  4. Applies the **Telemetry Deficit Invariant**: HTTP 404 responses map strictly to `ThreatIntelStatus.UNKNOWN`, never `CLEAN`.
  5. Scrubs API keys and tokens from all error messages and serialization outputs.
- **Outputs:** `ThreatIntelResult`.
- **Technologies:** `httpx` asynchronous HTTP client, Python `threading.Lock`.
- **Safety Constraints:** Zero network requests are permitted when operating under offline mock configuration; secret credentials are sanitized before logging.

---

## Module 8: Threat Assessment

- **Purpose:** Evaluates raw threat intelligence telemetry to compute explainable threat reputation scores and independent confidence ratings.
- **Inputs:** `ThreatIntelResult`.
- **Processing:**
  1. Evaluates structured contributing signals (detection ratios, engine consensus, malicious category weights, reputation flags).
  2. Computes the **Threat Score** ($0.0–100.0$):
     $$\text{ThreatScore} = \text{clamp}\left(\sum w_i \cdot s_i, 0.0, 100.0\right)$$
  3. Computes the **Threat Confidence** ($0.0–1.0$) based on engine depth and provider credibility.
  4. Maps scores to categorical severity tiers (`UNKNOWN`, `LOW`, `MEDIUM`, `HIGH`, `CRITICAL`).
  5. Generates human-readable explanatory reasons for each contributing signal.
- **Outputs:** `ThreatAssessment`.
- **Technologies:** Deterministic mathematical scoring engine, Pydantic v2.
- **Safety Constraints:** Invariant: Threat Score and Threat Confidence are decoupled. High threat score with low confidence (e.g., single-engine detection) is preserved without artificial inflation.

---

## Module 9: Threat Correlation

- **Purpose:** Establishes directional, evidence-backed relationships across IOCs, raw log events, anomalies, incidents, and attack chains into a consolidated context.
- **Inputs:** `IOC`, optional `ThreatAssessment`, `ThreatIntelResult`.
- **Processing:**
  1. Computes directional relationships (`IOC_TO_EVENT`, `IOC_TO_ANOMALY`, `IOC_TO_INCIDENT`, `IOC_TO_ATTACK_CHAIN`).
  2. Evaluates link confidence based on explicit IDs, shared events, and temporal windows ($\le 30\text{s}$, $30\text{s}–5\text{m}$, $5\text{m}–15\text{m}$, $>15\text{m}$).
  3. Applies cross-session safeguards: unconfirmed cross-session links receive a $0.40$ penalty multiplier and `confirmed = False`.
  4. Derives bridges from Threat Assessments to Incidents and Attack Chains.
  5. Assembles the `UnifiedThreatContext` containing all related entities, correlation records, and factual investigation metrics.
- **Outputs:** `UnifiedThreatContext`, `List[ThreatCorrelation]`.
- **Technologies:** Relational correlation algorithms, graph traversal.
- **Safety Constraints:** Core design principle: **Correlation is NOT Classification**. Automated correlation never modifies `IOCStatus`, `Incident.severity`, or `AttackChain.status`.

---

## Module 10: SOC Investigation

- **Purpose:** Delivers a comprehensive web-based Security Operations Center dashboard enabling human analysts to explore, filter, audit, and triage security telemetry.
- **Inputs:** FastAPI REST endpoints, WebSocket streams.
- **Processing:**
  1. Visualizes real-time metrics, anomaly distributions, and incident queues.
  2. Renders interactive attack chain timelines and directed acyclic progression graphs.
  3. Provides an interactive IOC management workspace with evidence inspection and status transition workflows.
  4. Hosts the dedicated Threat Intelligence SOC dashboard (`/threat-intelligence`) displaying unified correlation context, threat scores, and contributing signals.
- **Outputs:** Interactive React/Next.js UI views across 15 routes.
- **Technologies:** Next.js 16 (App Router), React 19, TypeScript, Tailwind CSS, Lucide React icons.
- **Safety Constraints:** React auto-escaping natively prevents XSS injection; zero use of `dangerouslySetInnerHTML`.

---

## Module 11: Persistence

- **Purpose:** Provides durable, restart-resilient storage across application lifecycles with pluggable backend implementations.
- **Inputs:** Domain entities (`LogSession`, `LogEntry`, `Anomaly`, `Incident`, `AttackChain`, `IOC`, `ThreatAssessment`, etc.).
- **Processing:**
  1. Manages a 12-table relational database schema via SQLAlchemy.
  2. Implements connection pooling, transaction isolation, and foreign-key cascade constraints.
  3. Supports three operational backends:
     - `memory`: High-speed ephemeral dictionary store for testing.
     - `sqlite`: File-based relational storage with zero external dependencies.
     - `postgres`: Enterprise-grade PostgreSQL/Supabase database for production deployments.
  4. Sanitizes database connection URLs (`sanitize_db_url`) to redact credentials in logs and readiness checks.
- **Outputs:** Durable disk records, query result collections.
- **Technologies:** SQLAlchemy 2.0+, SQLite3, PostgreSQL dialect, Pydantic v2.
- **Safety Constraints:** Process restart test guarantees zero data loss; foreign-key relationships prevent orphaned child entities.

---

## Module 12: Audit Reporting

- **Purpose:** Generates cryptographically verifiable, high-fidelity PDF audit reports of security incidents, attack chains, and forensic evidence for regulatory compliance.
- **Inputs:** `session_id`, `title`, incident and anomaly query collections.
- **Processing:**
  1. Aggregates complete session telemetry (raw event count, detected anomalies, reconstructed incidents, attack chains, extracted IOCs).
  2. Formats tabular summaries, severity distributions, and remediation recommendations.
  3. Compiles document flowables using ReportLab Platypus.
  4. Generates a standalone PDF artifact saved to the reports directory with automated download URL generation.
- **Outputs:** Portable Document Format (`.pdf`) binary files starting with `%PDF` magic bytes.
- **Technologies:** ReportLab 4.2+, Python `io.BytesIO`.
- **Safety Constraints:** Report compilation is read-only; output documents are sanitized to prevent secret or password leakage.

