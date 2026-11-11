# PROBLEM STATEMENT

**Project:** MICHAEL – THE GUARDIAN AI  
**Academic Title:** Intelligent Log Analysis and Anomaly Detection Using Artificial Intelligence  

---

## 1. Context & Operational Challenges

Security Operations Centers (SOCs) are tasked with maintaining visibility and defensive resilience across an increasingly fragmented enterprise footprint. In this environment, infrastructure components—operating system kernels, web servers, authentication daemons, firewalls, and microservices—generate billions of unstructured log events every day. 

Despite the widespread adoption of traditional Security Information and Event Management (SIEM) solutions, security teams face persistent systemic challenges that degrade triage velocity and leave organizations vulnerable to compromise.

---

## 2. Specific Problem Dimensions

### 2.1 The Volume and Velocity Dilemma
Manual log review has become intractable. Human analysts cannot review raw logs numbering in the tens of thousands per minute. Consequently, organizations either truncate log retention or rely on coarse sampling, discarding vital forensic evidence.

### 2.2 Alert Fatigue and High False-Alarm Ratios
Traditional SIEM tools rely heavily on static threshold rules (e.g., "more than 5 failed logins within 60 seconds"). Such rules suffer from two fundamental weaknesses:
1. **False Positives:** Legitimate operational anomalies (e.g., network latency spikes, automated batch jobs, misconfigured client credentials) trigger high volumes of priority alarms.
2. **False Negatives:** Stealthy "low-and-slow" attackers deliberately operate below static thresholds, evading detection entirely.

### 2.3 Context-Free Anomaly Detection
Unsupervised machine learning algorithms (e.g., clustering, basic density estimators) are capable of flagging statistical outliers in log text. However, standalone ML detectors typically emit an abstract numerical score (e.g., "anomaly score: 0.94") without explaining:
- What specific token or entity was unusual.
- Which preceding or subsequent events related to this behavior.
- Whether the anomaly corresponds to a recognized adversarial attack tactic.

### 2.4 Fragmented Threat Intelligence and False-Safe Assumptions
When indicators (IP addresses, domain names, file hashes) are extracted from logs, analysts must manually submit them to disparate external threat intelligence platforms. This manual process introduces several vulnerabilities:
1. **Telemetry Deficit Misinterpretation:** When a threat feed returns a "404 Not Found" or empty record for an indicator, naive systems erroneously classify the entity as "Clean" or "Benign." In reality, a missing record indicates an absence of intelligence (`UNKNOWN`), not proof of innocence.
2. **Conflating Severity with Confidence:** A high threat score derived from a single untrusted source is fundamentally different from a high threat score corroborated by fifty industry antivirus engines. Failing to decouple threat score from confidence skews incident prioritization.

### 2.5 Disconnected Investigation Lifecycles & Destructive Workflows
Existing security tools frequently create artificial conclusions or mutate human analyst triage decisions. If an automated process correlates an indicator to an incident, it may improperly escalate the incident's severity or mark an unverified IP as malicious. Automated correlation must act as an evidence provider, not a final adjudicator.

---

## 3. Formal Problem Statement

> **How can an autonomous security monitoring architecture ingest heterogeneous system logs, reliably detect statistical, semantic, and temporal anomalies with minimal false positives, correlate disparate security objects into coherent multi-stage attack narratives, and enrich indicators with deterministic threat intelligence while strictly preserving forensic evidence immutability and analyst triage sovereignty?**

---

## 4. Architectural Requirements Addressed by MICHAEL

1. **Heterogeneous Ingestion:** Seamless normalization of Syslog, Web, SSH, Firewall, and Application logs.
2. **Explainable Hybrid ML:** Multi-model detection combining Isolation Forest, TF-IDF, Z-scores, and rule heuristics.
3. **Temporal Awareness:** Multi-scale sliding window metrics capturing rate-of-change and burst anomalies.
4. **Automated Synthesis:** Reconstruction of MITRE ATT&CK chains and incident grouping without manual intervention.
5. **Strict Forensic Invariants:** Separation of Threat Score from Confidence, preservation of `UNKNOWN != CLEAN`, and non-destructive additive correlation.
6. **Enterprise Resilience:** Deterministic zero-data-loss relational persistence across process restarts.

