# EXISTING VS. PROPOSED SYSTEM

**Project:** MICHAEL – THE GUARDIAN AI  
**Academic Title:** Intelligent Log Analysis and Anomaly Detection Using Artificial Intelligence  

---

## 1. Overview

This document provides a comparative analysis contrasting traditional cybersecurity log monitoring solutions (legacy SIEMs, rule-based syslog collectors, point anomaly detectors) with the architecture implemented in **MICHAEL – THE GUARDIAN AI**.

Claims presented herein reflect empirical observations and the verified implementation boundaries established during controlled testing.

---

## 2. Comparative Analysis Table

| Capability Area | Existing / Traditional Approach | Proposed System (MICHAEL) | Architectural Benefit in MICHAEL |
|---|---|---|---|
| **Log Ingestion & Parsing** | Format-specific regex parsers that break on minor delimiter variations or novel microservice headers. | Modular multi-format parser supporting Syslog, SSH, Nginx, Linux Kernel, CSV, and plain text with line-indexed tracking. | Robust ingestion across heterogeneous infrastructure without discarding unrecognized lines. |
| **Anomaly Detection** | Static threshold alerts (e.g., $>5$ failures/min) or black-box single-model ML detectors. | Hybrid Ensemble: Unsupervised Isolation Forest + TF-IDF semantic dispersion + Statistical Z-scores + Deterministic Heuristics. | High precision on known threats combined with high recall on novel zero-day syntactic anomalies. |
| **Temporal Dynamics** | Static time windows (fixed 5-minute aggregation buckets) blind to sliding burst patterns. | Multi-scale sliding windows (10s, 30s, 60s, 300s) computing rolling mean, std dev, EMA, and rate-of-change. | Detects rapid brute-force surges and volumetric spikes while respecting sub-minute temporal boundaries. |
| **Incident Triage** | Alerts emitted individually; analysts manually correlate related alerts across disjoint screens. | Automatic grouping of related anomalies into structured `Incident` entities with impact assessment and root cause hypotheses. | Alleviates SOC alert fatigue by consolidating alerts into actionable investigation cases. |
| **Attack Chain Reconstruction** | Manual cross-referencing of logs against the MITRE ATT&CK matrix; external diagramming tools. | Automated reconstruction of multi-stage chronological progressions (`AttackChain`) with MITRE tactic mapping and graph visualization. | Provides immediate visibility into end-to-end intrusion campaigns from Initial Access to C2. |
| **IOC Processing** | Ad-hoc regex extraction; non-standardized values; no validation or evidence provenance. | Canonical extraction, strict RFC normalization (IPv4/IPv6/URL/Domain), validation tiers, and append-only evidence linking (`IOCEvidence`). | Eliminates duplicate entries and ensures every indicator links to exact raw log line numbers. |
| **Threat Intelligence** | Manual lookup on external portals or naive API calls; missing records often treated as "Clean". | Pluggable providers (`OfflineMock` + `VirusTotal`); strict invariant: missing records ($404$) map to `UNKNOWN`, never `CLEAN`. | Prevents catastrophic false-negative classifications caused by telemetry deficits. |
| **Scoring & Confidence** | Conflates severity with confidence into a single opaque rating (e.g., "7/10 threat"). | Decouples Threat Score ($0–100$) from Threat Confidence ($0–1$); explicit contributing signal decomposition. | Analysts can distinguish between a confirmed minor threat and a tentative critical threat. |
| **Context Correlation** | Automated systems often mutate entity states (e.g., automatically marking an incident critical because an IP was looked up). | Non-destructive, evidence-based directional correlation; derives `UnifiedThreatContext` while preserving analyst triage states. | Adheres to "Correlation is NOT Classification," ensuring AI assists rather than overwrites human authority. |
| **State Persistence** | Many research prototypes are strictly ephemeral, losing all state upon process restart. | 12-table relational schema supporting In-Memory, SQLite, and PostgreSQL with zero data loss across restarts. | Production-grade operational durability suitable for multi-day investigation lifecycles. |
| **SOC Interface & Reporting** | Fragmented command-line utilities, raw JSON outputs, or generic BI dashboards. | Dedicated 15-route responsive Next.js SOC workspace with interactive graphs, drill-down timelines, and forensic PDF generation. | Purpose-built for security analysts, accelerating triage from hours to minutes. |

---

## 3. Detailed Architectural Differentiators

### 3.1 Non-Destructive Evidence-Based Correlation
In conventional SIEMs, correlation rules often execute destructive state mutations—overwriting ticket severities, auto-closing incidents, or blindly flagging assets as compromised. MICHAEL enforces a strict separation:
$$\text{Correlation} \ne \text{Classification}$$
Correlating an indicator adds evidence bullets, updates confidence metrics, and links entities, but leaves the analyst's lifecycle status (`EXTRACTED`, `UNDER_REVIEW`, `CONFIRMED`, `FALSE_POSITIVE`) completely under human control.

### 3.2 Telemetry Deficit Defense
Traditional platforms that ingest threat intelligence frequently evaluate a `404 Not Found` response as a signal that the indicator is harmless. In adversarial operations, newly registered domains and novel attacker IP addresses have zero historical presence in commercial threat feeds. MICHAEL strictly maps:
$$\text{HTTP } 404 \implies \text{ThreatIntelStatus.UNKNOWN}$$
$$\text{UNKNOWN} \implies \text{ThreatScore} = 0.0, \quad \text{Confidence} = 0.0$$
This ensures security analysts are explicitly notified that an entity lacks intelligence rather than being falsely assured it is safe.

### 3.3 Explainable Contributing Signals
Rather than outputting an opaque scalar score, MICHAEL's Threat Reputation Engine decomposes every score into an array of verifiable `ContributingSignal` objects. Each signal details the rule name, point contribution, category, and textual justification, enabling analysts to audit why an indicator received its score.

