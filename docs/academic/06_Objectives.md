# CHAPTER 6: OBJECTIVES

## 4.1 Primary Objective
The primary objective of this project is to research, design, develop, empirically evaluate, and document **MICHAEL – THE GUARDIAN AI**: an intelligent, production-hardened log analysis, anomaly detection, and threat correlation platform that bridges raw telemetry with actionable SOC cyber defense.

## 4.2 Specific Technical Objectives
1. **Multi-Format Ingestion:** Develop an extensible log parsing service capable of ingesting and normalizing Syslog, SSHD, Nginx, Linux Kernel, and CSV/TXT logs with $100\%$ raw line preservation.
2. **Hybrid Anomaly Detection:** Implement an explainable multi-model detection ensemble combining unsupervised Isolation Forest spatial isolation, TF-IDF semantic dispersion, statistical Z-score thresholds, and deterministic heuristic rules.
3. **Temporal Intelligence:** Design a multi-scale sliding-window temporal engine ($10\text{s}$, $30\text{s}$, $60\text{s}$, $300\text{s}$) that captures rolling statistics and volumetric burst attacks.
4. **Incident & Attack Chain Derivation:** Develop algorithmic clustering to group concurrent anomalies into structured `Incident` entities and synthesize chronological `AttackChain` graphs mapped to MITRE ATT&CK tactics.
5. **Forensic IOC Normalization & Evidence Mapping:** Implement canonical extraction, RFC normalization (IPv4/IPv6/URL/Domain), and append-only evidence linking across 9 indicator classes while preserving analyst triage sovereignty.
6. **Deterministic Threat Intelligence & Reputation:** Implement a pluggable provider interface supporting both air-gapped offline mock data and live VirusTotal v3 lookups; enforce the `UNKNOWN != CLEAN` invariant; decouple Threat Score ($0–100$) from Threat Confidence ($0–1$).
7. **Directional Threat Correlation:** Form directional evidence relationships connecting IOCs, events, anomalies, incidents, and attack chains into a consolidated `UnifiedThreatContext` under strict cross-session safety constraints ($0.40$ penalty multiplier).
8. **Enterprise Persistence:** Engineer a 12-table relational database schema supporting In-Memory, SQLite, and PostgreSQL modes with zero data loss across process termination.
9. **SOC Web Interface & Forensic PDF Reporting:** Build a responsive 15-route Next.js 16 SOC dashboard and automated ReportLab PDF audit generator.
10. **Validation & Security Auditing:** Verify $100\%$ passing status across a $\ge 400$-test regression suite and conduct a comprehensive 12-vector defensive security audit.

