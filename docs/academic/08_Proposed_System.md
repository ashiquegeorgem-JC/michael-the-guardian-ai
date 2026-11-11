# CHAPTER 8: PROPOSED SYSTEM: MICHAEL – THE GUARDIAN AI

## 6.1 Architectural Vision
The proposed system, **MICHAEL – THE GUARDIAN AI**, overcomes the deficiencies of traditional log analysis by establishing an integrated, multi-tier defense architecture:

```text
Log Ingestion ──▶ Multi-Model Anomaly Detection ──▶ Temporal Intelligence
                                                           │
                                                           ▼
SOC UI ◀── Correlation ◀── Threat Reputation ◀── Attack Chains & Incidents
```

## 6.2 Key Architectural Innovations

### 1. Explainable Hybrid Anomaly Detection
MICHAEL rejects the trade-off between rule-based precision and machine learning generalization. The platform fuses four complementary analytical models:
- **Isolation Forest:** Evaluates spatial isolation across message entropy, token density, and length.
- **TF-IDF Semantic Dispersion:** Identifies rare vocabulary and exploit syntax.
- **Statistical Z-Score:** Flags volumetric numerical outliers.
- **Heuristic Rule Engine:** Guarantees $100\%$ precision on verified critical exploit signatures.
- **Ensemble Fusion:** Combines model scores into an explainable, normalized score ($0.0–1.0$).

### 2. Multi-Scale Temporal Behaviour Intelligence
Rather than relying on fixed static time intervals, MICHAEL implements four concurrent sliding windows ($10\text{s}$, $30\text{s}$, $60\text{s}$, $300\text{s}$) to monitor rolling statistics (mean, std dev, EMA, Z-score) and first-order rates of change. This enables the autonomous detection of rapid brute-force surges and periodic C2 beaconing.

### 3. Automated Incident & Attack Chain Synthesis
Anomalies occurring on shared entities are automatically aggregated into structured `Incident` records with root-cause hypotheses and remediation steps. Incidents are further synthesized into chronological directed acyclic graphs (`AttackChain`) mapped to the MITRE ATT&CK matrix.

### 4. RFC-Compliant Canonical IOC Intelligence
Indicators are canonicalized using strict RFC standards (IPv4 zero-stripping, IPv6 RFC 5952 compression, domain case-folding, URL default port stripping). Append-only evidence references (`IOCEvidence`) preserve unbroken links back to exact raw log line numbers.

### 5. Telemetry Deficit Defense & Decoupled Scoring
External threat intelligence queries strictly enforce the invariant that $404\text{ Not Found}$ maps to `ThreatIntelStatus.UNKNOWN`, never `CLEAN`. Furthermore, Threat Score ($0–100$) and Threat Confidence ($0–1$) are calculated independently.

### 6. Non-Destructive Threat Correlation
Automated correlation operates under the rule that "Correlation is NOT Classification." Directional evidence relationships are established without mutating human analyst triage statuses (`IOCStatus`).

### 7. Pluggable Enterprise Persistence & Modern SOC Dashboard
A 12-table relational schema guarantees zero data loss across process termination in SQLite and PostgreSQL modes, while a responsive 15-route Next.js SOC interface provides single-pane investigation.

