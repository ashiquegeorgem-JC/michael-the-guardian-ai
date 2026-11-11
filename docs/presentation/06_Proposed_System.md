# Slide 06: The Proposed System: MICHAEL

## Intelligent Log Analysis and Anomaly Detection Using AI

---

### Key Points
- **Hybrid Multi-Model Ensemble:** Combines unsupervised tree partitioning with NLP semantic dispersion and deterministic exploit rules.
- **Dynamic Temporal Sliding Windows:** Evaluates rolling mean, std dev, EMA, and rate-of-change across 10s, 30s, 60s, and 300s.
- **Automated Incident & Chain Synthesis:** Connects anomalies into multi-stage attack narratives mapped to MITRE ATT&CK.
- **Forensic Evidence Provenance:** Preserves append-only line-number references back to source log lines.
- **Sovereign Non-Destructive Correlation:** Provides unified investigation context without mutating analyst workflow states.

---

### Suggested Visual
- High-level block diagram illustrating the unified MICHAEL pipeline from Raw Logs to the SOC Dashboard.

---

### Presenter Notes
"MICHAEL proposes an evidence-driven architecture. We don't just alert that an anomaly occurred; we explain what happened, link it to related events, correlate it with threat intelligence, and project it onto the MITRE ATT&CK matrix."

