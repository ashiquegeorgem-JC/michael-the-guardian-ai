# Slide 19: Demonstration Architecture & Live Flow

## Reproducible End-to-End Validation

---

### Key Points
- **Scenario A (Baseline):** Routine logs $\to$ Normal telemetry, zero false alarms.
- **Scenario B (Brute Force):** SSH burst $\to$ Rule & Temporal Z-score detection $\to$ Incident creation.
- **Scenario C (C2 Outbound):** Beaconing pattern $\to$ Threat Intelligence lookup $\to$ Threat Score $85.0$.
- **Scenario D (Multi-Stage Intrusion):** SQLi $\to$ Dropper $\to$ Exfiltration $\to$ MITRE Attack Chain Graph.
- **Scenario E (Telemetry Deficit):** Unrecognized IP $\to$ Provider 404 $\to$ Strict `UNKNOWN` rating ($\text{UNKNOWN} \ne \text{CLEAN}$).
- **Compliance Export:** One-click automated forensic PDF report generation.

---

### Suggested Visual
- Flowchart mapping the 5 demonstration scenarios through the ingestion, detection, and SOC visualization tiers.

---

### Presenter Notes
"We have prepared five deterministic demonstration scenarios that take you through the complete pipeline: from normal baseline operations and brute-force bursts to multi-stage attack chains and proving our UNKNOWN != CLEAN invariant."

