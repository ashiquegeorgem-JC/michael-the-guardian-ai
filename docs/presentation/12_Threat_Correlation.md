# Slide 12: Threat Correlation & Unified Context

## Non-Destructive, Evidence-Based Investigation

---

### Key Points
- **Cardinal Rule: Correlation is NOT Classification:**
  - Automated correlation adds evidence; it NEVER automatically modifies `IOCStatus`, `Incident.severity`, or `AttackChain.status`.
- **6 Directional Relational Models:**
  - `IOC_TO_EVENT`, `IOC_TO_ANOMALY`, `IOC_TO_INCIDENT`, `IOC_TO_ATTACK_CHAIN`
  - `THREAT_ASSESSMENT_TO_INCIDENT`, `THREAT_ASSESSMENT_TO_ATTACK_CHAIN`
- **Calibrated Temporal Proximity Windows:**
  - $\le 30\text{s}$ (Immediate: $0.40$), $30\text{s}–5\text{m}$ (Short: $0.30$), $5\text{m}–15\text{m}$ (Extended: $0.20$), $>15\text{m}$ (Rejected).
- **Cross-Session Safeguards:**
  - Unconfirmed cross-session correlations receive a $0.40$ penalty multiplier and `confirmed=False`.
- **`UnifiedThreatContext`:** Single consolidated investigation context for the SOC analyst.

---

### Suggested Visual
- Network graph illustrating an IOC connecting to events, anomalies, incidents, and MITRE attack-chain stages.

---

### Presenter Notes
"Correlation must assist, not overwrite, the analyst. We enforce that correlation is never classification. We derive six directional relationships with strict temporal bounds and cross-session penalties to prevent false links."

