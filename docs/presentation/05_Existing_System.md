# Slide 05: Existing Systems vs. Operational Reality

## The Limitations of Legacy Monitoring

---

### Key Points
- **Brittle Regex Parsers:** Break upon encountering minor delimiter changes or modern container JSON headers.
- **Static Threshold Alerts:** Generate massive false-positive volumes (e.g., promotional traffic flagged as DDoS).
- **Point-Based Blindness:** Evaluating logs in isolation misses time-series bursts, brute-force surges, and periodic beaconing.
- **Dangerous Coercion:** Missing intelligence records ($404$) are naively coerced to "Clean," allowing zero-day C2 to slip through.
- **Destructive Mutation:** Automated tools often overwrite ticket severities without analyst corroboration.

---

### Suggested Visual
- Comparison table summarizing Legacy SIEMs vs. Modern Threat Environment realities.

---

### Presenter Notes
"Traditional SIEM platforms were designed for compliance auditing, not modern real-time defense. They rely on brittle static thresholds that drown analysts in noise while remaining vulnerable to stealthy low-and-slow campaigns."

