# Slide 11: Threat Intelligence & Reputation Scoring

## Decoupled Scoring & Defending Against Telemetry Deficits

---

### Key Points
- **Pluggable Provider Architecture:**
  - `OfflineMockThreatIntelProvider`: Deterministic in-memory database for air-gapped zero-network environments.
  - `VirusTotalProvider`: Authenticated v3 REST API with rate-limiting backoff.
- **The Core Invariant: `UNKNOWN != CLEAN`:**
  - Missing records (HTTP 404) map strictly to `UNKNOWN`. Absence of evidence is NOT evidence of innocence.
- **Decoupled Threat Score vs. Confidence:**
  - **Threat Score ($0.0–100.0$):** Magnitude of malicious behavior.
  - **Threat Confidence ($0.0–1.0$):** Depth and credibility of supporting telemetry.
- **Explainable Contributing Signals:**
  - Decomposes scores into verifiable signal points and explanatory reasons.

---

### Suggested Visual
- Diagram showing 404 response routing to UNKNOWN, alongside a card comparing high-score/low-confidence vs. clean/high-confidence scenarios.

---

### Presenter Notes
"A major contribution of our work is addressing the telemetry deficit trap. If an external provider has no record of an IP, we strictly classify it as UNKNOWN, never CLEAN. Furthermore, we decouple the threat score from confidence."

