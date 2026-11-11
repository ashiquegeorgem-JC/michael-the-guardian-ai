# Slide 07: System Architecture & Decomposition

## Decoupled, Multi-Tier Engineering Topology

---

### Key Points
- **Tier 1 (Ingestion):** Multi-format parser, UTC standardisation, session boundary enforcement.
- **Tier 2 (Detection):** Isolation Forest + TF-IDF + Z-Score + Rule Engine + Temporal Windows.
- **Tier 3 (Aggregation):** Entity clustering, Incident derivation, MITRE ATT&CK chain engine.
- **Tier 4 (IOC & Intelligence):** Canonical RFC normalizer, Evidence mapper, VirusTotal + Mock providers, Reputation scoring.
- **Tier 5 (Threat Correlation):** 6 directional relationship models, UnifiedThreatContext builder.
- **Tier 6 (Persistence & UI):** 12-table relational schema (Memory/SQLite/Postgres), 15-route Next.js SOC interface, PDF reporter.

---

### Suggested Visual
- Layered architectural diagram showing the 6 tiers and data flow.

---

### Presenter Notes
"Our architecture is strictly modular. Each layer operates through clean interfaces, decoupling ingestion, machine learning, threat intelligence, and persistence so that components can scale and adapt independently."

