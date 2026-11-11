# Slide 04: Project Objectives

## Ten Core Engineering Goals

---

### Key Points
1. **Multi-Format Ingestion:** Syslog, SSH, Nginx, Linux Kernel, and CSV/TXT with $100\%$ raw line preservation.
2. **Hybrid Anomaly Detection:** Isolation Forest + TF-IDF semantic dispersion + Statistical Z-scores + Rule heuristics.
3. **Temporal Intelligence:** 4 sliding window horizons ($10\text{s}$, $30\text{s}$, $60\text{s}$, $300\text{s}$) for burst and rate-of-change detection.
4. **Attack Chain Synthesis:** Automated incident clustering and MITRE ATT&CK progression reconstruction.
5. **RFC IOC Normalization:** Canonical extraction and evidence mapping across 9 indicator classes.
6. **Telemetry Deficit Protection:** Strict invariant mapping $404 \implies \text{UNKNOWN} \ne \text{CLEAN}$.
7. **Decoupled Scoring:** Independent Threat Score ($0–100$) and Threat Confidence ($0–1$).
8. **Non-Destructive Correlation:** "Correlation is NOT Classification"; zero state mutation.
9. **Relational Persistence:** 12-table schema with zero data loss across process termination.
10. **Modern SOC Workspace:** 15-route responsive Next.js dashboard and automated PDF audit generation.

---

### Suggested Visual
- Circular checklist icon grid highlighting the 10 core engineering milestones.

---

### Presenter Notes
"We formulated ten precise engineering objectives spanning the complete lifecycle: from parsing heterogeneous logs to machine learning anomaly detection, MITRE attack-chain synthesis, threat intelligence, and enterprise persistence."

