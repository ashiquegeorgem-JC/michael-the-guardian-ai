# Slide 16: Empirical Results & Benchmarks

## Controlled Synthetic Validation Outcomes

---

### Key Points
- **Detection Accuracy (N=190 Benchmark):**
  - **MICHAEL Hybrid Ensemble:** **$94.21\%$ Accuracy**, **$92.75\%$ Precision**, **$91.43\%$ Recall**, **$0.9209$ F1-Score**, **$0.9927$ ROC-AUC**.
  - Isolated $100\%$ of previously unseen zero-day exploit patterns.
- **Persistence Scaling (SQLite File Mode):**
  - Sustained bulk ingestion: **$8,290$ to $10,559$ log events/second**.
  - Point-read latency: **$0.49\text{ms}$ to $0.81\text{ms}$**.
  - Process restart data recovery: **$100\%$ zero data loss**.
- **Threat Intelligence & Context Velocity:**
  - Reputation scoring: $0.1125\text{ms}$ per assessment ($\sim 8,889\text{ ops/sec}$).
  - Unified context assembly: $9.33\text{ms}$ average traversal latency.

---

### Suggested Visual
- Bar chart comparing F1-Scores across Heuristics (0.44), Statistical (0.08), Isolation Forest (0.85), and MICHAEL Hybrid (0.92).

---

### Presenter Notes
"In controlled synthetic evaluations, our hybrid ensemble achieved an F1-score of 0.9209 and an ROC-AUC of 0.9927. In persistence benchmarks, the platform ingested over 8,000 logs a second with sub-millisecond query lookups."

