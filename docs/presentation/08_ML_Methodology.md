# Slide 08: Machine Learning Methodology

## Hybrid Multi-Model Ensemble

---

### Key Points
- **Isolation Forest (Spatial Isolation):**
  - Isolates structural outliers on numeric feature vectors: length, numeric density, Shannon character entropy:
    $$H(m) = -\sum p(c_i)\log_2 p(c_i)$$
  - Anomaly score $s(x, n) = 2^{-\frac{\mathbb{E}(h(x))}{c(n)}}$; shorter path length = higher anomaly.
- **TF-IDF Semantic Dispersion:**
  - Tokenizes log messages; weights rare vocabulary and exploit syntax (e.g., `UNION SELECT`, `chmod 777`).
- **Statistical Z-Score Model:**
  - Flags extreme quantitative deviations ($Z \ge 2.5$).
- **Deterministic Rules & Fusion:**
  - Guaranteed $100\%$ precision on verified signatures; fuses outputs into a normalized score ($0.0–1.0$).

---

### Suggested Visual
- Diagram showing an Isolation Tree splitting an outlier near the root compared to a deep normal path, alongside TF-IDF vector weights.

---

### Presenter Notes
"Rather than relying on a single black-box model, we combine Isolation Forest for structural anomalies, TF-IDF for semantic vocabulary outliers, Z-scores for volume spikes, and deterministic rules for verified exploits."

