# CHAPTER 13: RESULTS & PERFORMANCE EVALUATION

## 11.1 Detection Performance (Controlled Benchmark)
The anomaly detection architectures were benchmarked against a strictly partitioned, held-out dataset of 190 log entries ($N=190$, 120 normal, 70 anomalous) across 10 distinct operational and threat classes under anti-leakage spatial and temporal separation:

```text
====================================================================================
               BENCHMARK COMPARISON: DETECTION ARCHITECTURES (N=190)
====================================================================================
Model Architecture           | Accuracy | Precision | Recall   | F1-Score | ROC-AUC
-----------------------------|----------|-----------|----------|----------|--------
Deterministic Heuristic Rules| 73.68%   | 100.00%   | 28.57%   | 0.4444   | 0.6429
Statistical Z-Score Model    | 64.74%   | 100.00%   | 4.29%    | 0.0822   | 0.5214
Isolation Forest (Standalone)| 88.95%   | 87.88%    | 82.86%   | 0.8529   | 0.9452
MICHAEL Hybrid Multi-Model   | 94.21%   | 92.75%    | 91.43%   | 0.9209   | 0.9927
====================================================================================
```

### Empirical Observations:
- **Heuristic Rules:** Attained perfect precision ($100\%$) on known signatures, but exhibited poor recall ($28.57\%$) when exposed to novel zero-day patterns.
- **Statistical Model:** Captured volumetric spikes, but was ineffective on semantic code exploits ($4.29\%$ recall).
- **MICHAEL Hybrid Multi-Model:** Synthesized structural tree partitioning with semantic dispersion and deterministic rules, achieving **$94.21\%$ Accuracy**, **$92.75\%$ Precision**, **$91.43\%$ Recall**, and **$0.9927$ ROC-AUC**, successfully isolating $100\%$ of previously unseen zero-day patterns.

## 11.2 Ingestion & Persistence Throughput (Phase 5.0 Benchmarks)
Persistence throughput was evaluated across four dataset scales using local SQLite file persistence:

| Scale Tier | Total Items | Insert Avg Latency | Insert P95 Latency | Throughput (Items/sec) | Query P95 Latency |
|---|---|---|---|---|---|
| **Tier 1** | 100 items | $0.5269\text{ ms}$ | $0.5269\text{ ms}$ | $\sim 1,898\text{ ops/sec}$ | $1.5239\text{ ms}$ |
| **Tier 2** | 1,000 items | $0.0947\text{ ms}$ | $0.0948\text{ ms}$ | $\sim 10,559\text{ ops/sec}$ | $1.3606\text{ ms}$ |
| **Tier 3** | 5,000 items | $0.1000\text{ ms}$ | $0.1454\text{ ms}$ | $\sim 10,000\text{ ops/sec}$ | $1.6215\text{ ms}$ |
| **Tier 4** | 10,000 items | $0.1206\text{ ms}$ | $0.1563\text{ ms}$ | $\sim 8,290\text{ ops/sec}$ | $2.2013\text{ ms}$ |

- **Bulk Insertion Throughput:** Sustained rates exceeding **$8,000$ to $10,500$ events/second**.
- **Point Read Latency:** Maintained sub-millisecond lookups (**$0.49\text{ms}–0.81\text{ms}$** average).

## 11.3 Threat Intelligence & Correlation Latency (Phase 4.2B.6 Benchmarks)
- **IOC Extraction Velocity:** Sustained $>10,000\text{ lines/sec}$ on $1,000$-line batches; $>1,700\text{ lines/sec}$ on $10,000$-line batches.
- **Normalization Latency:** Average $0.0142\text{ ms}$ per indicator ($\sim 70,422\text{ ops/sec}$).
- **Validation Latency:** Average $0.0391\text{ ms}$ per indicator ($\sim 25,575\text{ ops/sec}$).
- **Threat Reputation Scoring:** Average $0.1125\text{ ms}$ per assessment ($\sim 8,889\text{ ops/sec}$).
- **Unified Context Assembly:** Average $9.33\text{ ms}$ to traverse and correlate all related events, anomalies, incidents, and attack chains.

