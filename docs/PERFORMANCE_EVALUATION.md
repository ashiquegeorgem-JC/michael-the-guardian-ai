# PERFORMANCE EVALUATION & BENCHMARKING

**Project:** MICHAEL – THE GUARDIAN AI  
**Academic Title:** Intelligent Log Analysis and Anomaly Detection Using Artificial Intelligence  

---

## 1. Benchmarking Methodology & Environment

Performance benchmarks for **MICHAEL – THE GUARDIAN AI** were executed across dedicated stress-testing harnesses (`backend/tests/benchmark_threat_intelligence.py` and `backend/tests/benchmark_persistence.py`).

- **Hardware Environment:** AMD64 / 12 Logical Cores / 14 GB RAM / Local NVMe SSD
- **Runtime Environment:** Windows 11 / Python 3.12+ / FastAPI / SQLAlchemy (SQLite & In-Memory engines)
- **Evaluation Designation:** **Controlled Synthetic Benchmark**

---

## 2. Ingestion & Persistence Throughput (Phase 5.0 Benchmarks)

Persistence throughput was evaluated across four dataset scales using SQLite file-based persistence:

| Scale Tier | Total Items | Insert Avg Latency | Insert P95 Latency | Throughput (Items/sec) | Query P95 Latency |
|---|---|---|---|---|---|
| **Tier 1** | 100 items | $0.5269\text{ ms}$ | $0.5269\text{ ms}$ | $\sim 1,898\text{ ops/sec}$ | $1.5239\text{ ms}$ |
| **Tier 2** | 1,000 items | $0.0947\text{ ms}$ | $0.0948\text{ ms}$ | $\sim 10,559\text{ ops/sec}$ | $1.3606\text{ ms}$ |
| **Tier 3** | 5,000 items | $0.1000\text{ ms}$ | $0.1454\text{ ms}$ | $\sim 10,000\text{ ops/sec}$ | $1.6215\text{ ms}$ |
| **Tier 4** | 10,000 items | $0.1206\text{ ms}$ | $0.1563\text{ ms}$ | $\sim 8,290\text{ ops/sec}$ | $2.2013\text{ ms}$ |

### Key Persistence Observations:
1. **Bulk Insertion Scaling:** Ingestion achieves sustained velocities exceeding **$8,000$ to $10,500$ entries per second** using batched transaction commits.
2. **Point Read Latency:** Sub-millisecond lookup latency ($0.49\text{ms}–0.81\text{ms}$ average) across all dataset sizes, verifying indexed primary key lookups.
3. **Database P95 Query Bound:** P95 read latency remained under $2.25\text{ms}$ even under the 10,000-record tier.

---

## 3. IOC Intelligence Performance (Phase 4.2B.6 Benchmarks)

### 3.1 IOC Extraction Velocity
Extraction throughput was evaluated on log batches of increasing size:

| Batch Size | Duration | Velocity (Lines/sec) | Extracted IOCs | Unique IOCs |
|---|---|---|---|---|
| **100 lines** | $7.93\text{ ms}$ | $12,614.2\text{ lines/sec}$ | 80 IOCs | 8 unique |
| **1,000 lines** | $98.70\text{ ms}$ | $10,131.5\text{ lines/sec}$ | 800 IOCs | 8 unique |
| **5,000 lines** | $1,572.51\text{ ms}$ | $3,179.6\text{ lines/sec}$ | 4,000 IOCs | 8 unique |
| **10,000 lines** | $5,693.68\text{ ms}$ | $1,756.3\text{ lines/sec}$ | 8,000 IOCs | 8 unique |

### 3.2 RFC Normalization & Structural Validation Latency (2,000 Iterations)

| Operational Stage | Average | Median | P95 | P99 | Throughput |
|---|---|---|---|---|---|
| **IOC Normalization** | $0.0142\text{ ms}$ | $0.0072\text{ ms}$ | $0.0391\text{ ms}$ | $0.0620\text{ ms}$ | $\sim 70,422\text{ ops/sec}$ |
| **Structural Validation**| $0.0391\text{ ms}$ | $0.0329\text{ ms}$ | $0.0870\text{ ms}$ | $0.1724\text{ ms}$ | $\sim 25,575\text{ ops/sec}$ |

### 3.3 Canonical Deduplication Overhead
- Measuring insertion of repeated observations with append-only evidence linking:
  - Average latency: **$5.85\text{ms}–6.90\text{ms}$ per item**.
  - Confirms constant-time $O(1)$ hash index performance during deduplication.

---

## 4. Threat Intelligence & Reputation Latency (1,500 Assessments)

Evaluated across the `ThreatReputationEngine` with offline mock provider:

| Metric | Measured Value | Operational Impact |
|---|---|---|
| **Average Latency** | $0.1125\text{ ms}$ | Rapid real-time assessment during high-volume ingestion. |
| **Median Latency** | $0.0862\text{ ms}$ | Baseline evaluation time for typical indicators. |
| **P95 Latency** | $0.2387\text{ ms}$ | Worst-case evaluation for complex multi-signal IOCs. |
| **P99 Latency** | $0.3159\text{ ms}$ | Tail latency bound. |
| **Throughput** | **$8,889.3\text{ assessments/sec}$** | Capable of supporting enterprise-scale lookups. |

---

## 5. Threat Correlation & Unified Context Assembly (500 Runs)

Evaluated against a populated session store containing 100 anomalies, 50 incidents, and 20 attack chains:

| Operation | Average | Median | P95 | P99 | Throughput |
|---|---|---|---|---|---|
| **Directional Correlation** | $7.85\text{ ms}$ | $7.21\text{ ms}$ | $10.84\text{ ms}$ | $13.74\text{ ms}$ | $\sim 127\text{ runs/sec}$ |
| **Unified Context Assembly** | $9.33\text{ ms}$ | $8.88\text{ ms}$ | $12.22\text{ ms}$ | $17.56\text{ ms}$ | $\sim 107\text{ runs/sec}$ |

### Latency Summary:
Assembling the full `UnifiedThreatContext` (linking an IOC to all its matching events, anomalies, incidents, attack chains, and computing investigation summaries) completes in **under 10 milliseconds average**, ensuring instant UI responsiveness in the Next.js SOC workspace.

