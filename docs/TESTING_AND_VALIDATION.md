# TESTING & VALIDATION SPECIFICATION

**Project:** MICHAEL – THE GUARDIAN AI  
**Academic Title:** Intelligent Log Analysis and Anomaly Detection Using Artificial Intelligence  

---

## 1. Quality Assurance Strategy & Test Hierarchy

To guarantee operational correctness, mathematical precision, security resilience, and forensic immutability, **MICHAEL – THE GUARDIAN AI** enforces a multi-tiered validation methodology:

```text
┌────────────────────────────────────────────────────────┐
│                   TESTING PYRAMID                      │
├────────────────────────────────────────────────────────┤
│  [ Phase 5.1 End-to-End & Security Audit Suite ] (11)  │
│  [ Dedicated Subsystem & Validation Suites ]    (140)  │
│  [ Integration & Multi-Component Suites ]       (120)  │
│  [ Unit Tests & Analytical Parser Suites ]      (141)  │
├────────────────────────────────────────────────────────┤
│  TOTAL BACKEND REGRESSION SUITE: 412 TESTS (100% PASS) │
└────────────────────────────────────────────────────────┘
```

---

## 2. Current Verified Test Status

```text
======================================================================
Ran 412 tests in 13.769s
OK

[ML BENCHMARK] TP=20, FP=0, TN=20, FN=0
[ML BENCHMARK] Precision: 1.0000, Recall: 1.0000, F1: 1.0000, FPR: 0.0000

[SYNTHETIC IOC EXTRACTION] TP=23/23, FP=0, FN=0
[SYNTHETIC IOC EXTRACTION] Precision=1.0000, Recall=1.0000, F1=1.0000

FRONTEND PRODUCTION BUILD:
15 / 15 routes prerendered cleanly (0 TypeScript errors)
======================================================================
```

---

## 3. Test Categories & Suite Breakdown

### 3.1 Unit Testing
- **Scope:** Verifies individual functions, regular expressions, mathematical formulas, and data model validators in complete isolation.
- **Key Modules Tested:**
  - `test_log_parser.py`: Timestamp standardisation, level extraction, malformed line handling.
  - `test_anomaly_detection.py`: Feature vector generation, entropy calculations, threshold boundaries.
  - `test_temporal_intelligence.py`: Rolling mean, std dev, EMA, and rate-of-change math.
  - `test_ioc_normalization.py`: RFC 5952 IPv6 compression, IPv4 zero-stripping, URL normalization.
  - `test_threat_reputation.py`: Clamping threat scores to $[0.0, 100.0]$, signal point summation.

### 3.2 Integration Testing
- **Scope:** Verifies inter-component communication, repository persistence, and provider caching.
- **Key Modules Tested:**
  - `test_persistence.py` (9 tests): Validates CRUD operations across `SQLStoreRepository` and `SQLIOCRepository` under SQLite and In-Memory modes; tests process restart recovery.
  - `test_threat_intelligence.py`: Caching semantics, offline mock lookups, provider registration.
  - `test_attack_chains.py`: Incident linking, MITRE stage mapping, chronological sorting.

### 3.3 End-to-End Integration Testing (`test_e2e_integration_audit.py` - 11 Tests)
- **Scope:** Validates the uninterrupted operational flow across the complete system:
  $$\text{Raw Logs} \to \text{Parser} \to \text{Anomalies} \to \text{Incidents} \to \text{AttackChains} \to \text{IOCs} \to \text{ThreatIntel} \to \text{Correlation} \to \text{API}$$
- **Specific Audits Executed:**
  1. `test_01_complete_pipeline_connectivity`: 7-event scenario generating 2 anomalies, 2 incidents, 1 attack chain, canonical IOCs, threat intelligence lookups, and unified context.
  2. `test_02_traceability_audit`: Asserts $0$ broken pointers across all `evidence_references`.
  3. `test_03_cross_session_safety`: Asserts cross-session links receive $0.40$ penalty multiplier and `confirmed=False`.
  4. `test_04_temporal_correlation_boundaries`: Verifies $\le 30\text{s}$, $30\text{s}–5\text{m}$, $5\text{m}–15\text{m}$, and $>15\text{m}$ out-of-window rejection.
  5. `test_05_threat_intel_taxonomy_invariants`: Asserts `UNKNOWN != CLEAN` and decouples Threat Score from Confidence.
  6. `test_06_virustotal_mock_error_safety`: Evaluates HTTP 200, 401, 403, 404, 429, 500, and timeout handling.
  7. `test_07_immutability_and_ioc_integrity`: Validates deep-snapshot equality before and after correlation.
  8. `test_08_api_contract_and_error_leakage`: Tests negative inputs, pagination, and error message sanitization.
  9. `test_09_database_failure_readiness`: Tests database disconnection simulating `/api/health` (200) vs `/api/ready` (503).
  10. `test_10_pdf_report_generation`: Validates ReportLab PDF generation and magic bytes (`%PDF`).
  11. `test_11_deterministic_reproducibility`: Dual identical pipeline runs assert `run_1 == run_2`.

### 3.4 Security Testing
- Evaluated against the 12-vector security matrix documented in `docs/SECURITY_ARCHITECTURE.md`.
- Zero committed credentials, zero unhandled network exceptions, zero XSS vulnerabilities (`dangerouslySetInnerHTML`), strict CORS restrictions, and recursive secret scrubbing.

### 3.5 Synthetic & Controlled Benchmarks
- **Detection Benchmark:** 190 strictly partitioned log entries evaluated against ground-truth labels across 10 threat classes ($N=190$, Accuracy $= 94.21\%$, Precision $= 92.75\%$, Recall $= 91.43\%$, F1-Score $= 0.9209$, ROC-AUC $= 0.9927$).
- **IOC Extraction Benchmark:** 23 synthetic ground-truth fixtures evaluated against 9 IOC types (Precision $= 1.0$, Recall $= 1.0$, F1 $= 1.0$).
- *Note:* These metrics reflect strictly controlled synthetic evaluation; real-world enterprise deployments with noisy custom application payloads require ongoing baseline calibration.

### 3.6 Performance Benchmarking
- **Log Insertion Throughput:** $8,290–10,559$ operations/second.
- **Single Point-Read Latency:** $0.49\text{ms}–0.81\text{ms}$.
- **IOC Extraction Velocity:** $>1,700$ lines/sec on $10,000$-line batches.
- **Threat Reputation Evaluation:** $0.112\text{ms}$ average latency per IOC ($\sim 8,889$ ops/sec).

### 3.7 Regression Testing
- **Regression Protocol:** Executed automatically before and after all engineering milestones.
- **Baseline Progress:**
  - Phase 4.2B.6 Baseline: 392 tests PASS
  - Phase 5.0 Persistence Baseline: 401 tests PASS
  - Phase 5.1 / 5.2 Frozen Baseline: **412 tests PASS (100%)**

