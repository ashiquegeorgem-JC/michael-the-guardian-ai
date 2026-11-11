# PHASE 5.3 — BACKEND RELEASE TEST REPORT

**Project:** MICHAEL – THE GUARDIAN AI  
**Academic Title:** Intelligent Log Analysis and Anomaly Detection Using Artificial Intelligence  
**Test Suite:** Complete Automated Backend Regression Suite  
**Date:** November 10, 2026  
**Execution Command:** `python -m unittest discover -s backend/tests -p "test_*.py"`  
**Result:** **412 / 412 TESTS PASS (100% SUCCESS RATE)**  
**Execution Time:** 13.431 seconds  

---

## 1. Executive Summary

The complete backend regression test suite was executed against the frozen release baseline. The suite comprises 25 test modules spanning parsing, machine learning anomaly detection, temporal sliding windows, attack chain graph synthesis, IOC extraction, RFC normalization, external threat intelligence integration, reputation scoring, directional threat correlation, relational persistence, and the end-to-end security audit.

**All 412 test cases executed cleanly with zero failures and zero errors.**

---

## 2. Test Execution Log Output

```text
..2026-11-10 21:02:15,332 [INFO] michael.threat_intel: Registered ThreatIntel provider: virustotal (v1.0.0)
...2026-11-10 21:02:15,337 [ERROR] michael.threat_intel.virustotal: Failed to parse VirusTotal JSON response for 9.9.9.9: not json
......2026-11-10 21:02:15,350 [WARNING] michael.threat_intel.virustotal: VirusTotal authentication failure (HTTP 401)
..2026-11-10 21:02:15,354 [WARNING] michael.threat_intel.virustotal: VirusTotal lookup timed out for IOC test.com
...
----------------------------------------------------------------------
Ran 412 tests in 13.431s
OK

[ML BENCHMARK] TP=20, FP=0, TN=20, FN=0
[ML BENCHMARK] Precision: 1.0000, Recall: 1.0000, F1: 1.0000, FPR: 0.0000

[SYNTHETIC IOC EXTRACTION] TP=23/23, FP=0, FN=0
[SYNTHETIC IOC EXTRACTION] Precision=1.0000, Recall=1.0000, F1=1.0000
```

---

## 3. Subsystem Breakdown & Test Coverage

| Subsystem Module | Test Module / Script | Test Count | Verified Quality Gates | Status |
|---|---|---|---|---|
| **Log Parser & Ingestion** | `test_log_parser.py` | 45 tests | ISO UTC normalization, multi-format regex, raw line preservation. | **PASS** |
| **ML & Statistical Anomaly** | `test_anomaly_detection.py`, `test_isolation_forest.py`, `test_tfidf_detector.py` | 62 tests | Entropy calculations, tree partition depth, vocabulary dispersion, score fusion. | **PASS** |
| **Temporal Intelligence** | `test_temporal_intelligence.py` | 38 tests | Multi-scale sliding windows (10s, 30s, 60s, 300s), EMA, rate-of-change burst detection. | **PASS** |
| **Incident & Attack Chains** | `test_incidents.py`, `test_attack_chains.py` | 50 tests | Entity clustering, root-cause derivation, chronological MITRE ATT&CK graph reconstruction. | **PASS** |
| **IOC Intelligence** | `test_ioc_extractor.py`, `test_ioc_normalization.py` | 55 tests | 9 indicator types, RFC 5952 compression, deduplication, evidence mapping. | **PASS** |
| **Threat Intelligence & VT** | `test_threat_intel_service.py`, `test_virustotal_provider.py` | 42 tests | TTL cache hits, offline mock air-gap, 404 UNKNOWN guard, rate-limit backoff. | **PASS** |
| **Threat Reputation Scoring** | `test_threat_reputation.py` | 50 tests | Score clamping [0, 100], confidence decoupling [0, 1], contributing signal breakdown. | **PASS** |
| **Threat Correlation Engine** | `test_threat_correlation.py` | 50 tests | 6 directional relationships, temporal bounds, cross-session safety, UnifiedContext. | **PASS** |
| **Persistence & SQL Store** | `test_persistence.py` | 9 tests | SQLite & In-Memory modes, 12-table relational schema, restart zero data loss. | **PASS** |
| **Phase 5.1 E2E Security Audit**| `test_e2e_integration_audit.py` | 11 tests | End-to-end pipeline, traceability, immutability, 12-vector security matrix. | **PASS** |
| **Total Test Suite** | **25 modules** | **412 tests** | **Complete Full-System Verification Baseline** | **100% PASS** |

---

## 4. Benchmark Invariants Confirmed
- **Traceability:** 0 orphaned evidence references across all tests.
- **Forensic Immutability:** Bitwise deep-equality confirmed before and after correlation.
- **Reproducibility:** Dual consecutive runs on identical inputs yield identical outputs (`run_1 == run_2`).
- **Telemetry Deficit Defense:** Missing provider records (404) map strictly to `UNKNOWN`, never `CLEAN`.
- **Cross-Session Penalty:** Cross-session correlations enforce `confirmed=False` with a $0.40$ penalty multiplier.

