# CHAPTER 12: TESTING & VALIDATION

## 10.1 Quality Assurance Strategy
To ensure that **MICHAEL – THE GUARDIAN AI** operates reliably in mission-critical defensive deployments, the engineering methodology instituted a multi-layered automated test harness. Every phase of development was verified against a frozen regression baseline.

## 10.2 Regression Baseline & Test Hierarchy

```text
======================================================================
Ran 412 tests in 13.769s
OK

[ML BENCHMARK] TP=20, FP=0, TN=20, FN=0
[ML BENCHMARK] Precision: 1.0000, Recall: 1.0000, F1: 1.0000, FPR: 0.0000

[SYNTHETIC IOC EXTRACTION] TP=23/23, FP=0, FN=0
[SYNTHETIC IOC EXTRACTION] Precision=1.0000, Recall=1.0000, F1=1.0000

FRONTEND PRODUCTION BUILD:
15 / 15 routes prerendered cleanly with 0 TypeScript errors
======================================================================
```

| Testing Tier | Test File Count | Total Tests | Focus Area | Status |
|---|---|---|---|---|
| **Tier 1: Unit Testing** | 12 files | 141 tests | Parsers, mathematical validators, entropy calculations, normalization rules. | **100% PASS** |
| **Tier 2: Component Integration** | 8 files | 120 tests | Incident generation heuristics, MITRE attack-chain mapping, repository caching. | **100% PASS** |
| **Tier 3: Subsystem Validation** | 4 files | 140 tests | Threat intelligence models, reputation engine, offline socket trap, persistence recovery. | **100% PASS** |
| **Tier 4: End-to-End Audit** | 1 file | 11 tests | Complete pipeline connectivity, traceability, temporal boundaries, security matrix. | **100% PASS** |
| **Total Test Suite** | **25 files** | **412 tests** | **Complete Full-System Regression** | **100% PASS** |

## 10.3 Phase 5.1 End-to-End Audit Validation Suite (`test_e2e_integration_audit.py`)
The final validation suite executed 11 comprehensive tests evaluating critical operational invariants:
1. `test_01_complete_pipeline_connectivity`: Ingested 7 heterogeneous log events; verified end-to-end traversal from raw logs to `UnifiedThreatContext`.
2. `test_02_traceability_audit`: Verified that zero ($0$) orphaned evidence references exist across all generated objects.
3. `test_03_cross_session_safety`: Confirmed that cross-session correlations enforce `confirmed=False` and apply the $0.40$ penalty multiplier.
4. `test_04_temporal_correlation_boundaries`: Validated the four calibrated temporal windows ($\le 30\text{s}$, $30\text{s}–5\text{m}$, $5\text{m}–15\text{m}$, $>15\text{m}$ out-of-window rejection).
5. `test_05_threat_intel_taxonomy_invariants`: Confirmed that missing records ($404$) map to `UNKNOWN`, never `CLEAN`, and verified decoupling of Threat Score from Confidence.
6. `test_06_virustotal_mock_error_safety`: Tested HTTP 200, 401, 403, 404, 429, 500, timeout, and malformed JSON responses without unhandled crashes.
7. `test_07_immutability_and_ioc_integrity`: Verified bitwise deep equality of source entities before and after correlation.
8. `test_08_api_contract_and_error_leakage`: Verified that negative requests and missing IDs return clean JSON errors without leaking stack traces or internal filesystem paths.
9. `test_09_database_failure_readiness`: Verified that a database outage causes `/api/ready` to return 503 while `/api/health` remains 200.
10. `test_10_pdf_report_generation`: Validated automated compilation of forensic PDF reports starting with `%PDF` magic bytes.
11. `test_11_deterministic_reproducibility`: Dual consecutive pipeline runs on identical raw logs verified $100\%$ exact match (`run_1 == run_2`).

## 10.4 Frontend Verification
The Next.js 16 frontend was compiled under production mode (`npm run build`). All 15 routes were statically pre-rendered with zero TypeScript or build errors:
`○ /anomalies`, `○ /attack-chains`, `○ /copilot`, `○ /dashboard`, `○ /incidents`, `○ /iocs`, `○ /logs`, `○ /monitoring`, `○ /reports`, `○ /settings`, `○ /threat-intelligence`, `○ /_not-found`.

