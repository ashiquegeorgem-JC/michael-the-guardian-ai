# Phase 5.0 — Baseline Freeze

**Date:** 2026-11-07  
**Platform:** MICHAEL – THE GUARDIAN AI  
**Baseline Status:** FROZEN & VERIFIED CLEAN  

---

## 1. Backend Baseline

- **Total Tests Executed:** 392
- **Passing Tests:** 392 (100%)
- **Failures / Errors:** 0
- **Execution Duration:** 6.47s
- **ML Benchmark Invariant:** TP=20, FP=0, TN=20, FN=0 | Precision: 1.0000, Recall: 1.0000, F1: 1.0000, FPR: 0.0000
- **IOC Synthetic Extraction Benchmark:** TP=23/23, FP=0, FN=0 | Precision: 1.0000, Recall: 1.0000, F1: 1.0000
- **Existing Warnings:** DeprecationWarning for `datetime.utcnow()` in legacy models scheduled for Python 3.15 standard library lifecycle.

---

## 2. Frontend Baseline

- **Build Engine:** Next.js 16.4.4 (Turbopack)
- **TypeScript Errors:** 0
- **Build Status:** Exit code 0 (Success)
- **Static Pre-rendered Routes (15 / 15):**
  - `○ /`
  - `○ /_not-found`
  - `○ /anomalies`
  - `○ /attack-chains`
  - `○ /copilot`
  - `○ /dashboard`
  - `○ /incidents`
  - `○ /iocs`
  - `○ /logs`
  - `○ /monitoring`
  - `○ /reports`
  - `○ /settings`
  - `○ /threat-intelligence`
- **Warnings:** 1 non-fatal PostCSS warning for `@theme` rule in `globals.css` (Tailwind v4 directive).

---

## 3. Freeze Declaration

The current platform is confirmed stable, regression-free, and frozen. No changes will proceed until the architecture audit in Step 1 is executed and verified.

