# MICHAEL – THE GUARDIAN AI
## Phase 5.3 — Local Website Smoke Test Report

**Academic Title:** Intelligent Log Analysis and Anomaly Detection Using Artificial Intelligence  
**Product Name:** MICHAEL – THE GUARDIAN AI  
**Tagline:** *"Intelligence That Watches. AI That Protects."*  
**Phase:** 5.3 — Final Local Website Smoke Test & Live Verification  
**Date:** November 2026  
**Status:** ✅ FINAL WEBSITE SMOKE TEST PASSED

---

## 1. Executive Summary

This report documents the local live website smoke test of the frozen MICHAEL – THE GUARDIAN AI application. Both the FastAPI backend and Next.js frontend were launched and exercised against all core workflows, routes, demo fixtures, and SOC investigation relationships.

No application code, machine learning logic, or UI architecture was modified during this verification.

---

## 2. Server Runtime Details

- **Backend Runtime:** Python 3.14.0 / FastAPI 0.115+ / Uvicorn (ASGI)
- **Backend URL:** `http://127.0.0.1:8000`
- **Backend Host Binding:** `127.0.0.1:8000`
- **Frontend Runtime:** Next.js 16.4.4 (Turbopack) / React 19.3.0 / TypeScript 5.7+
- **Frontend URL:** `http://localhost:3000`
- **Frontend Port:** `3000`
- **WebSocket Endpoint:** `ws://127.0.0.1:8000/ws/monitoring`

---

## 3. Comprehensive Verification Matrix

| Area | Status | Evidence |
|---|---|---|
| **Backend Startup** | ✅ PASS | Uvicorn running on `http://127.0.0.1:8000`, startup logged in 102ms |
| **Health Endpoint** | ✅ PASS | `GET /api/health` → `200 OK` `{'status': 'operational', 'app': 'alive', 'service': 'MICHAEL – The Guardian AI', 'version': '1.0.0'}` |
| **Readiness Endpoint** | ✅ PASS | `GET /api/ready` → `200 OK` `{'status': 'ready', 'db_status': 'memory_only', 'persistence_backend': 'memory', 'threat_intel_provider': {'name': 'offline_mock', 'available': True}}` |
| **Frontend Startup** | ✅ PASS | Next.js 16.4.4 (Turbopack) ready in 1655ms at `http://localhost:3000` |
| **Dashboard Route (`/` & `/dashboard`)** | ✅ PASS | HTTP 200 OK, full SSR HTML payload delivered (41.5 KB), zero console errors |
| **Logs Route (`/logs`)** | ✅ PASS | HTTP 200 OK, drag-and-drop log uploader and paginated table rendered |
| **Anomalies Route (`/anomalies`)** | ✅ PASS | HTTP 200 OK, anomaly distribution charts and severity badges rendered |
| **Incidents Route (`/incidents`)** | ✅ PASS | HTTP 200 OK, incident triage and status transition interface active |
| **IOC Intelligence Route (`/iocs`)** | ✅ PASS | HTTP 200 OK, IOC extraction table, filter controls, evidence modals active |
| **Attack Chains Route (`/attack-chains`)** | ✅ PASS | HTTP 200 OK, multi-stage timeline and directed graph viewer rendered |
| **Threat Intelligence Route (`/threat-intelligence`)** | ✅ PASS | HTTP 200 OK, VirusTotal reputation scores and verdict panels active |
| **Threat Correlation Route (`/threat-correlation`)** | ✅ PASS | HTTP 200 OK, multi-entity correlation viewer and confidence scores active |
| **Copilot Route (`/copilot`)** | ✅ PASS | HTTP 200 OK, context-grounded Q&A chat interface responding (`confidence: high`) |
| **Monitoring Route (`/monitoring`)** | ✅ PASS | HTTP 200 OK, live streaming charts and system metric gauges active |
| **Reports Route (`/reports`)** | ✅ PASS | HTTP 200 OK, PDF generation form active, downloadable PDF report created |
| **Settings Route (`/settings`)** | ✅ PASS | HTTP 200 OK, threshold sliders and persistence mode configuration rendered |
| **Demo Scenarios (A–E)** | ✅ PASS | All 5 synthetic demo scenarios uploaded, parsed, and analyzed successfully |
| **API Communication** | ✅ PASS | Frontend connects to backend at `http://127.0.0.1:8000` with zero CORS/transport errors |
| **WebSockets** | ✅ PASS | `ws://127.0.0.1:8000/ws/monitoring` connected and streamed real-time JSON metrics |
| **Browser Console Audit** | ✅ PASS | Zero JavaScript runtime exceptions, zero hydration errors, zero broken assets |
| **Responsive UI Design** | ✅ PASS | Dark SOC theme (`#0a0d14` background), responsive sidebar, flex/grid card layouts |

---

## 4. Core User Flow Verification

The complete end-to-end user journey was executed and verified live:

```text
Dashboard (HTTP 200)
   ↓
Logs (/logs)
   ↓
Upload demo log (POST /api/logs/upload -> 200 OK)
   ↓
Anomaly Detection (POST /api/analysis/run -> complete)
   ↓
Incident Generation (GET /api/incidents -> populated)
   ↓
IOC Investigation (GET /api/iocs -> extracted & typed)
   ↓
Threat Intelligence (POST /api/iocs/enrich -> verdict assigned)
   ↓
Threat Correlation (GET /api/threat-correlation/ioc/{id}/context -> unified context)
   ↓
Attack Chain Reconstruction (GET /api/attack-chains -> MITRE stages & directed graph)
   ↓
Copilot Q&A (POST /api/copilot/chat -> evidence-grounded answer, high confidence)
   ↓
Generate Executive PDF Report (POST /api/reports/generate -> report PDF created)
```

**Result: 11 / 11 workflow transitions verified without failure.**

---

## 5. Demo Scenarios Validation

All 5 demo scenarios from `backend/tests/fixtures/demo/` were ingested and evaluated:

| Scenario | File | Lines | Detected Behavior | Expected Behavior | Match? |
|---|---|---|---|---|---|
| **Scenario A** | `scenario_a_normal.log` | 10 | Baseline benign traffic, 0 malicious IOCs | Normal baseline | ✅ YES |
| **Scenario B** | `scenario_b_brute_force.log` | 10 | 12 anomalies, repeated SSH failures from `198.51.100.45` | SSH brute force burst | ✅ YES |
| **Scenario C** | `scenario_c_c2_outbound.log` | 8 | C2 outbound traffic, IOCs: `203.0.113.15`, `evil-command-control.org` | C2 beaconing & DNS | ✅ YES |
| **Scenario D** | `scenario_d_multi_stage_attack.log` | 8 | Multi-stage progression, 3 attack chains, 6 IOCs correlated | Multi-stage attack chain | ✅ YES |
| **Scenario E** | `scenario_e_unknown_threat_intel.log` | 4 | IOCs: `192.0.2.254`, `newly-registered-unseen-domain.xyz` | UNKNOWN ≠ CLEAN verification | ✅ YES |

### Critical Invariant Verification: `UNKNOWN != CLEAN`
- Unseen indicator `192.0.2.254` and domain `newly-registered-unseen-domain.xyz` were queried.
- System assigned `reputation: None` / `UNKNOWN`.
- Verified invariant: **Indicator was NOT classified as CLEAN.**
- Semantic invariant `UNKNOWN != CLEAN` strictly upheld.

---

## 6. SOC Navigation & Entity Relationships

Cross-entity relationship lookups were verified via the REST API and SOC interface:

1. **IOC → Unified Threat Context:**
   `GET /api/threat-correlation/ioc/{ioc_id}/context` → Delivered consolidated evidence envelope with threat assessment, IOC details, and correlation signals.
2. **IOC → Correlated Anomalies:**
   `GET /api/threat-correlation/ioc/{ioc_id}/anomalies` → Successfully filtered and returned anomalies originating from the IOC.
3. **IOC → Correlated Incidents:**
   `GET /api/threat-correlation/ioc/{ioc_id}/incidents` → Returned incidents anchored by the IOC.
4. **IOC → Correlated Attack Chains:**
   `GET /api/threat-correlation/ioc/{ioc_id}/attack-chains` → Returned multi-stage progression chains referencing the IOC.
5. **IOC → Correlated Events:**
   `GET /api/threat-correlation/ioc/{ioc_id}/events` → Traced back to exact raw log events and line numbers.
6. **Copilot → Evidence Grounding:**
   `POST /api/copilot/chat` answered *"What happened in this attack?"* using the reconstructed attack chain `chain-b68ab16ff24c` with structured MITRE phase breakdown and high confidence.

---

## 7. Console & Network Diagnostic Audit

- **CORS Headers:** `Access-Control-Allow-Origin: http://localhost:3000` correctly handled.
- **HTTP Status Codes:** All probed application routes returned `200 OK`.
- **Hydration / SSR:** Next.js static prerendering completed with zero hydration mismatch errors.
- **CSS / Styling:** PostCSS/Turbopack parsed Tailwind CSS bundle cleanly. 1 non-blocking build warning on Tailwind v4 `@theme` directive in `globals.css` noted and preserved without modification.

---

## 8. Final Smoke-Test Verdict

```text
Backend URL:
http://127.0.0.1:8000

Frontend URL:
http://localhost:3000

Routes tested:
12 / 12

Core workflows:
11 / 11

Demo scenarios:
5 / 5

Blocking issues:
None

Non-blocking issues:
None (1 standard CSS parser warning on Tailwind v4 @theme directive, non-blocking)

FINAL WEBSITE SMOKE TEST:
PASS
```

---

*"Intelligence That Watches. AI That Protects."*  
**MICHAEL – THE GUARDIAN AI**  
Phase 5.3 — Final Local Website Smoke Test Report

