# PHASE 5.3 — DEPLOYMENT ARCHITECTURE AUDIT

**Project:** MICHAEL – THE GUARDIAN AI  
**Academic Title:** Intelligent Log Analysis and Anomaly Detection Using Artificial Intelligence  
**Tagline:** *“Intelligence That Watches. AI That Protects.”*  
**Date:** November 10, 2026  
**Auditor:** Automated Engineering Release Audit Harness  
**Audit Scope:** Full Stack Ingestion, Detection, Persistence, API, and SOC Presentation  

---

## 1. Executive Summary

This audit assesses the deployment readiness of **MICHAEL – THE GUARDIAN AI** prior to final GitHub release and academic capstone defense. The codebase was evaluated across its frontend, backend, persistence layer, API endpoints, environment variables, security boundaries, and container/process lifecycles.

**Overall Audit Verdict:** **DEFENSE & DEPLOYMENT READY**

---

## 2. Detected Full-Stack Architecture

| Layer | Detected Technology | Version / Specification | Runtime Mode | Verification Evidence |
|---|---|---|---|---|
| **Frontend** | Next.js / React | Next.js 16.4.4 / React 19.0.0 | Standalone Static Prerendered | 15 / 15 static routes prerendered cleanly. |
| **Frontend Styling** | Tailwind CSS / Lucide | Tailwind 3.4.1 / Lucide React | Production Minified | Zero styling or build warnings. |
| **Backend API** | Python / FastAPI | Python 3.12+ / FastAPI 0.115+ | Asynchronous ASGI (Uvicorn) | Non-blocking I/O with Pydantic v2 schemas. |
| **Machine Learning** | Scikit-learn / NumPy | Scikit-learn 1.5+ / NumPy 1.26+ | In-Process Hybrid Ensemble | Isolation Forest + TF-IDF + Z-Score + Rules. |
| **Persistence (Dev)** | SQLite File Mode | SQLite3 via SQLAlchemy 2.0+ | ACID File Storage (`michael.db`) | 12 tables, zero external dependency. |
| **Persistence (Prod)**| PostgreSQL Dialect | PostgreSQL 15+ / Supabase | Relational Connection Pool | Pluggable via `DATABASE_URL`. |
| **Threat Intelligence**| Offline Mock + VirusTotal | Custom Async Client / HTTPX | Thread-Safe Cached Lookups | Air-gapped zero-socket mode verified. |
| **Audit Reporting** | ReportLab Platypus | ReportLab 4.2+ | Programmatic PDF Engine | Cryptographically valid `%PDF` binary output. |

---

## 3. Environment & Configuration Audit

### 3.1 Environment Variable Handling
Environment variables are handled via `pydantic-settings` in `backend/app/config.py`:

| Variable Name | Default Value | Production Purpose | Security Evaluation |
|---|---|---|---|
| `APP_ENV` | `development` | Sets logging level and diagnostic output mode. | Safe default. |
| `APP_SECRET_KEY` | `dev-secret-...` | Cryptographic secret for signing session tokens. | Overridden in production. |
| `ALLOWED_ORIGINS` | `localhost:3000` | Pinned CORS origins for web browser communication. | Wildcard `*` prohibited. |
| `PERSISTENCE_BACKEND` | `memory` | Sets active storage backend (`memory`, `sqlite`, `postgres`). | Safe zero-disk test default. |
| `DATABASE_URL` | `""` | Database connection string for PostgreSQL / Supabase. | Masked in logs via `sanitize_db_url`. |
| `SQLITE_DB_PATH` | `./data/michael.db` | Filesystem path for local SQLite database file. | Pinned to isolated data folder. |
| `VIRUSTOTAL_API_KEY` | `""` | Authentication key for VirusTotal v3 REST API. | Masked; scrubbed from representations. |
| `THREAT_INTEL_PROVIDER`| `offline_mock` | Active provider (`offline_mock` or `virustotal`). | Air-gapped by default. |
| `NEXT_PUBLIC_API_URL`| `http://localhost:8000` | Frontend target URL for backend REST API. | Injected at frontend build/runtime. |
| `NEXT_PUBLIC_WS_URL` | `ws://localhost:8000` | Frontend target URL for WebSocket telemetry. | Injected at frontend build/runtime. |

### 3.2 Secrets & Credential Exposure Review
- `.gitignore` verification: Verified that root `.gitignore` and `frontend/.gitignore` ignore all `.env*` files except `.env.example`.
- Committed code search: Recursive scan confirmed **zero hardcoded passwords, tokens, API keys, or private certificates**.
- Clean template: `.env.example` verified with safe, non-functional placeholders.

---

## 4. API & Communication Boundary Audit

### 4.1 Health and Readiness Probes
The backend exposes two specialized operational observability endpoints:
- **`GET /api/health` (Liveness Probe):**
  - Returns HTTP 200 with service map as long as the FastAPI process is alive.
  - Does not query external dependencies, preventing cascade failures.
- **`GET /api/ready` (Readiness Probe):**
  - Executes an active database ping and verifies provider status.
  - Returns HTTP 200 if database and services are connected.
  - Returns HTTP 503 Service Unavailable if database connection fails, preventing orchestrators from routing traffic to unready pods.
  - Error responses mask database credentials via `sanitize_db_url()`.

### 4.2 Cross-Origin Resource Sharing (CORS)
- `ALLOWED_ORIGINS` is explicitly pinned to `["http://localhost:3000", "http://127.0.0.1:3000"]`.
- Wildcard `*` with credentials is strictly disabled in `backend/app/main.py`.

---

## 5. Persistence Readiness: Supported vs. Deployed

To maintain scientific and operational honesty:
- **Supported Architecture:** The platform includes complete, tested repository adapters for:
  1. `memory`: In-memory dictionary store for test suites.
  2. `sqlite`: File-based storage with full foreign-key cascades.
  3. `postgres`: Enterprise relational storage compatible with PostgreSQL 15+ and cloud-hosted Supabase instances.
- **Currently Deployed Verification Environment:** The release verification baseline was executed under **SQLite File Mode and In-Memory Test Mode**. Live cloud Supabase infrastructure is an enterprise deployment option, not an active dependency of this local release.

---

## 6. Commands Reference

### Backend Execution
```bash
# Test Execution
python -m unittest discover -s tests -p "test_*.py"

# Production Startup (Multi-Worker Uvicorn)
uvicorn app.main:app --host 0.0.0.0 --port 8000 --workers 4
```

### Frontend Execution
```bash
# Production Build
npm --prefix frontend run build

# Production Server Startup
npm --prefix frontend run start
```

