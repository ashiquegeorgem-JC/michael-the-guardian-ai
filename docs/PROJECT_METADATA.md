# PROJECT METADATA

**Project:** MICHAEL – THE GUARDIAN AI  
**Academic Title:** Intelligent Log Analysis and Anomaly Detection Using Artificial Intelligence  
**Tagline:** *“Intelligence That Watches. AI That Protects.”*  
**Version:** 1.0.0 (Production Release / Phase 5.2 Frozen Baseline)  
**Date:** November 2026  

---

## 1. Core Identification

- **Project Name:** MICHAEL – THE GUARDIAN AI
- **Acronym / Concept:** MICHAEL (Multitier Intelligent Cybersecurity Heuristic & Anomaly Evaluation Logic)
- **Academic Classification:** Undergraduate Engineering Capstone Project / Applied Cybersecurity Research Defense
- **Primary Domain:** Autonomous Cyber Defense, Log Analytics, Machine Learning Intrusion Detection, Threat Intelligence

---

## 2. Verified Technology Stack

### Backend Tier
- **Language / Runtime:** Python 3.12+ (Compatible with Python 3.13, 3.14)
- **Web Framework:** FastAPI (v0.115+)
- **ASGI Server:** Uvicorn (v0.32+)
- **Data Validation & Schemas:** Pydantic v2 (v2.10+)
- **HTTP Client (Async):** HTTPX (v0.28+)
- **Testing Framework:** Python Standard Library `unittest`
- **PDF Compilation:** ReportLab (v4.2+)

### Machine Learning & Data Processing
- **ML Framework:** Scikit-learn (v1.5+)
- **Numerical Computation:** NumPy (v1.26+ / v2.0+)
- **NLP / Semantics:** TF-IDF Vectorizer (`sklearn.feature_extraction.text.TfidfVectorizer`)
- **Unsupervised Anomaly Model:** Isolation Forest (`sklearn.ensemble.IsolationForest`)

### Persistence & Storage
- **Object Relational Mapper:** SQLAlchemy (v2.0+)
- **Relational Schema:** 12 Relational Tables (UUID Primary Keys, UTC Timestamps)
- **Supported Storage Modes:**
  - `memory`: High-Speed Ephemeral Dictionary Singleton Store
  - `sqlite`: Local ACID File-Based Storage (`sqlite:///./michael.db`)
  - `postgres`: Enterprise PostgreSQL / Supabase Relational Database

### Threat Intelligence & Correlation
- **Provider Architecture:** Pluggable `ThreatIntelProvider` Interface
- **Active Providers:**
  - `OfflineMockThreatIntelProvider`: In-Memory Ground-Truth Telemetry for Air-Gapped Environments
  - `VirusTotalProvider`: Authenticated Public VirusTotal v3 REST API Integration
- **Threat Reputation Engine:** Deterministic Threat Scoring ($0–100$), Confidence Modeling ($0–1$), Contributing Signal Decomposition
- **Threat Correlation Engine:** 6 Directional Relational Heuristics with Unified Threat Context Generation

### Frontend Tier
- **Framework:** Next.js 16 (React 19 / Turbopack)
- **Language:** TypeScript 5.7+
- **Styling System:** Tailwind CSS (v3.4+)
- **Iconography:** Lucide React
- **Visualization:** Interactive Canvas / SVG Attack Graphs and Progression Timelines
- **Routes:** 15 Static Pre-rendered Routes

---

## 3. Verified Verification Baseline

- **Total Backend Tests:** 412 / 412 Tests PASS (100%)
- **End-to-End Audit Suite:** 11 / 11 Tests PASS
- **Frontend Build Status:** 15 / 15 Routes Clean Build (0 TypeScript Errors)
- **Security Audit:** 12 / 12 Defensive Vectors PASSED
- **Traceability Guarantee:** 0 Broken or Orphaned Evidence References
- **Reproducibility Guarantee:** Dual Identical Runs Verified (`run_1 == run_2`)
- **Process Restart Data Loss:** 0% Data Loss Verified via Disk Recovery

