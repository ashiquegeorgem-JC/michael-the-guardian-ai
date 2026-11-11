# SECURITY ARCHITECTURE

**Project:** MICHAEL – THE GUARDIAN AI  
**Academic Title:** Intelligent Log Analysis and Anomaly Detection Using Artificial Intelligence  

---

## 1. Security Philosophy & Defense-in-Depth

As an autonomous cyber defense and log analysis platform, **MICHAEL – THE GUARDIAN AI** operates under strict defensive design principles. A security monitoring system must never introduce new vulnerabilities into the environment it is tasked with protecting.

The security architecture enforces a defense-in-depth model across 12 distinct defensive vectors, formally audited during Phase 5.1.

```mermaid
flowchart TD
    subgraph PERIMETER["1. Perimeter & Transport Security"]
        CORS["Strict CORS Origins\n(No Wildcards)"]
        Validation["Pydantic Strict Schema\nValidation"]
        SSRF["SSRF Defense\n(Hardcoded Endpoint Pinned)"]
    end

    subgraph ISOLATION["2. Execution & Data Isolation"]
        AirGap["Air-Gapped Zero-Socket\nOffline Mode"]
        Tenant["Cross-Session Tenant\nSegregation"]
        Scrubbing["Recursive Credential\nScrubbing"]
    end

    subgraph INTEGRITY["3. Forensic & Lifecycle Sovereignty"]
        Immutable["Forensic Immutability\n(Additive Correlation)"]
        Decoupled["Decoupled Scoring\n(UNKNOWN != CLEAN)"]
        AnalystSov["Analyst Workflow\nSovereignty"]
    end

    subgraph RESILIENCE["4. Error & Operational Resilience"]
        HealthDecouple["Health vs. Ready\nDecoupling"]
        SanitizedErr["Error Sanitization\n(Zero Path / Stack Traces)"]
        RateLimit["Rate-Limit Backoff\n& Caching"]
    end
```

---

## 2. The 12 Defensive Security Vectors

### Vector 1: Hardcoded Secret Prevention
- **Invariant:** Zero credentials, API keys, database passwords, or auth tokens are committed in source code or default configuration files.
- **Enforcement:** All sensitive secrets are resolved exclusively at runtime via OS environment variables (`VIRUSTOTAL_API_KEY`, `DATABASE_URL`). Recursive repository audits confirmed zero committed secrets.

### Vector 2: Threat Intelligence Credential Scrubbing
- **Invariant:** Third-party API keys (e.g., VirusTotal tokens) must never appear in log records, error diagnostics, model representations, or serialized API responses.
- **Enforcement:** Sanitization filters recursively mask keys (`mo********ey`). Serialized string representations of provider results exclude raw authorization tokens.

### Vector 3: Database Credential Sanitization
- **Invariant:** Database connection URIs containing username/password credentials must never leak into log files, stack traces, or readiness probe responses.
- **Enforcement:** Implements `sanitize_db_url()`:
  `postgresql://user:secret@db.internal:5432/michael` $\to$ `postgresql://user:******@db.internal:5432/michael`.

### Vector 4: Information Disclosure & Error Sanitization
- **Invariant:** Internal filesystem paths (`C:\Users\...`, `/var/app/...`), database schema dumps, and raw Python stack traces must never be exposed to clients.
- **Enforcement:** Global FastAPI exception handlers trap unhandled errors, log details to an internal secure logger, and return sanitized, generic error payloads with unique tracking UUIDs.

### Vector 5: Server-Side Request Forgery (SSRF) Defense
- **Invariant:** External HTTP clients must not accept arbitrary user-controlled URLs for outbound requests.
- **Enforcement:** The `VirusTotalProvider` strictly prepends validated canonical indicator values to a hardcoded base URI (`https://www.virustotal.com/api/v3/`). Arbitrary URL redirect following is disabled.

### Vector 6: Cross-Site Scripting (XSS) Immunity
- **Invariant:** Malicious script payloads embedded in log files (e.g., `<script>alert(1)</script>`) must not execute in the analyst's browser.
- **Enforcement:** The Next.js / React frontend renders all log text, entity labels, and investigation summaries via native JSX string escaping. The codebase contains **zero** instances of `dangerouslySetInnerHTML`.

### Vector 7: Cross-Origin Resource Sharing (CORS) Boundaries
- **Invariant:** Cross-origin access must be restricted to explicit, trusted origins; wildcard `*` with credentials is strictly prohibited.
- **Enforcement:** The FastAPI backend restricts `ALLOWED_ORIGINS` to `["http://localhost:3000", "http://127.0.0.1:3000"]`.

### Vector 8: Input Validation & Type Enforcement
- **Invariant:** All API payloads, file uploads, query parameters, and pagination offsets must satisfy strict schema criteria before execution.
- **Enforcement:** Pydantic v2 schemas reject malformed payloads with HTTP 422 Unprocessable Entity, preventing buffer overflows, type coercion exploits, and SQL injection.

### Vector 9: Forensic Immutability & Status Sovereignty
- **Invariant:** Automated machine learning models and correlation heuristics must not mutate human analyst triage classifications or existing evidence records.
- **Enforcement:** Correlation is strictly additive. The system creates separate `ThreatCorrelation` and `UnifiedThreatContext` records while leaving source `IOC`, `Incident`, and `AttackChain` objects unmodified. Deep-snapshot audits verified zero state drift.

### Vector 10: Health vs. Readiness Decoupling
- **Invariant:** A database outage must not cause the application process to report itself as dead to orchestrators (preventing endless restart loops), but must signal that it is not ready to serve traffic.
- **Enforcement:**
  - `/api/health`: Returns HTTP 200 as long as the FastAPI process is responsive.
  - `/api/ready`: Executes a database ping; returns HTTP 503 Service Unavailable if the persistence store is disconnected.

### Vector 11: Cross-Session Tenant & Evidence Segregation
- **Invariant:** Multi-session correlations must not allow an indicator in one tenant's dataset to artificially confirm an attack in another tenant's session.
- **Enforcement:** Cross-session correlations enforce `confirmed = False`, receive an automatic $0.40$ confidence penalty multiplier, and are explicitly annotated with warning evidence bullets.

### Vector 12: Rate-Limiting & Denial-of-Service Defense
- **Invariant:** External threat feed lookups must not overwhelm API quotas or crash upon receiving HTTP 429 Rate Limit responses.
- **Enforcement:** `ThreatIntelService` implements thread-safe deterministic TTL caching, respecting provider `Retry-After` headers and gracefully degrading to `ThreatIntelStatus.ERROR` without throwing unhandled exceptions.

---

## 3. Phase 5.1 Security Audit Verification

The security controls were subjected to automated penetration and boundary validation in `backend/tests/test_e2e_integration_audit.py`:
- **Hardcoded Secret Scan:** $0$ committed secrets found.
- **API Key Scrubbing:** Tested in `test_06_virustotal_mock_error_safety` across 5 HTTP error codes.
- **Database Readiness:** Tested in `test_09_database_failure_readiness` simulating database disconnection.
- **Immutability Verification:** Tested in `test_07_immutability_and_ioc_integrity` using bitwise deep equality snapshots.
- **Audit Verdict:** **100% PASS across all 12 security vectors.**

