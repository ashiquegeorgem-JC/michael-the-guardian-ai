# REST API DOCUMENTATION

**Project:** MICHAEL – THE GUARDIAN AI  
**Academic Title:** Intelligent Log Analysis and Anomaly Detection Using Artificial Intelligence  
**Base URL:** `http://localhost:8000`  
**Protocol:** HTTP/1.1 REST + JSON  

---

## 1. System Health & Observability Endpoints

### 1.1 Process Vitality Probe
- **Method & Path:** `GET /api/health`
- **Purpose:** Verifies whether the FastAPI application process is alive and responsive. Used by Kubernetes/Docker liveness probes.
- **Request Parameters:** None.
- **Response (`200 OK`):**
  ```json
  {
    "status": "operational",
    "timestamp": "2026-11-10T20:30:00.000000Z",
    "version": "1.0.0",
    "services": {
      "fastapi": "running",
      "threat_intel": "active",
      "threat_correlation": "active"
    }
  }
  ```

### 1.2 Deep Dependency Readiness Probe
- **Method & Path:** `GET /api/ready`
- **Purpose:** Verifies that underlying persistence and provider dependencies are operational. Used by readiness probes before routing traffic.
- **Request Parameters:** None.
- **Response (`200 OK` — Database Connected):**
  ```json
  {
    "status": "ready",
    "timestamp": "2026-11-10T20:30:00.000000Z",
    "persistence_backend": "sqlite",
    "db_status": "connected",
    "active_providers": ["offline_mock"]
  }
  ```
- **Response (`503 Service Unavailable` — Database Disconnected):**
  ```json
  {
    "status": "not_ready",
    "timestamp": "2026-11-10T20:30:00.000000Z",
    "persistence_backend": "postgres",
    "db_status": "disconnected",
    "error": "Connection refused"
  }
  ```

---

## 2. Log Ingestion & Session Endpoints

### 2.1 Upload Log File
- **Method & Path:** `POST /api/logs/upload`
- **Purpose:** Ingests raw log files, generates a unique `LogSession`, parses entries into structured records, and stores them in the active persistence backend.
- **Request:** `multipart/form-data` with `file: UploadFile`.
- **Response (`200 OK`):**
  ```json
  {
    "session_id": "3fa85f64-5717-4562-b3fc-2c963f66afa6",
    "filename": "auth_audit.log",
    "total_lines": 1250,
    "parsed_entries": 1250,
    "status": "ready"
  }
  ```

### 2.2 Query Log Entries
- **Method & Path:** `GET /api/logs`
- **Purpose:** Returns paginated, filtered log entries for a given session.
- **Query Parameters:**
  - `session_id` (string, required): Target session identifier.
  - `page` (int, default: 1): Page index ($\ge 1$).
  - `page_size` (int, default: 50): Items per page ($1–500$).
  - `level` (string, optional): Filter by `INFO`, `WARNING`, `ERROR`, `CRITICAL`.
  - `source` (string, optional): Filter by service source (e.g., `sshd`, `nginx`).
- **Response (`200 OK`):**
  ```json
  {
    "total": 1250,
    "page": 1,
    "page_size": 50,
    "entries": [
      {
        "id": "ev-001",
        "session_id": "3fa85f64-5717-4562-b3fc-2c963f66afa6",
        "timestamp": "2026-11-10T12:00:10Z",
        "level": "WARNING",
        "source": "sshd",
        "message": "Failed password for invalid user root from 198.51.100.45 port 44321 ssh2",
        "line_number": 1
      }
    ]
  }
  ```

---

## 3. Indicator of Compromise (IOC) Endpoints

### 3.1 List IOCs with Filters
- **Method & Path:** `GET /api/iocs`
- **Query Parameters:**
  - `session_id` (string, optional)
  - `ioc_type` (string, optional: `ipv4`, `domain`, `sha256`, etc.)
  - `status` (string, optional: `EXTRACTED`, `UNDER_REVIEW`, `CONFIRMED`, `FALSE_POSITIVE`)
  - `validation_status` (string, optional: `VALID`, `INVALID`, `SUSPICIOUS`)
  - `page` (int, default: 1), `page_size` (int, default: 50)
- **Response (`200 OK`):** Paginated collection of `IOC` records.

### 3.2 Search IOCs
- **Method & Path:** `GET /api/iocs/search`
- **Query Parameters:**
  - `q` (string, required): Substring or exact term.
  - `ioc_type`, `status`, `min_confidence` ($0.0–1.0$).
- **Response (`200 OK`):** List of matching IOCs with occurrence metrics.

### 3.3 Aggregate IOC Summary Statistics
- **Method & Path:** `GET /api/iocs/summary`
- **Query Parameters:** `session_id` (string, optional).
- **Response (`200 OK`):**
  ```json
  {
    "total_iocs": 42,
    "type_counts": { "ipv4": 24, "domain": 12, "sha256": 6 },
    "status_counts": { "EXTRACTED": 35, "UNDER_REVIEW": 5, "CONFIRMED": 2 },
    "validation_counts": { "VALID": 38, "SUSPICIOUS": 4 },
    "average_confidence": 0.88
  }
  ```

### 3.4 Retrieve Single IOC Detail
- **Method & Path:** `GET /api/iocs/{ioc_id}`
- **Response (`200 OK`):** Full `IOC` entity with source sessions and tags.
- **Error (`404 Not Found`):** JSON error when ID is absent.

### 3.5 Retrieve IOC Evidence References
- **Method & Path:** `GET /api/iocs/{ioc_id}/evidence`
- **Response (`200 OK`):**
  ```json
  {
    "ioc_id": "ioc-45",
    "total_evidence": 3,
    "evidence": [
      {
        "event_id": "ev-001",
        "session_id": "sess-alpha",
        "timestamp": "2026-11-10T12:00:10Z",
        "raw_value": "198.51.100.45",
        "source_field": "src_ip",
        "line_number": 14
      }
    ]
  }
  ```

### 3.6 Update IOC Analyst Review Status
- **Method & Path:** `PATCH /api/iocs/{ioc_id}/status`
- **Request Body:**
  ```json
  {
    "status": "CONFIRMED",
    "analyst_note": "Confirmed brute-force origin via firewall corroboration.",
    "actor": "analyst_jdoe"
  }
  ```
- **Response (`200 OK`):** Updated `IOC` object with updated status and audit logging.

---

## 4. Threat Correlation & Unified Intelligence Endpoints

### 4.1 Retrieve Unified Threat Context
- **Method & Path:** `GET /api/threat-correlation/ioc/{ioc_id}/context`
- **Purpose:** Primary SOC single-pane investigation endpoint assembling intelligence, reputation, and all linked security objects.
- **Query Parameters:** `force_refresh` (bool, default: false).
- **Response (`200 OK`):** `UnifiedThreatContext` JSON payload containing:
  - IOC core attributes & analyst status.
  - `threat_assessment` (score, severity, confidence, contributing signals).
  - `related_events`, `related_anomalies`, `related_incidents`, `related_attack_chains`.
  - `correlations` (array of `ThreatCorrelation` directional link records).
  - `overall_correlation_confidence` & `investigation_summary`.

### 4.2 Query Correlated Anomalies
- **Method & Path:** `GET /api/threat-correlation/ioc/{ioc_id}/anomalies`
- **Response (`200 OK`):** List of anomaly correlations with explicit evidence bullets and confidence scores.

### 4.3 Query Correlated Incidents
- **Method & Path:** `GET /api/threat-correlation/ioc/{ioc_id}/incidents`
- **Response (`200 OK`):** List of incident correlations with root-cause context.

### 4.4 Query Correlated Attack Chains
- **Method & Path:** `GET /api/threat-correlation/ioc/{ioc_id}/attack-chains`
- **Response (`200 OK`):** Attack chains linked to this indicator with MITRE stage mapping.

### 4.5 Query Correlated Log Events
- **Method & Path:** `GET /api/threat-correlation/ioc/{ioc_id}/events`
- **Response (`200 OK`):** Direct raw events containing the indicator with line numbers.

### 4.6 Query All Directional Correlations
- **Method & Path:** `GET /api/threat-correlation/ioc/{ioc_id}`
- **Query Parameters:** `correlation_type` (optional), `confirmed_only` (bool, default: false).
- **Response (`200 OK`):** Complete collection of directional correlation records.

---

## 5. Audit Reporting Endpoints

### 5.1 Generate Forensic Audit Report
- **Method & Path:** `POST /api/reports/generate`
- **Request Body:**
  ```json
  {
    "session_id": "3fa85f64-5717-4562-b3fc-2c963f66afa6",
    "title": "Incident Investigation Audit Report"
  }
  ```
- **Response (`200 OK`):**
  ```json
  {
    "report_id": "4439dccb",
    "session_id": "3fa85f64-5717-4562-b3fc-2c963f66afa6",
    "generated_at": "2026-11-10T20:30:00Z",
    "filename": "MICHAEL_Report_4439dccb_20261110_150810.pdf",
    "download_url": "/api/reports/download/MICHAEL_Report_4439dccb_20261110_150810.pdf"
  }
  ```

### 5.2 Download Forensic PDF
- **Method & Path:** `GET /api/reports/download/{filename}`
- **Response (`200 OK`):** Binary stream with `Content-Type: application/pdf`.

