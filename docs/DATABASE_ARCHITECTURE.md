# DATABASE ARCHITECTURE & PERSISTENCE SPECIFICATION

**Project:** MICHAEL – THE GUARDIAN AI  
**Academic Title:** Intelligent Log Analysis and Anomaly Detection Using Artificial Intelligence  

---

## 1. Architectural Overview & Pluggable Storage

The persistence layer of **MICHAEL – THE GUARDIAN AI** employs an abstract repository pattern that isolates domain logic from underlying storage technologies. This enables the platform to operate across three distinct environments without altering business logic:

```mermaid
flowchart TD
    Domain["Domain Services (ThreatCorrelation, IncidentService, etc.)"]
    RepoInterface["Abstract Repository Interfaces\n(BaseSessionStore, BaseIOCRepository)"]
    
    Domain --> RepoInterface
    
    RepoInterface -->|PERSISTENCE_BACKEND = 'memory'| Mem["InMemoryStore\n(Ephemeral Dictionary Singletons for Testing)"]
    RepoInterface -->|PERSISTENCE_BACKEND = 'sqlite'| SQLite["SQLAlchemy SQLite Engine\n(Zero-Dependency Local File Storage)"]
    RepoInterface -->|PERSISTENCE_BACKEND = 'postgres'| PG["SQLAlchemy PostgreSQL Engine\n(Production Relational DB / Supabase Dialect)"]
```

---

## 2. Relational Schema (12 Tables)

The physical database schema comprises 12 interconnected tables enforcing relational integrity, foreign-key cascades, timezone-aware UTC timestamps, and composite indexing:

```mermaid
erDiagram
    sessions ||--o{ events : "contains"
    sessions ||--o{ anomalies : "generates"
    sessions ||--o{ model_metrics : "evaluates"
    sessions ||--o{ incidents : "tracks"
    sessions ||--o{ attack_chains : "reconstructs"
    sessions ||--o{ ioc_evidence : "records"
    
    iocs ||--o{ ioc_evidence : "supported_by"
    iocs ||--o{ threat_intel_results : "queried_by"
    iocs ||--o{ threat_assessments : "evaluated_by"
    iocs ||--o{ threat_correlations : "correlated_in"
    
    anomalies ||--o{ incidents : "causes"
    incidents ||--o{ attack_chains : "participates_in"
```

### Table 1: `sessions`
- **Purpose:** Tracks analysis session boundaries and uploaded file metadata.
- **Primary Key:** `id` (VARCHAR 64, UUID)
- **Columns:** `filename` (VARCHAR 255), `uploaded_at` (DATETIME UTC), `total_lines` (INTEGER), `file_size` (INTEGER), `status` (VARCHAR 32: `pending`, `processing`, `ready`, `failed`).
- **Indexes:** Primary key index on `id`.

### Table 2: `events`
- **Purpose:** Stores parsed forensic log entries.
- **Primary Key:** `id` (VARCHAR 64, UUID)
- **Foreign Keys:** `session_id` $\to$ `sessions.id` (ON DELETE CASCADE)
- **Columns:** `timestamp` (DATETIME UTC), `level` (VARCHAR 16), `source` (VARCHAR 64), `message` (TEXT), `raw_line` (TEXT), `line_number` (INTEGER).
- **Indexes:** Composite index on `(session_id, timestamp)`, index on `source`.

### Table 3: `anomalies`
- **Purpose:** Records detected structural, semantic, and temporal anomalies.
- **Primary Key:** `id` (VARCHAR 64, UUID)
- **Foreign Keys:** `session_id` $\to$ `sessions.id` (ON DELETE CASCADE)
- **Columns:** `score` (FLOAT, $0.0–1.0$), `severity` (VARCHAR 16), `reason` (TEXT), `detected_at` (DATETIME UTC), `method` (VARCHAR 32), `log_entry_ids` (JSON), `supporting_logs` (JSON), `metadata` (JSON).
- **Indexes:** Composite index on `(session_id, severity)`.

### Table 4: `model_metrics`
- **Purpose:** Stores session-level machine learning evaluation parameters and accuracy indicators.
- **Primary Key:** `session_id` (VARCHAR 64) $\to$ `sessions.id` (ON DELETE CASCADE)
- **Columns:** `total_logs` (INTEGER), `anomalies_detected` (INTEGER), `contamination_rate` (FLOAT), `detection_methods` (JSON), `tfidf_top_terms` (JSON), `analysis_duration_seconds` (FLOAT), `evaluated_at` (DATETIME UTC).

### Table 5: `incidents`
- **Purpose:** Stores security incidents derived from clustered anomalies.
- **Primary Key:** `id` (VARCHAR 64, UUID)
- **Foreign Keys:** `session_id` $\to$ `sessions.id` (ON DELETE CASCADE)
- **Columns:** `anomaly_id` (VARCHAR 64), `category` (VARCHAR 64), `severity` (VARCHAR 16), `title` (VARCHAR 255), `description` (TEXT), `root_cause_hypothesis` (TEXT), `potential_impact` (TEXT), `remediation_steps` (JSON), `first_seen` (DATETIME UTC), `last_seen` (DATETIME UTC), `status` (VARCHAR 32: `OPEN`, `INVESTIGATING`, `CONTAINED`, `CLOSED`), `affected_ips` (JSON), `mitre_tactics` (JSON).
- **Indexes:** Index on `(session_id, status)`.

### Table 6: `attack_chains`
- **Purpose:** Reconstructs multi-stage attack narratives.
- **Primary Key:** `id` (VARCHAR 64, UUID)
- **Foreign Keys:** `session_id` $\to$ `sessions.id` (ON DELETE CASCADE)
- **Columns:** `name` (VARCHAR 255), `severity` (VARCHAR 16), `confidence` (FLOAT, $0.0–1.0$), `stages` (JSON), `incident_ids` (JSON), `chain_events` (JSON), `status` (VARCHAR 32), `first_seen` (DATETIME UTC), `last_seen` (DATETIME UTC).

### Table 7: `iocs`
- **Purpose:** Stores canonical Indicators of Compromise deduplicated by type and normalized value.
- **Primary Key:** `id` (VARCHAR 64, UUID)
- **Unique Constraint:** `(ioc_type, normalized_value)`
- **Columns:** `ioc_type` (VARCHAR 32), `raw_value` (VARCHAR 512), `normalized_value` (VARCHAR 512), `confidence` (FLOAT, $0.0–1.0$), `status` (VARCHAR 32: `EXTRACTED`, `UNDER_REVIEW`, `CONFIRMED`, `FALSE_POSITIVE`), `validation_status` (VARCHAR 32: `VALID`, `INVALID`, `SUSPICIOUS`), `first_seen` (DATETIME UTC), `last_seen` (DATETIME UTC), `occurrence_count` (INTEGER), `source_sessions` (JSON), `tags` (JSON).
- **Indexes:** B-tree index on `(ioc_type, normalized_value)`, index on `status`.

### Table 8: `ioc_evidence`
- **Purpose:** Append-only forensic evidence references linking indicators to exact raw log events.
- **Primary Key:** `id` (VARCHAR 64, UUID)
- **Foreign Keys:** `ioc_id` $\to$ `iocs.id` (ON DELETE CASCADE), `session_id` $\to$ `sessions.id` (ON DELETE CASCADE)
- **Columns:** `event_id` (VARCHAR 64), `timestamp` (DATETIME UTC), `raw_value` (VARCHAR 512), `source_field` (VARCHAR 64), `line_number` (INTEGER), `anomaly_id` (VARCHAR 64, NULLABLE), `incident_id` (VARCHAR 64, NULLABLE).
- **Indexes:** Index on `(ioc_id, session_id)`.

### Table 9: `threat_intel_results`
- **Purpose:** Caches raw external threat intelligence query outcomes.
- **Primary Key:** `id` (VARCHAR 64, UUID)
- **Foreign Keys:** `ioc_id` $\to$ `iocs.id` (ON DELETE CASCADE)
- **Columns:** `provider_name` (VARCHAR 64), `source` (VARCHAR 32), `status` (VARCHAR 32: `CLEAN`, `SUSPICIOUS`, `MALICIOUS`, `UNKNOWN`, `ERROR`), `confidence` (FLOAT), `detection_count` (INTEGER), `total_engines` (INTEGER), `reputation_score` (FLOAT), `categories` (JSON), `raw_metadata` (JSON), `queried_at` (DATETIME UTC), `expires_at` (DATETIME UTC).
- **Indexes:** Index on `(ioc_id, provider_name, expires_at)`.

### Table 10: `threat_assessments`
- **Purpose:** Stores deterministic threat reputation scores and contributing signals.
- **Primary Key:** `id` (VARCHAR 64, UUID)
- **Foreign Keys:** `ioc_id` $\to$ `iocs.id` (ON DELETE CASCADE)
- **Columns:** `threat_score` (FLOAT, $0.0–100.0$), `confidence` (FLOAT, $0.0–1.0$), `severity` (VARCHAR 16), `status` (VARCHAR 32), `reasons` (JSON), `contributing_signals` (JSON), `assessed_at` (DATETIME UTC), `expires_at` (DATETIME UTC), `engine_version` (VARCHAR 32).
- **Indexes:** Index on `(ioc_id, assessed_at)`.

### Table 11: `threat_correlations`
- **Purpose:** Stores directional relational links between security objects.
- **Primary Key:** `id` (VARCHAR 64, UUID)
- **Columns:** `correlation_type` (VARCHAR 64), `source_id` (VARCHAR 64), `source_type` (VARCHAR 32), `target_id` (VARCHAR 64), `target_type` (VARCHAR 32), `confidence_score` (FLOAT), `confidence_level` (VARCHAR 16), `evidence` (JSON), `correlation_method` (VARCHAR 64), `confirmed` (BOOLEAN), `first_seen` (DATETIME UTC), `last_seen` (DATETIME UTC), `created_at` (DATETIME UTC).
- **Indexes:** Composite index on `(source_id, target_id)`, index on `correlation_type`.

### Table 12: `audit_records`
- **Purpose:** Immutable audit trail tracking human analyst review actions and lifecycle transitions.
- **Primary Key:** `id` (VARCHAR 64, UUID)
- **Columns:** `entity_type` (VARCHAR 32: `ioc`, `incident`, `attack_chain`), `entity_id` (VARCHAR 64), `action` (VARCHAR 64: `STATUS_CHANGE`, `ANALYST_NOTE`, `MANUAL_CORRELATION`), `previous_state` (JSON), `new_state` (JSON), `actor` (VARCHAR 64), `timestamp` (DATETIME UTC), `ip_address` (VARCHAR 64).

---

## 3. Operational Persistence Modes

### 1. In-Memory Mode (`PERSISTENCE_BACKEND=memory`)
- **Use Case:** Default configuration for unit testing, CI/CD pipelines, and local development.
- **Characteristics:** Zero disk footprint, instantaneous teardown, zero external dependencies. State resets upon process termination.

### 2. SQLite File Mode (`PERSISTENCE_BACKEND=sqlite`)
- **Use Case:** Production deployment for single-node installations, small SOC instances, and edge server monitoring.
- **Characteristics:** Zero external database server required; writes to a local SQLite database file (`michael.db`). Fully ACID-compliant, supports complete restart recovery.

### 3. PostgreSQL / Supabase Mode (`PERSISTENCE_BACKEND=postgres`)
- **Use Case:** Enterprise multi-user SOC environments and cloud container deployments.
- **Configuration:** Configured via `DATABASE_URL` (e.g., `postgresql+asyncpg://user:pass@host:5432/michael`).
- **Supabase Compatibility:** Supabase operates on standard PostgreSQL; connection strings pointing to Supabase transaction poolers or direct instances are natively supported without modifying table definitions.

