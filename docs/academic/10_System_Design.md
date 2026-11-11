# CHAPTER 10: SYSTEM DESIGN & ARCHITECTURE

## 8.1 Architectural Design Principles
The design of **MICHAEL – THE GUARDIAN AI** adheres to four core principles:
1. **Separation of Concerns:** Business logic, machine learning detection, intelligence lookups, and storage persistence reside in distinct, loosely coupled layers.
2. **Defensive Non-Destructive Operation:** Correlation and analysis engines act as additive evidence providers; source entities remain bitwise immutable.
3. **Forensic Traceability:** Every higher-level detection (anomaly, incident, attack chain, IOC) maintains an unbroken reference back to exact source log line numbers.
4. **Pluggability:** Storage backends (Memory, SQLite, PostgreSQL) and threat intelligence providers (OfflineMock, VirusTotal) implement standard interfaces and can be swapped via configuration flags.

## 8.2 Component Hierarchy & Data Flow

```mermaid
flowchart TD
    subgraph INGESTION["Ingestion Tier"]
        RawLogs["Raw Logs (.log, .txt, .csv)"] --> LogParser["Log Parser Service"]
        LogParser --> LogSession["LogSession Entity"]
        LogParser --> LogEntry["LogEntry Entities"]
    end

    subgraph DETECTION["Detection Tier"]
        LogEntry --> DetectionEngine["Hybrid Anomaly Engine"]
        DetectionEngine --> Anomalies["Anomaly Entities"]
        DetectionEngine --> Temporal["Temporal Engine (10s, 30s, 60s, 300s)"]
        Temporal --> Anomalies
    end

    subgraph AGGREGATION["Incident & Attack Chain Tier"]
        Anomalies --> IncidentService["Incident Service"]
        IncidentService --> Incidents["Incident Entities"]
        Incidents --> AttackChainEngine["Attack Chain Engine"]
        AttackChainEngine --> AttackChains["AttackChain Entities (MITRE ATT&CK)"]
    end

    subgraph IOC_INTEL["IOC & Threat Intelligence Tier"]
        LogEntry --> IOCExtractor["IOC Extractor"]
        Anomalies --> IOCExtractor
        Incidents --> IOCExtractor
        AttackChains --> IOCExtractor
        IOCExtractor --> Normalizer["RFC Normalizer (9 Types)"]
        Normalizer --> IOCRepo["IOC Repository & Evidence Mapper"]
        IOCRepo --> ThreatService["ThreatIntelService"]
        ThreatService --> Providers["Providers (OfflineMock / VirusTotal)"]
        Providers --> ReputationEngine["Threat Reputation Engine"]
    end

    subgraph CORRELATION["Correlation Tier"]
        ReputationEngine --> CorrelationEngine["Threat Correlation Engine"]
        IOCRepo --> CorrelationEngine
        Incidents --> CorrelationEngine
        AttackChains --> CorrelationEngine
        CorrelationEngine --> UnifiedContext["UnifiedThreatContext"]
    end

    subgraph PERSISTENCE["Storage Tier"]
        Persistence["Abstract Repository Interface"]
        Persistence --> SQLite["SQLite File Backend"]
        Persistence --> Postgres["PostgreSQL / Supabase Backend"]
        Persistence --> Memory["In-Memory Testing Backend"]
    end

    subgraph PRESENTATION["Presentation Tier"]
        FastAPI["FastAPI REST API Layer"]
        NextJS["Next.js 16 SOC Dashboard (15 Routes)"]
        PDF["ReportLab PDF Generator"]
        
        UnifiedContext --> FastAPI
        FastAPI --> NextJS
        FastAPI --> PDF
    end
```

## 8.3 Entity Relationship Model (12-Table Schema)
The physical database design enforces relational constraints across twelve tables:
- `sessions`: Session tracking, line counts, and upload timestamps.
- `events`: Individual parsed log lines with exact line numbers and timestamps.
- `anomalies`: Anomaly detections with scores, severities, and method tags.
- `model_metrics`: Session-level ML accuracy and contamination parameters.
- `incidents`: Aggregated incidents with impact analyses and remediation guidance.
- `attack_chains`: Multi-stage attack progression graphs with MITRE ATT&CK stages.
- `iocs`: Canonical indicators deduplicated by `(ioc_type, normalized_value)`.
- `ioc_evidence`: Append-only forensic evidence links mapping IOCs to events.
- `threat_intel_results`: Cached external provider query outcomes.
- `threat_assessments`: Deterministic threat reputation scores and contributing signals.
- `threat_correlations`: Directional links connecting security objects.
- `audit_records`: Immutable log of human analyst triage actions.

