-- =============================================================================
-- MICHAEL – THE GUARDIAN AI
-- Production Persistence Schema (PostgreSQL / Supabase)
-- Phase 5.0 — Production Hardening & Persistence Integration
-- =============================================================================

-- Enable UUID extension if not already available
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- -----------------------------------------------------------------------------
-- 1. SESSIONS TABLE
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS sessions (
    id VARCHAR(128) PRIMARY KEY,
    filename TEXT NOT NULL,
    uploaded_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    total_lines INTEGER NOT NULL CHECK (total_lines >= 0),
    file_size BIGINT NOT NULL CHECK (file_size >= 0),
    status VARCHAR(50) NOT NULL DEFAULT 'uploaded',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_sessions_uploaded_at ON sessions(uploaded_at DESC);
CREATE INDEX IF NOT EXISTS idx_sessions_status ON sessions(status);

-- -----------------------------------------------------------------------------
-- 2. EVENTS (LOG ENTRIES) TABLE
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS events (
    id VARCHAR(128) PRIMARY KEY,
    session_id VARCHAR(128) NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
    line_number INTEGER NOT NULL CHECK (line_number >= 1),
    timestamp TIMESTAMPTZ NOT NULL,
    level VARCHAR(20) NOT NULL,
    source VARCHAR(128) NOT NULL,
    message TEXT NOT NULL,
    raw TEXT NOT NULL,
    ip_address VARCHAR(128),
    user_name VARCHAR(128),
    action VARCHAR(128),
    status_code INTEGER,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_events_session_id ON events(session_id);
CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events(timestamp);
CREATE INDEX IF NOT EXISTS idx_events_level ON events(level);
CREATE INDEX IF NOT EXISTS idx_events_ip_address ON events(ip_address) WHERE ip_address IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_events_session_line ON events(session_id, line_number);

-- -----------------------------------------------------------------------------
-- 3. ANOMALIES TABLE
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS anomalies (
    id VARCHAR(128) PRIMARY KEY,
    session_id VARCHAR(128) NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
    score DOUBLE PRECISION NOT NULL CHECK (score >= 0.0 AND score <= 1.0),
    severity VARCHAR(20) NOT NULL,
    reason TEXT NOT NULL,
    method VARCHAR(50) NOT NULL,
    detected_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    log_entry_ids JSONB NOT NULL DEFAULT '[]'::jsonb,
    features JSONB DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_anomalies_session_id ON anomalies(session_id);
CREATE INDEX IF NOT EXISTS idx_anomalies_severity ON anomalies(severity);
CREATE INDEX IF NOT EXISTS idx_anomalies_score ON anomalies(score DESC);
CREATE INDEX IF NOT EXISTS idx_anomalies_detected_at ON anomalies(detected_at DESC);

-- -----------------------------------------------------------------------------
-- 4. MODEL METRICS TABLE
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS model_metrics (
    id VARCHAR(128) PRIMARY KEY,
    session_id VARCHAR(128) NOT NULL UNIQUE REFERENCES sessions(id) ON DELETE CASCADE,
    total_logs INTEGER NOT NULL CHECK (total_logs >= 0),
    anomalies_detected INTEGER NOT NULL CHECK (anomalies_detected >= 0),
    contamination_rate DOUBLE PRECISION NOT NULL,
    processing_time_ms DOUBLE PRECISION NOT NULL,
    baseline_deviation DOUBLE PRECISION NOT NULL,
    severity_distribution JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_metrics_session_id ON model_metrics(session_id);

-- -----------------------------------------------------------------------------
-- 5. INCIDENTS TABLE
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS incidents (
    id VARCHAR(128) PRIMARY KEY,
    anomaly_id VARCHAR(128) NOT NULL,
    session_id VARCHAR(128) NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
    category VARCHAR(50) NOT NULL,
    severity VARCHAR(20) NOT NULL,
    title VARCHAR(255) NOT NULL,
    description TEXT NOT NULL,
    root_cause_hypothesis TEXT NOT NULL,
    potential_impact TEXT NOT NULL,
    first_seen TIMESTAMPTZ NOT NULL,
    last_seen TIMESTAMPTZ NOT NULL,
    status VARCHAR(30) NOT NULL DEFAULT 'open',
    assigned_analyst VARCHAR(128),
    remediation_steps JSONB DEFAULT '[]'::jsonb,
    evidence JSONB DEFAULT '[]'::jsonb,
    evidence_log_lines JSONB DEFAULT '[]'::jsonb,
    affected_sources JSONB DEFAULT '[]'::jsonb,
    affected_ips JSONB DEFAULT '[]'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT chk_incident_dates CHECK (first_seen <= last_seen)
);

CREATE INDEX IF NOT EXISTS idx_incidents_session_id ON incidents(session_id);
CREATE INDEX IF NOT EXISTS idx_incidents_anomaly_id ON incidents(anomaly_id);
CREATE INDEX IF NOT EXISTS idx_incidents_status ON incidents(status);
CREATE INDEX IF NOT EXISTS idx_incidents_severity ON incidents(severity);
CREATE INDEX IF NOT EXISTS idx_incidents_first_seen ON incidents(first_seen DESC);

-- -----------------------------------------------------------------------------
-- 6. ATTACK CHAINS TABLE
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS attack_chains (
    id VARCHAR(128) PRIMARY KEY,
    session_id VARCHAR(128) NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
    title VARCHAR(255) NOT NULL,
    summary TEXT NOT NULL,
    severity VARCHAR(20) NOT NULL,
    confidence_score DOUBLE PRECISION NOT NULL CHECK (confidence_score >= 0.0 AND confidence_score <= 1.0),
    first_seen TIMESTAMPTZ NOT NULL,
    last_seen TIMESTAMPTZ NOT NULL,
    duration_seconds DOUBLE PRECISION NOT NULL DEFAULT 0.0 CHECK (duration_seconds >= 0.0),
    stages_observed JSONB DEFAULT '[]'::jsonb,
    stages_unconfirmed JSONB DEFAULT '[]'::jsonb,
    source_ips JSONB DEFAULT '[]'::jsonb,
    target_systems JSONB DEFAULT '[]'::jsonb,
    affected_users JSONB DEFAULT '[]'::jsonb,
    affected_processes JSONB DEFAULT '[]'::jsonb,
    associated_anomaly_ids JSONB DEFAULT '[]'::jsonb,
    associated_incident_ids JSONB DEFAULT '[]'::jsonb,
    event_ids JSONB DEFAULT '[]'::jsonb,
    events JSONB DEFAULT '[]'::jsonb,
    supporting_evidence JSONB DEFAULT '[]'::jsonb,
    hypotheses_unconfirmed JSONB DEFAULT '[]'::jsonb,
    potential_impact TEXT NOT NULL,
    correlation_explanation TEXT NOT NULL,
    recommended_actions JSONB DEFAULT '[]'::jsonb,
    graph_data JSONB DEFAULT '{}'::jsonb,
    status VARCHAR(30) NOT NULL DEFAULT 'NEW',
    analyst_note TEXT,
    status_history JSONB DEFAULT '[]'::jsonb,
    related_chain_ids JSONB DEFAULT '[]'::jsonb,
    cross_session_evidence JSONB DEFAULT '[]'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT chk_chain_dates CHECK (first_seen <= last_seen)
);

CREATE INDEX IF NOT EXISTS idx_chains_session_id ON attack_chains(session_id);
CREATE INDEX IF NOT EXISTS idx_chains_status ON attack_chains(status);
CREATE INDEX IF NOT EXISTS idx_chains_severity ON attack_chains(severity);
CREATE INDEX IF NOT EXISTS idx_chains_confidence ON attack_chains(confidence_score DESC);

-- -----------------------------------------------------------------------------
-- 7. INDICATORS OF COMPROMISE (IOCS) TABLE
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS iocs (
    id VARCHAR(128) PRIMARY KEY,
    ioc_type VARCHAR(30) NOT NULL,
    raw_value TEXT NOT NULL,
    normalized_value TEXT NOT NULL,
    status VARCHAR(30) NOT NULL DEFAULT 'EXTRACTED',
    validation_status VARCHAR(30) NOT NULL DEFAULT 'VALID',
    ip_scope VARCHAR(30),
    confidence_score DOUBLE PRECISION NOT NULL DEFAULT 0.5 CHECK (confidence_score >= 0.0 AND confidence_score <= 1.0),
    occurrence_count INTEGER NOT NULL DEFAULT 1 CHECK (occurrence_count >= 1),
    first_seen TIMESTAMPTZ NOT NULL,
    last_seen TIMESTAMPTZ NOT NULL,
    source_sessions JSONB DEFAULT '[]'::jsonb,
    associated_anomaly_ids JSONB DEFAULT '[]'::jsonb,
    associated_incident_ids JSONB DEFAULT '[]'::jsonb,
    associated_chain_ids JSONB DEFAULT '[]'::jsonb,
    tags JSONB DEFAULT '[]'::jsonb,
    analyst_notes TEXT,
    status_history JSONB DEFAULT '[]'::jsonb,
    raw_metadata JSONB DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT uq_ioc_canonical UNIQUE (ioc_type, normalized_value),
    CONSTRAINT chk_ioc_dates CHECK (first_seen <= last_seen)
);

CREATE INDEX IF NOT EXISTS idx_iocs_type ON iocs(ioc_type);
CREATE INDEX IF NOT EXISTS idx_iocs_normalized ON iocs(normalized_value);
CREATE INDEX IF NOT EXISTS idx_iocs_status ON iocs(status);
CREATE INDEX IF NOT EXISTS idx_iocs_last_seen ON iocs(last_seen DESC);

-- -----------------------------------------------------------------------------
-- 8. IOC EVIDENCE REFERENCES TABLE
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS ioc_evidence (
    id VARCHAR(128) PRIMARY KEY,
    ioc_id VARCHAR(128) NOT NULL REFERENCES iocs(id) ON DELETE CASCADE,
    event_id VARCHAR(128) NOT NULL,
    session_id VARCHAR(128) NOT NULL,
    timestamp TIMESTAMPTZ NOT NULL,
    raw_value TEXT NOT NULL,
    source_field VARCHAR(100) NOT NULL,
    line_number INTEGER,
    surrounding_context TEXT,
    anomaly_id VARCHAR(128),
    incident_id VARCHAR(128),
    attack_chain_id VARCHAR(128),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_evidence_ioc_id ON ioc_evidence(ioc_id);
CREATE INDEX IF NOT EXISTS idx_evidence_event_id ON ioc_evidence(event_id);
CREATE INDEX IF NOT EXISTS idx_evidence_session_id ON ioc_evidence(session_id);
CREATE INDEX IF NOT EXISTS idx_evidence_anomaly_id ON ioc_evidence(anomaly_id) WHERE anomaly_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_evidence_incident_id ON ioc_evidence(incident_id) WHERE incident_id IS NOT NULL;

-- -----------------------------------------------------------------------------
-- 9. THREAT INTEL RESULTS TABLE
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS threat_intel_results (
    id VARCHAR(128) PRIMARY KEY,
    ioc_id VARCHAR(128) NOT NULL REFERENCES iocs(id) ON DELETE CASCADE,
    ioc_type VARCHAR(30) NOT NULL,
    ioc_value TEXT NOT NULL,
    normalized_value TEXT NOT NULL,
    status VARCHAR(30) NOT NULL,
    confidence DOUBLE PRECISION NOT NULL DEFAULT 0.0 CHECK (confidence >= 0.0 AND confidence <= 1.0),
    source VARCHAR(50) NOT NULL,
    provider_name VARCHAR(50) NOT NULL,
    provider_version VARCHAR(30),
    queried_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMPTZ NOT NULL,
    lookup_latency_ms DOUBLE PRECISION,
    detection_count INTEGER CHECK (detection_count >= 0),
    total_engines INTEGER CHECK (total_engines >= 0),
    reputation_score DOUBLE PRECISION CHECK (reputation_score >= 0.0 AND reputation_score <= 1.0),
    categories JSONB DEFAULT '[]'::jsonb,
    tags JSONB DEFAULT '[]'::jsonb,
    country VARCHAR(10),
    asn VARCHAR(50),
    raw_metadata JSONB DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT uq_threat_intel_provider UNIQUE (provider_name, ioc_type, normalized_value)
);

CREATE INDEX IF NOT EXISTS idx_threat_intel_ioc_id ON threat_intel_results(ioc_id);
CREATE INDEX IF NOT EXISTS idx_threat_intel_expires_at ON threat_intel_results(expires_at);
CREATE INDEX IF NOT EXISTS idx_threat_intel_status ON threat_intel_results(status);

-- -----------------------------------------------------------------------------
-- 10. THREAT ASSESSMENTS TABLE
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS threat_assessments (
    assessment_id VARCHAR(128) PRIMARY KEY,
    ioc_id VARCHAR(128) NOT NULL REFERENCES iocs(id) ON DELETE CASCADE,
    ioc_type VARCHAR(30) NOT NULL,
    ioc_value TEXT NOT NULL,
    normalized_value TEXT NOT NULL,
    threat_score DOUBLE PRECISION NOT NULL CHECK (threat_score >= 0.0 AND threat_score <= 100.0),
    confidence DOUBLE PRECISION NOT NULL CHECK (confidence >= 0.0 AND confidence <= 1.0),
    severity VARCHAR(30) NOT NULL,
    status VARCHAR(30) NOT NULL,
    reasons JSONB DEFAULT '[]'::jsonb,
    contributing_signals JSONB DEFAULT '[]'::jsonb,
    assessed_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMPTZ NOT NULL,
    engine_version VARCHAR(30) NOT NULL,
    raw_metadata JSONB DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_assessments_ioc_id ON threat_assessments(ioc_id);
CREATE INDEX IF NOT EXISTS idx_assessments_severity ON threat_assessments(severity);
CREATE INDEX IF NOT EXISTS idx_assessments_threat_score ON threat_assessments(threat_score DESC);

-- -----------------------------------------------------------------------------
-- 11. THREAT CORRELATIONS TABLE
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS threat_correlations (
    correlation_id VARCHAR(128) PRIMARY KEY,
    correlation_type VARCHAR(50) NOT NULL,
    source_id VARCHAR(128) NOT NULL,
    source_type VARCHAR(50) NOT NULL,
    target_id VARCHAR(128) NOT NULL,
    target_type VARCHAR(50) NOT NULL,
    confidence JSONB NOT NULL,
    evidence JSONB NOT NULL DEFAULT '[]'::jsonb,
    correlation_method VARCHAR(100) NOT NULL,
    first_seen TIMESTAMPTZ,
    last_seen TIMESTAMPTZ,
    confirmed BOOLEAN NOT NULL DEFAULT TRUE,
    analyst_note TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT chk_corr_dates CHECK (first_seen IS NULL OR last_seen IS NULL OR first_seen <= last_seen)
);

CREATE INDEX IF NOT EXISTS idx_corr_source ON threat_correlations(source_id, source_type);
CREATE INDEX IF NOT EXISTS idx_corr_target ON threat_correlations(target_id, target_type);
CREATE INDEX IF NOT EXISTS idx_corr_type ON threat_correlations(correlation_type);
CREATE INDEX IF NOT EXISTS idx_corr_confirmed ON threat_correlations(confirmed);

-- -----------------------------------------------------------------------------
-- 12. AUDIT RECORDS TABLE
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS audit_records (
    id VARCHAR(128) PRIMARY KEY,
    action VARCHAR(100) NOT NULL,
    entity_type VARCHAR(50) NOT NULL,
    entity_id VARCHAR(128) NOT NULL,
    analyst VARCHAR(128),
    details JSONB DEFAULT '{}'::jsonb,
    ip_address VARCHAR(128),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_audit_entity ON audit_records(entity_type, entity_id);
CREATE INDEX IF NOT EXISTS idx_audit_created_at ON audit_records(created_at DESC);

