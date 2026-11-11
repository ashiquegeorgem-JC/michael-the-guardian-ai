// ── Core Types for MICHAEL – The Guardian AI ─────────────────────────────

export type LogLevel = 'DEBUG' | 'INFO' | 'WARNING' | 'ERROR' | 'CRITICAL' | 'UNKNOWN';
export type Severity = 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
export type IncidentStatus = 'open' | 'investigating' | 'resolved' | 'false_positive';
export type DetectionMethod = 'isolation_forest' | 'statistical' | 'tfidf' | 'rule_based' | 'temporal';

export interface LogSession {
  id: string;
  filename: string;
  uploaded_at: string;
  total_lines: number;
  line_count?: number;
  file_size: number;
  status: 'pending' | 'processing' | 'ready' | 'failed';
}

export interface LogEntry {
  id: string;
  session_id: string;
  timestamp: string | null;
  level: LogLevel;
  source: string | null;
  message: string;
  raw_line: string;
  line_number: number;
  anomaly_score?: number | null;
  is_anomaly?: boolean;
  source_ip?: string | null;
  host?: string | null;
  service?: string | null;
}

export interface LogsResponse {
  session_id: string;
  total: number;
  page: number;
  page_size: number;
  entries: LogEntry[];
}

export interface Anomaly {
  id: string;
  session_id: string;
  log_entry_ids: string[];
  score: number;
  severity: Severity;
  reason: string;
  detected_at: string;
  timestamp?: string | null;
  source_ip?: string | null;
  host?: string | null;
  method: DetectionMethod;
  supporting_logs: string[];
  metadata: Record<string, unknown>;
  incident_id?: string | null;
}

export interface ModelMetrics {
  session_id: string;
  total_logs: number;
  anomalies_detected: number;
  contamination_rate: number;
  detection_methods: string[];
  tfidf_top_terms: Array<{ term: string; score: number }>;
  isolation_forest_params: Record<string, unknown>;
  analysis_duration_seconds: number;
  training_time_ms?: number;
  evaluated_at: string;
}

export interface AnalysisResults {
  session_id: string;
  anomalies: Anomaly[];
  metrics: ModelMetrics | null;
  total_anomalies: number;
}

export interface Incident {
  id: string;
  anomaly_id: string;
  session_id: string;
  category: string;
  severity: Severity;
  title: string;
  description: string;
  evidence: string[];
  evidence_log_lines: string[];
  root_cause_hypothesis: string;
  potential_impact: string;
  remediation_steps: string[];
  first_seen: string;
  last_seen: string;
  created_at: string;
  status: IncidentStatus;
  affected_sources: string[];
  affected_ips: string[];
  affected_hosts?: string[];
}

export interface IncidentsResponse {
  session_id: string;
  total: number;
  page: number;
  page_size: number;
  incidents: Incident[];
}

export interface CopilotResponse {
  question: string;
  answer: string;
  evidence: string[];
  confidence: 'low' | 'medium' | 'high';
  session_id: string;
  timestamp: string;
}

export interface SystemMetrics {
  cpu_percent: number;
  memory_percent: number;
  memory_used_gb: number;
  memory_total_gb: number;
  disk_percent: number;
  disk_used_gb: number;
  disk_total_gb: number;
  net_bytes_sent_mb: number;
  net_bytes_recv_mb: number;
  is_simulated: boolean;
  timestamp: string;
}

export interface DashboardStats {
  total_logs: number;
  total_anomalies: number;
  total_incidents: number;
  critical_incidents: number;
  open_incidents: number;
  sessions: number;
  active_session: string | null;
  system: SystemMetrics;
}

export interface LogStats {
  session_id: string;
  total: number;
  anomaly_count?: number;
  source_distribution?: Record<string, number>;
  level_distribution: Record<LogLevel, number>;
  hourly_volume: Array<{ time: string; count: number }>;
}

export interface AnalysisStatus {
  session_id: string;
  status: 'not_started' | 'pending' | 'running' | 'complete' | 'failed';
  progress: number;
  message: string;
}

export interface IncidentSummary {
  total: number;
  critical_count?: number;
  open_count?: number;
  severity_distribution: Record<Severity, number>;
  category_distribution: Record<string, number>;
}

export interface WsMessage {
  type: 'metrics' | 'anomaly_alert';
  timestamp: string;
  is_simulated: boolean;
  data: {
    cpu_percent: number;
    memory_percent: number;
    disk_percent: number;
    network_in_kbps: number;
    network_out_kbps: number;
    active_connections: number;
    log_events_per_min: number;
    latest_event: string;
  };
}

// ── Attack Chain Types (Phase 4.1) ─────────────────────────────────────────

export type AttackStage =
  | 'Reconnaissance'
  | 'Initial Access'
  | 'Credential Attack'
  | 'Privilege Escalation'
  | 'Execution'
  | 'Persistence'
  | 'Command and Control'
  | 'Lateral Movement'
  | 'Data Access'
  | 'Exfiltration'
  | 'Unknown';

export type GraphNodeType =
  | 'source_ip'
  | 'target_host'
  | 'user_account'
  | 'process'
  | 'attack_stage'
  | 'incident'
  | 'endpoint';

export interface ChainLinkEvent {
  id: string;
  log_entry_id: string | null;
  line_number: number | null;
  timestamp: string | null;
  stage: AttackStage;
  stage_confidence: number;
  source_ip: string | null;
  destination_ip: string | null;
  target_resource: string | null;
  user: string | null;
  process: string | null;
  raw_log: string;
  message: string;
  correlation_reason: string;
  anomaly_id: string | null;
  incident_id: string | null;
  is_confirmed: boolean;
}

export interface AttackGraphNode {
  id: string;
  label: string;
  type: GraphNodeType;
  details: Record<string, unknown>;
  severity: Severity | null;
}

export interface AttackGraphEdge {
  id: string;
  source: string;
  target: string;
  label: string;
  timestamp: string | null;
  confidence: number;
  stage: string | null;
  evidence: string | null;
}

export interface AttackGraphData {
  nodes: AttackGraphNode[];
  edges: AttackGraphEdge[];
}

export interface AttackChain {
  id: string;
  session_id: string;
  title: string;
  summary: string;
  severity: Severity;
  confidence_score: number;
  first_seen: string | null;
  last_seen: string | null;
  duration_seconds: number;
  stages_observed: AttackStage[];
  stages_unconfirmed: AttackStage[];
  source_ips: string[];
  target_systems: string[];
  affected_users: string[];
  affected_processes: string[];
  associated_anomaly_ids: string[];
  associated_incident_ids: string[];
  event_ids: string[];
  events: ChainLinkEvent[];
  supporting_evidence: string[];
  hypotheses_unconfirmed: string[];
  potential_impact: string;
  correlation_explanation: string;
  recommended_actions: string[];
  graph_data: AttackGraphData | null;
  status?: ChainStatus;
  analyst_note?: string | null;
  status_history?: ChainStatusHistory[];
  related_chain_ids?: string[];
  cross_session_evidence?: string[];
}

export interface AttackChainTimeline {
  chain_id: string;
  session_id: string;
  first_seen: string | null;
  last_seen: string | null;
  duration_seconds: number;
  total_events: number;
  events: ChainLinkEvent[];
}

// ── Phase 4.1B — SOC Attack Chain Intelligence ───────────────────────────

export type ChainStatus = 'NEW' | 'INVESTIGATING' | 'CONFIRMED' | 'FALSE_POSITIVE' | 'RESOLVED';

export interface ChainStatusHistory {
  previous_status: ChainStatus;
  new_status: ChainStatus;
  changed_at: string;
  changed_by?: string | null;
  reason: string;
}

export interface ChainStatusUpdate {
  status: ChainStatus;
  reason: string;
  changed_by?: string | null;
}

export interface RelatedEntity {
  entity_type: 'ip' | 'user' | 'host' | 'session' | 'chain' | string;
  entity_value: string;
  relationship_type: string;
  evidence: string[];
  confidence: number;
}

export interface RelatedChainLink {
  chain_id: string;
  session_id: string;
  title: string;
  severity: Severity;
  shared_signals: string[];
  correlation_explanation: string;
  confidence: number;
  is_confirmed: boolean;
}

export interface RelatedEntitiesResponse {
  chain_id: string;
  related_ips: RelatedEntity[];
  related_users: RelatedEntity[];
  related_hosts: RelatedEntity[];
  related_sessions: RelatedEntity[];
  related_chains: RelatedChainLink[];
  total_relationships: number;
}

export interface ChainSummary {
  total_chains: number;
  by_severity: Record<string, number>;
  by_status: Record<string, number>;
  by_stage: Record<string, number>;
  top_source_ips: Array<[string, number]>;
  avg_confidence: number;
  avg_duration_seconds: number;
  recent_chains: AttackChain[];
}

export interface ChainSearchParams {
  session_id?: string;
  chain_id?: string;
  source_ip?: string;
  destination_ip?: string;
  username?: string;
  stage?: string;
  severity?: string;
  status?: ChainStatus;
  keyword?: string;
  start_time?: string;
  end_time?: string;
  event_id?: string;
  page?: number;
  page_size?: number;
  sort_by?: string;
  sort_desc?: boolean;
}

export interface ChainSearchResult {
  total: number;
  page: number;
  page_size: number;
  chains: AttackChain[];
}

// ── IOC Types (Phase 4.2A) ─────────────────────────────────────────────────

export type IOCType =
  | 'ipv4'
  | 'ipv6'
  | 'domain'
  | 'url'
  | 'md5'
  | 'sha1'
  | 'sha256'
  | 'email'
  | 'file_path';

export type IOCStatus = 'EXTRACTED' | 'UNDER_REVIEW' | 'CONFIRMED' | 'FALSE_POSITIVE';

export type ValidationStatus = 'VALID' | 'INVALID' | 'SUSPICIOUS';

export type IPScope =
  | 'public'
  | 'private'
  | 'loopback'
  | 'link-local'
  | 'multicast'
  | 'reserved'
  | 'unspecified';

export interface IOCEvidence {
  event_id: string;
  session_id: string;
  timestamp: string | null;
  raw_value: string;
  source_field: string;
  line_number: number | null;
  surrounding_context: string;
  chain_link_event_id: string | null;
  incident_id: string | null;
  anomaly_id: string | null;
}

export interface IOCStatusHistory {
  previous_status: IOCStatus;
  new_status: IOCStatus;
  changed_at: string;
  changed_by: string | null;
  reason: string;
}

export interface IOC {
  id: string;
  ioc_type: IOCType;
  raw_value: string;
  normalized_value: string;
  status: IOCStatus;
  confidence: number;
  first_seen: string | null;
  last_seen: string | null;
  extracted_at: string;
  occurrence_count: number;
  evidence_references: IOCEvidence[];
  source_sessions: string[];
  extraction_methods: string[];
  associated_chain_ids: string[];
  associated_incident_ids: string[];
  associated_anomaly_ids: string[];
  analyst_note: string | null;
  tags: string[];
  status_history: IOCStatusHistory[];
  mitre_technique_ids: string[];
  reputation_score: number | null;
  validation_status?: ValidationStatus;
  validation_reason?: string | null;
  ip_scope?: IPScope | null;
}

export interface IOCListResponse {
  items: IOC[];
  total: number;
  page: number;
  page_size: number;
  total_pages: number;
}

export interface IOCSummary {
  session_id: string | null;
  total_iocs: number;
  by_type: Record<string, number>;
  by_status: Record<string, number>;
  by_validation_status: Record<string, number>;
  public_ip_count: number;
  private_ip_count: number;
  suspicious_count: number;
  confirmed_count: number;
  under_review_count: number;
  false_positive_count: number;
  top_ips: Array<[string, number]>;
  top_domains: Array<[string, number]>;
  top_hashes: Array<[string, number]>;
  chains_with_iocs: number;
  incidents_with_iocs: number;
  generated_at: string;
}

export interface IOCEvidenceResponse {
  ioc_id: string;
  ioc_type: IOCType;
  normalized_value: string;
  occurrence_count: number;
  evidence_count: number;
  evidence: IOCEvidence[];
}

export interface IOCRelationships {
  ioc_id: string;
  ioc_type: IOCType;
  normalized_value: string;
  relationship_count: number;
  sessions: Array<{ session_id: string }>;
  events: Array<{
    event_id: string;
    session_id: string;
    timestamp: string | null;
    line_number: number | null;
    raw_value: string;
    source_field: string;
    surrounding_context: string;
  }>;
  anomalies: Array<{ anomaly_id: string }>;
  incidents: Array<{ incident_id: string }>;
  attack_chains: Array<{ chain_id: string }>;
}

export interface IOCStatusUpdate {
  status: IOCStatus;
  reason: string;
  changed_by?: string | null;
  analyst_note?: string | null;
}

export interface IOCSearchParams {
  page?: number;
  page_size?: number;
  ioc_type?: string;
  status?: string;
  validation_status?: string;
  normalized_value?: string;
  session_id?: string;
  event_id?: string;
  anomaly_id?: string;
  incident_id?: string;
  attack_chain_id?: string;
}

// ── Threat Intelligence & Correlation Types (Phase 4.2B) ───────────────────

export type ThreatIntelStatus = 'UNKNOWN' | 'CLEAN' | 'SUSPICIOUS' | 'MALICIOUS' | 'ERROR';

export type ThreatSeverity = 'UNKNOWN' | 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';

export type ThreatIntelSource =
  | 'offline_mock'
  | 'virustotal'
  | 'abuseipdb'
  | 'urlhaus'
  | 'greynoise'
  | 'alienvault'
  | 'custom';

export interface ContributingSignal {
  signal_name: string;
  value: unknown;
  weight: number;
  contribution: number;
  explanation: string;
  available: boolean;
}

export interface ThreatAssessment {
  assessment_id: string;
  ioc_id: string;
  ioc_type: IOCType;
  ioc_value: string;
  normalized_value: string;
  threat_score: number;
  confidence: number;
  severity: ThreatSeverity;
  status: ThreatIntelStatus;
  reasons: string[];
  contributing_signals: ContributingSignal[];
  assessed_at: string;
  expires_at: string;
  engine_version: string;
  raw_metadata?: Record<string, unknown> | null;
}

export interface ThreatIntelResult {
  id: string;
  ioc_id: string;
  ioc_type: IOCType;
  ioc_value: string;
  normalized_value: string;
  status: ThreatIntelStatus;
  confidence: number;
  source: ThreatIntelSource;
  provider_name: string;
  provider_version?: string;
  queried_at: string;
  expires_at: string;
  lookup_latency_ms?: number | null;
  source_reference?: string | null;
  detection_count?: number | null;
  total_engines?: number | null;
  reputation_score?: number | null;
  categories: string[];
  tags: string[];
  country?: string | null;
  asn?: string | null;
  first_seen?: string | null;
  last_seen?: string | null;
  raw_metadata?: Record<string, unknown> | null;
}

export type ThreatCorrelationType =
  | 'IOC_TO_ANOMALY'
  | 'IOC_TO_INCIDENT'
  | 'IOC_TO_ATTACK_CHAIN'
  | 'IOC_TO_EVENT'
  | 'THREAT_ASSESSMENT_TO_INCIDENT'
  | 'THREAT_ASSESSMENT_TO_ATTACK_CHAIN';

export type CorrelationConfidenceLevel = 'LOW' | 'MEDIUM' | 'HIGH';

export interface CorrelationConfidence {
  score: number;
  confidence_level: CorrelationConfidenceLevel;
  evidence_count: number;
  correlation_method: string;
  calculated_at: string;
  correlated_at?: string;
}

export interface ThreatCorrelation {
  correlation_id: string;
  correlation_type: ThreatCorrelationType;
  source_id: string;
  source_type: string;
  target_id: string;
  target_type: string;
  confidence: CorrelationConfidence;
  evidence: string[];
  correlation_method: string;
  first_seen?: string | null;
  last_seen?: string | null;
  created_at: string;
  confirmed: boolean;
  analyst_note?: string | null;
}

export interface UnifiedThreatContext {
  ioc_id: string;
  ioc_value: string;
  normalized_value: string;
  ioc_type: IOCType;
  analyst_status: IOCStatus;
  threat_intel_result?: ThreatIntelResult | null;
  threat_assessment?: ThreatAssessment | null;
  related_events: Array<{
    event_id: string;
    confidence: number;
    confirmed: boolean;
    evidence: string[];
  }>;
  related_anomalies: Array<{
    anomaly_id: string;
    confidence: number;
    confirmed: boolean;
    evidence: string[];
  }>;
  related_incidents: Array<{
    incident_id: string;
    confidence: number;
    confirmed: boolean;
    evidence: string[];
  }>;
  related_attack_chains: Array<{
    chain_id: string;
    confidence: number;
    confirmed: boolean;
    evidence: string[];
  }>;
  correlations: ThreatCorrelation[];
  overall_correlation_confidence: number;
  investigation_summary: {
    total_correlations: number;
    confirmed_correlations: number;
    unconfirmed_correlations: number;
    event_count: number;
    anomaly_count: number;
    incident_count: number;
    attack_chain_count: number;
    highest_confidence: number;
    highest_confidence_level: string;
    key_findings: string[];
  };
  generated_at: string;
}

export interface CorrelatedAnomaliesResponse {
  ioc_id: string;
  ioc_type: string;
  normalized_value: string;
  total: number;
  anomalies: ThreatCorrelation[];
}

export interface CorrelatedIncidentsResponse {
  ioc_id: string;
  ioc_type: string;
  normalized_value: string;
  total: number;
  incidents: ThreatCorrelation[];
}

export interface CorrelatedAttackChainsResponse {
  ioc_id: string;
  ioc_type: string;
  normalized_value: string;
  total: number;
  attack_chains: ThreatCorrelation[];
}

export interface CorrelatedEventsResponse {
  ioc_id: string;
  ioc_type: string;
  normalized_value: string;
  total: number;
  events: ThreatCorrelation[];
}

export interface ThreatCorrelationsResponse {
  ioc_id: string;
  ioc_type: string;
  normalized_value: string;
  total: number;
  confirmed_count: number;
  unconfirmed_count: number;
  correlations: ThreatCorrelation[];
}



