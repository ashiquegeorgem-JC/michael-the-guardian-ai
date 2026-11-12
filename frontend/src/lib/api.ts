// API client for MICHAEL backend
import type {
  LogsResponse, LogStats, LogSession, AnalysisResults,
  AnalysisStatus, IncidentsResponse, IncidentSummary, Incident,
  CopilotResponse, SystemMetrics, DashboardStats, ModelMetrics,
  AttackChain, AttackChainTimeline, AttackGraphData,
  ChainSearchParams, ChainSearchResult, ChainStatusUpdate,
  RelatedEntitiesResponse, ChainSummary,
  IOC, IOCListResponse, IOCSummary, IOCEvidenceResponse,
  IOCRelationships, IOCStatusUpdate, IOCSearchParams,
  UnifiedThreatContext, CorrelatedAnomaliesResponse,
  CorrelatedIncidentsResponse, CorrelatedAttackChainsResponse,
  CorrelatedEventsResponse, ThreatCorrelationsResponse,
} from '@/types';

const BASE = (process.env.NEXT_PUBLIC_API_URL || 'https://michael-the-guardian-ai.onrender.com').replace(/\/+$/, '');

async function request<T>(path: string, options?: RequestInit): Promise<T> {
  const cleanPath = path.startsWith('/') ? path : `/${path}`;
  try {
    const res = await fetch(`${BASE}${cleanPath}`, {
      headers: { 'Content-Type': 'application/json', ...options?.headers },
      ...options,
    });
    if (!res.ok) {
      const error = await res.json().catch(() => ({ detail: res.statusText }));
      throw new Error(error.detail || `Request failed with status ${res.status}`);
    }
    return res.json();
  } catch (err: any) {
    if (err.name === 'TypeError' && err.message.includes('fetch')) {
      throw new Error('Unable to connect to MICHAEL security backend. Please check network connection.');
    }
    throw err;
  }
}

// ── Logs ──────────────────────────────────────────────────────────────────

export async function uploadLogFile(file: File): Promise<{
  session_id: string; filename: string; total_lines: number;
  file_size: number; status: string; message: string;
}> {
  const form = new FormData();
  form.append('file', file);
  try {
    const res = await fetch(`${BASE}/api/logs/upload`, { method: 'POST', body: form });
    if (!res.ok) {
      const err = await res.json().catch(() => ({ detail: res.statusText }));
      throw new Error(err.detail || `Upload failed with status ${res.status}`);
    }
    return res.json();
  } catch (err: any) {
    if (err.name === 'TypeError' && err.message.includes('fetch')) {
      throw new Error('Unable to connect to MICHAEL security backend for log upload.');
    }
    throw err;
  }
}

export async function getLogs(params?: {
  session_id?: string; level?: string; keyword?: string;
  page?: number; page_size?: number;
}): Promise<LogsResponse> {
  const q = new URLSearchParams();
  if (params?.session_id) q.set('session_id', params.session_id);
  if (params?.level) q.set('level', params.level);
  if (params?.keyword) q.set('keyword', params.keyword);
  if (params?.page) q.set('page', String(params.page));
  if (params?.page_size) q.set('page_size', String(params.page_size));
  return request<LogsResponse>(`/api/logs?${q}`);
}

export async function getLogStats(session_id?: string): Promise<LogStats> {
  const q = session_id ? `?session_id=${session_id}` : '';
  return request<LogStats>(`/api/logs/stats${q}`);
}

export async function getSessions(): Promise<{ sessions: LogSession[] }> {
  return request(`/api/logs/sessions`);
}

// ── Analysis ──────────────────────────────────────────────────────────────

export async function runAnalysis(session_id: string, contamination?: number) {
  return request(`/api/analysis/run`, {
    method: 'POST',
    body: JSON.stringify({ session_id, contamination }),
  });
}

export async function getAnalysisStatus(session_id: string): Promise<AnalysisStatus> {
  return request<AnalysisStatus>(`/api/analysis/status/${session_id}`);
}

export async function getAnalysisResults(session_id?: string): Promise<AnalysisResults> {
  const q = session_id ? `?session_id=${session_id}` : '';
  return request<AnalysisResults>(`/api/analysis/results${q}`);
}

export async function getModelMetrics(session_id?: string): Promise<ModelMetrics> {
  const q = session_id ? `?session_id=${session_id}` : '';
  return request<ModelMetrics>(`/api/analysis/metrics${q}`);
}

export async function getResearchBenchmark(): Promise<any> {
  return request<any>(`/api/analysis/benchmark`);
}

// ── Incidents ─────────────────────────────────────────────────────────────

export async function getIncidents(params?: {
  session_id?: string; severity?: string; status?: string;
  page?: number; page_size?: number;
}): Promise<IncidentsResponse> {
  const q = new URLSearchParams();
  if (params?.session_id) q.set('session_id', params.session_id);
  if (params?.severity) q.set('severity', params.severity);
  if (params?.status) q.set('status', params.status);
  if (params?.page) q.set('page', String(params.page));
  if (params?.page_size) q.set('page_size', String(params.page_size));
  return request<IncidentsResponse>(`/api/incidents?${q}`);
}

export async function getIncidentSummary(session_id?: string): Promise<IncidentSummary> {
  const q = session_id ? `?session_id=${session_id}` : '';
  return request<IncidentSummary>(`/api/incidents/summary${q}`);
}

export async function getIncident(id: string): Promise<Incident> {
  return request<Incident>(`/api/incidents/${id}`);
}

export async function updateIncidentStatus(id: string, status: string) {
  return request(`/api/incidents/${id}/status?status=${status}`, { method: 'PATCH' });
}

// ── Copilot ───────────────────────────────────────────────────────────────

export async function askCopilot(question: string, session_id?: string): Promise<CopilotResponse> {
  return request<CopilotResponse>(`/api/copilot/chat`, {
    method: 'POST',
    body: JSON.stringify({ question, session_id }),
  });
}

export async function getCopilotSuggestions(): Promise<{ suggestions: string[] }> {
  return request(`/api/copilot/suggestions`);
}

// ── Monitoring ────────────────────────────────────────────────────────────

export async function getSystemMetrics(): Promise<SystemMetrics> {
  return request<SystemMetrics>(`/api/monitoring/metrics`);
}

export async function getDashboardStats(): Promise<DashboardStats> {
  return request<DashboardStats>(`/api/monitoring/dashboard`);
}

export async function getMetricHistory(points?: number): Promise<{
  history: Array<{ timestamp: string; cpu_percent: number; memory_percent: number; network_mbps: number; is_simulated: boolean }>;
  note: string;
}> {
  const q = points ? `?points=${points}` : '';
  return request(`/api/monitoring/history${q}`);
}

// ── Reports ───────────────────────────────────────────────────────────────

export async function generateReport(session_id?: string, title?: string): Promise<{
  report_id: string; filename: string; download_url: string; generated_at: string;
}> {
  return request(`/api/reports/generate`, {
    method: 'POST',
    body: JSON.stringify({ session_id, title }),
  });
}

export function getReportDownloadUrl(filename: string): string {
  return `${BASE}/api/reports/download/${filename}`;
}

// ── Temporal ──────────────────────────────────────────────────────────────

export async function getTemporalTelemetry(session_id?: string): Promise<any> {
  const q = session_id ? `?session_id=${session_id}` : '';
  return request(`/api/temporal/telemetry${q}`);
}

export async function getTemporalAnomalies(session_id?: string): Promise<any> {
  const q = session_id ? `?session_id=${session_id}` : '';
  return request(`/api/temporal/anomalies${q}`);
}

export async function getTemporalBenchmark(): Promise<any> {
  return request(`/api/temporal/benchmark`);
}

// ── Health ────────────────────────────────────────────────────────────────

export interface HealthStatus {
  status: string;
  service: string;
  version: string;
  docs?: string;
  is_operational: boolean;
}

export async function checkHealth(): Promise<HealthStatus> {
  try {
    const res = await request<{ status: string; service: string; version: string; docs?: string }>(`/`);
    return {
      ...res,
      is_operational: res.status?.toLowerCase() === 'operational',
    };
  } catch {
    // Fallback to /api/health if reverse proxy rewrites root
    const res = await request<{ status: string; service: string; version: string }>(`/api/health`);
    return {
      ...res,
      is_operational: res.status?.toLowerCase() === 'operational',
    };
  }
}

// ── Attack Chains (Phase 4.1) ─────────────────────────────────────────────

export async function getAttackChains(params?: {
  session_id?: string;
  severity?: string;
  stage?: string;
}): Promise<AttackChain[]> {
  const q = new URLSearchParams();
  if (params?.session_id) q.set('session_id', params.session_id);
  if (params?.severity) q.set('severity', params.severity);
  if (params?.stage) q.set('stage', params.stage);
  return request<AttackChain[]>(`/api/attack-chains?${q}`);
}

export async function getAttackChain(chain_id: string): Promise<AttackChain> {
  return request<AttackChain>(`/api/attack-chains/${chain_id}`);
}

export async function getAttackChainTimeline(chain_id: string): Promise<AttackChainTimeline> {
  return request<AttackChainTimeline>(`/api/attack-chains/${chain_id}/timeline`);
}

export async function getAttackChainGraph(chain_id: string): Promise<AttackGraphData> {
  return request<AttackGraphData>(`/api/attack-chains/${chain_id}/graph`);
}

// ── Phase 4.1B — SOC Attack Chain Intelligence ───────────────────────────

export async function searchAttackChains(params: ChainSearchParams): Promise<ChainSearchResult> {
  const q = new URLSearchParams();
  if (params.session_id) q.set('session_id', params.session_id);
  if (params.chain_id) q.set('chain_id', params.chain_id);
  if (params.source_ip) q.set('source_ip', params.source_ip);
  if (params.destination_ip) q.set('destination_ip', params.destination_ip);
  if (params.username) q.set('username', params.username);
  if (params.stage) q.set('stage', params.stage);
  if (params.severity) q.set('severity', params.severity);
  if (params.status) q.set('status', params.status);
  if (params.keyword) q.set('keyword', params.keyword);
  if (params.start_time) q.set('start_time', params.start_time);
  if (params.end_time) q.set('end_time', params.end_time);
  if (params.event_id) q.set('event_id', params.event_id);
  if (params.page) q.set('page', String(params.page));
  if (params.page_size) q.set('page_size', String(params.page_size));
  if (params.sort_by) q.set('sort_by', params.sort_by);
  if (params.sort_desc !== undefined) q.set('sort_desc', String(params.sort_desc));

  return request<ChainSearchResult>(`/api/attack-chains/search?${q}`);
}

export async function updateAttackChainStatus(
  chain_id: string,
  update: ChainStatusUpdate
): Promise<AttackChain> {
  return request<AttackChain>(`/api/attack-chains/${chain_id}/status`, {
    method: 'PATCH',
    body: JSON.stringify(update),
  });
}

export async function confirmAttackChainEvent(
  chain_id: string,
  event_id: string,
  data: { is_confirmed: boolean; reason: string; changed_by?: string }
): Promise<{
  chain_id: string;
  event_id: string;
  decision: string;
  is_confirmed: boolean;
  correlation_reason: string;
  changed_by?: string;
}> {
  return request(`/api/attack-chains/${chain_id}/events/${event_id}/confirm`, {
    method: 'POST',
    body: JSON.stringify(data),
  });
}

export async function getAttackChainRelated(chain_id: string): Promise<RelatedEntitiesResponse> {
  return request<RelatedEntitiesResponse>(`/api/attack-chains/${chain_id}/related`);
}

export async function getAttackChainSummary(session_id?: string): Promise<ChainSummary> {
  const q = session_id ? `?session_id=${session_id}` : '';
  return request<ChainSummary>(`/api/attack-chains/summary${q}`);
}

// ── IOCs (Phase 4.2A.5 / 4.2A.6) ──────────────────────────────────────────

export async function listIOCs(params?: IOCSearchParams): Promise<IOCListResponse> {
  const q = new URLSearchParams();
  if (params?.page) q.set('page', String(params.page));
  if (params?.page_size) q.set('page_size', String(params.page_size));
  if (params?.ioc_type) q.set('ioc_type', params.ioc_type);
  if (params?.status) q.set('status', params.status);
  if (params?.validation_status) q.set('validation_status', params.validation_status);
  if (params?.normalized_value) q.set('normalized_value', params.normalized_value);
  if (params?.session_id) q.set('session_id', params.session_id);
  if (params?.event_id) q.set('event_id', params.event_id);
  if (params?.anomaly_id) q.set('anomaly_id', params.anomaly_id);
  if (params?.incident_id) q.set('incident_id', params.incident_id);
  if (params?.attack_chain_id) q.set('attack_chain_id', params.attack_chain_id);
  return request<IOCListResponse>(`/api/iocs?${q}`);
}

export async function searchIOCs(params?: IOCSearchParams): Promise<IOCListResponse> {
  const q = new URLSearchParams();
  if (params?.page) q.set('page', String(params.page));
  if (params?.page_size) q.set('page_size', String(params.page_size));
  if (params?.ioc_type) q.set('ioc_type', params.ioc_type);
  if (params?.status) q.set('status', params.status);
  if (params?.validation_status) q.set('validation_status', params.validation_status);
  if (params?.normalized_value) q.set('normalized_value', params.normalized_value);
  if (params?.session_id) q.set('session_id', params.session_id);
  if (params?.event_id) q.set('event_id', params.event_id);
  if (params?.anomaly_id) q.set('anomaly_id', params.anomaly_id);
  if (params?.incident_id) q.set('incident_id', params.incident_id);
  if (params?.attack_chain_id) q.set('attack_chain_id', params.attack_chain_id);
  return request<IOCListResponse>(`/api/iocs/search?${q}`);
}

export async function getIOCSummary(session_id?: string): Promise<IOCSummary> {
  const q = session_id ? `?session_id=${session_id}` : '';
  return request<IOCSummary>(`/api/iocs/summary${q}`);
}

export async function getIOC(ioc_id: string): Promise<IOC> {
  return request<IOC>(`/api/iocs/${ioc_id}`);
}

export async function getIOCEvidence(ioc_id: string): Promise<IOCEvidenceResponse> {
  return request<IOCEvidenceResponse>(`/api/iocs/${ioc_id}/evidence`);
}

export async function updateIOCStatus(ioc_id: string, update: IOCStatusUpdate): Promise<IOC> {
  return request<IOC>(`/api/iocs/${ioc_id}/status`, {
    method: 'PATCH',
    body: JSON.stringify(update),
  });
}

export async function getIOCRelationships(ioc_id: string): Promise<IOCRelationships> {
  return request<IOCRelationships>(`/api/iocs/${ioc_id}/relationships`);
}

// ── Threat Correlation (Phase 4.2B) ────────────────────────────────────────

export async function getUnifiedThreatContext(
  ioc_id: string,
  force_refresh?: boolean,
): Promise<UnifiedThreatContext> {
  const q = force_refresh ? '?force_refresh=true' : '';
  return request<UnifiedThreatContext>(`/api/threat-correlation/ioc/${ioc_id}/context${q}`);
}

export async function getCorrelatedAnomalies(ioc_id: string): Promise<CorrelatedAnomaliesResponse> {
  return request<CorrelatedAnomaliesResponse>(`/api/threat-correlation/ioc/${ioc_id}/anomalies`);
}

export async function getCorrelatedIncidents(ioc_id: string): Promise<CorrelatedIncidentsResponse> {
  return request<CorrelatedIncidentsResponse>(`/api/threat-correlation/ioc/${ioc_id}/incidents`);
}

export async function getCorrelatedAttackChains(
  ioc_id: string,
): Promise<CorrelatedAttackChainsResponse> {
  return request<CorrelatedAttackChainsResponse>(
    `/api/threat-correlation/ioc/${ioc_id}/attack-chains`,
  );
}

export async function getCorrelatedEvents(ioc_id: string): Promise<CorrelatedEventsResponse> {
  return request<CorrelatedEventsResponse>(`/api/threat-correlation/ioc/${ioc_id}/events`);
}

export async function getIOCCorrelations(
  ioc_id: string,
  params?: { correlation_type?: string; confirmed_only?: boolean },
): Promise<ThreatCorrelationsResponse> {
  const q = new URLSearchParams();
  if (params?.correlation_type) q.set('correlation_type', params.correlation_type);
  if (params?.confirmed_only !== undefined) q.set('confirmed_only', String(params.confirmed_only));
  const queryStr = q.toString() ? `?${q.toString()}` : '';
  return request<ThreatCorrelationsResponse>(`/api/threat-correlation/ioc/${ioc_id}${queryStr}`);
}



