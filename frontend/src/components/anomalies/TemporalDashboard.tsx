'use client';

import React, { useState, useEffect, useCallback } from 'react';
import {
  LineChart, Line, BarChart, Bar, AreaChart, Area,
  XAxis, YAxis, CartesianGrid, Tooltip, Legend,
  ResponsiveContainer, ReferenceLine,
} from 'recharts';
import { Card } from '@/components/ui/Card';
import { Badge } from '@/components/ui/Badge';
import { Button } from '@/components/ui/Button';
import { chartTooltipProps } from '@/lib/chartTheme';
import {
  Activity, AlertTriangle, Clock, Globe, Server,
  Zap, TrendingUp, RefreshCw, Shield, Radio,
} from 'lucide-react';

// ─────────────────────────────────────────────────────────────────────────────
// Types
// ─────────────────────────────────────────────────────────────────────────────

interface WindowStats {
  window_seconds: number;
  n_buckets: number;
  counts: number[];
  mean: number;
  std: number;
  ema: number;
  z_score: number;
  rate_of_change: number;
  latest_count: number;
  spike_detected: boolean;
}

interface TemporalTelemetry {
  global_windows: Record<string, WindowStats>;
  ip_spikes: Array<{ ip: string; window: number; z_score: number; latest_count: number }>;
  endpoint_spikes: Array<{ endpoint: string; window: number; z_score: number }>;
  category_spikes: Array<{ category: string; window: number; z_score: number }>;
  auth_burst_ips: Array<{ ip: string; burst_windows: number }>;
  http_error_rate_buckets: Array<{ bucket_minute: number; error_rate: number; total: number; errors: number }>;
}

interface TemporalAnomaly {
  id: string;
  score: number;
  severity: string;
  reason: string;
  method: string;
  detected_at: string;
  metadata: Record<string, unknown>;
}

interface TemporalData {
  session_id: string;
  temporal_anomaly_count: number;
  anomalies: TemporalAnomaly[];
  summary: {
    ip_spikes: number;
    endpoint_spikes: number;
    category_spikes: number;
    auth_burst_ips: number;
    http_error_buckets: number;
  };
}

interface TelemetryData {
  session_id: string;
  total_entries: number;
  telemetry: TemporalTelemetry;
}

// ─────────────────────────────────────────────────────────────────────────────
// Sub-components
// ─────────────────────────────────────────────────────────────────────────────

const WINDOW_LABELS: Record<string, string> = {
  '10s': '10s Window',
  '30s': '30s Window',
  '60s': '1min Window',
  '300s': '5min Window',
};

const WINDOW_COLORS: Record<string, string> = {
  '10s': '#6366f1',
  '30s': '#f59e0b',
  '60s': '#10b981',
  '300s': '#ef4444',
};

function GlobalTrafficChart({ globalWindows }: { globalWindows: Record<string, WindowStats> }) {
  const windowKeys = Object.keys(globalWindows);
  if (windowKeys.length === 0) return null;

  const zScoreData = windowKeys.map((wk) => {
    const stats = globalWindows[wk];
    return {
      window: WINDOW_LABELS[wk] || wk,
      z_score: stats.z_score,
      mean: stats.mean,
      latest: stats.latest_count,
      ema: stats.ema,
      spike: stats.spike_detected,
    };
  });

  return (
    <Card className="p-5">
      <div className="flex items-center justify-between mb-4">
        <div className="flex items-center gap-2">
          <Activity className="w-4 h-4 text-indigo-400" />
          <span className="text-sm font-semibold text-slate-200">Global Traffic Z-Score by Window</span>
        </div>
        <Badge variant="blue" size="sm">Sliding Windows</Badge>
      </div>
      <ResponsiveContainer width="100%" height={220}>
        <BarChart data={zScoreData} margin={{ top: 5, right: 10, left: -10, bottom: 5 }}>
          <CartesianGrid strokeDasharray="3 3" stroke="#1E2D4A" />
          <XAxis dataKey="window" tick={{ fill: '#94a3b8', fontSize: 11 }} />
          <YAxis tick={{ fill: '#94a3b8', fontSize: 11 }} />
          <Tooltip
            contentStyle={chartTooltipProps.contentStyle}
            labelStyle={chartTooltipProps.labelStyle}
            itemStyle={chartTooltipProps.itemStyle}
            cursor={chartTooltipProps.cursor}
          />
          <ReferenceLine y={3} stroke="#ef4444" strokeDasharray="4 4" label={{ value: 'Z=3 Threshold', fill: '#ef4444', fontSize: 10 }} />
          <Bar dataKey="z_score" fill="#6366f1" radius={[4, 4, 0, 0]} name="Z-Score" />
          <Bar dataKey="ema" fill="#f59e0b" radius={[4, 4, 0, 0]} name="EMA" opacity={0.7} />
        </BarChart>
      </ResponsiveContainer>
    </Card>
  );
}

function FrequencyTimelineChart({ globalWindows }: { globalWindows: Record<string, WindowStats> }) {
  const windowKey = '30s';
  const stats = globalWindows[windowKey];
  if (!stats || !stats.counts || stats.counts.length === 0) return null;

  const data = stats.counts.map((count, i) => ({
    bucket: `B${i + 1}`,
    count,
    mean: stats.mean,
    ema: i === stats.counts.length - 1 ? stats.ema : undefined,
  }));

  return (
    <Card className="p-5">
      <div className="flex items-center justify-between mb-4">
        <div className="flex items-center gap-2">
          <TrendingUp className="w-4 h-4 text-amber-400" />
          <span className="text-sm font-semibold text-slate-200">Request Frequency Timeline (30s Buckets)</span>
        </div>
        <div className="flex items-center gap-2">
          <span className="text-xs text-slate-400">Mean: <strong className="text-slate-200">{stats.mean}</strong></span>
          <span className="text-xs text-slate-400 ml-2">Z: <strong className={stats.z_score > 3 ? 'text-rose-400' : 'text-emerald-400'}>{stats.z_score.toFixed(2)}</strong></span>
        </div>
      </div>
      <ResponsiveContainer width="100%" height={200}>
        <AreaChart data={data} margin={{ top: 5, right: 10, left: -10, bottom: 5 }}>
          <defs>
            <linearGradient id="countGrad" x1="0" y1="0" x2="0" y2="1">
              <stop offset="5%" stopColor="#f59e0b" stopOpacity={0.3} />
              <stop offset="95%" stopColor="#f59e0b" stopOpacity={0.0} />
            </linearGradient>
          </defs>
          <CartesianGrid strokeDasharray="3 3" stroke="#1E2D4A" />
          <XAxis dataKey="bucket" tick={{ fill: '#94a3b8', fontSize: 10 }} />
          <YAxis tick={{ fill: '#94a3b8', fontSize: 10 }} />
          <Tooltip
            contentStyle={chartTooltipProps.contentStyle}
            labelStyle={chartTooltipProps.labelStyle}
            itemStyle={chartTooltipProps.itemStyle}
            cursor={chartTooltipProps.cursor}
          />
          <ReferenceLine y={stats.mean} stroke="#4ade80" strokeDasharray="3 3" label={{ value: 'Mean', fill: '#4ade80', fontSize: 10 }} />
          <Area dataKey="count" stroke="#f59e0b" fill="url(#countGrad)" strokeWidth={2} name="Events/Window" dot={false} />
        </AreaChart>
      </ResponsiveContainer>
    </Card>
  );
}

function AuthBurstTable({ authBursts }: { authBursts: Array<{ ip: string; burst_windows: number }> }) {
  if (authBursts.length === 0) return null;
  return (
    <Card className="p-5">
      <div className="flex items-center gap-2 mb-4">
        <Shield className="w-4 h-4 text-rose-400" />
        <span className="text-sm font-semibold text-slate-200">Auth Brute-Force Burst Detection</span>
        <Badge variant="red" size="sm">{authBursts.length} IP{authBursts.length !== 1 ? 's' : ''}</Badge>
      </div>
      <div className="space-y-2">
        {authBursts.map((item, i) => (
          <div key={i} className="flex items-center justify-between p-2.5 rounded-lg bg-rose-500/5 border border-rose-500/20">
            <div className="flex items-center gap-2">
              <Radio className="w-3.5 h-3.5 text-rose-400" />
              <span className="text-xs font-mono text-slate-200">{item.ip}</span>
            </div>
            <Badge variant="red" size="sm">{item.burst_windows} burst window{item.burst_windows !== 1 ? 's' : ''}</Badge>
          </div>
        ))}
      </div>
    </Card>
  );
}

function HttpErrorRateChart({ buckets }: { buckets: Array<{ bucket_minute: number; error_rate: number; total: number; errors: number }> }) {
  if (buckets.length === 0) return null;
  const data = buckets.map((b, i) => ({
    minute: `Min ${i + 1}`,
    error_rate: Math.round(b.error_rate * 100),
    total: b.total,
    errors: b.errors,
  }));

  return (
    <Card className="p-5">
      <div className="flex items-center gap-2 mb-4">
        <Server className="w-4 h-4 text-orange-400" />
        <span className="text-sm font-semibold text-slate-200">HTTP Error-Rate Spikes (%)</span>
        <Badge variant="orange" size="sm">{buckets.length} minute bucket{buckets.length !== 1 ? 's' : ''}</Badge>
      </div>
      <ResponsiveContainer width="100%" height={180}>
        <BarChart data={data} margin={{ top: 5, right: 10, left: -10, bottom: 5 }}>
          <CartesianGrid strokeDasharray="3 3" stroke="#1E2D4A" />
          <XAxis dataKey="minute" tick={{ fill: '#94a3b8', fontSize: 11 }} />
          <YAxis unit="%" tick={{ fill: '#94a3b8', fontSize: 11 }} domain={[0, 100]} />
          <Tooltip
            contentStyle={chartTooltipProps.contentStyle}
            labelStyle={chartTooltipProps.labelStyle}
            itemStyle={chartTooltipProps.itemStyle}
            cursor={chartTooltipProps.cursor}
            formatter={(val) => [`${val}%`, 'Error Rate']}
          />
          <ReferenceLine y={50} stroke="#ef4444" strokeDasharray="4 4" label={{ value: '50% threshold', fill: '#ef4444', fontSize: 10 }} />
          <Bar dataKey="error_rate" fill="#f97316" radius={[4, 4, 0, 0]} name="Error Rate %" />
        </BarChart>
      </ResponsiveContainer>
    </Card>
  );
}

function IpSpikeList({ ipSpikes }: { ipSpikes: Array<{ ip: string; window: number; z_score: number; latest_count: number }> }) {
  if (ipSpikes.length === 0) return null;
  return (
    <Card className="p-5">
      <div className="flex items-center gap-2 mb-4">
        <Globe className="w-4 h-4 text-purple-400" />
        <span className="text-sm font-semibold text-slate-200">Per-IP Frequency Spikes</span>
        <Badge variant="purple" size="sm">{ipSpikes.length}</Badge>
      </div>
      <div className="space-y-2 max-h-48 overflow-y-auto pr-1">
        {ipSpikes.map((item, i) => (
          <div key={i} className="flex items-center justify-between p-2 rounded-lg bg-purple-500/5 border border-purple-500/15">
            <div className="flex items-center gap-2">
              <span className="text-xs font-mono text-purple-300">{item.ip}</span>
              <span className="text-xs text-slate-500">in {item.window}s window</span>
            </div>
            <div className="flex items-center gap-2">
              <span className="text-xs text-slate-400">{item.latest_count} events</span>
              <Badge variant="purple" size="sm">Z={item.z_score?.toFixed(1) ?? 'N/A'}</Badge>
            </div>
          </div>
        ))}
      </div>
    </Card>
  );
}

function TemporalAnomalyList({ anomalies }: { anomalies: TemporalAnomaly[] }) {
  const sevColor: Record<string, string> = {
    CRITICAL: 'text-rose-400 border-rose-500/30 bg-rose-500/5',
    HIGH: 'text-orange-400 border-orange-500/30 bg-orange-500/5',
    MEDIUM: 'text-amber-400 border-amber-500/30 bg-amber-500/5',
    LOW: 'text-blue-400 border-blue-500/30 bg-blue-500/5',
  };

  if (anomalies.length === 0) {
    return (
      <Card className="p-10 text-center">
        <Zap className="w-8 h-8 text-slate-600 mx-auto mb-3" />
        <p className="text-sm text-slate-400">No temporal anomalies detected for this session.</p>
        <p className="text-xs text-slate-500 mt-1">Upload logs with sufficient time-stamped entries to enable temporal analysis.</p>
      </Card>
    );
  }

  return (
    <div className="space-y-2">
      {anomalies.map((a) => (
        <div key={a.id} className={`p-3.5 rounded-xl border ${sevColor[a.severity] || sevColor.LOW} text-xs`}>
          <div className="flex items-start justify-between gap-3">
            <div className="flex-1 min-w-0">
              <p className="text-slate-200 font-medium leading-relaxed">{a.reason}</p>
              <p className="text-slate-500 mt-1 font-mono">
                Score: <strong className="text-slate-300">{(a.score * 100).toFixed(1)}%</strong>
                &nbsp;·&nbsp;{new Date(a.detected_at).toLocaleString()}
              </p>
            </div>
            <Badge
              variant={a.severity === 'CRITICAL' ? 'red' : a.severity === 'HIGH' ? 'orange' : a.severity === 'MEDIUM' ? 'yellow' : 'blue'}
              size="sm"
            >
              {a.severity}
            </Badge>
          </div>
        </div>
      ))}
    </div>
  );
}

// ─────────────────────────────────────────────────────────────────────────────
// Main Component
// ─────────────────────────────────────────────────────────────────────────────

const BASE = (process.env.NEXT_PUBLIC_API_URL || 'https://michael-the-guardian-ai.onrender.com').replace(/\/+$/, '');

async function fetchJSON<T>(path: string): Promise<T> {
  const res = await fetch(`${BASE}${path}`);
  if (!res.ok) throw new Error(`Request failed: ${res.status}`);
  return res.json();
}

export function TemporalDashboard({ sessionId }: { sessionId?: string } = {}) {
  const [temporalData, setTemporalData] = useState<TemporalData | null>(null);
  const [telemetryData, setTelemetryData] = useState<TelemetryData | null>(null);
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(async () => {
    setIsLoading(true);
    setError(null);
    try {
      const q = sessionId ? `?session_id=${sessionId}` : '';
      const [td, tl] = await Promise.all([
        fetchJSON<TemporalData>(`/api/temporal/anomalies${q}`),
        fetchJSON<TelemetryData>(`/api/temporal/telemetry${q}`),
      ]);
      setTemporalData(td);
      setTelemetryData(tl);
    } catch (e: unknown) {
      const msg = e instanceof Error ? e.message : String(e);
      setError(msg);
    } finally {
      setIsLoading(false);
    }
  }, [sessionId]);

  useEffect(() => { load(); }, [load]);

  const telemetry = telemetryData?.telemetry;
  const anomalies = temporalData?.anomalies ?? [];
  const summary = temporalData?.summary;

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h3 className="text-base font-bold text-slate-100 flex items-center gap-2">
            <Clock className="w-5 h-5 text-indigo-400" />
            Temporal Behaviour Intelligence Engine
          </h3>
          <p className="text-xs text-slate-400 mt-0.5">
            Sliding-window frequency analysis · EMA · Z-score · Rate-of-change · Auth burst detection
          </p>
        </div>
        <Button
          variant="glass"
          size="sm"
          onClick={load}
          isLoading={isLoading}
          leftIcon={<RefreshCw className="w-3.5 h-3.5" />}
        >
          Refresh
        </Button>
      </div>

      {/* Error state */}
      {error && (
        <Card className="p-4 border-rose-500/30 bg-rose-500/5">
          <div className="flex items-center gap-2 text-rose-400 text-sm">
            <AlertTriangle className="w-4 h-4 shrink-0" />
            <span>{error.includes('No active session') ? 'No active session — upload and analyse a log file first.' : error}</span>
          </div>
        </Card>
      )}

      {/* Summary stat row */}
      {summary && (
        <div className="grid grid-cols-2 sm:grid-cols-5 gap-3">
          {[
            { label: 'Temporal Anomalies', value: temporalData?.temporal_anomaly_count ?? 0, icon: Zap, color: 'text-indigo-400' },
            { label: 'IP Spikes', value: summary.ip_spikes, icon: Globe, color: 'text-purple-400' },
            { label: 'Endpoint Spikes', value: summary.endpoint_spikes, icon: Server, color: 'text-amber-400' },
            { label: 'Auth Burst IPs', value: summary.auth_burst_ips, icon: Shield, color: 'text-rose-400' },
            { label: 'HTTP Error Buckets', value: summary.http_error_buckets, icon: Activity, color: 'text-orange-400' },
          ].map(({ label, value, icon: Icon, color }) => (
            <Card key={label} className="p-3.5 text-center">
              <Icon className={`w-4 h-4 mx-auto mb-1.5 ${color}`} />
              <div className="text-xl font-bold text-slate-100">{value}</div>
              <div className="text-xs text-slate-400 mt-0.5">{label}</div>
            </Card>
          ))}
        </div>
      )}

      {/* Charts row */}
      {telemetry && (
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-5">
          <GlobalTrafficChart globalWindows={telemetry.global_windows ?? {}} />
          <FrequencyTimelineChart globalWindows={telemetry.global_windows ?? {}} />
          <AuthBurstTable authBursts={telemetry.auth_burst_ips ?? []} />
          <HttpErrorRateChart buckets={telemetry.http_error_rate_buckets ?? []} />
          {(telemetry.ip_spikes?.length ?? 0) > 0 && (
            <IpSpikeList ipSpikes={telemetry.ip_spikes} />
          )}
        </div>
      )}

      {/* Anomaly list */}
      {!isLoading && !error && (
        <div className="space-y-3">
          <div className="flex items-center justify-between">
            <h4 className="text-sm font-semibold text-slate-300 flex items-center gap-2">
              <AlertTriangle className="w-4 h-4 text-amber-400" />
              Detected Temporal Anomalies
              {anomalies.length > 0 && (
                <Badge variant="yellow" size="sm">{anomalies.length}</Badge>
              )}
            </h4>
          </div>
          <TemporalAnomalyList anomalies={anomalies} />
        </div>
      )}
    </div>
  );
}
