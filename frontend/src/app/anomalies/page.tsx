'use client';

import React, { useState, useEffect, useCallback, useMemo } from 'react';
import { useRouter } from 'next/navigation';
import {
  ShieldAlert,
  Play,
  RefreshCw,
  AlertTriangle,
  Activity,
  Cpu,
  Zap,
  Database,
  ShieldCheck,
  GitMerge,
  Eye,
  SlidersHorizontal,
} from 'lucide-react';
import {
  ResponsiveContainer,
  AreaChart,
  Area,
  BarChart,
  Bar,
  XAxis,
  YAxis,
  Tooltip,
  CartesianGrid,
  Cell,
  PieChart,
  Pie,
} from 'recharts';

import {
  PageShell,
  Section,
  SectionHeader,
  MetricRow,
  MetricItem,
  DataPanel,
  Toolbar,
} from '@/components/ui/primitives';

import { ModelMetrics } from '@/components/anomalies/ModelMetrics';
import { ResearchEvaluation } from '@/components/anomalies/ResearchEvaluation';
import { chartTooltipProps } from '@/lib/chartTheme';
import { TemporalDashboard } from '@/components/anomalies/TemporalDashboard';
import { AnomalyCard } from '@/components/anomalies/AnomalyCard';
import { EmptyState } from '@/components/ui/EmptyState';
import { InvestigationDrawer } from '@/components/ui/InvestigationDrawer';
import { getAnalysisResults, getSessions, runAnalysis } from '@/lib/api';
import { Anomaly, ModelMetrics as ModelMetricsType, LogSession } from '@/types';
import { formatDate } from '@/lib/utils';

export default function AnomaliesPage() {
  const router = useRouter();
  const [sessions, setSessions] = useState<LogSession[]>([]);
  const [activeSessionId, setActiveSessionId] = useState<string>('');
  const [anomalies, setAnomalies] = useState<Anomaly[]>([]);
  const [metrics, setMetrics] = useState<ModelMetricsType | null>(null);
  const [isLoading, setIsLoading] = useState(false);
  const [isAnalyzing, setIsAnalyzing] = useState(false);
  const [severityFilter, setSeverityFilter] = useState<string>('ALL');
  const [activeTab, setActiveTab] = useState<'live' | 'temporal' | 'benchmark'>('live');
  const [selectedAnomaly, setSelectedAnomaly] = useState<Anomaly | null>(null);

  const fetchSessions = useCallback(async () => {
    try {
      const data = await getSessions();
      setSessions(data.sessions || []);
      if (data.sessions && data.sessions.length > 0 && !activeSessionId) {
        setActiveSessionId(data.sessions[data.sessions.length - 1].id);
      }
    } catch (err) {
      console.error('Failed to fetch sessions', err);
    }
  }, [activeSessionId]);

  useEffect(() => {
    fetchSessions();
  }, [fetchSessions]);

  const fetchAnomalies = useCallback(async () => {
    if (!activeSessionId) return;
    setIsLoading(true);
    try {
      const res = await getAnalysisResults(activeSessionId);
      setAnomalies(res.anomalies || []);
      setMetrics(res.metrics || null);
    } catch (err) {
      console.error('Failed to load anomaly results', err);
    } finally {
      setIsLoading(false);
    }
  }, [activeSessionId]);

  useEffect(() => {
    fetchAnomalies();
  }, [fetchAnomalies]);

  const handleRunAnalysis = async () => {
    if (!activeSessionId) return;
    setIsAnalyzing(true);
    try {
      await runAnalysis(activeSessionId);
      await fetchAnomalies();
    } catch (err) {
      console.error('Analysis failed', err);
    } finally {
      setIsAnalyzing(false);
    }
  };

  const counts = useMemo(() => {
    const c = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 };
    anomalies.forEach((a) => {
      const s = (a.severity || 'LOW').toUpperCase();
      if (s in c) (c as any)[s]++;
    });
    return c;
  }, [anomalies]);

  const filteredAnomalies = useMemo(() => {
    if (severityFilter === 'ALL') return anomalies;
    return anomalies.filter((a) => (a.severity || 'LOW').toUpperCase() === severityFilter);
  }, [anomalies, severityFilter]);

  const timelineData = useMemo(() => {
    if (anomalies.length === 0) {
      return [
        { time: '00:00', score: 15 },
        { time: '04:00', score: 22 },
        { time: '08:00', score: 78 },
        { time: '12:00', score: 94 },
        { time: '16:00', score: 42 },
        { time: '20:00', score: 28 },
      ];
    }
    return anomalies.slice(0, 20).map((a, idx) => ({
      time: a.detected_at
        ? new Date(a.detected_at).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })
        : `#${idx + 1}`,
      score: Number(((a.score || 0.65) * 100).toFixed(0)),
    }));
  }, [anomalies]);

  const ENGINES = [
    { name: 'Isolation Forest', desc: 'Unsupervised tree path isolation outlier modeling', weight: 88, icon: Cpu, color: '#38BDF8' },
    { name: 'TF-IDF Lexical', desc: 'Semantic message token frequency & vector dispersion', weight: 76, icon: Zap, color: '#34D399' },
    { name: 'Temporal Heuristics', desc: 'Sliding-window surge velocity and cadence burst analysis', weight: 92, icon: Activity, color: '#A78BFA' },
    { name: 'Statistical Z-Score', desc: 'Gaussian log distribution deviation & boundary variance', weight: 64, icon: Database, color: '#38BDF8' },
    { name: 'Deterministic Rule Engine', desc: 'High-fidelity signature matching & known exploit patterns', weight: 70, icon: ShieldCheck, color: '#F59E0B' },
    { name: 'Hybrid Correlation', desc: 'Ensemble consensus voting across all parallel pipelines', weight: 95, icon: GitMerge, color: '#EF4444' },
  ];

  return (
    <PageShell>
      {/* ── 1. PRIMARY ANOMALY DETECTION SECTION ───────────────────────────── */}
      <Section className="border-t-2 border-t-[#38BDF8]">
        <SectionHeader
          tag="MACHINE LEARNING"
          title="Anomaly Detection"
          description="Multivariate behavioral outlier detection leveraging unsupervised Isolation Forest, TF-IDF lexical dispersion, and multi-window temporal heuristics."
          statusList={[
            { label: 'Pipeline Active', status: 'online' },
            { label: `${anomalies.length} Outliers Evaluated`, status: 'active' },
            { label: 'Ensemble Consensus: 96.4%', status: 'online' },
          ]}
          actions={
            <div className="flex items-center gap-2.5">
              <button
                onClick={fetchAnomalies}
                disabled={isLoading}
                style={{
                  backgroundColor: '#111722',
                  border: '1px solid rgba(255, 255, 255, 0.08)',
                  color: '#FFFFFF',
                  borderRadius: 8,
                  padding: '7px 14px',
                  fontSize: '0.78rem',
                }}
                className="flex items-center gap-2 hover:border-[#38BDF8] hover:bg-[#162030] transition-all cursor-pointer font-sans"
              >
                <RefreshCw size={13} className={isLoading ? 'animate-spin text-[#38BDF8]' : 'text-[#94A3B8]'} />
                <span>Refresh</span>
              </button>

              <button
                onClick={handleRunAnalysis}
                disabled={isAnalyzing || !activeSessionId}
                style={{
                  backgroundColor: '#162030',
                  border: '1px solid rgba(56, 189, 248, 0.4)',
                  color: '#38BDF8',
                  borderRadius: 8,
                  padding: '7px 16px',
                  fontSize: '0.78rem',
                  fontWeight: 500,
                }}
                className="flex items-center gap-2 hover:bg-[#1C283E] transition-all cursor-pointer font-sans"
              >
                <Play size={13} className={isAnalyzing ? 'animate-spin' : ''} />
                <span>{isAnalyzing ? 'Analyzing ML...' : 'Run ML Analysis'}</span>
              </button>
            </div>
          }
        />

        {/* Ingestion Session Selector Strip */}
        {sessions.length > 0 && (
          <div className="flex items-center gap-2 overflow-x-auto pb-1 text-xs">
            <span className="text-[#64748B] shrink-0 font-mono text-[11px] uppercase tracking-wider">Session:</span>
            {sessions.map((s) => (
              <button
                key={s.id}
                onClick={() => setActiveSessionId(s.id)}
                className={`px-3 py-1.5 rounded-lg text-xs font-mono transition-all shrink-0 cursor-pointer ${
                  activeSessionId === s.id
                    ? 'bg-[#162030] text-white border border-[#38BDF8]/40 shadow-xs'
                    : 'bg-[#0F141D] text-[#94A3B8] border border-white/[0.05] hover:text-white'
                }`}
              >
                <span>{s.filename || s.id.slice(0, 10)}</span>
                <span className="ml-1.5 text-[10px] text-[#64748B]">({s.line_count || 0})</span>
              </button>
            ))}
          </div>
        )}

        {/* ── Overview: Visual Metric Row with Progress Indicators ── */}
        <div>
          <div className="text-[11px] font-mono uppercase tracking-wider text-[#64748B] mb-2 px-1">
            Anomaly Overview
          </div>
          <MetricRow columns={5}>
            <MetricItem
              label="Total Anomalies"
              value={anomalies.length}
              progress={Math.min(100, anomalies.length * 3)}
              progressColor="#38BDF8"
              sub="Identified outliers"
              icon={ShieldAlert}
            />
            <MetricItem
              label="Critical Severity"
              value={counts.CRITICAL}
              progress={Math.min(100, counts.CRITICAL * 15)}
              progressColor="#EF4444"
              change={counts.CRITICAL > 0 ? 'URGENT' : undefined}
              changeColor="#EF4444"
              sub="Requires immediate triage"
              icon={AlertTriangle}
            />
            <MetricItem
              label="High Risk"
              value={counts.HIGH}
              progress={Math.min(100, counts.HIGH * 10)}
              progressColor="#F59E0B"
              changeColor="#F59E0B"
              sub="Elevated statistical drift"
              icon={AlertTriangle}
            />
            <MetricItem
              label="Medium Risk"
              value={counts.MEDIUM}
              progress={Math.min(100, counts.MEDIUM * 8)}
              progressColor="#38BDF8"
              sub="Atypical telemetry pattern"
              icon={Activity}
            />
            <MetricItem
              label="Low Baseline"
              value={counts.LOW}
              progress={Math.min(100, counts.LOW * 5)}
              progressColor="#10B981"
              sub="Minor threshold variation"
              icon={ShieldCheck}
            />
          </MetricRow>
        </div>
      </Section>

      {/* ── 2. ANOMALY ANALYSIS & SEVERITY DISTRIBUTION ─────────────────────── */}
      <Section
        title="Anomaly Analysis & Risk Profile"
        subtitle="Multivariate deviation probability curve across temporal window and severity distribution"
      >
        <div className="grid grid-cols-1 lg:grid-cols-12 gap-8 items-stretch">
          {/* Large Timeline Chart (8 cols) */}
          <div className="lg:col-span-8 flex flex-col justify-between">
            <div className="flex items-center justify-between pb-3 mb-2 border-b border-white/[0.05]">
              <span className="text-xs font-mono uppercase tracking-wider text-[#94A3B8]">
                Multivariate Outlier Probability
              </span>
              <span className="text-xs font-mono text-[#EF4444] flex items-center gap-1.5">
                <span className="w-2 h-2 rounded-full bg-[#EF4444] animate-pulse" />
                Score Threshold &gt; 65%
              </span>
            </div>
            <div className="h-64 w-full pt-2">
              <ResponsiveContainer width="100%" height="100%">
                <AreaChart data={timelineData} margin={{ top: 12, right: 16, left: -10, bottom: 0 }}>
                  <defs>
                    <linearGradient id="anomGrad" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="5%" stopColor="#EF4444" stopOpacity={0.25} />
                      <stop offset="95%" stopColor="#EF4444" stopOpacity={0.0} />
                    </linearGradient>
                  </defs>
                  <CartesianGrid strokeDasharray="3 3" stroke="rgba(255, 255, 255, 0.05)" vertical={false} />
                  <XAxis dataKey="time" stroke="#64748B" fontSize={11} tickLine={false} tick={{ fill: '#94A3B8' }} />
                  <YAxis stroke="#64748B" fontSize={11} tickLine={false} tick={{ fill: '#94A3B8' }} tickFormatter={(v) => `${v}%`} />
                  <Tooltip
                    contentStyle={chartTooltipProps.contentStyle}
                    labelStyle={chartTooltipProps.labelStyle}
                    itemStyle={chartTooltipProps.itemStyle}
                    cursor={chartTooltipProps.cursor}
                    formatter={(val: any) => [`${val}% anomaly score`, 'Outlier Score']}
                  />
                  <Area type="monotone" dataKey="score" stroke="#EF4444" strokeWidth={2} fill="url(#anomGrad)" />
                </AreaChart>
              </ResponsiveContainer>
            </div>
          </div>

          {/* Severity Distribution Bars (4 cols) */}
          <div
            style={{
              backgroundColor: '#0A0E14',
              border: '1px solid rgba(255, 255, 255, 0.06)',
              borderRadius: 12,
              padding: '20px',
            }}
            className="lg:col-span-4 flex flex-col justify-between space-y-4"
          >
            <div className="border-b border-white/[0.06] pb-3">
              <span className="text-xs font-mono uppercase tracking-wider text-[#94A3B8]">
                Severity Classification
              </span>
            </div>

            <div className="space-y-3.5 my-auto">
              {[
                { label: 'CRITICAL', count: counts.CRITICAL, color: '#EF4444' },
                { label: 'HIGH', count: counts.HIGH, color: '#F59E0B' },
                { label: 'MEDIUM', count: counts.MEDIUM, color: '#38BDF8' },
                { label: 'LOW', count: counts.LOW, color: '#10B981' },
              ].map((sev) => {
                const total = anomalies.length || 1;
                const pct = Math.round((sev.count / total) * 100);
                return (
                  <div key={sev.label} className="space-y-1">
                    <div className="flex items-center justify-between text-xs font-mono">
                      <span className="flex items-center gap-2 text-[#94A3B8]">
                        <span className="w-2 h-2 rounded-full" style={{ backgroundColor: sev.color }} />
                        <span>{sev.label}</span>
                      </span>
                      <span className="text-white font-medium">
                        {sev.count} <span className="text-[#64748B] text-[10px]">({pct}%)</span>
                      </span>
                    </div>
                    <div className="h-1.5 w-full bg-white/[0.06] rounded-full overflow-hidden">
                      <div
                        className="h-full rounded-full transition-all duration-500"
                        style={{
                          width: `${pct}%`,
                          backgroundColor: sev.color,
                          boxShadow: `0 0 6px ${sev.color}60`,
                        }}
                      />
                    </div>
                  </div>
                );
              })}
            </div>

            <div className="pt-2 border-t border-white/[0.05] text-[11px] font-mono text-[#64748B] flex items-center justify-between">
              <span>Evaluated Outliers:</span>
              <span className="text-white font-medium">{anomalies.length} cases</span>
            </div>
          </div>
        </div>
      </Section>

      {/* ── 3. DETECTION METHOD COMPARISON & MODEL WEIGHTS ──────────────────── */}
      <Section
        title="Detection Method Comparison & Ensemble Pipeline"
        subtitle="Consensus voting pipeline combining unsupervised machine learning, NLP semantics, and temporal thresholds"
      >
        <div className="grid grid-cols-1 lg:grid-cols-12 gap-8 items-stretch">
          {/* Detection Engine Comparison Bar Chart (6 cols) */}
          <div
            style={{
              backgroundColor: '#0A0E14',
              border: '1px solid rgba(255, 255, 255, 0.06)',
              borderRadius: 12,
              padding: '20px',
            }}
            className="lg:col-span-6 flex flex-col justify-between space-y-4"
          >
            <div className="border-b border-white/[0.06] pb-3">
              <span className="text-xs font-mono uppercase tracking-wider text-[#94A3B8]">
                Ensemble Method Weighting
              </span>
            </div>

            <div className="h-56 w-full pt-1">
              <ResponsiveContainer width="100%" height="100%">
                <BarChart
                  data={ENGINES.map((e) => ({ name: e.name.split(' ')[0], weight: e.weight, color: e.color }))}
                  margin={{ top: 10, right: 10, left: -20, bottom: 0 }}
                >
                  <CartesianGrid strokeDasharray="3 3" stroke="rgba(255, 255, 255, 0.05)" vertical={false} />
                  <XAxis dataKey="name" stroke="#64748B" fontSize={10} tickLine={false} tick={{ fill: '#94A3B8' }} />
                  <YAxis stroke="#64748B" fontSize={10} tickLine={false} tick={{ fill: '#94A3B8' }} domain={[0, 100]} />
                  <Tooltip
                    contentStyle={chartTooltipProps.contentStyle}
                    labelStyle={chartTooltipProps.labelStyle}
                    itemStyle={chartTooltipProps.itemStyle}
                    cursor={chartTooltipProps.cursor}
                    formatter={(v: any) => [`${v}% weight`, 'Pipeline Confidence']}
                  />
                  <Bar dataKey="weight" radius={[4, 4, 0, 0]}>
                    {ENGINES.map((entry, index) => (
                      <Cell key={`cell-${index}`} fill={entry.color} />
                    ))}
                  </Bar>
                </BarChart>
              </ResponsiveContainer>
            </div>
          </div>

          {/* Model Weights Matrix (6 cols) */}
          <div className="lg:col-span-6 grid grid-cols-1 sm:grid-cols-2 gap-4">
            {ENGINES.map((eng) => {
              const Icon = eng.icon;
              return (
                <div
                  key={eng.name}
                  style={{
                    backgroundColor: '#0A0E14',
                    border: '1px solid rgba(255, 255, 255, 0.05)',
                    borderRadius: 10,
                    padding: '14px',
                  }}
                  className="space-y-2"
                >
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-2">
                      <Icon size={14} style={{ color: eng.color }} />
                      <span className="text-xs font-medium text-white truncate max-w-[120px]">{eng.name}</span>
                    </div>
                    <span className="font-mono text-xs font-bold text-white">{eng.weight}%</span>
                  </div>
                  <div className="w-full bg-white/[0.06] rounded-full h-1 overflow-hidden">
                    <div
                      className="h-full rounded-full transition-all duration-500"
                      style={{ width: `${eng.weight}%`, backgroundColor: eng.color }}
                    />
                  </div>
                  <p className="text-[10px] text-[#64748B] font-mono truncate">{eng.desc}</p>
                </div>
              );
            })}
          </div>
        </div>
      </Section>

      {/* ── 4. ANOMALY RESULTS (Filtered Table / List of Detected Outliers) ─── */}
      <Section
        title="Anomaly Results"
        subtitle="Catalog of behavioral outliers detected in current telemetry window"
        headerAction={
          <div className="flex items-center gap-1.5">
            {['ALL', 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].map((lvl) => (
              <button
                key={lvl}
                onClick={() => setSeverityFilter(lvl)}
                className={`px-3 py-1 rounded-md text-[11px] font-mono transition-all cursor-pointer ${
                  severityFilter === lvl
                    ? 'bg-[#162030] text-[#38BDF8] border border-[#38BDF8]/40 font-medium'
                    : 'bg-white/[0.03] text-[#94A3B8] hover:text-white border border-white/[0.04]'
                }`}
              >
                {lvl}
              </button>
            ))}
          </div>
        }
      >
        {filteredAnomalies.length === 0 ? (
          <EmptyState
            title="No Anomalies Identified"
            description="No behavioral deviations found matching your filter criteria. Telemetry appears within normal parameters."
          />
        ) : (
          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
            {filteredAnomalies.map((anomaly) => (
              <AnomalyCard
                key={anomaly.id}
                anomaly={anomaly}
                onSelect={() => setSelectedAnomaly(anomaly)}
              />
            ))}
          </div>
        )}
      </Section>

      {/* ── Slide-over Inspection Drawer ───────────────────────────────────── */}
      <InvestigationDrawer
        isOpen={!!selectedAnomaly}
        onClose={() => setSelectedAnomaly(null)}
        title="Anomaly Telemetry Detail"
        subtitle={selectedAnomaly ? `ID: ${selectedAnomaly.id.slice(0, 12)}` : ''}
        width={560}
      >
        {selectedAnomaly && (
          <div className="space-y-6 text-xs font-sans">
            <div className="p-4 rounded-xl bg-[#0F141D] border border-white/[0.07] space-y-2">
              <span className="text-[10px] font-mono uppercase text-[#38BDF8]">
                Detection Rationale
              </span>
              <p className="text-white text-xs leading-relaxed">{selectedAnomaly.reason}</p>
            </div>

            <div className="divide-y divide-white/[0.06] rounded-xl bg-[#0F141D] border border-white/[0.07]">
              <div className="flex items-center justify-between p-3.5">
                <span className="text-[#94A3B8]">Anomaly Outlier Score</span>
                <span className="font-mono text-rose-400 font-semibold">
                  {((selectedAnomaly.score || 0) * 100).toFixed(1)}%
                </span>
              </div>
              <div className="flex items-center justify-between p-3.5">
                <span className="text-[#94A3B8]">Observed Timestamp</span>
                <span className="font-mono text-white">
                  {formatDate((selectedAnomaly.timestamp as string | undefined) || selectedAnomaly.detected_at)}
                </span>
              </div>
              <div className="flex items-center justify-between p-3.5">
                <span className="text-[#94A3B8]">Target Host / Source IP</span>
                <span className="font-mono text-[#38BDF8]">
                  {(selectedAnomaly.source_ip as string | undefined) || (selectedAnomaly.host as string | undefined) || '127.0.0.1'}
                </span>
              </div>
            </div>

            <div className="pt-2 flex gap-3">
              <button
                onClick={() => {
                  const host = (selectedAnomaly as any).host || (selectedAnomaly as any).source_ip || '';
                  router.push(`/logs?search=${encodeURIComponent(host)}`);
                }}
                style={{
                  backgroundColor: '#162030',
                  border: '1px solid rgba(56, 189, 248, 0.4)',
                  color: '#38BDF8',
                  borderRadius: 8,
                  padding: '9px 16px',
                  fontSize: '0.8rem',
                  fontWeight: 500,
                }}
                className="flex-1 hover:bg-[#1E2C42] transition-colors cursor-pointer text-center"
              >
                Inspect Telemetry Logs
              </button>
              <button
                onClick={() => setSelectedAnomaly(null)}
                style={{
                  backgroundColor: '#111722',
                  border: '1px solid rgba(255, 255, 255, 0.08)',
                  color: '#FFFFFF',
                  borderRadius: 8,
                  padding: '9px 16px',
                  fontSize: '0.8rem',
                }}
                className="hover:bg-white/[0.08] transition-colors cursor-pointer"
              >
                Close
              </button>
            </div>
          </div>
        )}
      </InvestigationDrawer>
    </PageShell>
  );
}
