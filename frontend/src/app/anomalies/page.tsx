'use client';

import React, { useState, useEffect, useCallback, useMemo } from 'react';
import Link from 'next/link';
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
  Sparkles,
} from 'lucide-react';
import {
  ResponsiveContainer,
  AreaChart,
  Area,
  XAxis,
  YAxis,
  Tooltip,
  CartesianGrid,
} from 'recharts';
import { ModelMetrics } from '@/components/anomalies/ModelMetrics';
import { ResearchEvaluation } from '@/components/anomalies/ResearchEvaluation';
import { TemporalDashboard } from '@/components/anomalies/TemporalDashboard';
import { AnomalyCard } from '@/components/anomalies/AnomalyCard';
import { PageHeader } from '@/components/ui/PageHeader';
import { Button } from '@/components/ui/Button';
import { Badge } from '@/components/ui/Badge';
import { MetricCard } from '@/components/ui/MetricCard';
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
        { time: '00:00', score: 0.15 },
        { time: '04:00', score: 0.22 },
        { time: '08:00', score: 0.78 },
        { time: '12:00', score: 0.94 },
        { time: '16:00', score: 0.42 },
        { time: '20:00', score: 0.28 },
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
    { name: 'Isolation Forest', desc: 'Unsupervised tree path isolation', weight: 88, icon: Cpu, color: '#3B82F6' },
    { name: 'TF-IDF Dispersion', desc: 'Lexical token vector distance', weight: 76, icon: Zap, color: '#22B8FF' },
    { name: 'Temporal Heuristics', desc: 'Window burst velocity & interval', weight: 92, icon: Activity, color: '#8B5CF6' },
    { name: 'Statistical Z-Score', desc: 'Gaussian log frequency variance', weight: 64, icon: Database, color: '#22C55E' },
    { name: 'Rule Engine', desc: 'Signature match & known exploits', weight: 70, icon: ShieldCheck, color: '#F59E0B' },
    { name: 'Hybrid Correlation', desc: 'Ensemble multi-signal consensus', weight: 95, icon: GitMerge, color: '#EF4444' },
  ];

  return (
    <div className="space-y-6 pb-12 font-sans text-slate-100">
      {/* 1. Page Header */}
      <PageHeader
        tag="Machine Learning"
        title="Anomaly Detection"
        description="Multivariate behavioral outlier detection leveraging Isolation Forest, TF-IDF lexical dispersion, and temporal heuristics."
        actions={
          activeSessionId && (
            <>
              <Button
                variant="secondary"
                size="sm"
                onClick={fetchAnomalies}
                isLoading={isLoading}
                leftIcon={<RefreshCw className="w-3.5 h-3.5" />}
              >
                Refresh
              </Button>
              <Button
                variant="primary"
                size="sm"
                onClick={handleRunAnalysis}
                isLoading={isAnalyzing}
                leftIcon={<Play className="w-3.5 h-3.5" />}
              >
                Re-run ML Pipeline
              </Button>
            </>
          )
        }
      />

      {/* 2. Session Selector Strip */}
      {sessions.length > 0 && (
        <div className="flex items-center gap-2 overflow-x-auto pb-1 text-xs">
          <span className="text-[#687589] shrink-0 font-medium">Session:</span>
          {sessions.map((s) => (
            <button
              key={s.id}
              onClick={() => setActiveSessionId(s.id)}
              className={`px-3 py-1.5 rounded-lg text-xs font-medium transition-all shrink-0 cursor-pointer ${
                activeSessionId === s.id
                  ? 'bg-[#111823] text-[#F5F7FA] border border-white/20'
                  : 'bg-[#0C1119] text-[#A7B1C0] border border-white/[0.06] hover:text-white'
              }`}
            >
              <span className="font-mono">{s.filename || s.id.slice(0, 10)}</span>
              <span className="ml-1.5 text-[10px] text-[#687589]">({s.line_count || 0})</span>
            </button>
          ))}
        </div>
      )}

      {/* 3. KPI Row: Severity Outlier Counts */}
      <div className="grid grid-cols-2 sm:grid-cols-5 gap-4">
        <MetricCard
          label="Total Anomalies"
          value={anomalies.length}
          subValue="Identified outliers"
          icon={ShieldAlert}
          accentColor="#3B82F6"
        />
        <MetricCard
          label="Critical Outliers"
          value={counts.CRITICAL}
          subValue="Immediate triage"
          icon={AlertTriangle}
          accentColor="#EF4444"
          trend={counts.CRITICAL > 0 ? { value: 'URGENT', positive: false } : undefined}
        />
        <MetricCard
          label="High Risk"
          value={counts.HIGH}
          subValue="Elevated deviation"
          icon={AlertTriangle}
          accentColor="#F59E0B"
        />
        <MetricCard
          label="Medium Risk"
          value={counts.MEDIUM}
          subValue="Atypical pattern"
          icon={Activity}
          accentColor="#22B8FF"
        />
        <MetricCard
          label="Low Baseline"
          value={counts.LOW}
          subValue="Minor drift"
          icon={ShieldCheck}
          accentColor="#22C55E"
        />
      </div>

      {/* 4. Tab Navigation Strip */}
      <div className="flex items-center justify-between border-b border-white/[0.06] pb-1">
        <div className="flex items-center gap-2">
          <button
            onClick={() => setActiveTab('live')}
            className={`px-3.5 py-2 text-xs font-medium rounded-lg transition-all cursor-pointer ${
              activeTab === 'live'
                ? 'bg-[#111823] text-[#F5F7FA] border border-white/10'
                : 'text-[#A7B1C0] hover:text-[#F5F7FA]'
            }`}
          >
            Detection Outliers ({filteredAnomalies.length})
          </button>
          <button
            onClick={() => setActiveTab('temporal')}
            className={`px-3.5 py-2 text-xs font-medium rounded-lg transition-all cursor-pointer ${
              activeTab === 'temporal'
                ? 'bg-[#111823] text-[#F5F7FA] border border-white/10'
                : 'text-[#A7B1C0] hover:text-[#F5F7FA]'
            }`}
          >
            Temporal Burst Analytics
          </button>
          <button
            onClick={() => setActiveTab('benchmark')}
            className={`px-3.5 py-2 text-xs font-medium rounded-lg transition-all cursor-pointer ${
              activeTab === 'benchmark'
                ? 'bg-[#111823] text-[#F5F7FA] border border-white/10'
                : 'text-[#A7B1C0] hover:text-[#F5F7FA]'
            }`}
          >
            Model Evaluation & Research
          </button>
        </div>

        {activeTab === 'live' && (
          <div className="flex items-center gap-1.5 text-xs">
            {['ALL', 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].map((lvl) => (
              <button
                key={lvl}
                onClick={() => setSeverityFilter(lvl)}
                className={`px-2.5 py-1 rounded-md text-[11px] font-medium transition-all cursor-pointer ${
                  severityFilter === lvl
                    ? 'bg-[#3B82F6] text-white'
                    : 'bg-white/[0.03] text-[#A7B1C0] hover:text-white'
                }`}
              >
                {lvl}
              </button>
            ))}
          </div>
        )}
      </div>

      {/* Tab: Temporal Analysis */}
      {activeTab === 'temporal' && (
        <div className="space-y-6">
          <TemporalDashboard sessionId={activeSessionId || undefined} />
        </div>
      )}

      {/* Tab: Research Evaluation */}
      {activeTab === 'benchmark' && (
        <div className="space-y-6">
          <ModelMetrics metrics={metrics} />
          <ResearchEvaluation />
        </div>
      )}

      {/* Tab: Live Detection */}
      {activeTab === 'live' && (
        <div className="space-y-6">
          {/* Anomaly Timeline & Signal Engines */}
          <div className="grid grid-cols-1 lg:grid-cols-12 gap-5">
            {/* Timeline Area (8 cols) */}
            <div
              style={{
                backgroundColor: '#0C1119',
                border: '1px solid rgba(255, 255, 255, 0.08)',
                borderRadius: '12px',
                padding: '20px',
              }}
              className="lg:col-span-8 flex flex-col justify-between"
            >
              <div className="flex items-center justify-between border-b border-white/[0.06] pb-3 mb-3">
                <div>
                  <h3 className="text-sm font-semibold text-[#F5F7FA]">
                    Anomaly Outlier Timeline
                  </h3>
                  <p className="text-xs text-[#A7B1C0] mt-0.5">
                    Deviation probability curve across time sequence
                  </p>
                </div>
                <Badge variant="blue" size="sm">
                  Threshold: 50%
                </Badge>
              </div>

              <div className="h-56 w-full pt-2">
                <ResponsiveContainer width="100%" height="100%">
                  <AreaChart data={timelineData} margin={{ top: 10, right: 10, left: -20, bottom: 0 }}>
                    <defs>
                      <linearGradient id="anomGrad" x1="0" y1="0" x2="0" y2="1">
                        <stop offset="5%" stopColor="#EF4444" stopOpacity={0.25} />
                        <stop offset="95%" stopColor="#EF4444" stopOpacity={0.0} />
                      </linearGradient>
                    </defs>
                    <CartesianGrid strokeDasharray="3 3" stroke="rgba(255, 255, 255, 0.05)" vertical={false} />
                    <XAxis dataKey="time" stroke="#687589" fontSize={11} tickLine={false} tick={{ fill: '#A7B1C0' }} />
                    <YAxis stroke="#687589" fontSize={11} tickLine={false} tick={{ fill: '#A7B1C0' }} tickFormatter={(v) => `${v}%`} />
                    <Tooltip
                      contentStyle={{
                        backgroundColor: '#111823',
                        border: '1px solid rgba(255, 255, 255, 0.1)',
                        borderRadius: '8px',
                        fontSize: '12px',
                        color: '#F5F7FA',
                      }}
                      formatter={(val: any) => [`${val}% anomaly score`, 'Score']}
                    />
                    <Area type="monotone" dataKey="score" stroke="#EF4444" strokeWidth={2} fill="url(#anomGrad)" />
                  </AreaChart>
                </ResponsiveContainer>
              </div>
            </div>

            {/* Signal Engines (4 cols) */}
            <div
              style={{
                backgroundColor: '#0C1119',
                border: '1px solid rgba(255, 255, 255, 0.08)',
                borderRadius: '12px',
                padding: '20px',
              }}
              className="lg:col-span-4 flex flex-col justify-between space-y-3"
            >
              <div className="border-b border-white/[0.06] pb-3">
                <h3 className="text-sm font-semibold text-[#F5F7FA]">
                  Ensemble Detection Engines
                </h3>
                <p className="text-xs text-[#A7B1C0] mt-0.5">
                  Multi-signal voting weights
                </p>
              </div>

              <div className="space-y-2.5">
                {ENGINES.map((eng) => {
                  const Icon = eng.icon;
                  return (
                    <div key={eng.name} className="flex items-center justify-between text-xs">
                      <div className="flex items-center gap-2">
                        <Icon size={14} style={{ color: eng.color }} />
                        <span className="text-[#A7B1C0]">{eng.name}</span>
                      </div>
                      <span className="font-mono text-[#F5F7FA] font-medium">{eng.weight}%</span>
                    </div>
                  );
                })}
              </div>
            </div>
          </div>

          {/* Anomaly Cards Grid */}
          {filteredAnomalies.length === 0 ? (
            <EmptyState
              title="No Anomalies Identified"
              description="No behavioral deviations found matching your filter criteria. Try running analysis or adjusting the severity filter."
            />
          ) : (
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
              {filteredAnomalies.map((a) => (
                <AnomalyCard
                  key={a.id}
                  anomaly={a}
                  onSelect={() => setSelectedAnomaly(a)}
                />
              ))}
            </div>
          )}
        </div>
      )}

      {/* Investigation Drawer */}
      <InvestigationDrawer
        isOpen={!!selectedAnomaly}
        onClose={() => setSelectedAnomaly(null)}
        title="Anomaly Forensic Details"
        subtitle={`ID: ${selectedAnomaly?.id || ''}`}
        width={500}
      >
        {selectedAnomaly && (
          <div className="space-y-6 text-xs font-sans">
            <div className="p-4 rounded-xl bg-amber-500/10 border border-amber-500/30 flex items-start gap-3">
              <AlertTriangle className="w-5 h-5 text-[#F59E0B] shrink-0 mt-0.5" />
              <div>
                <div className="font-semibold text-[#F59E0B]">
                  {selectedAnomaly.reason}
                </div>
                <p className="text-[#A7B1C0] mt-1 leading-relaxed">
                  Flagged by {selectedAnomaly.method || 'Isolation Forest'} with deviation probability of{' '}
                  {((selectedAnomaly.score || 0.85) * 100).toFixed(0)}%.
                </p>
              </div>
            </div>

            <div className="rounded-xl bg-[#080C12] border border-white/[0.06] divide-y divide-white/[0.04]">
              <div className="flex items-center justify-between p-3.5">
                <span className="text-[#A7B1C0]">Severity</span>
                <Badge variant={selectedAnomaly.severity} size="sm">
                  {selectedAnomaly.severity}
                </Badge>
              </div>
              <div className="flex items-center justify-between p-3.5">
                <span className="text-[#A7B1C0]">Anomaly Score</span>
                <span className="font-mono text-[#EF4444] font-semibold">
                  {((selectedAnomaly.score || 0.85) * 100).toFixed(1)}%
                </span>
              </div>
              <div className="flex items-center justify-between p-3.5">
                <span className="text-[#A7B1C0]">Observed Time</span>
                <span className="font-mono text-[#F5F7FA]">
                  {formatDate((selectedAnomaly.timestamp as string | undefined) || selectedAnomaly.detected_at)}
                </span>
              </div>
              <div className="flex items-center justify-between p-3.5">
                <span className="text-[#A7B1C0]">Source IP</span>
                <span className="font-mono text-[#3B82F6]">
                  {(selectedAnomaly.source_ip as string | undefined) || (selectedAnomaly.host as string | undefined) || '127.0.0.1'}
                </span>
              </div>
            </div>

            <div className="pt-2 flex gap-3">
              <Button
                variant="primary"
                size="md"
                className="flex-1"
                leftIcon={<Sparkles size={14} />}
                onClick={() => {
                  router.push(
                    `/copilot?prompt=${encodeURIComponent(
                      `Investigate this security anomaly:\nReason: ${selectedAnomaly.reason}\nHost: ${(selectedAnomaly as any).host || (selectedAnomaly as any).source_ip || 'unknown'}\nScore: ${selectedAnomaly.score}`
                    )}`
                  );
                }}
              >
                Investigate in Copilot
              </Button>
              <Button variant="secondary" size="md" onClick={() => setSelectedAnomaly(null)}>
                Close
              </Button>
            </div>
          </div>
        )}
      </InvestigationDrawer>
    </div>
  );
}
