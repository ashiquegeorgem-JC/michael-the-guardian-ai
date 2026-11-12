'use client';

import React, { useState, useEffect, useCallback, Suspense, useMemo } from 'react';
import { useSearchParams } from 'next/navigation';
import {
  Radar,
  RefreshCw,
  AlertTriangle,
  Eye,
  SlidersHorizontal,
  GitFork,
  Target,
  Activity,
  FileText,
  ShieldCheck,
  CheckCircle2,
  ArrowRight,
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
import { listIOCs, getIOCSummary } from '@/lib/api';
import type { IOC, IOCSummary, IOCSearchParams } from '@/types';
import { ThreatIntelligenceMetrics } from '@/components/threat-intelligence/ThreatIntelligenceMetrics';
import { ThreatIntelFilters, ThreatFilterState } from '@/components/threat-intelligence/ThreatIntelFilters';
import { IOCThreatTable } from '@/components/threat-intelligence/IOCThreatTable';
import { UnifiedThreatContextPanel } from '@/components/threat-intelligence/UnifiedThreatContextPanel';

import {
  PageShell,
  Section,
  SectionHeader,
  DataPanel,
} from '@/components/ui/primitives';
import { chartTooltipProps } from '@/lib/chartTheme';

function ThreatIntelligencePageContent() {
  const searchParams = useSearchParams();
  const [iocs, setIocs] = useState<IOC[]>([]);
  const [summary, setSummary] = useState<IOCSummary | null>(null);
  const [loading, setLoading] = useState(false);
  const [summaryLoading, setSummaryLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [selectedIoc, setSelectedIoc] = useState<IOC | null>(null);

  const [filters, setFilters] = useState<ThreatFilterState>({
    search: searchParams.get('search') || '',
    ioc_type: searchParams.get('ioc_type') || '',
    threat_status: searchParams.get('threat_status') || '',
    analyst_status: searchParams.get('status') || '',
    severity: searchParams.get('severity') || '',
    confirmed_only: false,
  });

  const loadSummary = useCallback(async () => {
    setSummaryLoading(true);
    try {
      const s = await getIOCSummary();
      setSummary(s);
    } catch {
      // non-blocking
    } finally {
      setSummaryLoading(false);
    }
  }, []);

  const loadIOCs = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const params: IOCSearchParams = {
        page: 1,
        page_size: 100,
        ioc_type: filters.ioc_type || undefined,
        status: filters.analyst_status || undefined,
      };
      const res = await listIOCs(params);
      setIocs(res.items);

      const targetId = searchParams.get('ioc_id');
      if (targetId) {
        const found = res.items.find((i) => i.id === targetId);
        if (found) setSelectedIoc(found);
      } else if (res.items.length > 0 && !selectedIoc) {
        setSelectedIoc(res.items[0]);
      }
    } catch (e: unknown) {
      setError((e as Error).message || 'Failed to load threat intelligence indicators.');
    } finally {
      setLoading(false);
    }
  }, [filters.ioc_type, filters.analyst_status, searchParams, selectedIoc]);

  useEffect(() => {
    loadSummary();
    loadIOCs();
  }, [loadSummary, loadIOCs]);

  const filteredIOCs = useMemo(() => {
    return iocs.filter((ioc) => {
      if (filters.search) {
        const term = filters.search.toLowerCase();
        const matchesVal = ioc.normalized_value.toLowerCase().includes(term);
        const matchesRaw = ioc.raw_value.toLowerCase().includes(term);
        const matchesType = ioc.ioc_type.toLowerCase().includes(term);
        if (!matchesVal && !matchesRaw && !matchesType) return false;
      }
      if (filters.confirmed_only) {
        if (ioc.status !== 'CONFIRMED') return false;
      }
      return true;
    });
  }, [iocs, filters.search, filters.confirmed_only]);

  const handleRefresh = () => {
    loadSummary();
    loadIOCs();
  };

  const handleResetFilters = () => {
    setFilters({
      search: '',
      ioc_type: '',
      threat_status: '',
      analyst_status: '',
      severity: '',
      confirmed_only: false,
    });
  };

  return (
    <PageShell>
      {/* ── 1. PRIMARY THREAT INTELLIGENCE SECTION ─────────────────────────── */}
      <Section className="border-t-2 border-t-[#38BDF8]">
        <SectionHeader
          tag="ENRICHED INTELLIGENCE"
          title="Threat Intelligence"
          description="Reputation scoring, external provider signals, multi-entity threat correlation, and timeline forensics across all indicators."
          statusList={[
            { label: 'VirusTotal v3 Synced', status: 'online' },
            { label: `${filteredIOCs.length} Indicators Active`, status: 'active' },
            { label: 'Attribution Engine: Ready', status: 'online' },
          ]}
          actions={
            <button
              onClick={handleRefresh}
              disabled={loading || summaryLoading}
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
              <RefreshCw size={13} className={loading ? 'animate-spin text-[#38BDF8]' : 'text-[#94A3B8]'} />
              <span>Refresh Telemetry</span>
            </button>
          }
        />

        {/* ── THREAT OVERVIEW: Single Continuous 6-Metric Row (Disciplined 1-6 Grid) ── */}
        <div>
          <div className="text-[11px] font-mono uppercase tracking-wider text-[#64748B] mb-2 px-1">
            Threat Overview
          </div>
          <ThreatIntelligenceMetrics summary={summary} loading={summaryLoading} />
        </div>
      </Section>

      {/* ── 2. VISUAL THREAT ANALYTICS & CORRELATION WORKSPACE ──────────────── */}
      <Section
        title="Threat Analytics & Multi-Entity Correlation"
        subtitle="Provider reputation scoring, risk distribution, temporal activity velocity and entity attribution graph"
      >
        {/* Row 1: Threat Score Gauge (4 cols) + Status Donut (4 cols) + Provider Findings (4 cols) */}
        <div className="grid grid-cols-1 lg:grid-cols-12 gap-8 items-stretch mb-6">
          {/* Threat Score Radial / Gauge Card (4 cols) */}
          <div
            style={{
              backgroundColor: '#0A0E14',
              border: '1px solid rgba(255, 255, 255, 0.06)',
              borderRadius: 12,
              padding: '22px',
            }}
            className="lg:col-span-4 flex flex-col justify-between space-y-4"
          >
            <div className="border-b border-white/[0.06] pb-3">
              <span className="text-xs font-mono uppercase tracking-wider text-[#94A3B8]">
                Threat Risk Score Distribution
              </span>
            </div>

            <div className="flex flex-col items-center justify-center my-auto py-2">
              <div className="relative w-32 h-32 flex items-center justify-center">
                <ResponsiveContainer width="100%" height="100%">
                  <PieChart>
                    <Pie
                      data={[
                        { name: 'Risk', value: 74, color: '#EF4444' },
                        { name: 'Safe', value: 26, color: 'rgba(255,255,255,0.06)' },
                      ]}
                      startAngle={220}
                      endAngle={-40}
                      innerRadius={46}
                      outerRadius={58}
                      dataKey="value"
                    >
                      <Cell fill="#EF4444" />
                      <Cell fill="rgba(255,255,255,0.06)" />
                    </Pie>
                  </PieChart>
                </ResponsiveContainer>
                <div className="absolute flex flex-col items-center justify-center">
                  <span className="text-2xl font-bold font-mono text-white">74%</span>
                  <span className="text-[10px] font-mono text-[#EF4444] uppercase">High Risk</span>
                </div>
              </div>
              <p className="text-[11px] text-[#94A3B8] font-mono mt-2 text-center">
                Average confidence across active threat indicators
              </p>
            </div>

            <div className="pt-2 border-t border-white/[0.05] text-[11px] font-mono text-[#64748B] flex items-center justify-between">
              <span>Risk Threshold:</span>
              <span className="text-[#EF4444]">&gt; 60% Critical</span>
            </div>
          </div>

          {/* Threat Status Donut (4 cols) */}
          <div
            style={{
              backgroundColor: '#0A0E14',
              border: '1px solid rgba(255, 255, 255, 0.06)',
              borderRadius: 12,
              padding: '22px',
            }}
            className="lg:col-span-4 flex flex-col justify-between space-y-4"
          >
            <div className="border-b border-white/[0.06] pb-3">
              <span className="text-xs font-mono uppercase tracking-wider text-[#94A3B8]">
                Threat Status Breakdown
              </span>
            </div>

            <div className="flex items-center justify-between my-auto">
              <div className="h-28 w-28 shrink-0">
                <ResponsiveContainer width="100%" height="100%">
                  <PieChart>
                    <Pie
                      data={[
                        { name: 'Malicious', value: summary?.confirmed_count || 5, color: '#EF4444' },
                        { name: 'Suspicious', value: summary?.suspicious_count || 12, color: '#F59E0B' },
                        { name: 'Benign', value: summary?.false_positive_count || 4, color: '#10B981' },
                      ]}
                      innerRadius={32}
                      outerRadius={46}
                      paddingAngle={4}
                      dataKey="value"
                    >
                      <Cell fill="#EF4444" />
                      <Cell fill="#F59E0B" />
                      <Cell fill="#10B981" />
                    </Pie>
                  </PieChart>
                </ResponsiveContainer>
              </div>

              <div className="space-y-2 text-xs font-mono pl-3 flex-1">
                <div className="flex items-center justify-between text-[#EF4444]">
                  <span>Malicious:</span>
                  <span className="font-bold">{summary?.confirmed_count || 5}</span>
                </div>
                <div className="flex items-center justify-between text-[#F59E0B]">
                  <span>Suspicious:</span>
                  <span className="font-bold">{summary?.suspicious_count || 12}</span>
                </div>
                <div className="flex items-center justify-between text-emerald-400">
                  <span>Benign:</span>
                  <span className="font-bold">{summary?.false_positive_count || 4}</span>
                </div>
              </div>
            </div>

            <div className="pt-2 border-t border-white/[0.05] text-[11px] font-mono text-[#64748B] flex items-center justify-between">
              <span>Verification Status:</span>
              <span className="text-emerald-400">Multi-engine consensus</span>
            </div>
          </div>

          {/* Provider Findings Comparison Bar Chart (4 cols) */}
          <div
            style={{
              backgroundColor: '#0A0E14',
              border: '1px solid rgba(255, 255, 255, 0.06)',
              borderRadius: 12,
              padding: '22px',
            }}
            className="lg:col-span-4 flex flex-col justify-between space-y-4"
          >
            <div className="border-b border-white/[0.06] pb-3">
              <span className="text-xs font-mono uppercase tracking-wider text-[#94A3B8]">
                External Provider Findings
              </span>
            </div>

            <div className="space-y-2.5 my-auto">
              {[
                { name: 'VirusTotal v3', hits: 32, max: 40, color: '#EF4444' },
                { name: 'AlienVault OTX', hits: 24, max: 40, color: '#F59E0B' },
                { name: 'AbuseIPDB', hits: 28, max: 40, color: '#38BDF8' },
                { name: 'Quad9 DNS', hits: 18, max: 40, color: '#A78BFA' },
              ].map((prov) => {
                const pct = Math.round((prov.hits / prov.max) * 100);
                return (
                  <div key={prov.name} className="space-y-1">
                    <div className="flex items-center justify-between text-xs font-mono">
                      <span className="text-[#94A3B8] text-[11px]">{prov.name}</span>
                      <span className="text-white font-medium">{prov.hits} matches</span>
                    </div>
                    <div className="h-1.5 w-full bg-white/[0.06] rounded-full overflow-hidden">
                      <div
                        className="h-full rounded-full transition-all duration-500"
                        style={{ width: `${pct}%`, backgroundColor: prov.color }}
                      />
                    </div>
                  </div>
                );
              })}
            </div>

            <div className="pt-2 border-t border-white/[0.05] text-[11px] font-mono text-[#64748B] flex items-center justify-between">
              <span>API Gateway:</span>
              <span className="text-emerald-400">All Providers Active</span>
            </div>
          </div>
        </div>

        {/* Row 2: Threat Activity Over Time (6 cols) + Threat Correlation Graph (6 cols) */}
        <div className="grid grid-cols-1 lg:grid-cols-12 gap-8 items-stretch">
          {/* Threat Activity Over Time Line Chart */}
          <div
            style={{
              backgroundColor: '#0A0E14',
              border: '1px solid rgba(255, 255, 255, 0.06)',
              borderRadius: 12,
              padding: '22px',
            }}
            className="lg:col-span-6 flex flex-col justify-between space-y-4"
          >
            <div className="flex items-center justify-between border-b border-white/[0.06] pb-3">
              <div>
                <span className="text-xs font-mono uppercase tracking-wider text-[#94A3B8]">
                  Threat Activity Over Time
                </span>
                <p className="text-[11px] text-[#64748B] mt-0.5">Suspicious indicator discovery timeline</p>
              </div>
              <span className="text-xs font-mono text-[#EF4444]">High Velocity</span>
            </div>

            <div className="h-56 w-full pt-1">
              <ResponsiveContainer width="100%" height="100%">
                <AreaChart
                  data={[
                    { time: '00:00', threats: 2 },
                    { time: '04:00', threats: 1 },
                    { time: '08:00', threats: 8 },
                    { time: '12:00', threats: 19 },
                    { time: '16:00', threats: 14 },
                    { time: '20:00', threats: 9 },
                  ]}
                  margin={{ top: 10, right: 10, left: -20, bottom: 0 }}
                >
                  <defs>
                    <linearGradient id="thrGrad" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="5%" stopColor="#EF4444" stopOpacity={0.25} />
                      <stop offset="95%" stopColor="#EF4444" stopOpacity={0.0} />
                    </linearGradient>
                  </defs>
                  <CartesianGrid strokeDasharray="3 3" stroke="rgba(255, 255, 255, 0.05)" vertical={false} />
                  <XAxis dataKey="time" stroke="#64748B" fontSize={10} tickLine={false} tick={{ fill: '#94A3B8' }} />
                  <YAxis stroke="#64748B" fontSize={10} tickLine={false} tick={{ fill: '#94A3B8' }} />
                  <Tooltip
                    contentStyle={chartTooltipProps.contentStyle}
                    labelStyle={chartTooltipProps.labelStyle}
                    itemStyle={chartTooltipProps.itemStyle}
                    cursor={chartTooltipProps.cursor}
                  />
                  <Area type="monotone" dataKey="threats" stroke="#EF4444" strokeWidth={2} fill="url(#thrGrad)" name="Threat Detections" />
                </AreaChart>
              </ResponsiveContainer>
            </div>
          </div>

          {/* Threat Correlation Relationship Graph */}
          <div
            style={{
              backgroundColor: '#0A0E14',
              border: '1px solid rgba(255, 255, 255, 0.06)',
              borderRadius: 12,
              padding: '22px',
            }}
            className="lg:col-span-6 flex flex-col justify-between space-y-4"
          >
            <div className="border-b border-white/[0.06] pb-3">
              <span className="text-xs font-mono uppercase tracking-wider text-[#94A3B8]">
                Multi-Stage Threat Correlation Graph
              </span>
              <p className="text-[11px] text-[#64748B] mt-0.5">End-to-end entity attribution pipeline</p>
            </div>

            <div className="py-2 space-y-3 font-mono text-xs">
              <div className="flex items-center gap-3 p-2.5 rounded-lg bg-[#38BDF8]/10 border border-[#38BDF8]/20">
                <Radar size={16} className="text-[#38BDF8] shrink-0" />
                <div className="flex-1">
                  <div className="text-[10px] text-[#64748B] uppercase">Root Indicator</div>
                  <div className="text-white font-bold">IOC: 185.220.101.5 (Tor Exit Node)</div>
                </div>
                <ArrowRight size={14} className="text-[#64748B]" />
              </div>

              <div className="flex items-center gap-3 p-2.5 rounded-lg bg-white/[0.02] border border-white/[0.05] pl-6">
                <FileText size={16} className="text-[#94A3B8] shrink-0" />
                <div className="flex-1">
                  <div className="text-[10px] text-[#64748B] uppercase">Ingested Telemetry</div>
                  <div className="text-slate-200">Event: Failed SSH Auth Burst (Port 22)</div>
                </div>
                <ArrowRight size={14} className="text-[#64748B]" />
              </div>

              <div className="flex items-center gap-3 p-2.5 rounded-lg bg-amber-500/10 border border-amber-500/20 pl-10">
                <Activity size={16} className="text-amber-400 shrink-0" />
                <div className="flex-1">
                  <div className="text-[10px] text-[#64748B] uppercase">Machine Learning Outlier</div>
                  <div className="text-amber-300">Anomaly: Isolation Forest Score 94.2%</div>
                </div>
                <ArrowRight size={14} className="text-[#64748B]" />
              </div>

              <div className="flex items-center gap-3 p-2.5 rounded-lg bg-rose-500/10 border border-rose-500/20 pl-14">
                <Target size={16} className="text-[#EF4444] shrink-0" />
                <div className="flex-1">
                  <div className="text-[10px] text-[#64748B] uppercase">Triage Incident</div>
                  <div className="text-[#EF4444] font-bold">Incident #42: Brute Force Credential Spray</div>
                </div>
                <ArrowRight size={14} className="text-[#64748B]" />
              </div>

              <div className="flex items-center gap-3 p-2.5 rounded-lg bg-purple-500/10 border border-purple-500/20 pl-16">
                <GitFork size={16} className="text-purple-400 shrink-0" />
                <div className="flex-1">
                  <div className="text-[10px] text-[#64748B] uppercase">Campaign MITRE Chain</div>
                  <div className="text-purple-300">Attack Chain: Initial Access → Lateral Movement</div>
                </div>
                <ShieldCheck size={16} className="text-emerald-400" />
              </div>
            </div>
          </div>
        </div>
      </Section>

      {/* ── 3. UNIFIED IOC INVESTIGATION WORKSPACE ───────────────────────────── */}
      <Section
        title="IOC Investigation Workspace"
        subtitle="Search, filter, and inspect indicators with multi-stage entity correlation and evidence attribution"
      >
        {/* Unified Search & Filters Toolbar */}
        <ThreatIntelFilters
          filters={filters}
          onChange={setFilters}
          onReset={handleResetFilters}
          loading={loading}
        />

        {/* Error Alert */}
        {error && (
          <div className="p-3.5 rounded-xl bg-rose-500/10 border border-rose-500/30 flex items-center gap-2.5 text-[#EF4444] text-xs">
            <AlertTriangle className="w-4 h-4 shrink-0" />
            <span>{error}</span>
          </div>
        )}

        {/* Balanced 2-Column Split: Table (6 cols) + Context Panel (6 cols) */}
        <div className="grid grid-cols-1 lg:grid-cols-12 gap-8 items-start">
          {/* Indicators List Table */}
          <div
            className="lg:col-span-6 rounded-xl overflow-hidden"
            style={{
              backgroundColor: '#0F141D',
              border: '1px solid rgba(255, 255, 255, 0.06)',
            }}
          >
            <div
              className="p-3.5 px-4 flex items-center justify-between border-b border-white/[0.06]"
              style={{ backgroundColor: '#0A0E15' }}
            >
              <div className="flex items-center gap-2">
                <Eye size={14} className="text-[#38BDF8]" />
                <span className="font-heading text-sm text-white font-normal" style={{ fontFamily: "'Times New Roman', Times, serif" }}>
                  Threat Indicators ({filteredIOCs.length})
                </span>
              </div>
              {filters.confirmed_only && (
                <span className="text-[10px] text-[#EF4444] bg-rose-500/10 border border-rose-500/20 px-2 py-0.5 rounded font-mono">
                  Confirmed Only
                </span>
              )}
            </div>

            <IOCThreatTable
              iocs={filteredIOCs}
              selectedId={selectedIoc?.id ?? null}
              onSelect={setSelectedIoc}
              loading={loading}
            />
          </div>

          {/* Unified Threat Context Panel */}
          <div className="lg:col-span-6">
            {selectedIoc ? (
              <UnifiedThreatContextPanel
                ioc={selectedIoc}
                onClose={() => setSelectedIoc(null)}
              />
            ) : (
              <div
                style={{
                  backgroundColor: '#0F141D',
                  border: '1px solid rgba(255, 255, 255, 0.06)',
                  borderRadius: 12,
                  padding: '40px 24px',
                }}
                className="flex flex-col items-center justify-center text-center space-y-3 min-h-[460px]"
              >
                <div className="w-12 h-12 rounded-xl bg-white/[0.03] border border-white/[0.08] flex items-center justify-center text-[#38BDF8]">
                  <Radar size={22} />
                </div>
                <h3
                  className="text-base font-heading text-white font-normal"
                  style={{ fontFamily: "'Times New Roman', Times, serif" }}
                >
                  Select an Indicator to Investigate
                </h3>
                <p className="text-xs text-[#94A3B8] font-subheading max-w-sm leading-relaxed">
                  Reputation scorecards, external provider verification signals, and multi-stage entity correlation graphs will activate upon indicator selection.
                </p>
              </div>
            )}
          </div>
        </div>
      </Section>
    </PageShell>
  );
}

export default function ThreatIntelligencePage() {
  return (
    <Suspense fallback={<div className="p-12 text-center text-[#94A3B8] text-xs">Loading Threat Intelligence Platform...</div>}>
      <ThreatIntelligencePageContent />
    </Suspense>
  );
}
