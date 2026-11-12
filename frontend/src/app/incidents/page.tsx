'use client';

import React, { useState, useEffect, useCallback, useMemo } from 'react';
import {
  ShieldAlert,
  RefreshCw,
  AlertTriangle,
  Activity,
  CheckCircle2,
  Clock,
  ArrowRight,
} from 'lucide-react';
import {
  ResponsiveContainer,
  AreaChart,
  Area,
  XAxis,
  YAxis,
  Tooltip,
  CartesianGrid,
  PieChart,
  Pie,
  Cell,
} from 'recharts';

import {
  PageShell,
  Section,
  SectionHeader,
  MetricRow,
  MetricItem,
  Toolbar,
} from '@/components/ui/primitives';

import { IncidentCard } from '@/components/incidents/IncidentCard';
import { IncidentDetail } from '@/components/incidents/IncidentDetail';
import { EmptyState } from '@/components/ui/EmptyState';
import { getIncidents, updateIncidentStatus, getIncidentSummary, getSessions } from '@/lib/api';
import { Incident, IncidentStatus, IncidentSummary, LogSession } from '@/types';
import { chartTooltipProps } from '@/lib/chartTheme';

export default function IncidentsPage() {
  const [sessions, setSessions] = useState<LogSession[]>([]);
  const [activeSessionId, setActiveSessionId] = useState<string>('');
  const [incidents, setIncidents] = useState<Incident[]>([]);
  const [summary, setSummary] = useState<IncidentSummary | null>(null);
  const [selectedIncident, setSelectedIncident] = useState<Incident | null>(null);
  const [isLoading, setIsLoading] = useState(false);
  const [statusFilter, setStatusFilter] = useState<string>('ALL');
  const [severityFilter, setSeverityFilter] = useState<string>('ALL');

  const fetchSessions = useCallback(async () => {
    try {
      const data = await getSessions();
      setSessions(data.sessions || []);
      if (data.sessions && data.sessions.length > 0 && !activeSessionId) {
        setActiveSessionId(data.sessions[data.sessions.length - 1].id);
      }
    } catch (err) {
      console.error('Failed to load sessions', err);
    }
  }, [activeSessionId]);

  useEffect(() => {
    fetchSessions();
  }, [fetchSessions]);

  const fetchIncidents = useCallback(async () => {
    setIsLoading(true);
    try {
      const [res, sum] = await Promise.all([
        getIncidents({
          session_id: activeSessionId || undefined,
          status: statusFilter !== 'ALL' ? statusFilter : undefined,
          severity: severityFilter !== 'ALL' ? severityFilter : undefined,
        }),
        getIncidentSummary(activeSessionId || undefined).catch(() => null),
      ]);
      const list = res.incidents || [];
      setIncidents(list);
      if (sum) setSummary(sum);
    } catch (err) {
      console.error('Failed to load incidents', err);
    } finally {
      setIsLoading(false);
    }
  }, [activeSessionId, statusFilter, severityFilter]);

  useEffect(() => {
    fetchIncidents();
  }, [fetchIncidents]);

  const handleStatusChange = async (id: string, newStatus: IncidentStatus) => {
    try {
      await updateIncidentStatus(id, newStatus);
      setIncidents((prev) =>
        prev.map((inc) => (inc.id === id ? { ...inc, status: newStatus } : inc))
      );
      if (selectedIncident?.id === id) {
        setSelectedIncident((prev) => (prev ? { ...prev, status: newStatus } : null));
      }
    } catch (err) {
      console.error('Failed to update incident status', err);
    }
  };

  const statusCounts = useMemo(() => {
    const counts = { open: 0, investigating: 0, resolved: 0, false_positive: 0 };
    incidents.forEach((i) => {
      const s = (i.status || 'open') as keyof typeof counts;
      if (s in counts) counts[s]++;
    });
    return counts;
  }, [incidents]);

  const criticalCount = summary?.critical_count ?? incidents.filter((i) => (i.severity || '').toUpperCase() === 'CRITICAL').length;

  return (
    <PageShell>
      {/* ── 1. PRIMARY INCIDENT CENTRE SECTION ──────────────────────────────── */}
      <Section className="border-t-2 border-t-[#38BDF8]">
        <SectionHeader
          tag="SECURITY OPERATIONS"
          title="Incident Centre"
          description="Correlated multi-signal security alerts, root-cause forensic hypotheses, and case-management triage."
          statusList={[
            { label: 'Triage Engine: Active', status: 'online' },
            { label: `${incidents.length} Correlated Cases`, status: 'active' },
            { label: 'Attribution Consensus: 94.2%', status: 'online' },
          ]}
          actions={
            <button
              onClick={fetchIncidents}
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
              <span>Refresh Queue</span>
            </button>
          }
        />

        {/* Session Selector Strip */}
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

        {/* Single Continuous Metric Row: Total | Critical | Investigating | Resolved */}
        <div>
          <div className="text-[11px] font-mono uppercase tracking-wider text-[#64748B] mb-2 px-1">
            Triage Summary
          </div>
          <MetricRow columns={4}>
            <MetricItem
              label="Total Incidents"
              value={incidents.length}
              progress={Math.min(100, incidents.length * 10)}
              progressColor="#38BDF8"
              sub="Active correlated cases"
              icon={ShieldAlert}
            />
            <MetricItem
              label="Critical Triage"
              value={criticalCount}
              progress={Math.min(100, criticalCount * 25)}
              progressColor="#EF4444"
              change={criticalCount > 0 ? 'URGENT' : undefined}
              changeColor="#EF4444"
              sub="Immediate containment"
              icon={AlertTriangle}
            />
            <MetricItem
              label="Under Investigation"
              value={statusCounts.investigating}
              progress={Math.min(100, statusCounts.investigating * 20)}
              progressColor="#F59E0B"
              changeColor="#F59E0B"
              sub="In-progress review"
              icon={Activity}
            />
            <MetricItem
              label="Resolved / Contained"
              value={statusCounts.resolved}
              progress={Math.min(100, statusCounts.resolved * 20)}
              progressColor="#10B981"
              changeColor="#10B981"
              sub="Mitigated threats"
              icon={CheckCircle2}
            />
          </MetricRow>
        </div>
      </Section>

      {/* ── 2. VISUAL INCIDENT INTELLIGENCE & TIMELINE ──────────────────────── */}
      <Section
        title="Incident Trend & Severity Analytics"
        subtitle="Temporal frequency progression, status breakdown and containment lifecycle"
      >
        <div className="grid grid-cols-1 lg:grid-cols-12 gap-8 items-stretch">
          {/* Incident Trend Line/Area Chart (7 cols) */}
          <div
            style={{
              backgroundColor: '#0A0E14',
              border: '1px solid rgba(255, 255, 255, 0.06)',
              borderRadius: 12,
              padding: '22px',
            }}
            className="lg:col-span-7 flex flex-col justify-between space-y-4"
          >
            <div className="flex items-center justify-between border-b border-white/[0.06] pb-3">
              <div>
                <span className="text-xs font-mono uppercase tracking-wider text-[#94A3B8]">
                  Incident Velocity Trend
                </span>
                <p className="text-[11px] text-[#64748B] mt-0.5">Correlated security events over monitoring window</p>
              </div>
              <span className="text-xs font-mono text-[#38BDF8]">Daily Rate</span>
            </div>

            <div className="h-56 w-full pt-1">
              <ResponsiveContainer width="100%" height="100%">
                <AreaChart
                  data={[
                    { time: '00:00', count: 1, resolved: 0 },
                    { time: '04:00', count: 3, resolved: 1 },
                    { time: '08:00', count: 7, resolved: 2 },
                    { time: '12:00', count: 12, resolved: 5 },
                    { time: '16:00', count: 8, resolved: 6 },
                    { time: '20:00', count: 4, resolved: 4 },
                  ]}
                  margin={{ top: 10, right: 10, left: -20, bottom: 0 }}
                >
                  <defs>
                    <linearGradient id="incGrad" x1="0" y1="0" x2="0" y2="1">
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
                  <Area type="monotone" dataKey="count" stroke="#EF4444" strokeWidth={2} fill="url(#incGrad)" name="Detected" />
                </AreaChart>
              </ResponsiveContainer>
            </div>

            {/* Progression Pipeline Timeline */}
            <div className="pt-3 border-t border-white/[0.05]">
              <div className="text-[10px] font-mono text-[#64748B] uppercase tracking-wider mb-2">
                Incident Response Progression
              </div>
              <div className="grid grid-cols-4 gap-2 text-center text-xs font-mono">
                <div className="p-2 rounded bg-emerald-500/10 border border-emerald-500/20 text-emerald-400">
                  <div className="text-[10px] text-[#94A3B8]">01. Detect</div>
                  <div className="font-bold mt-0.5">Automated</div>
                </div>
                <div className="p-2 rounded bg-[#38BDF8]/10 border border-[#38BDF8]/20 text-[#38BDF8]">
                  <div className="text-[10px] text-[#94A3B8]">02. Correlate</div>
                  <div className="font-bold mt-0.5">Multi-host</div>
                </div>
                <div className="p-2 rounded bg-amber-500/10 border border-amber-500/20 text-amber-400">
                  <div className="text-[10px] text-[#94A3B8]">03. Triage</div>
                  <div className="font-bold mt-0.5">Analyst</div>
                </div>
                <div className="p-2 rounded bg-purple-500/10 border border-purple-500/20 text-purple-400">
                  <div className="text-[10px] text-[#94A3B8]">04. Mitigate</div>
                  <div className="font-bold mt-0.5">Contained</div>
                </div>
              </div>
            </div>
          </div>

          {/* Incident Severity & Status (5 cols) */}
          <div
            style={{
              backgroundColor: '#0A0E14',
              border: '1px solid rgba(255, 255, 255, 0.06)',
              borderRadius: 12,
              padding: '22px',
            }}
            className="lg:col-span-5 flex flex-col justify-between space-y-4"
          >
            <div className="border-b border-white/[0.06] pb-3">
              <span className="text-xs font-mono uppercase tracking-wider text-[#94A3B8]">
                Severity & Case Status
              </span>
            </div>

            {/* Horizontal Severity Bars */}
            <div className="space-y-3">
              {[
                { label: 'CRITICAL', count: criticalCount, color: '#EF4444' },
                { label: 'HIGH', count: incidents.filter((i) => (i.severity || '').toUpperCase() === 'HIGH').length, color: '#F59E0B' },
                { label: 'MEDIUM', count: incidents.filter((i) => (i.severity || '').toUpperCase() === 'MEDIUM').length, color: '#38BDF8' },
                { label: 'LOW', count: incidents.filter((i) => (i.severity || '').toUpperCase() === 'LOW').length, color: '#10B981' },
              ].map((sev) => {
                const total = incidents.length || 1;
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
                        style={{ width: `${pct}%`, backgroundColor: sev.color }}
                      />
                    </div>
                  </div>
                );
              })}
            </div>

            {/* Case Status Donut Breakdown */}
            <div className="pt-3 border-t border-white/[0.05] flex items-center justify-between">
              <div className="h-24 w-24 shrink-0">
                <ResponsiveContainer width="100%" height="100%">
                  <PieChart>
                    <Pie
                      data={[
                        { name: 'Open', value: statusCounts.open || 1, color: '#EF4444' },
                        { name: 'Investigating', value: statusCounts.investigating || 1, color: '#F59E0B' },
                        { name: 'Resolved', value: statusCounts.resolved || 1, color: '#10B981' },
                      ]}
                      innerRadius={28}
                      outerRadius={40}
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

              <div className="space-y-1.5 text-xs font-mono pl-4 flex-1">
                <div className="flex items-center justify-between text-[#EF4444]">
                  <span>Open:</span>
                  <span className="font-bold">{statusCounts.open}</span>
                </div>
                <div className="flex items-center justify-between text-[#F59E0B]">
                  <span>Investigating:</span>
                  <span className="font-bold">{statusCounts.investigating}</span>
                </div>
                <div className="flex items-center justify-between text-emerald-400">
                  <span>Resolved:</span>
                  <span className="font-bold">{statusCounts.resolved}</span>
                </div>
              </div>
            </div>
          </div>
        </div>
      </Section>

      {/* ── 3. INCIDENT TRIAGE QUEUE ────────────────────────────────────────── */}
      <Section
        title="Incident Triage Queue"
        subtitle="Filter by case status and severity level to investigate active adversary containment playbooks"
        headerAction={
          <div className="flex flex-wrap items-center gap-3">
            {/* Status Filter */}
            <div className="flex items-center gap-1">
              {['ALL', 'OPEN', 'INVESTIGATING', 'RESOLVED'].map((st) => (
                <button
                  key={st}
                  onClick={() => setStatusFilter(st)}
                  className={`px-2.5 py-1 rounded text-[11px] font-mono transition-all cursor-pointer ${
                    statusFilter === st
                      ? 'bg-[#162030] text-[#38BDF8] border border-[#38BDF8]/40 font-medium'
                      : 'bg-white/[0.03] text-[#94A3B8] hover:text-white border border-white/[0.04]'
                  }`}
                >
                  {st}
                </button>
              ))}
            </div>

            {/* Severity Filter */}
            <div className="flex items-center gap-1 border-l border-white/[0.08] pl-3">
              {['ALL', 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].map((sev) => (
                <button
                  key={sev}
                  onClick={() => setSeverityFilter(sev)}
                  className={`px-2.5 py-1 rounded text-[11px] font-mono transition-all cursor-pointer ${
                    severityFilter === sev
                      ? 'bg-[#162030] text-[#38BDF8] border border-[#38BDF8]/40 font-medium'
                      : 'text-[#94A3B8] hover:text-white'
                  }`}
                >
                  {sev}
                </button>
              ))}
            </div>
          </div>
        }
      >
        {incidents.length === 0 ? (
          <EmptyState
            title="No Security Incidents Found"
            description="There are no active security incidents matching your filter criteria. Telemetry appears normal."
          />
        ) : (
          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
            {incidents.map((incident) => (
              <IncidentCard
                key={incident.id}
                incident={incident}
                onSelect={setSelectedIncident}
                onStatusChange={handleStatusChange}
              />
            ))}
          </div>
        )}
      </Section>

      {/* Slide-over Investigation Detail Drawer */}
      <IncidentDetail
        incident={selectedIncident}
        onClose={() => setSelectedIncident(null)}
        onStatusChange={handleStatusChange}
      />
    </PageShell>
  );
}
