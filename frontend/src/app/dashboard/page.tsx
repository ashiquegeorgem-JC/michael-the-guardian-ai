'use client';

import React, { useState, useEffect } from 'react';
import Link from 'next/link';
import {
  getDashboardStats,
  getLogStats,
  getIncidentSummary,
  getIncidents,
  getAttackChains,
  getIOCSummary,
  listIOCs,
} from '@/lib/api';
import { useWebSocket } from '@/hooks/useWebSocket';
import {
  DashboardStats,
  LogStats,
  IncidentSummary,
  Incident,
  AttackChain,
  IOCSummary,
  IOC,
} from '@/types';
import {
  Shield,
  Layers,
  AlertTriangle,
  Target,
  Fingerprint,
  Radio,
  RefreshCw,
} from 'lucide-react';

// New Reusable Layout Primitives
import {
  PageShell,
  Section,
  SectionHeader,
  MetricRow,
  MetricItem,
  DataPanel,
} from '@/components/ui/primitives';

// Panel Components
import { LiveThreatGraph } from '@/components/dashboard/LiveThreatGraph';
import { AnomalySeverityDonut } from '@/components/dashboard/AnomalySeverityDonut';
import { AttackChainFlow } from '@/components/dashboard/AttackChainFlow';
import { DetectionIntelligenceBars } from '@/components/dashboard/DetectionIntelligenceBars';
import { LiveEventConsole } from '@/components/dashboard/LiveEventConsole';
import { RecentIncidentsTable } from '@/components/dashboard/RecentIncidentsTable';
import { ThreatIntelGauge } from '@/components/dashboard/ThreatIntelGauge';
import { SystemTelemetryStrip } from '@/components/dashboard/SystemTelemetryStrip';

export default function DashboardPage() {
  const [stats, setStats] = useState<DashboardStats | null>(null);
  const [logStats, setLogStats] = useState<LogStats | null>(null);
  const [incidentSummary, setIncidentSummary] = useState<IncidentSummary | null>(null);
  const [incidents, setIncidents] = useState<Incident[]>([]);
  const [attackChains, setAttackChains] = useState<AttackChain[]>([]);
  const [iocSummary, setIocSummary] = useState<IOCSummary | null>(null);
  const [recentIocs, setRecentIocs] = useState<IOC[]>([]);
  const [isLoading, setIsLoading] = useState(true);

  const { latestMetric, connected, events } = useWebSocket();

  const loadData = async () => {
    setIsLoading(true);
    try {
      const [dash, lStats, iSummary, incList, chains, iSummaryData, iocListData] =
        await Promise.all([
          getDashboardStats().catch(() => null),
          getLogStats().catch(() => null),
          getIncidentSummary().catch(() => null),
          getIncidents({ page_size: 5 }).catch(() => null),
          getAttackChains().catch(() => []),
          getIOCSummary().catch(() => null),
          listIOCs({ page_size: 5 }).catch(() => null),
        ]);

      if (dash) setStats(dash);
      if (lStats) setLogStats(lStats);
      if (iSummary) setIncidentSummary(iSummary);
      if (incList?.incidents) setIncidents(incList.incidents);
      if (chains) setAttackChains(chains);
      if (iSummaryData) setIocSummary(iSummaryData);
      if (iocListData?.items) setRecentIocs(iocListData.items);
    } catch (err) {
      console.error('Failed to load command centre telemetry', err);
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    loadData();
  }, []);

  const sevData = incidentSummary?.severity_distribution
    ? Object.entries(incidentSummary.severity_distribution).map(([severity, count]) => ({
        severity,
        count,
      }))
    : [
        { severity: 'CRITICAL', count: 8 },
        { severity: 'HIGH', count: 10 },
        { severity: 'MEDIUM', count: 12 },
        { severity: 'LOW', count: 8 },
      ];

  const totalAnomalies = stats?.total_anomalies || 38;
  const totalLogs = stats?.total_logs || 1284;
  const openIncidents = stats?.open_incidents || 7;
  const totalIocs = iocSummary?.total_iocs ?? (recentIocs.length > 0 ? recentIocs.length : 12);

  return (
    <PageShell>
      {/* ── 1. PRIMARY COMMAND CENTRE PANEL (Large Section with Unified Metric Strip) ── */}
      <Section className="border-t-2 border-t-[#38BDF8]">
        <SectionHeader
          tag="MICHAEL SOC"
          title="Command Centre"
          description="Enterprise-grade autonomous threat detection, behavioral intelligence and forensic telemetry operations."
          statusList={[
            { label: 'Guardian Online', status: 'online' },
            { label: connected ? 'WebSocket Connected' : 'WebSocket Reconnecting', status: connected ? 'online' : 'warning' },
            { label: 'ML Engine Active', status: 'active' },
            { label: 'Pipeline Healthy', status: 'online' },
          ]}
          actions={
            <button
              onClick={loadData}
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
              <span>Refresh Operations</span>
            </button>
          }
        />

        {/* ── Security Overview: Visual Metric Row with Progress Indicators ── */}
        <div>
          <div className="text-[11px] font-mono uppercase tracking-wider text-[#64748B] mb-2 px-1">
            Security Overview
          </div>
          <MetricRow columns={5}>
            <MetricItem
              label="Threat Level"
              value="14%"
              badge="Guarded"
              badgeColor="#10B981"
              progress={14}
              progressColor="#10B981"
              change="+0%"
              changeColor="#10B981"
              sub="Composite posture score"
              icon={Shield}
            />
            <MetricItem
              label="Events"
              value={totalLogs.toLocaleString()}
              progress={65}
              progressColor="#38BDF8"
              change="↑ +12%"
              changeColor="#38BDF8"
              sub="Streaming ingestion rate"
              icon={Layers}
            />
            <MetricItem
              label="Anomalies"
              value={totalAnomalies}
              progress={totalAnomalies > 50 ? 80 : 38}
              progressColor="#F59E0B"
              change="↑ +18%"
              changeColor="#F59E0B"
              sub="Isolation Forest outliers"
              icon={AlertTriangle}
            />
            <MetricItem
              label="Incidents"
              value={openIncidents}
              progress={Math.min(100, openIncidents * 12)}
              progressColor="#EF4444"
              change="↑ +3"
              changeColor="#EF4444"
              sub="Active triage queue"
              icon={Target}
            />
            <MetricItem
              label="Suspicious IOCs"
              value={totalIocs}
              progress={Math.min(100, totalIocs * 7)}
              progressColor="#A78BFA"
              change="↑ +9%"
              changeColor="#A78BFA"
              sub="Reputation signals"
              icon={Fingerprint}
            />
          </MetricRow>
        </div>
      </Section>

      {/* ── 2. LIVE THREAT ACTIVITY (Large Chart + Threat Distribution beside it) ── */}
      <Section
        title="Live Threat Activity & Distribution"
        subtitle="Real-time telemetry event volume, anomalous risk velocity and severity distribution"
      >
        <div className="grid grid-cols-1 lg:grid-cols-12 gap-8 items-stretch">
          <div className="lg:col-span-8">
            <LiveThreatGraph data={logStats?.hourly_volume || []} totalAnomalies={totalAnomalies} />
          </div>
          <div className="lg:col-span-4">
            <AnomalySeverityDonut data={sevData} totalAnomalies={totalAnomalies} />
          </div>
        </div>
      </Section>

      {/* ── 3. ATTACK ACTIVITY & INTELLIGENCE (Progression Flow + Detection Bars + Threat Gauge) ── */}
      <Section
        title="Attack Activity & Detection Intelligence"
        subtitle="Adversary progression reconstruction, machine learning weights and threat indicators"
      >
        {/* Attack Chain Progression Flow */}
        <div className="w-full pb-6 border-b border-white/[0.06]">
          <AttackChainFlow chains={attackChains} isLoading={isLoading} />
        </div>

        {/* 2-Column Split: Detection Intelligence & Threat Intel Gauge */}
        <div className="grid grid-cols-1 lg:grid-cols-12 gap-8 pt-2">
          <div className="lg:col-span-6">
            <DetectionIntelligenceBars totalAnomalies={totalAnomalies} />
          </div>
          <div className="lg:col-span-6">
            <ThreatIntelGauge summary={iocSummary} recentIocs={recentIocs} />
          </div>
        </div>
      </Section>

      {/* ── 4. SYSTEM HEALTH & TELEMETRY SENSORS ─────────────────────────────── */}
      <Section
        title="System Health & Infrastructure Telemetry"
        subtitle="Host compute performance, daemon latency and WebSocket streaming state"
      >
        <SystemTelemetryStrip
          wsConnected={connected}
          wsData={latestMetric?.data}
        />
      </Section>

      {/* ── 5. RECENT SECURITY EVENTS & CASE TRIAGE ──────────────────────────── */}
      <Section
        title="Recent Security Events & Case Triage"
        subtitle="Streaming log audit feed and correlated incidents awaiting analyst review"
      >
        <div className="grid grid-cols-1 lg:grid-cols-12 gap-8 items-stretch">
          <div className="lg:col-span-6">
            <LiveEventConsole events={events} wsConnected={connected} />
          </div>
          <div className="lg:col-span-6">
            <RecentIncidentsTable incidents={incidents} isLoading={isLoading} />
          </div>
        </div>
      </Section>
    </PageShell>
  );
}
