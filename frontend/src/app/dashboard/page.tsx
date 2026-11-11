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
  Upload,
  Sparkles,
  RefreshCw,
} from 'lucide-react';

// Specialized Cyber Defense SOC Components
import { LiveThreatGraph } from '@/components/dashboard/LiveThreatGraph';
import { AnomalySeverityDonut } from '@/components/dashboard/AnomalySeverityDonut';
import { AttackChainFlow } from '@/components/dashboard/AttackChainFlow';
import { DetectionIntelligenceBars } from '@/components/dashboard/DetectionIntelligenceBars';
import { LiveEventConsole } from '@/components/dashboard/LiveEventConsole';
import { RecentIncidentsTable } from '@/components/dashboard/RecentIncidentsTable';
import { ThreatIntelGauge } from '@/components/dashboard/ThreatIntelGauge';
import { SystemTelemetryStrip } from '@/components/dashboard/SystemTelemetryStrip';

function MiniSparkline({ color, points }: { color: string; points: string }) {
  return (
    <svg className="w-14 h-6 overflow-visible shrink-0" viewBox="0 0 56 24">
      <polyline
        fill="none"
        stroke={color}
        strokeWidth="2.5"
        strokeLinecap="round"
        strokeLinejoin="round"
        points={points}
      />
    </svg>
  );
}

export default function DashboardPage() {
  const [stats, setStats] = useState<DashboardStats | null>(null);
  const [logStats, setLogStats] = useState<LogStats | null>(null);
  const [incidentSummary, setIncidentSummary] = useState<IncidentSummary | null>(null);
  const [incidents, setIncidents] = useState<Incident[]>([]);
  const [attackChains, setAttackChains] = useState<AttackChain[]>([]);
  const [iocSummary, setIocSummary] = useState<IOCSummary | null>(null);
  const [recentIocs, setRecentIocs] = useState<IOC[]>([]);
  const [isLoading, setIsLoading] = useState(true);

  // Live WebSocket Telemetry Stream
  const { latestMetric, connected, events } = useWebSocket();

  const loadData = async () => {
    setIsLoading(true);
    try {
      const [
        dash,
        lStats,
        iSummary,
        incList,
        chains,
        iSummaryData,
        iocListData,
      ] = await Promise.all([
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
    <div className="space-y-6 pb-12 font-sans text-[#FAF9F5]">
      {/* 1. Hero Banner: Autonomous Security Operations (Celestial Gold & Warm Charcoal) */}
      <div
        style={{
          background:
            'linear-gradient(135deg, #182027 0%, #222C35 50%, #192128 100%)',
          border: '1px solid rgba(212, 175, 55, 0.28)',
          borderRadius: '16px',
          padding: '26px 30px',
          boxShadow: '0 8px 32px rgba(0, 0, 0, 0.5), 0 0 24px rgba(212, 175, 55, 0.12)',
        }}
        className="flex flex-col md:flex-row md:items-center justify-between gap-6"
      >
        {/* Left: Glowing Archangel Michael Emblem + Title & Subtitle */}
        <div className="flex items-center gap-4">
          <div
            style={{
              position: 'relative',
              width: 56,
              height: 56,
              borderRadius: '50%',
              overflow: 'hidden',
              flexShrink: 0,
              border: '2px solid rgba(212, 175, 55, 0.7)',
              boxShadow: '0 0 20px rgba(212, 175, 55, 0.45)',
              background: '#12171B',
            }}
          >
            <img
              src="/michael-logo.png"
              alt="Archangel Michael"
              style={{ width: '100%', height: '100%', objectFit: 'cover' }}
            />
          </div>

          <div>
            <h1 className="text-2xl md:text-[27px] font-bold tracking-tight text-[#FAF9F5] font-heading leading-tight">
              Autonomous Security Operations
            </h1>
            <p className="text-sm text-[#D1CBC0] font-subheading font-light mt-1 max-w-xl">
              Real-time threat detection, behavioural intelligence and automated forensic analysis.
            </p>
          </div>
        </div>

        {/* Right: Quick Action Buttons (Celestial Gold theme) */}
        <div className="flex items-center gap-3 shrink-0 flex-wrap">
          <Link href="/logs" style={{ textDecoration: 'none' }}>
            <button
              style={{
                backgroundColor: '#D4AF37',
                color: '#12171B',
                boxShadow: '0 0 16px rgba(212, 175, 55, 0.4)',
              }}
              className="flex items-center gap-2 px-4 py-2.5 rounded-xl text-xs font-bold transition-all hover:bg-[#E5C07B] font-subheading cursor-pointer"
            >
              <Upload size={14} color="#12171B" />
              <span>Ingest Logs</span>
            </button>
          </Link>

          <Link href="/copilot" style={{ textDecoration: 'none' }}>
            <button
              style={{
                background: 'rgba(212, 175, 55, 0.1)',
                border: '1px solid rgba(212, 175, 55, 0.35)',
              }}
              className="flex items-center gap-2 px-4 py-2.5 rounded-xl text-xs font-semibold text-[#FAF9F5] hover:text-[#D4AF37] transition-all font-subheading cursor-pointer hover:border-[#D4AF37]"
            >
              <Sparkles size={14} className="text-[#D4AF37]" />
              <span>AI Copilot</span>
            </button>
          </Link>

          <button
            onClick={loadData}
            title="Refresh Command Centre"
            style={{
              backgroundColor: '#1C242B',
              border: '1px solid rgba(212, 175, 55, 0.18)',
            }}
            className="flex items-center justify-center w-9 h-9 rounded-xl hover:bg-[#222C35] text-[#D1CBC0] hover:text-[#FAF9F5] transition-all cursor-pointer"
          >
            <RefreshCw size={15} className={isLoading ? 'animate-spin text-[#D4AF37]' : ''} />
          </button>
        </div>
      </div>

      {/* 2. KPI Row: 5 Cards in Bethesda Charcoal & Celestial Gold */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-5 gap-4">
        {/* KPI 1: Threat Level */}
        <div
          style={{
            backgroundColor: '#1C242B',
            border: '1px solid rgba(212, 175, 55, 0.14)',
            borderRadius: '14px',
            padding: '18px 20px',
            boxShadow: '0 4px 16px rgba(0, 0, 0, 0.4)',
          }}
          className="flex flex-col justify-between"
        >
          <div className="flex items-center justify-between mb-2">
            <span className="text-xs font-subheading text-[#D1CBC0]">Threat Level</span>
            <div className="w-8 h-8 rounded-lg bg-emerald-500/10 border border-emerald-500/20 flex items-center justify-center text-[#22C55E]">
              <Shield size={15} />
            </div>
          </div>
          <div className="flex items-center justify-between gap-2 my-1">
            <div className="flex items-baseline gap-2">
              <span className="text-2xl font-bold font-mono text-[#FAF9F5]">14%</span>
              <span className="text-[11px] font-semibold font-subheading px-2 py-0.5 rounded-full bg-emerald-500/15 text-[#22C55E] border border-emerald-500/30">
                Guarded
              </span>
            </div>
            <MiniSparkline color="#22C55E" points="2,20 16,14 30,17 44,8 54,12" />
          </div>
          <div className="text-[11px] font-subheading font-light text-[#8E877D] mt-2 pt-2 border-t border-[rgba(212,175,55,0.08)]">
            Composite posture score
          </div>
        </div>

        {/* KPI 2: Events Processed */}
        <div
          style={{
            backgroundColor: '#1C242B',
            border: '1px solid rgba(212, 175, 55, 0.14)',
            borderRadius: '14px',
            padding: '18px 20px',
            boxShadow: '0 4px 16px rgba(0, 0, 0, 0.4)',
          }}
          className="flex flex-col justify-between"
        >
          <div className="flex items-center justify-between mb-2">
            <span className="text-xs font-subheading text-[#D1CBC0]">Events Processed</span>
            <div className="w-8 h-8 rounded-lg bg-[rgba(212,175,55,0.12)] border border-[rgba(212,175,55,0.25)] flex items-center justify-center text-[#D4AF37]">
              <Layers size={15} />
            </div>
          </div>
          <div className="flex items-center justify-between gap-2 my-1">
            <div className="flex items-baseline gap-2">
              <span className="text-2xl font-bold font-mono text-[#FAF9F5]">{totalLogs.toLocaleString()}</span>
              <span className="text-[11px] font-mono text-[#D4AF37]">↑ +12%</span>
            </div>
            <MiniSparkline color="#D4AF37" points="2,18 16,16 30,10 44,6 54,4" />
          </div>
          <div className="text-[11px] font-subheading font-light text-[#8E877D] mt-2 pt-2 border-t border-[rgba(212,175,55,0.08)]">
            Streaming ingestion velocity
          </div>
        </div>

        {/* KPI 3: Anomalies */}
        <div
          style={{
            backgroundColor: '#1C242B',
            border: '1px solid rgba(212, 175, 55, 0.14)',
            borderRadius: '14px',
            padding: '18px 20px',
            boxShadow: '0 4px 16px rgba(0, 0, 0, 0.4)',
          }}
          className="flex flex-col justify-between"
        >
          <div className="flex items-center justify-between mb-2">
            <span className="text-xs font-subheading text-[#D1CBC0]">Anomalies</span>
            <div className="w-8 h-8 rounded-lg bg-amber-500/10 border border-amber-500/20 flex items-center justify-center text-[#F59E0B]">
              <AlertTriangle size={15} />
            </div>
          </div>
          <div className="flex items-center justify-between gap-2 my-1">
            <div className="flex items-baseline gap-2">
              <span className="text-2xl font-bold font-mono text-[#FAF9F5]">{totalAnomalies}</span>
              <span className="text-[11px] font-mono text-[#F59E0B]">↑ +18%</span>
            </div>
            <MiniSparkline color="#F59E0B" points="2,19 16,15 30,18 44,9 54,5" />
          </div>
          <div className="text-[11px] font-subheading font-light text-[#8E877D] mt-2 pt-2 border-t border-[rgba(212,175,55,0.08)]">
            Isolation Forest & heuristics
          </div>
        </div>

        {/* KPI 4: Active Incidents */}
        <div
          style={{
            backgroundColor: '#1C242B',
            border: '1px solid rgba(212, 175, 55, 0.14)',
            borderRadius: '14px',
            padding: '18px 20px',
            boxShadow: '0 4px 16px rgba(0, 0, 0, 0.4)',
          }}
          className="flex flex-col justify-between"
        >
          <div className="flex items-center justify-between mb-2">
            <span className="text-xs font-subheading text-[#D1CBC0]">Active Incidents</span>
            <div className="w-8 h-8 rounded-lg bg-rose-500/10 border border-rose-500/20 flex items-center justify-center text-[#EF4444]">
              <Target size={15} />
            </div>
          </div>
          <div className="flex items-center justify-between gap-2 my-1">
            <div className="flex items-baseline gap-2">
              <span className="text-2xl font-bold font-mono text-[#FAF9F5]">{openIncidents}</span>
              <span className="text-[11px] font-mono text-[#EF4444]">↑ +3</span>
            </div>
            <MiniSparkline color="#EF4444" points="2,16 16,14 30,8 44,12 54,6" />
          </div>
          <div className="text-[11px] font-subheading font-light text-[#8E877D] mt-2 pt-2 border-t border-[rgba(212,175,55,0.08)]">
            Normal triage
          </div>
        </div>

        {/* KPI 5: Suspicious IOCs */}
        <div
          style={{
            backgroundColor: '#1C242B',
            border: '1px solid rgba(212, 175, 55, 0.14)',
            borderRadius: '14px',
            padding: '18px 20px',
            boxShadow: '0 4px 16px rgba(0, 0, 0, 0.4)',
          }}
          className="flex flex-col justify-between"
        >
          <div className="flex items-center justify-between mb-2">
            <span className="text-xs font-subheading text-[#D1CBC0]">Suspicious IOCs</span>
            <div className="w-8 h-8 rounded-lg bg-[rgba(212,175,55,0.12)] border border-[rgba(212,175,55,0.25)] flex items-center justify-center text-[#D4AF37]">
              <Fingerprint size={15} />
            </div>
          </div>
          <div className="flex items-center justify-between gap-2 my-1">
            <div className="flex items-baseline gap-2">
              <span className="text-2xl font-bold font-mono text-[#FAF9F5]">{totalIocs}</span>
              <span className="text-[11px] font-mono text-[#D4AF37]">↑ +9%</span>
            </div>
            <MiniSparkline color="#D4AF37" points="2,17 16,12 30,14 44,8 54,4" />
          </div>
          <div className="text-[11px] font-subheading font-light text-[#8E877D] mt-2 pt-2 border-t border-[rgba(212,175,55,0.08)]">
            Threat intelligence indicators
          </div>
        </div>
      </div>

      {/* 3. Row 2: Live Threat Activity + Threat Distribution */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        <div className="lg:col-span-8">
          <LiveThreatGraph
            data={logStats?.hourly_volume || []}
            totalAnomalies={totalAnomalies}
          />
        </div>

        <div className="lg:col-span-4">
          <AnomalySeverityDonut
            data={sevData}
            totalAnomalies={totalAnomalies}
          />
        </div>
      </div>

      {/* 4. Row 3: Attack Chain Reconstruction + Detection Intelligence */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        <div className="lg:col-span-8">
          <AttackChainFlow
            chains={attackChains}
            isLoading={isLoading}
          />
        </div>

        <div className="lg:col-span-4">
          <DetectionIntelligenceBars
            totalAnomalies={totalAnomalies}
          />
        </div>
      </div>

      {/* 5. Row 4: Live Security Event Stream + Recent Incidents */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        <div className="lg:col-span-7">
          <LiveEventConsole
            events={events}
            wsConnected={connected}
          />
        </div>

        <div className="lg:col-span-5">
          <RecentIncidentsTable
            incidents={incidents}
            isLoading={isLoading}
          />
        </div>
      </div>

      {/* 6. Row 5: Threat Intelligence + System Telemetry */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        <div className="lg:col-span-6">
          <ThreatIntelGauge
            summary={iocSummary}
            recentIocs={recentIocs}
          />
        </div>

        <div className="lg:col-span-6">
          <SystemTelemetryStrip
            metrics={stats?.system}
            wsData={latestMetric?.data}
            wsConnected={connected}
          />
        </div>
      </div>
    </div>
  );
}
