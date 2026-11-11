'use client';

import React, { useState, useEffect, Suspense } from 'react';
import Link from 'next/link';
import {
  Sparkles,
  Layers,
  ShieldAlert,
  Fingerprint,
  GitFork,
  Radar,
  ArrowUpRight,
  Shield,
  Activity,
} from 'lucide-react';
import { ChatInterface } from '@/components/copilot/ChatInterface';
import { PageHeader } from '@/components/ui/PageHeader';
import { MetricCard } from '@/components/ui/MetricCard';
import { Badge } from '@/components/ui/Badge';
import { getSessions, getDashboardStats, getIOCSummary } from '@/lib/api';
import { LogSession, DashboardStats, IOCSummary } from '@/types';

function CopilotContent() {
  const [sessions, setSessions] = useState<LogSession[]>([]);
  const [activeSessionId, setActiveSessionId] = useState<string>('');
  const [dashStats, setDashStats] = useState<DashboardStats | null>(null);
  const [iocSummary, setIocSummary] = useState<IOCSummary | null>(null);

  useEffect(() => {
    Promise.all([
      getSessions().catch(() => ({ sessions: [] })),
      getDashboardStats().catch(() => null),
      getIOCSummary().catch(() => null),
    ]).then(([sessData, stats, iocSum]) => {
      if (sessData?.sessions && sessData.sessions.length > 0) {
        setSessions(sessData.sessions);
        setActiveSessionId(sessData.sessions[sessData.sessions.length - 1].id);
      }
      if (stats) setDashStats(stats);
      if (iocSum) setIocSummary(iocSum);
    });
  }, []);

  const activeSession = sessions.find((s) => s.id === activeSessionId);

  return (
    <div className="space-y-6 pb-12 font-sans text-slate-100">
      {/* 1. Page Header */}
      <PageHeader
        tag="Autonomous Reasoning"
        title="AI Copilot"
        description="Context-aware LLM reasoning powered by session log embeddings, anomaly clusters, and automated threat forensics."
        actions={
          sessions.length > 0 && (
            <div className="flex items-center gap-2 p-1.5 rounded-lg bg-[#0C1119] border border-white/[0.08] text-xs">
              <Layers size={14} className="text-[#3B82F6] ml-1" />
              <span className="text-[#A7B1C0]">Session:</span>
              <select
                value={activeSessionId}
                onChange={(e) => setActiveSessionId(e.target.value)}
                className="bg-[#080C12] text-[#F5F7FA] border border-white/10 rounded-md px-2 py-1 focus:outline-none cursor-pointer"
              >
                {sessions.map((s) => (
                  <option key={s.id} value={s.id}>
                    {s.filename || s.id.slice(0, 10)}
                  </option>
                ))}
              </select>
            </div>
          )
        }
      />

      {/* 2. KPI Context Strip */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
        <MetricCard
          label="Active Incidents"
          value={dashStats?.total_incidents || 2}
          subValue="Incident triage context"
          icon={ShieldAlert}
          accentColor="#EF4444"
          trend={{ value: 'CRITICAL', positive: false }}
        />
        <MetricCard
          label="Threat Posture"
          value="Elevated"
          subValue="Confidence rate 94.2%"
          icon={Shield}
          accentColor="#F59E0B"
        />
        <MetricCard
          label="Tracked IOCs"
          value={iocSummary?.total_iocs || 12}
          subValue="Extracted indicators"
          icon={Fingerprint}
          accentColor="#22B8FF"
        />
        <MetricCard
          label="Total Logs Ingested"
          value={dashStats?.total_logs || 1284}
          subValue="Active session scope"
          icon={Activity}
          accentColor="#3B82F6"
        />
      </div>

      {/* 3. Main Workspace: Context Sidebar (4 cols) + Chat Interface (8 cols) */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-5 items-start">
        {/* Left: Investigation Context (4 cols) */}
        <div className="lg:col-span-4 space-y-4">
          {/* Active Context Card */}
          <div
            style={{
              backgroundColor: '#0C1119',
              border: '1px solid rgba(255, 255, 255, 0.08)',
              borderRadius: '12px',
              padding: '20px',
            }}
            className="space-y-4 text-xs"
          >
            <div className="flex items-center justify-between border-b border-white/[0.06] pb-3">
              <span className="font-semibold text-sm text-[#F5F7FA]">
                Investigation Context
              </span>
              <Badge variant="blue" size="sm">
                Live State
              </Badge>
            </div>

            <div className="space-y-3">
              <div className="p-3 rounded-lg bg-[#080C12] border border-white/[0.04] space-y-1">
                <span className="text-[#687589]">Active Ingestion File:</span>
                <div className="font-mono text-[#F5F7FA] truncate">
                  {activeSession?.filename || 'scenario_b_brute_force.log'}
                </div>
                <div className="text-[10px] text-[#A7B1C0]">
                  {activeSession?.line_count || 1284} total lines evaluated
                </div>
              </div>

              <div className="p-3 rounded-lg bg-[#080C12] border border-white/[0.04] space-y-1">
                <span className="text-[#687589]">Primary Anomaly Focus:</span>
                <div className="font-medium text-[#F59E0B]">
                  SSH Password Spraying & Brute Force
                </div>
                <div className="text-[10px] text-[#A7B1C0]">
                  Attacker IP: 198.51.100.45 • 42 Failed Attempts
                </div>
              </div>

              <div className="p-3 rounded-lg bg-[#080C12] border border-white/[0.04] space-y-1">
                <span className="text-[#687589]">Correlated ATT&CK Stage:</span>
                <div className="font-medium text-[#8B5CF6]">
                  Credential Access (T1110)
                </div>
                <div className="text-[10px] text-[#A7B1C0]">
                  Followed by Lateral Movement attempt
                </div>
              </div>
            </div>

            {/* Quick Links */}
            <div className="pt-2 border-t border-white/[0.06] space-y-2">
              <span className="text-[11px] text-[#687589] font-medium uppercase tracking-wider">
                Cross-Module Navigation
              </span>
              <div className="flex flex-col gap-1.5 text-xs">
                <Link
                  href="/incidents"
                  className="flex items-center justify-between text-[#A7B1C0] hover:text-[#3B82F6] p-1.5 rounded-md hover:bg-white/[0.02] transition-colors"
                >
                  <span className="flex items-center gap-1.5">
                    <ShieldAlert size={13} className="text-[#EF4444]" />
                    Review Incident Queue
                  </span>
                  <ArrowUpRight size={12} />
                </Link>

                <Link
                  href="/attack-chains"
                  className="flex items-center justify-between text-[#A7B1C0] hover:text-[#3B82F6] p-1.5 rounded-md hover:bg-white/[0.02] transition-colors"
                >
                  <span className="flex items-center gap-1.5">
                    <GitFork size={13} className="text-[#8B5CF6]" />
                    Inspect Attack Chains
                  </span>
                  <ArrowUpRight size={12} />
                </Link>

                <Link
                  href="/threat-intelligence"
                  className="flex items-center justify-between text-[#A7B1C0] hover:text-[#3B82F6] p-1.5 rounded-md hover:bg-white/[0.02] transition-colors"
                >
                  <span className="flex items-center gap-1.5">
                    <Radar size={13} className="text-[#22B8FF]" />
                    Check Threat Intelligence
                  </span>
                  <ArrowUpRight size={12} />
                </Link>
              </div>
            </div>
          </div>
        </div>

        {/* Right: Copilot Chat Workspace (8 cols) */}
        <div className="lg:col-span-8">
          <ChatInterface sessionId={activeSessionId} />
        </div>
      </div>
    </div>
  );
}

export default function CopilotPage() {
  return (
    <Suspense fallback={<div className="p-12 text-center text-[#A7B1C0] text-xs">Loading AI Copilot...</div>}>
      <CopilotContent />
    </Suspense>
  );
}
