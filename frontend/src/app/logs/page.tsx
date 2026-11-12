'use client';

import React, { useState, useEffect, useCallback } from 'react';
import { useRouter } from 'next/navigation';
import {
  FileText,
  Play,
  RefreshCw,
  ShieldAlert,
  Activity,
  UploadCloud,
} from 'lucide-react';

import {
  PageShell,
  Section,
  SectionHeader,
  MetricRow,
  MetricItem,
} from '@/components/ui/primitives';

import { DropZone } from '@/components/logs/DropZone';
import { LogVolumeGraph } from '@/components/logs/LogVolumeGraph';
import { getLogs, getSessions, runAnalysis, getLogStats } from '@/lib/api';
import { LogSession, LogStats } from '@/types';

export default function LogsPage() {
  const router = useRouter();
  const [sessions, setSessions] = useState<LogSession[]>([]);
  const [activeSessionId, setActiveSessionId] = useState<string>('');
  const [totalEntries, setTotalEntries] = useState<number>(0);
  const [isLoadingLogs, setIsLoadingLogs] = useState<boolean>(false);
  const [isAnalyzing, setIsAnalyzing] = useState<boolean>(false);
  const [stats, setStats] = useState<LogStats | null>(null);
  const [showUpload, setShowUpload] = useState<boolean>(false);

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

  const fetchLogs = useCallback(async () => {
    if (!activeSessionId) return;
    setIsLoadingLogs(true);
    try {
      const resp = await getLogs({
        session_id: activeSessionId,
        page: 1,
        page_size: 50,
      });
      setTotalEntries(resp.total || 0);

      const s = await getLogStats(activeSessionId).catch(() => null);
      if (s) setStats(s);
    } catch (err) {
      console.error('Failed to load logs', err);
    } finally {
      setIsLoadingLogs(false);
    }
  }, [activeSessionId]);

  useEffect(() => {
    fetchLogs();
  }, [fetchLogs]);

  const handleUploadSuccess = (newSessionId: string) => {
    setActiveSessionId(newSessionId);
    fetchSessions();
    setShowUpload(false);
  };

  const handleRunMLAnalysis = async () => {
    if (!activeSessionId) return;
    setIsAnalyzing(true);
    try {
      await runAnalysis(activeSessionId);
      await fetchLogs();
      router.push('/anomalies');
    } catch (err) {
      console.error('Analysis failed', err);
    } finally {
      setIsAnalyzing(false);
    }
  };

  return (
    <PageShell>
      {/* ── 1. PRIMARY LOG EXPLORER SECTION ─────────────────────────────────── */}
      <Section className="border-t-2 border-t-[#38BDF8]">
        <SectionHeader
          tag="SECURITY TELEMETRY"
          title="Log Explorer"
          description="Investigate real-time structured telemetry streams, anomalous rate fluctuations, and multi-source event distributions across monitored infrastructure."
          statusList={[
            { label: 'Ingestion Daemon: Active', status: 'online' },
            { label: `${totalEntries.toLocaleString()} Events Ingested`, status: 'active' },
            { label: 'Normalizer: ECS Ready', status: 'online' },
          ]}
          actions={
            <div className="flex items-center gap-2.5">
              <button
                onClick={() => setShowUpload(!showUpload)}
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
                <UploadCloud size={14} className="text-[#38BDF8]" />
                <span>{showUpload ? 'Hide Ingestion' : 'Ingest Logs'}</span>
              </button>

              <button
                onClick={handleRunMLAnalysis}
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

              <button
                onClick={fetchLogs}
                disabled={isLoadingLogs}
                style={{
                  backgroundColor: '#111722',
                  border: '1px solid rgba(255, 255, 255, 0.08)',
                  color: '#FFFFFF',
                  borderRadius: 8,
                  padding: '7px 12px',
                  fontSize: '0.78rem',
                }}
                className="hover:bg-white/[0.08] transition-colors cursor-pointer"
                title="Refresh logs"
              >
                <RefreshCw size={13} className={isLoadingLogs ? 'animate-spin text-[#38BDF8]' : 'text-[#94A3B8]'} />
              </button>
            </div>
          }
        />

        {/* Upload Panel (Expandable) */}
        {showUpload && (
          <div className="animate-in fade-in duration-200 pt-2">
            <DropZone onUploadSuccess={handleUploadSuccess} />
          </div>
        )}

        {/* Session Selector Strip */}
        {sessions.length > 0 && (
          <div className="flex items-center gap-2 overflow-x-auto pb-1 text-xs">
            <span className="text-[#64748B] shrink-0 font-mono text-[11px] uppercase tracking-wider">Session:</span>
            {sessions.map((s) => (
              <button
                key={s.id}
                onClick={() => {
                  setActiveSessionId(s.id);
                }}
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

        {/* Single Continuous Metric Row: Total | Anomalies | Critical | Feed Sources */}
        <div>
          <div className="text-[11px] font-mono uppercase tracking-wider text-[#64748B] mb-2 px-1">
            Telemetry Overview
          </div>
          <MetricRow columns={4}>
            <MetricItem
              label="Total Ingested Events"
              value={totalEntries.toLocaleString()}
              progress={totalEntries > 0 ? 70 : 0}
              progressColor="#38BDF8"
              sub="Active session count"
              icon={FileText}
            />
            <MetricItem
              label="Identified Anomalies"
              value={stats?.anomaly_count ?? 0}
              progress={stats?.anomaly_count ? Math.min(100, stats.anomaly_count * 4) : 0}
              progressColor="#F59E0B"
              changeColor="#F59E0B"
              sub="Isolation Forest outliers"
              icon={ShieldAlert}
            />
            <MetricItem
              label="Critical Severity"
              value={stats?.level_distribution?.CRITICAL ?? 0}
              progress={stats?.level_distribution?.CRITICAL ? Math.min(100, stats.level_distribution.CRITICAL * 8) : 0}
              progressColor="#EF4444"
              changeColor="#EF4444"
              sub="Requires analyst triage"
              icon={ShieldAlert}
            />
            <MetricItem
              label="Active Feed Sources"
              value={stats?.source_distribution ? Object.keys(stats.source_distribution).length : 4}
              progress={100}
              progressColor="#10B981"
              changeColor="#10B981"
              sub="Unique event origins"
              icon={Activity}
            />
          </MetricRow>
        </div>
      </Section>

      {/* ── 2. VISUAL TELEMETRY & INGESTION ANALYTICS ────────────────────────── */}
      <Section
        title="Ingestion Density, Categorical Distribution & Pipeline Intelligence"
        subtitle="Comprehensive visual telemetry analytics including temporal velocity curves, severity distribution, event taxonomies, and parser health"
      >
        <LogVolumeGraph stats={stats} totalEntries={totalEntries} />
      </Section>
    </PageShell>
  );
}
