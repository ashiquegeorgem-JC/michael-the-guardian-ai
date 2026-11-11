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
  CheckCircle2,
} from 'lucide-react';
import { DropZone } from '@/components/logs/DropZone';
import { LogTable } from '@/components/logs/LogTable';
import { LogVolumeGraph } from '@/components/logs/LogVolumeGraph';
import { LogInspector } from '@/components/logs/LogInspector';
import { PageHeader } from '@/components/ui/PageHeader';
import { Button } from '@/components/ui/Button';
import { MetricCard } from '@/components/ui/MetricCard';
import { getLogs, getSessions, runAnalysis, getLogStats } from '@/lib/api';
import { LogEntry, LogSession, LogStats } from '@/types';

export default function LogsPage() {
  const router = useRouter();
  const [sessions, setSessions] = useState<LogSession[]>([]);
  const [activeSessionId, setActiveSessionId] = useState<string>('');
  const [entries, setEntries] = useState<LogEntry[]>([]);
  const [totalEntries, setTotalEntries] = useState<number>(0);
  const [currentPage, setCurrentPage] = useState<number>(1);
  const [levelFilter, setLevelFilter] = useState<string>('');
  const [searchKeyword, setSearchKeyword] = useState<string>('');
  const [selectedLog, setSelectedLog] = useState<LogEntry | null>(null);
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
        page: currentPage,
        page_size: 50,
        level: levelFilter || undefined,
        keyword: searchKeyword || undefined,
      });
      setEntries(resp.entries || []);
      setTotalEntries(resp.total || 0);

      const s = await getLogStats(activeSessionId).catch(() => null);
      if (s) setStats(s);
    } catch (err) {
      console.error('Failed to load logs', err);
    } finally {
      setIsLoadingLogs(false);
    }
  }, [activeSessionId, currentPage, levelFilter, searchKeyword]);

  useEffect(() => {
    fetchLogs();
  }, [fetchLogs]);

  const handleUploadSuccess = (newSessionId: string) => {
    setActiveSessionId(newSessionId);
    setCurrentPage(1);
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
    <div className="space-y-6 pb-12 font-sans text-slate-100">
      {/* 1. Page Header */}
      <PageHeader
        tag="Security Telemetry"
        title="Log Explorer"
        description="Search, filter, ingest and investigate raw structured system events across all endpoints."
        actions={
          <>
            <Button
              variant="secondary"
              size="sm"
              onClick={() => setShowUpload(!showUpload)}
              leftIcon={<UploadCloud size={14} />}
            >
              {showUpload ? 'Hide Ingestion' : 'Ingest Logs'}
            </Button>

            <Button
              variant="primary"
              size="sm"
              isLoading={isAnalyzing}
              onClick={handleRunMLAnalysis}
              leftIcon={<Play size={14} />}
            >
              Run ML Anomaly Analysis
            </Button>

            <Button
              variant="secondary"
              size="sm"
              onClick={fetchLogs}
              title="Refresh logs"
            >
              <RefreshCw size={13} className={isLoadingLogs ? 'animate-spin' : ''} />
            </Button>
          </>
        }
      />

      {/* 2. Upload Panel (Expandable) */}
      {showUpload && (
        <div className="animate-in fade-in duration-200">
          <DropZone onUploadSuccess={handleUploadSuccess} />
        </div>
      )}

      {/* 3. Session Selector Strip */}
      {sessions.length > 0 && (
        <div className="flex items-center gap-2 overflow-x-auto pb-1 text-xs">
          <span className="text-[#687589] shrink-0 font-medium">Session:</span>
          {sessions.map((s) => (
            <button
              key={s.id}
              onClick={() => {
                setActiveSessionId(s.id);
                setCurrentPage(1);
              }}
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

      {/* 4. KPI Row: Log Summary */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        <MetricCard
          label="Total Ingested Events"
          value={totalEntries.toLocaleString()}
          subValue="Active session count"
          icon={FileText}
          accentColor="#3B82F6"
        />

        <MetricCard
          label="Identified Anomalies"
          value={stats?.anomaly_count ?? 0}
          subValue="Isolation Forest outliers"
          icon={ShieldAlert}
          accentColor="#F59E0B"
        />

        <MetricCard
          label="Critical Severity"
          value={stats?.level_distribution?.CRITICAL ?? 0}
          subValue="Requires analyst triage"
          icon={ShieldAlert}
          accentColor="#EF4444"
        />

        <MetricCard
          label="Active Feed Sources"
          value={stats?.source_distribution ? Object.keys(stats.source_distribution).length : 4}
          subValue="Unique event origins"
          icon={Activity}
          accentColor="#22C55E"
        />
      </div>

      {/* 5. Ingestion Timeline & Level Breakdown */}
      <LogVolumeGraph stats={stats} totalEntries={totalEntries} />

      {/* 6. Structured Log Explorer Table */}
      <LogTable
        entries={entries}
        total={totalEntries}
        currentPage={currentPage}
        pageSize={50}
        onPageChange={setCurrentPage}
        onLevelFilter={(lvl) => {
          setLevelFilter(lvl);
          setCurrentPage(1);
        }}
        onSearchChange={(kwd) => {
          setSearchKeyword(kwd);
          setCurrentPage(1);
        }}
        onSelectLog={setSelectedLog}
        selectedLogLevel={levelFilter}
        isLoading={isLoadingLogs}
      />

      {/* 7. Slide-over Event Detail Drawer */}
      <LogInspector log={selectedLog} onClose={() => setSelectedLog(null)} />
    </div>
  );
}
