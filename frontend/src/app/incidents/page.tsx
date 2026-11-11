'use client';

import React, { useState, useEffect, useCallback, useMemo } from 'react';
import {
  ShieldAlert,
  RefreshCw,
  AlertTriangle,
  Activity,
  CheckCircle2,
} from 'lucide-react';
import { IncidentCard } from '@/components/incidents/IncidentCard';
import { IncidentDetail } from '@/components/incidents/IncidentDetail';
import { PageHeader } from '@/components/ui/PageHeader';
import { Button } from '@/components/ui/Button';
import { MetricCard } from '@/components/ui/MetricCard';
import { EmptyState } from '@/components/ui/EmptyState';
import { getIncidents, updateIncidentStatus, getIncidentSummary, getSessions } from '@/lib/api';
import { Incident, IncidentStatus, IncidentSummary, LogSession } from '@/types';

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
    <div className="space-y-6 pb-12 font-sans text-slate-100">
      {/* 1. Page Header */}
      <PageHeader
        tag="Security Operations"
        title="Incident Centre"
        description="Correlated multi-signal security alerts, root-cause forensic hypotheses, and case-management triage."
        actions={
          <Button
            variant="secondary"
            size="sm"
            onClick={fetchIncidents}
            isLoading={isLoading}
            leftIcon={<RefreshCw size={13} />}
          >
            Refresh Queue
          </Button>
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

      {/* 3. KPI Row: Incident Triage Overview */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
        <MetricCard
          label="Total Incidents"
          value={incidents.length}
          subValue="Active correlated cases"
          icon={ShieldAlert}
          accentColor="#3B82F6"
        />

        <MetricCard
          label="Critical Triage"
          value={criticalCount}
          subValue="Immediate containment needed"
          icon={AlertTriangle}
          accentColor="#EF4444"
          trend={criticalCount > 0 ? { value: 'HIGH PRIORITY', positive: false } : undefined}
        />

        <MetricCard
          label="Active Investigation"
          value={statusCounts.investigating}
          subValue="In-progress analyst review"
          icon={Activity}
          accentColor="#F59E0B"
        />

        <MetricCard
          label="Resolved / Contained"
          value={statusCounts.resolved}
          subValue="Mitigated cases"
          icon={CheckCircle2}
          accentColor="#22C55E"
        />
      </div>

      {/* 4. Filter Strip */}
      <div className="flex flex-wrap items-center justify-between gap-3 p-4 rounded-xl bg-[#0C1119] border border-white/[0.08]">
        {/* Status Filters */}
        <div className="flex items-center gap-1.5 overflow-x-auto pb-1 sm:pb-0 text-xs">
          <span className="text-[#687589] font-medium mr-1">Status:</span>
          {['ALL', 'OPEN', 'INVESTIGATING', 'RESOLVED'].map((st) => (
            <button
              key={st}
              onClick={() => setStatusFilter(st)}
              className={`px-3 py-1.5 rounded-lg text-xs font-medium transition-all cursor-pointer ${
                statusFilter === st
                  ? 'bg-[#3B82F6] text-white shadow-sm'
                  : 'bg-white/[0.03] text-[#A7B1C0] hover:text-[#F5F7FA] hover:bg-white/[0.06]'
              }`}
            >
              {st}
            </button>
          ))}
        </div>

        {/* Severity Filters */}
        <div className="flex items-center gap-1.5 text-xs">
          <span className="text-[#687589] font-medium mr-1">Severity:</span>
          {['ALL', 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].map((sev) => (
            <button
              key={sev}
              onClick={() => setSeverityFilter(sev)}
              className={`px-2.5 py-1 rounded-md text-[11px] font-medium transition-all cursor-pointer ${
                severityFilter === sev
                  ? 'bg-[#111823] text-white border border-white/20'
                  : 'text-[#A7B1C0] hover:text-white'
              }`}
            >
              {sev}
            </button>
          ))}
        </div>
      </div>

      {/* 5. Incident Queue List */}
      {incidents.length === 0 ? (
        <EmptyState
          title="No Security Incidents Found"
          description="There are no active security incidents matching your filter criteria. Telemetry appears normal."
        />
      ) : (
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
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

      {/* 6. Investigation Detail Drawer */}
      <IncidentDetail
        incident={selectedIncident}
        onClose={() => setSelectedIncident(null)}
        onStatusChange={handleStatusChange}
      />
    </div>
  );
}
