'use client';

import React, { useState, useEffect } from 'react';
import {
  FileText,
  Download,
  ShieldCheck,
  CheckCircle2,
  Calendar,
  AlertTriangle,
  FileCode,
  Check,
  RefreshCw,
  ExternalLink,
  Shield,
  Layers,
} from 'lucide-react';
import { Button } from '@/components/ui/Button';
import { Badge } from '@/components/ui/Badge';
import { MetricCard } from '@/components/ui/MetricCard';
import { PageHeader } from '@/components/ui/PageHeader';
import { generateReport, getSessions } from '@/lib/api';
import { LogSession } from '@/types';
import { formatDate } from '@/lib/utils';

export default function ReportsPage() {
  const [sessions, setSessions] = useState<LogSession[]>([]);
  const [selectedSession, setSelectedSession] = useState<string>('');
  const [reportTitle, setReportTitle] = useState('MICHAEL Executive Threat Intelligence & Incident Report');
  const [includeLogs, setIncludeLogs] = useState(true);
  const [isGenerating, setIsGenerating] = useState(false);
  const [generatedReport, setGeneratedReport] = useState<{
    id: string;
    filename: string;
    downloadUrl: string;
    generatedAt: string;
  } | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    getSessions()
      .then((res) => {
        setSessions(res.sessions || []);
        if (res.sessions && res.sessions.length > 0) {
          setSelectedSession(res.sessions[res.sessions.length - 1].id);
        }
      })
      .catch(console.error);
  }, []);

  const handleGenerate = async () => {
    if (!selectedSession) return;
    setIsGenerating(true);
    setError(null);
    try {
      const res = await generateReport(selectedSession, reportTitle);
      const apiBase = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8000';
      setGeneratedReport({
        id: res.report_id,
        filename: res.filename,
        downloadUrl: `${apiBase}${res.download_url}`,
        generatedAt: res.generated_at || new Date().toISOString(),
      });
    } catch (err: any) {
      setError(err?.message || 'Failed to generate security audit report.');
    } finally {
      setIsGenerating(false);
    }
  };

  const STATIC_REPORTS = [
    {
      id: 'rep-01',
      title: 'MICHAEL Autonomous Security Audit & Forensic Attestation',
      type: 'Executive Incident Audit (PDF)',
      incident: 'SSH Brute Force & C2 Outbound Beacon',
      status: 'READY',
      date: '2026-11-10 22:30:00',
      size: '2.4 MB',
      compliance: 'NIST CSF v2.0',
    },
    {
      id: 'rep-02',
      title: 'MITRE ATT&CK Attack Chain Multi-Stage Reconstruction',
      type: 'Adversary Sequence Mapping',
      incident: 'Multi-Stage Lateral Movement Campaign',
      status: 'ARCHIVED',
      date: '2026-11-10 21:15:00',
      size: '1.8 MB',
      compliance: 'ISO 27001 A.12',
    },
    {
      id: 'rep-03',
      title: 'VirusTotal Threat Intelligence & IOC Attribution Brief',
      type: 'Reputation Evidence Brief',
      incident: 'Malicious External Infrastructure Cluster',
      status: 'VERIFIED',
      date: '2026-11-10 20:45:00',
      size: '950 KB',
      compliance: 'CIS Benchmark v8',
    },
  ];

  return (
    <div className="space-y-6 pb-12 font-sans text-slate-100">
      {/* 1. Page Header */}
      <PageHeader
        tag="Compliance & Attestation"
        title="Report Centre"
        description="Automated executive security summaries, NIST CSF compliance documentation, and cryptographic audit log exports."
      />

      {/* 2. KPI Summary Strip */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
        <MetricCard
          label="Generated Reports"
          value={STATIC_REPORTS.length + (generatedReport ? 1 : 0)}
          subValue="Available audit packages"
          icon={FileText}
          accentColor="#3B82F6"
        />
        <MetricCard
          label="Primary Standard"
          value="NIST CSF 2.0"
          subValue="Cyber Defense Framework"
          icon={ShieldCheck}
          accentColor="#22C55E"
        />
        <MetricCard
          label="Export Formats"
          value="PDF • JSON"
          subValue="Cryptographic signatures"
          icon={FileCode}
          accentColor="#8B5CF6"
        />
        <MetricCard
          label="Last Certified Audit"
          value="Today"
          subValue="Automated SOC pipeline"
          icon={Calendar}
          accentColor="#22B8FF"
        />
      </div>

      {/* 3. Generate Report Configuration Card */}
      <div
        style={{
          backgroundColor: '#0C1119',
          border: '1px solid rgba(255, 255, 255, 0.08)',
          borderRadius: '12px',
          padding: '24px',
        }}
        className="space-y-5"
      >
        <div className="border-b border-white/[0.06] pb-3">
          <h3 className="text-sm font-semibold text-[#F5F7FA]">
            Generate Security & Compliance Report
          </h3>
          <p className="text-xs text-[#A7B1C0] mt-0.5">
            Select an ingestion session to compile a comprehensive executive audit document
          </p>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-5 text-xs">
          {/* Report Title */}
          <div className="space-y-1.5">
            <label className="text-xs font-medium text-[#A7B1C0]">
              Report Document Title
            </label>
            <input
              type="text"
              value={reportTitle}
              onChange={(e) => setReportTitle(e.target.value)}
              className="w-full bg-[#080C12] border border-white/[0.08] text-xs text-[#F5F7FA] rounded-lg px-3.5 py-2.5 focus:outline-none focus:border-[#3B82F6]"
            />
          </div>

          {/* Session Selection */}
          <div className="space-y-1.5">
            <label className="text-xs font-medium text-[#A7B1C0]">
              Target Forensic Session
            </label>
            <select
              value={selectedSession}
              onChange={(e) => setSelectedSession(e.target.value)}
              className="w-full bg-[#080C12] border border-white/[0.08] text-xs text-[#F5F7FA] rounded-lg px-3.5 py-2.5 focus:outline-none focus:border-[#3B82F6] cursor-pointer"
            >
              {sessions.map((s) => (
                <option key={s.id} value={s.id}>
                  {s.filename || s.id} ({s.line_count || 0} lines)
                </option>
              ))}
            </select>
          </div>
        </div>

        {/* Checkbox: Include raw logs */}
        <div className="flex items-center gap-2 pt-1">
          <input
            type="checkbox"
            id="includeLogs"
            checked={includeLogs}
            onChange={(e) => setIncludeLogs(e.target.checked)}
            className="w-4 h-4 rounded bg-[#080C12] border border-white/20 text-[#3B82F6] focus:ring-0 cursor-pointer"
          />
          <label htmlFor="includeLogs" className="text-xs text-[#A7B1C0] cursor-pointer">
            Attach raw syslog evidentiary excerpts and Isolation Forest outlier timestamps
          </label>
        </div>

        {error && (
          <div className="flex items-center gap-2 text-xs text-[#EF4444] bg-rose-500/10 border border-rose-500/25 px-3.5 py-2 rounded-lg">
            <AlertTriangle size={14} />
            <span>{error}</span>
          </div>
        )}

        <div className="pt-2">
          <Button
            variant="primary"
            size="md"
            isLoading={isGenerating}
            onClick={handleGenerate}
            leftIcon={<FileText size={14} />}
          >
            Generate Executive Audit Report
          </Button>
        </div>

        {/* Recently Generated Banner */}
        {generatedReport && (
          <div className="p-4 rounded-xl bg-emerald-500/10 border border-emerald-500/25 flex flex-wrap items-center justify-between gap-3 text-xs">
            <div className="flex items-center gap-2.5">
              <CheckCircle2 size={16} className="text-[#22C55E]" />
              <div>
                <div className="font-semibold text-[#F5F7FA]">
                  Report Compiled Successfully
                </div>
                <div className="text-[#A7B1C0] text-[11px] font-mono">
                  {generatedReport.filename} • Ready for download
                </div>
              </div>
            </div>

            <a
              href={generatedReport.downloadUrl}
              download={generatedReport.filename}
              className="inline-flex items-center gap-1.5 px-3.5 py-2 rounded-lg bg-[#22C55E] hover:bg-[#16A34A] text-white font-medium text-xs transition-colors"
            >
              <Download size={13} />
              <span>Download PDF</span>
            </a>
          </div>
        )}
      </div>

      {/* 4. Available Historical Reports Table */}
      <div
        style={{
          backgroundColor: '#0C1119',
          border: '1px solid rgba(255, 255, 255, 0.08)',
          borderRadius: '12px',
          overflow: 'hidden',
        }}
      >
        <div className="p-4 border-b border-white/[0.06] bg-[#080C12] flex items-center justify-between">
          <h3 className="text-sm font-semibold text-[#F5F7FA]">
            Available Compliance Reports
          </h3>
          <span className="text-xs text-[#A7B1C0]">
            {STATIC_REPORTS.length} archived records
          </span>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs border-collapse">
            <thead>
              <tr className="border-b border-white/[0.06] text-[#A7B1C0] bg-[#080C12]/50 font-medium">
                <th className="py-3 px-4">Report Title</th>
                <th className="py-3 px-4 hidden sm:table-cell">Type & Standard</th>
                <th className="py-3 px-4 hidden md:table-cell">Generated</th>
                <th className="py-3 px-4">Status</th>
                <th className="py-3 px-4 text-right">Action</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-white/[0.04]">
              {STATIC_REPORTS.map((rep) => (
                <tr key={rep.id} className="hover:bg-white/[0.02] transition-colors">
                  <td className="py-3.5 px-4">
                    <div className="font-medium text-[#F5F7FA] line-clamp-1">
                      {rep.title}
                    </div>
                    <div className="text-[11px] text-[#687589]">
                      Context: {rep.incident}
                    </div>
                  </td>
                  <td className="py-3.5 px-4 hidden sm:table-cell">
                    <div className="text-[#A7B1C0]">{rep.type}</div>
                    <div className="text-[10px] text-[#3B82F6] font-mono">
                      {rep.compliance}
                    </div>
                  </td>
                  <td className="py-3.5 px-4 font-mono text-[11px] text-[#A7B1C0] hidden md:table-cell">
                    {rep.date}
                  </td>
                  <td className="py-3.5 px-4">
                    <Badge variant={rep.status === 'READY' ? 'success' : 'default'} size="sm">
                      {rep.status}
                    </Badge>
                  </td>
                  <td className="py-3.5 px-4 text-right">
                    <button
                      onClick={() => alert(`Downloading archived report ${rep.title}`)}
                      className="inline-flex items-center gap-1.5 px-2.5 py-1.5 rounded-lg bg-[#080C12] hover:bg-[#111823] border border-white/[0.08] text-xs text-[#3B82F6] hover:text-[#22B8FF] transition-colors"
                    >
                      <Download size={12} />
                      <span>Export</span>
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
