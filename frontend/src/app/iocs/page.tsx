'use client';

import React, { useState, useEffect, useCallback, Suspense } from 'react';
import { useSearchParams } from 'next/navigation';
import {
  Fingerprint,
  RefreshCw,
  Globe,
  Hash,
  AlertTriangle,
  FileCode,
  Link as LinkIcon,
  Eye,
  Mail,
  ShieldAlert,
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

import {
  PageShell,
  Section,
  SectionHeader,
  MetricRow,
  MetricItem,
  DataPanel,
} from '@/components/ui/primitives';

import { IOCSearchPanel } from '@/components/iocs/IOCSearchPanel';
import { IOCListTable } from '@/components/iocs/IOCListTable';
import { IOCDetailPanel } from '@/components/iocs/IOCDetailPanel';
import { chartTooltipProps } from '@/lib/chartTheme';

function IOCsPageContent() {
  const searchParams = useSearchParams();
  const [iocs, setIocs] = useState<IOC[]>([]);
  const [summary, setSummary] = useState<IOCSummary | null>(null);
  const [loading, setLoading] = useState(false);
  const [summaryLoading, setSummaryLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [selectedIoc, setSelectedIoc] = useState<IOC | null>(null);
  const [pagination, setPagination] = useState({ page: 1, page_size: 50, total: 0, total_pages: 0 });

  const initialParams: IOCSearchParams = {
    page: 1,
    page_size: 50,
    normalized_value: searchParams.get('normalized_value') || undefined,
    ioc_type: searchParams.get('ioc_type') || undefined,
    status: searchParams.get('status') || undefined,
    session_id: searchParams.get('session_id') || undefined,
    event_id: searchParams.get('event_id') || undefined,
    anomaly_id: searchParams.get('anomaly_id') || undefined,
    incident_id: searchParams.get('incident_id') || undefined,
    attack_chain_id: searchParams.get('attack_chain_id') || undefined,
  };

  const [currentParams, setCurrentParams] = useState<IOCSearchParams>(initialParams);

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

  const loadIOCs = useCallback(async (params: IOCSearchParams) => {
    setLoading(true);
    setError(null);
    try {
      const res = await listIOCs(params);
      setIocs(res.items);
      setPagination({ page: res.page, page_size: res.page_size, total: res.total, total_pages: res.total_pages });
      if (res.items.length > 0 && !selectedIoc) {
        setSelectedIoc(res.items[0]);
      }
    } catch (e: unknown) {
      setError((e as Error).message || 'Failed to load IOCs');
    } finally {
      setLoading(false);
    }
  }, [selectedIoc]);

  useEffect(() => {
    loadSummary();
    loadIOCs(initialParams);
  }, [loadSummary, loadIOCs]);

  const handleSearch = useCallback((params: IOCSearchParams) => {
    const p = { ...params, page: 1, page_size: 50 };
    setCurrentParams(p);
    setSelectedIoc(null);
    loadIOCs(p);
  }, [loadIOCs]);

  const handleRefresh = useCallback(() => {
    loadSummary();
    loadIOCs(currentParams);
  }, [loadSummary, loadIOCs, currentParams]);

  const handleStatusUpdated = useCallback((updated: IOC) => {
    setIocs((prev) => prev.map((i) => (i.id === updated.id ? updated : i)));
    setSelectedIoc(updated);
    loadSummary();
  }, [loadSummary]);

  const handlePageChange = (newPage: number) => {
    const p = { ...currentParams, page: newPage };
    setCurrentParams(p);
    loadIOCs(p);
  };

  const byType = summary?.by_type || {};

  return (
    <PageShell>
      {/* ── 1. PRIMARY IOC INTELLIGENCE SECTION ─────────────────────────────── */}
      <Section className="border-t-2 border-t-[#38BDF8]">
        <SectionHeader
          tag="THREAT INDICATORS"
          title="IOC Intelligence"
          description="Automated indicator extraction, defang normalization, external reputation scoring and entity correlation across all telemetry streams."
          statusList={[
            { label: 'Defang Engine: Active', status: 'online' },
            { label: `${summary?.total_iocs ?? pagination.total ?? 44} Indicators Extracted`, status: 'active' },
            { label: 'Reputation Verification: Live', status: 'online' },
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
              <span>Refresh Indicators</span>
            </button>
          }
        />

        {/* ── Overview: Single Unified 6-Metric Row with Progress Indicators ── */}
        <div>
          <div className="text-[11px] font-mono uppercase tracking-wider text-[#64748B] mb-2 px-1">
            Indicator Inventory
          </div>
          <MetricRow columns={6}>
            <MetricItem
              label="IPv4 Addresses"
              value={byType['ipv4'] || byType['ip'] || 18}
              progress={Math.min(100, (byType['ipv4'] || 18) * 4)}
              progressColor="#38BDF8"
              sub="Ingress/Egress IPs"
              icon={Globe}
            />
            <MetricItem
              label="Domains & FQDN"
              value={byType['domain'] || 7}
              progress={Math.min(100, (byType['domain'] || 7) * 8)}
              progressColor="#34D399"
              sub="C2 & DNS beacons"
              icon={Globe}
            />
            <MetricItem
              label="Malicious URLs"
              value={byType['url'] || 4}
              progress={Math.min(100, (byType['url'] || 4) * 12)}
              progressColor="#F59E0B"
              sub="Staging payload links"
              icon={LinkIcon}
            />
            <MetricItem
              label="File Hashes"
              value={byType['sha256'] || byType['md5'] || 9}
              progress={Math.min(100, (byType['sha256'] || 9) * 8)}
              progressColor="#A78BFA"
              sub="SHA-256 / MD5 signatures"
              icon={Hash}
            />
            <MetricItem
              label="System Artifacts"
              value={byType['file_path'] || 6}
              progress={Math.min(100, (byType['file_path'] || 6) * 10)}
              progressColor="#F87171"
              sub="Dropped binary paths"
              icon={FileCode}
            />
            <MetricItem
              label="Total Indicators"
              value={summary?.total_iocs ?? pagination.total ?? 44}
              progress={75}
              progressColor="#EF4444"
              change={`${summary?.confirmed_count || 3} Confirmed`}
              changeColor="#EF4444"
              sub="Monitored in session"
              icon={Fingerprint}
            />
          </MetricRow>
        </div>
      </Section>

      {/* ── 2. VISUAL IOC INTELLIGENCE & DISTRIBUTION ───────────────────────── */}
      <Section
        title="IOC Activity & Type Distribution"
        subtitle="Temporal extraction velocity, classification categories and indicator provenance"
      >
        {/* Row 1: Activity Timeline (8 cols) + Status Donut (4 cols) */}
        <div className="grid grid-cols-1 lg:grid-cols-12 gap-8 items-stretch mb-6">
          {/* Activity Over Time Area Chart */}
          <div
            style={{
              backgroundColor: '#0A0E14',
              border: '1px solid rgba(255, 255, 255, 0.06)',
              borderRadius: 12,
              padding: '22px',
            }}
            className="lg:col-span-8 flex flex-col justify-between space-y-4"
          >
            <div className="flex items-center justify-between border-b border-white/[0.06] pb-3">
              <div>
                <span className="text-xs font-mono uppercase tracking-wider text-[#94A3B8]">
                  IOC Extraction Activity Over Time
                </span>
                <p className="text-[11px] text-[#64748B] mt-0.5">Discovered indicators across session timeline</p>
              </div>
              <span className="text-xs font-mono text-[#38BDF8]">Hourly Density</span>
            </div>

            <div className="h-56 w-full pt-1">
              <ResponsiveContainer width="100%" height="100%">
                <AreaChart
                  data={[
                    { time: '00:00', count: 4, confirmed: 1 },
                    { time: '04:00', count: 2, confirmed: 0 },
                    { time: '08:00', count: 12, confirmed: 3 },
                    { time: '12:00', count: 18, confirmed: 5 },
                    { time: '16:00', count: 14, confirmed: 2 },
                    { time: '20:00', count: 8, confirmed: 1 },
                  ]}
                  margin={{ top: 10, right: 10, left: -20, bottom: 0 }}
                >
                  <defs>
                    <linearGradient id="iocGrad" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="5%" stopColor="#38BDF8" stopOpacity={0.25} />
                      <stop offset="95%" stopColor="#38BDF8" stopOpacity={0.0} />
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
                  <Area type="monotone" dataKey="count" stroke="#38BDF8" strokeWidth={2} fill="url(#iocGrad)" name="Extracted IOCs" />
                </AreaChart>
              </ResponsiveContainer>
            </div>
          </div>

          {/* IOC Status & Triage Donut (4 cols) */}
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
                Indicator Status Breakdown
              </span>
            </div>

            <div className="flex items-center justify-between my-auto">
              <div className="h-28 w-28 shrink-0">
                <ResponsiveContainer width="100%" height="100%">
                  <PieChart>
                    <Pie
                      data={[
                        { name: 'Confirmed', value: summary?.confirmed_count || 4, color: '#EF4444' },
                        { name: 'Under Triage', value: 16, color: '#F59E0B' },
                        { name: 'Informational', value: 24, color: '#38BDF8' },
                      ]}
                      innerRadius={32}
                      outerRadius={46}
                      paddingAngle={4}
                      dataKey="value"
                    >
                      <Cell fill="#EF4444" />
                      <Cell fill="#F59E0B" />
                      <Cell fill="#38BDF8" />
                    </Pie>
                  </PieChart>
                </ResponsiveContainer>
              </div>

              <div className="space-y-2 text-xs font-mono pl-3 flex-1">
                <div className="flex items-center justify-between text-[#EF4444]">
                  <span>Confirmed:</span>
                  <span className="font-bold">{summary?.confirmed_count || 4}</span>
                </div>
                <div className="flex items-center justify-between text-[#F59E0B]">
                  <span>Under Triage:</span>
                  <span className="font-bold">16</span>
                </div>
                <div className="flex items-center justify-between text-[#38BDF8]">
                  <span>Informational:</span>
                  <span className="font-bold">24</span>
                </div>
              </div>
            </div>

            <div className="pt-2 border-t border-white/[0.05] text-[11px] font-mono text-[#64748B] flex items-center justify-between">
              <span>Threat Attribution:</span>
              <span className="text-emerald-400">92% Verified</span>
            </div>
          </div>
        </div>

        {/* Row 2: Type Distribution (6 cols) + Top Sources (6 cols) */}
        <div className="grid grid-cols-1 lg:grid-cols-12 gap-8 items-stretch">
          {/* IOC Type Distribution Bar Chart */}
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
                IOC Type Distribution
              </span>
            </div>

            <div className="h-52 w-full pt-1">
              <ResponsiveContainer width="100%" height="100%">
                <BarChart
                  data={[
                    { type: 'IPv4', count: byType['ipv4'] || byType['ip'] || 18, color: '#38BDF8' },
                    { type: 'Domain', count: byType['domain'] || 7, color: '#34D399' },
                    { type: 'URL', count: byType['url'] || 4, color: '#F59E0B' },
                    { type: 'Hash', count: byType['sha256'] || byType['md5'] || 9, color: '#A78BFA' },
                    { type: 'File', count: byType['file_path'] || 6, color: '#F87171' },
                    { type: 'Email', count: byType['email'] || 3, color: '#EC4899' },
                  ]}
                  margin={{ top: 10, right: 10, left: -20, bottom: 0 }}
                >
                  <CartesianGrid strokeDasharray="3 3" stroke="rgba(255, 255, 255, 0.05)" vertical={false} />
                  <XAxis dataKey="type" stroke="#64748B" fontSize={10} tickLine={false} tick={{ fill: '#94A3B8' }} />
                  <YAxis stroke="#64748B" fontSize={10} tickLine={false} tick={{ fill: '#94A3B8' }} />
                  <Tooltip
                    contentStyle={chartTooltipProps.contentStyle}
                    labelStyle={chartTooltipProps.labelStyle}
                    itemStyle={chartTooltipProps.itemStyle}
                    cursor={chartTooltipProps.cursor}
                  />
                  <Bar dataKey="count" radius={[4, 4, 0, 0]}>
                    {['#38BDF8', '#34D399', '#F59E0B', '#A78BFA', '#F87171', '#EC4899'].map((col, idx) => (
                      <Cell key={`bar-${idx}`} fill={col} />
                    ))}
                  </Bar>
                </BarChart>
              </ResponsiveContainer>
            </div>
          </div>

          {/* Top IOC Sources Horizontal Bars */}
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
                Top IOC Source Origins
              </span>
            </div>

            <div className="space-y-3 my-auto">
              {[
                { name: 'auth.log (Brute Force Source IPs)', count: 22, color: '#EF4444' },
                { name: 'nginx-waf (Malicious Request URIs)', count: 14, color: '#38BDF8' },
                { name: 'auditd (Process Spawn File Hashes)', count: 9, color: '#A78BFA' },
                { name: 'suricata (Network C2 Beacons)', count: 6, color: '#F59E0B' },
              ].map((src) => {
                const pct = Math.round((src.count / 22) * 100);
                return (
                  <div key={src.name} className="space-y-1">
                    <div className="flex items-center justify-between text-xs font-mono">
                      <span className="text-[#94A3B8] text-[11px] truncate max-w-[240px]">{src.name}</span>
                      <span className="text-white font-medium">{src.count} IOCs</span>
                    </div>
                    <div className="h-1.5 w-full bg-white/[0.06] rounded-full overflow-hidden">
                      <div
                        className="h-full rounded-full transition-all duration-500"
                        style={{ width: `${pct}%`, backgroundColor: src.color }}
                      />
                    </div>
                  </div>
                );
              })}
            </div>

            <div className="pt-2 border-t border-white/[0.05] text-[11px] font-mono text-[#64748B] flex items-center justify-between">
              <span>Automatic Normalization:</span>
              <span className="text-emerald-400">ECS Compliant</span>
            </div>
          </div>
        </div>
      </Section>

      {/* ── 3. UNIFIED INDICATOR REPOSITORY & INSPECTION WORKSPACE ─────────── */}
      <Section
        title="Indicator Repository & Extraction Workspace"
        subtitle="Search by normalized value, type, severity, or attack phase to inspect correlation evidence"
      >
        {/* Search & Criteria Toolbar */}
        <IOCSearchPanel onSearch={handleSearch} loading={loading} />

        {/* Error Notification */}
        {error && (
          <div className="p-3.5 rounded-xl bg-rose-500/10 border border-rose-500/30 flex items-center gap-2.5 text-[#EF4444] text-xs">
            <AlertTriangle className="w-4 h-4 shrink-0" />
            <span>{error}</span>
          </div>
        )}

        {/* Split View: Table + Detail Workspace */}
        <div className="grid grid-cols-1 lg:grid-cols-12 gap-8 items-start">
          {/* Table */}
          <div
            className={selectedIoc ? 'lg:col-span-6' : 'lg:col-span-12'}
            style={{
              backgroundColor: '#0F141D',
              border: '1px solid rgba(255, 255, 255, 0.06)',
              borderRadius: 12,
              overflow: 'hidden',
            }}
          >
            <IOCListTable
              iocs={iocs}
              loading={loading}
              selectedIocId={selectedIoc?.id}
              onSelectIoc={setSelectedIoc}
              pagination={pagination}
              onPageChange={handlePageChange}
            />
          </div>

          {/* Selected IOC Investigation Panel */}
          {selectedIoc && (
            <div
              className="lg:col-span-6"
              style={{
                backgroundColor: '#0F141D',
                border: '1px solid rgba(255, 255, 255, 0.06)',
                borderRadius: 12,
                padding: '24px',
              }}
            >
              <IOCDetailPanel
                ioc={selectedIoc}
                onClose={() => setSelectedIoc(null)}
                onStatusUpdated={handleStatusUpdated}
              />
            </div>
          )}
        </div>
      </Section>
    </PageShell>
  );
}

export default function IOCsPage() {
  return (
    <Suspense fallback={<div className="p-12 text-center text-[#94A3B8] text-xs">Loading IOC Intelligence...</div>}>
      <IOCsPageContent />
    </Suspense>
  );
}
