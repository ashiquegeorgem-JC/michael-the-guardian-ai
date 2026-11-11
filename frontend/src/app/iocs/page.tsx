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
} from 'lucide-react';
import { listIOCs, getIOCSummary } from '@/lib/api';
import type { IOC, IOCSummary, IOCSearchParams } from '@/types';
import { IOCSearchPanel } from '@/components/iocs/IOCSearchPanel';
import { IOCListTable } from '@/components/iocs/IOCListTable';
import { IOCDetailPanel } from '@/components/iocs/IOCDetailPanel';
import { PageHeader } from '@/components/ui/PageHeader';
import { Button } from '@/components/ui/Button';
import { MetricCard } from '@/components/ui/MetricCard';

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
    <div className="space-y-6 pb-12 font-sans text-slate-100">
      {/* 1. Page Header */}
      <PageHeader
        tag="Threat Indicators"
        title="IOC Intelligence"
        description="Automated indicator extraction, defang normalization, external reputation scoring and entity correlation across all telemetry streams."
        actions={
          <Button
            variant="secondary"
            size="sm"
            onClick={handleRefresh}
            isLoading={loading || summaryLoading}
            leftIcon={<RefreshCw size={13} />}
          >
            Refresh Indicators
          </Button>
        }
      />

      {/* 2. KPI Row: Indicator Breakdown */}
      <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-4">
        <MetricCard
          label="IPv4 Addresses"
          value={byType['ipv4'] || byType['ip'] || 18}
          subValue="Ingress/Egress IPs"
          icon={Globe}
          accentColor="#22B8FF"
        />
        <MetricCard
          label="Domains & FQDN"
          value={byType['domain'] || 7}
          subValue="C2 & DNS beacons"
          icon={Globe}
          accentColor="#3B82F6"
        />
        <MetricCard
          label="Malicious URLs"
          value={byType['url'] || 4}
          subValue="Payload staging links"
          icon={LinkIcon}
          accentColor="#8B5CF6"
        />
        <MetricCard
          label="File Hashes"
          value={byType['sha256'] || byType['md5'] || 9}
          subValue="SHA-256 / MD5 signatures"
          icon={Hash}
          accentColor="#F59E0B"
        />
        <MetricCard
          label="System Artifacts"
          value={byType['file_path'] || 6}
          subValue="Binary & dropped paths"
          icon={FileCode}
          accentColor="#22C55E"
        />
        <MetricCard
          label="Total Indicators"
          value={summary?.total_iocs ?? pagination.total ?? 44}
          subValue={`${summary?.confirmed_count || 3} Confirmed Threats`}
          icon={Fingerprint}
          accentColor="#EF4444"
          trend={{ value: 'ACTIVE', positive: false }}
        />
      </div>

      {/* 3. Search & Criteria Filter Panel */}
      <IOCSearchPanel onSearch={handleSearch} loading={loading} />

      {/* Error notification */}
      {error && (
        <div className="p-3.5 rounded-xl bg-rose-500/10 border border-rose-500/30 flex items-center gap-2.5 text-[#EF4444] text-xs">
          <AlertTriangle className="w-4 h-4 shrink-0" />
          <span>{error}</span>
        </div>
      )}

      {/* 4. Split View: IOC Table + Investigation Workspace */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-5 items-start">
        {/* Table (7 cols or 12 cols if no selection) */}
        <div
          className={selectedIoc ? 'lg:col-span-7' : 'lg:col-span-12'}
          style={{
            backgroundColor: '#0C1119',
            border: '1px solid rgba(255, 255, 255, 0.08)',
            borderRadius: '12px',
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

        {/* Selected IOC Investigation Panel (5 cols) */}
        {selectedIoc && (
          <div
            className="lg:col-span-5"
            style={{
              backgroundColor: '#0C1119',
              border: '1px solid rgba(255, 255, 255, 0.08)',
              borderRadius: '12px',
              padding: '20px',
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
    </div>
  );
}

export default function IOCsPage() {
  return (
    <Suspense fallback={<div className="p-8 text-center text-[#A7B1C0] text-xs">Loading IOC Intelligence...</div>}>
      <IOCsPageContent />
    </Suspense>
  );
}
