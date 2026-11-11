'use client';

import React, { useState, useEffect, useCallback, Suspense, useMemo } from 'react';
import { useSearchParams } from 'next/navigation';
import {
  Radar,
  RefreshCw,
  AlertTriangle,
  Eye,
} from 'lucide-react';
import { listIOCs, getIOCSummary } from '@/lib/api';
import type { IOC, IOCSummary, IOCSearchParams } from '@/types';
import { ThreatIntelligenceMetrics } from '@/components/threat-intelligence/ThreatIntelligenceMetrics';
import { ThreatIntelFilters, ThreatFilterState } from '@/components/threat-intelligence/ThreatIntelFilters';
import { IOCThreatTable } from '@/components/threat-intelligence/IOCThreatTable';
import { UnifiedThreatContextPanel } from '@/components/threat-intelligence/UnifiedThreatContextPanel';
import { PageHeader } from '@/components/ui/PageHeader';
import { Button } from '@/components/ui/Button';
import { EmptyState } from '@/components/ui/EmptyState';

function ThreatIntelligencePageContent() {
  const searchParams = useSearchParams();
  const [iocs, setIocs] = useState<IOC[]>([]);
  const [summary, setSummary] = useState<IOCSummary | null>(null);
  const [loading, setLoading] = useState(false);
  const [summaryLoading, setSummaryLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [selectedIoc, setSelectedIoc] = useState<IOC | null>(null);

  const [filters, setFilters] = useState<ThreatFilterState>({
    search: searchParams.get('search') || '',
    ioc_type: searchParams.get('ioc_type') || '',
    threat_status: searchParams.get('threat_status') || '',
    analyst_status: searchParams.get('status') || '',
    severity: searchParams.get('severity') || '',
    confirmed_only: false,
  });

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

  const loadIOCs = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const params: IOCSearchParams = {
        page: 1,
        page_size: 100,
        ioc_type: filters.ioc_type || undefined,
        status: filters.analyst_status || undefined,
      };
      const res = await listIOCs(params);
      setIocs(res.items);

      const targetId = searchParams.get('ioc_id');
      if (targetId) {
        const found = res.items.find((i) => i.id === targetId);
        if (found) setSelectedIoc(found);
      } else if (res.items.length > 0 && !selectedIoc) {
        setSelectedIoc(res.items[0]);
      }
    } catch (e: unknown) {
      setError((e as Error).message || 'Failed to load threat intelligence indicators.');
    } finally {
      setLoading(false);
    }
  }, [filters.ioc_type, filters.analyst_status, searchParams, selectedIoc]);

  useEffect(() => {
    loadSummary();
    loadIOCs();
  }, [loadSummary, loadIOCs]);

  const filteredIOCs = useMemo(() => {
    return iocs.filter((ioc) => {
      if (filters.search) {
        const term = filters.search.toLowerCase();
        const matchesVal = ioc.normalized_value.toLowerCase().includes(term);
        const matchesRaw = ioc.raw_value.toLowerCase().includes(term);
        const matchesType = ioc.ioc_type.toLowerCase().includes(term);
        if (!matchesVal && !matchesRaw && !matchesType) return false;
      }
      if (filters.confirmed_only) {
        if (ioc.status !== 'CONFIRMED') return false;
      }
      return true;
    });
  }, [iocs, filters.search, filters.confirmed_only]);

  const handleRefresh = () => {
    loadSummary();
    loadIOCs();
  };

  const handleResetFilters = () => {
    setFilters({
      search: '',
      ioc_type: '',
      threat_status: '',
      analyst_status: '',
      severity: '',
      confirmed_only: false,
    });
  };

  return (
    <div className="space-y-6 pb-12 font-sans text-slate-100">
      {/* 1. Page Header */}
      <PageHeader
        tag="Enriched Intelligence"
        title="Threat Intelligence"
        description="Reputation scoring, external provider signals, multi-entity threat correlation, and timeline forensics across all indicators."
        actions={
          <Button
            variant="secondary"
            size="sm"
            onClick={handleRefresh}
            isLoading={loading || summaryLoading}
            leftIcon={<RefreshCw size={13} />}
          >
            Refresh Telemetry
          </Button>
        }
      />

      {/* 2. Top Threat Overview & KPI Cards */}
      <ThreatIntelligenceMetrics summary={summary} loading={summaryLoading} />

      {/* 3. Filter Bar */}
      <ThreatIntelFilters
        filters={filters}
        onChange={setFilters}
        onReset={handleResetFilters}
        loading={loading}
      />

      {/* Error Alert */}
      {error && (
        <div className="p-3.5 rounded-xl bg-rose-500/10 border border-rose-500/30 flex items-center gap-2.5 text-[#EF4444] text-xs">
          <AlertTriangle className="w-4 h-4 shrink-0" />
          <span>{error}</span>
        </div>
      )}

      {/* 4. Main Two-Column SOC Platform View */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-5 items-start">
        {/* Left Column (5 cols on lg): Indicators List Table */}
        <div
          className="lg:col-span-5 rounded-xl overflow-hidden"
          style={{
            backgroundColor: '#0C1119',
            border: '1px solid rgba(255, 255, 255, 0.08)',
            boxShadow: '0 4px 16px rgba(0, 0, 0, 0.35)',
          }}
        >
          <div
            className="p-3.5 flex items-center justify-between border-b border-white/[0.06]"
            style={{ backgroundColor: '#080C12' }}
          >
            <div className="flex items-center gap-2">
              <Eye size={14} className="text-[#3B82F6]" />
              <span className="font-semibold text-xs text-[#F5F7FA]">
                Threat Indicators ({filteredIOCs.length})
              </span>
            </div>
            {filters.confirmed_only && (
              <span className="text-[10px] text-[#EF4444] bg-rose-500/10 border border-rose-500/25 px-2 py-0.5 rounded-full font-medium">
                Confirmed Only
              </span>
            )}
          </div>

          <IOCThreatTable
            iocs={filteredIOCs}
            selectedId={selectedIoc?.id ?? null}
            onSelect={setSelectedIoc}
            loading={loading}
          />
        </div>

        {/* Right Column (7 cols on lg): Unified Threat Context Panel */}
        <div className="lg:col-span-7 sticky top-4">
          {selectedIoc ? (
            <UnifiedThreatContextPanel
              ioc={selectedIoc}
              onClose={() => setSelectedIoc(null)}
            />
          ) : (
            <EmptyState
              icon={Eye}
              title="Select an Indicator to Investigate"
              description="Enriched reputation scores, provider signals, and correlation graphs will appear here when an indicator is selected."
            />
          )}
        </div>
      </div>
    </div>
  );
}

export default function ThreatIntelligencePage() {
  return (
    <Suspense fallback={<div className="p-12 text-center text-[#A7B1C0] text-xs">Loading Threat Intelligence Platform...</div>}>
      <ThreatIntelligencePageContent />
    </Suspense>
  );
}
