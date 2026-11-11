'use client';

import { useState, useEffect, useCallback } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import {
  GitFork, RefreshCw, Shield, Filter, ChevronDown,
  Network, Clock, BarChart3, AlertTriangle, Info,
  Link2, CheckSquare, Search, Eye, SlidersHorizontal,
} from 'lucide-react';
import { getAttackChains, getAttackChainSummary } from '@/lib/api';
import type { AttackChain, AttackStage, ChainSummary, ChainLinkEvent, ChainStatus } from '@/types';
import { AttackGraph } from '@/components/attack-chains/AttackGraph';
import { AttackTimeline } from '@/components/attack-chains/AttackTimeline';
import { ForensicInvestigationPanel } from '@/components/attack-chains/ForensicInvestigationPanel';
import { AttackChainSummaryAnalytics } from '@/components/attack-chains/AttackChainSummaryAnalytics';
import { ChainSearchPanel } from '@/components/attack-chains/ChainSearchPanel';
import { EventConfirmationModal } from '@/components/attack-chains/EventConfirmationModal';
import { RelatedEntitiesPanel } from '@/components/attack-chains/RelatedEntitiesPanel';
import { PageHeader } from '@/components/ui/PageHeader';
import { Button } from '@/components/ui/Button';
import { Badge } from '@/components/ui/Badge';
import { EmptyState } from '@/components/ui/EmptyState';

const SEV_OPTIONS = ['ALL', 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW'];
const VIEW_TABS = ['Forensic Panels', 'Attack Graph', 'Timeline', 'Correlated Entities'] as const;
type ViewTab = typeof VIEW_TABS[number];

export default function AttackChainsPage() {
  const [chains, setChains] = useState<AttackChain[]>([]);
  const [summary, setSummary] = useState<ChainSummary | null>(null);
  const [loading, setLoading] = useState(false);
  const [summaryLoading, setSummaryLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [severityFilter, setSeverityFilter] = useState('ALL');
  const [expandedId, setExpandedId] = useState<string | null>(null);
  const [selectedChainId, setSelectedChainId] = useState<string | null>(null);
  const [activeTab, setActiveTab] = useState<ViewTab>('Forensic Panels');
  const [showFilter, setShowFilter] = useState(false);
  const [showAnalytics, setShowAnalytics] = useState(true);

  // Event Confirmation state
  const [confirmingEvent, setConfirmingEvent] = useState<ChainLinkEvent | null>(null);
  const [isConfirmModalOpen, setIsConfirmModalOpen] = useState(false);

  const loadChains = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const data = await getAttackChains({
        severity: severityFilter !== 'ALL' ? severityFilter : undefined,
      });
      setChains(data);
      if (data.length > 0 && !selectedChainId) {
        setSelectedChainId(data[0].id);
        setExpandedId(data[0].id);
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to fetch attack chains.');
    } finally {
      setLoading(false);
    }
  }, [severityFilter, selectedChainId]);

  const loadSummary = useCallback(async () => {
    setSummaryLoading(true);
    try {
      const data = await getAttackChainSummary();
      setSummary(data);
    } catch {
      // Non-critical: analytics dashboard degrades gracefully
    } finally {
      setSummaryLoading(false);
    }
  }, []);

  useEffect(() => {
    loadChains();
    loadSummary();
  }, [loadChains, loadSummary]);

  const handleSelectFromSearch = (chain: AttackChain) => {
    setSelectedChainId(chain.id);
    setExpandedId(chain.id);
    setChains(prev => {
      const exists = prev.some(c => c.id === chain.id);
      return exists ? prev : [chain, ...prev];
    });
  };

  const selectedChain = chains.find(c => c.id === selectedChainId) || chains[0] || null;

  return (
    <div className="space-y-6 pb-12 font-sans text-slate-100">
      {/* 1. Page Header */}
      <PageHeader
        tag="Adversary Progression"
        title="Attack Chains"
        description="MITRE ATT&CK multi-stage adversary progression reconstruction, temporal correlation, and evidence graphs."
        actions={
          <div className="flex items-center gap-2.5">
            <Button
              variant="secondary"
              size="sm"
              onClick={() => setShowAnalytics(!showAnalytics)}
              leftIcon={<BarChart3 size={13} />}
            >
              {showAnalytics ? 'Hide Analytics' : 'Show Analytics'}
            </Button>

            <Button
              variant="secondary"
              size="sm"
              onClick={() => {
                loadChains();
                loadSummary();
              }}
              isLoading={loading}
              leftIcon={<RefreshCw size={13} />}
            >
              Refresh
            </Button>
          </div>
        }
      />

      {/* 2. Summary Analytics Dashboard */}
      {showAnalytics && (
        <AttackChainSummaryAnalytics
          summary={summary}
          loading={summaryLoading}
          onSelectChain={(id) => {
            setSelectedChainId(id);
            setExpandedId(id);
          }}
        />
      )}

      {/* 3. Advanced Multi-Criteria Search Panel */}
      <ChainSearchPanel
        onSelectChain={handleSelectFromSearch}
        selectedChainId={selectedChainId}
        onClearSearch={loadChains}
      />

      {/* Error Banner */}
      {error && (
        <div className="flex items-center gap-2 p-4 rounded-xl bg-rose-500/10 border border-rose-500/30 text-[#EF4444] text-xs">
          <AlertTriangle size={14} />
          <span>{error}</span>
        </div>
      )}

      {/* Empty State */}
      {!loading && chains.length === 0 && !error && (
        <EmptyState
          title="No Attack Chains Reconstructed"
          description="Upload server logs and trigger analysis to detect anomalous multi-stage kill chains."
        />
      )}

      {/* Main SOC Workspace */}
      {chains.length > 0 && (
        <div className="grid grid-cols-1 lg:grid-cols-12 gap-5 items-start">
          {/* Left Sidebar: Attack Chain Selector List (4 cols) */}
          <div className="lg:col-span-4 flex flex-col gap-2.5">
            <div className="flex justify-between items-center px-1 mb-1 text-xs">
              <span className="text-[#A7B1C0] font-medium uppercase tracking-wider">
                {chains.length} Active Chain{chains.length !== 1 ? 's' : ''}
              </span>
              <span className="text-[#687589]">Click to inspect</span>
            </div>

            <div className="space-y-2 max-h-[750px] overflow-y-auto pr-1">
              {chains.map((chain) => {
                const isSelected = selectedChainId === chain.id;
                return (
                  <div
                    key={chain.id}
                    onClick={() => {
                      setSelectedChainId(chain.id);
                      setExpandedId(chain.id);
                    }}
                    style={{
                      backgroundColor: isSelected ? '#111823' : '#0C1119',
                      border: isSelected
                        ? '1px solid rgba(59, 130, 246, 0.4)'
                        : '1px solid rgba(255, 255, 255, 0.08)',
                      borderRadius: '12px',
                      padding: '14px',
                    }}
                    className="cursor-pointer transition-all hover:border-white/20 space-y-2"
                  >
                    <div className="flex items-center justify-between">
                      <div className="flex items-center gap-1.5">
                        <Badge variant={chain.severity} size="sm">
                          {chain.severity}
                        </Badge>
                        <Badge variant="default" size="sm">
                          {chain.status || 'NEW'}
                        </Badge>
                      </div>
                      <span className="font-mono text-[10px] text-[#A7B1C0]">
                        {chain.events.length} events
                      </span>
                    </div>

                    <h4 className="text-xs font-semibold text-[#F5F7FA] line-clamp-2 leading-relaxed">
                      {chain.title}
                    </h4>

                    <div className="flex flex-wrap gap-1 pt-1">
                      {chain.stages_observed.slice(0, 3).map((s) => (
                        <span
                          key={s}
                          className="text-[10px] text-[#A7B1C0] bg-white/[0.04] px-1.5 py-0.5 rounded border border-white/[0.04]"
                        >
                          {s}
                        </span>
                      ))}
                      {chain.stages_observed.length > 3 && (
                        <span className="text-[10px] text-[#687589]">
                          +{chain.stages_observed.length - 3}
                        </span>
                      )}
                    </div>
                  </div>
                );
              })}
            </div>
          </div>

          {/* Right Workspace (8 cols) */}
          <div className="lg:col-span-8 space-y-4">
            {selectedChain && (
              <div
                style={{
                  backgroundColor: '#0C1119',
                  border: '1px solid rgba(255, 255, 255, 0.08)',
                  borderRadius: '12px',
                  padding: '20px',
                }}
                className="space-y-4"
              >
                {/* View Tabs */}
                <div className="flex items-center gap-1 border-b border-white/[0.06] pb-2 text-xs">
                  {VIEW_TABS.map((tab) => (
                    <button
                      key={tab}
                      onClick={() => setActiveTab(tab)}
                      className={`px-3 py-1.5 rounded-lg font-medium transition-all cursor-pointer flex items-center gap-1.5 ${
                        activeTab === tab
                          ? 'bg-[#111823] text-[#3B82F6] border border-blue-500/30'
                          : 'text-[#A7B1C0] hover:text-white'
                      }`}
                    >
                      {tab === 'Forensic Panels' && <Shield size={13} />}
                      {tab === 'Attack Graph' && <Network size={13} />}
                      {tab === 'Timeline' && <Clock size={13} />}
                      {tab === 'Correlated Entities' && <Link2 size={13} />}
                      <span>{tab}</span>
                    </button>
                  ))}
                </div>

                {/* Tab: Forensic Panels */}
                {activeTab === 'Forensic Panels' && (
                  <ForensicInvestigationPanel
                    chain={selectedChain}
                    onStatusUpdate={() => {
                      loadChains();
                      loadSummary();
                    }}
                    onEventConfirm={(evt: any) => {
                      setConfirmingEvent(evt);
                      setIsConfirmModalOpen(true);
                    }}
                  />
                )}

                {/* Tab: Attack Graph */}
                {activeTab === 'Attack Graph' && (
                  <div>
                    {selectedChain.graph_data ? (
                      <AttackGraph data={selectedChain.graph_data} />
                    ) : (
                      <div className="p-8 text-center text-[#687589] text-xs">
                        No graph topological data computed for this chain.
                      </div>
                    )}
                  </div>
                )}

                {/* Tab: Timeline */}
                {activeTab === 'Timeline' && (
                  <div className="p-4 bg-[#080C12] rounded-xl border border-white/[0.04]">
                    <AttackTimeline
                      events={selectedChain.events}
                      onConfirmEvent={(evt) => {
                        setConfirmingEvent(evt);
                        setIsConfirmModalOpen(true);
                      }}
                    />
                  </div>
                )}

                {/* Tab: Correlated Entities */}
                {activeTab === 'Correlated Entities' && (
                  <RelatedEntitiesPanel chain={selectedChain} />
                )}
              </div>
            )}
          </div>
        </div>
      )}

      {/* Confirmation Modal */}
      {isConfirmModalOpen && confirmingEvent && selectedChain && (
        <EventConfirmationModal
          event={confirmingEvent}
          chainId={selectedChain.id}
          isOpen={isConfirmModalOpen}
          onClose={() => {
            setIsConfirmModalOpen(false);
            setConfirmingEvent(null);
          }}
          onSuccess={() => {
            loadChains();
            loadSummary();
          }}
        />
      )}
    </div>
  );
}
