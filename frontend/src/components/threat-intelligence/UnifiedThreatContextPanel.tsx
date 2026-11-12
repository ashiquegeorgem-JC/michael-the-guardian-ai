'use client';

import React, { useState, useEffect } from 'react';
import type { IOC, UnifiedThreatContext } from '@/types';
import { getUnifiedThreatContext } from '@/lib/api';
import { ThreatAssessmentCard } from './ThreatAssessmentCard';
import { ThreatSignalsPanel } from './ThreatSignalsPanel';
import { ProviderFindingsPanel } from './ProviderFindingsPanel';
import { ThreatCorrelationGraph } from './ThreatCorrelationGraph';
import { ThreatCorrelationTimeline } from './ThreatCorrelationTimeline';
import { RelatedSecurityObjectsPanel } from './RelatedSecurityObjectsPanel';
import {
  X, RefreshCw, ShieldCheck, Server, GitFork, Clock,
  Layers, AlertTriangle, ExternalLink, ShieldAlert
} from 'lucide-react';

interface UnifiedThreatContextPanelProps {
  ioc: IOC;
  onClose: () => void;
}

export function UnifiedThreatContextPanel({ ioc, onClose }: UnifiedThreatContextPanelProps) {
  const [context, setContext] = useState<UnifiedThreatContext | null>(null);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [activeTab, setActiveTab] = useState<'assessment' | 'provider' | 'correlations' | 'timeline' | 'objects'>('assessment');

  const loadContext = async (forceRefresh = false) => {
    if (forceRefresh) setRefreshing(true);
    else setLoading(true);
    setError(null);

    try {
      const data = await getUnifiedThreatContext(ioc.id, forceRefresh);
      setContext(data);
    } catch (e: unknown) {
      setError((e as Error).message || 'Failed to load threat context.');
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  };

  useEffect(() => {
    loadContext();
  }, [ioc.id]);

  return (
    <div
      style={{
        backgroundColor: '#11161E',
        border: '1px solid rgba(255, 255, 255, 0.08)',
        borderRadius: 16,
        display: 'flex',
        flexDirection: 'column',
        overflow: 'hidden',
        boxShadow: '0 4px 20px rgba(0, 0, 0, 0.35)',
      }}
    >
      {/* Top Header */}
      <div
        style={{
          padding: '16px 20px',
          borderBottom: '1px solid #1E2D4A',
          background: 'rgba(8, 12, 22, 0.8)',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
          flexWrap: 'wrap',
          gap: 12,
        }}
      >
        <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
          <div
            style={{
              width: 36,
              height: 36,
              borderRadius: 10,
              background: 'linear-gradient(135deg, #3B82F6, #7C3AED)',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
            }}
          >
            <ShieldAlert size={18} color="white" />
          </div>
          <div>
            <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
              <span style={{ fontSize: 15, fontWeight: 800, fontFamily: 'var(--font-mono)', color: '#F8FAFC' }}>
                {ioc.normalized_value}
              </span>
              <span
                style={{
                  fontSize: 10,
                  fontWeight: 700,
                  padding: '2px 6px',
                  borderRadius: 4,
                  background: '#1A253C',
                  color: '#94A3B8',
                  textTransform: 'uppercase',
                }}
              >
                {ioc.ioc_type}
              </span>
            </div>
            <div style={{ fontSize: 11, color: 'var(--text-muted)' }}>
              Unified SOC Threat Context &amp; Relationship Engine
            </div>
          </div>
        </div>

        <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
          <button
            type="button"
            onClick={() => loadContext(true)}
            disabled={loading || refreshing}
            style={{
              display: 'flex',
              alignItems: 'center',
              gap: 6,
              padding: '6px 12px',
              borderRadius: 6,
              background: '#0D1424',
              border: '1px solid #1E2D4A',
              color: 'var(--text-secondary)',
              fontSize: 12,
              cursor: 'pointer',
            }}
          >
            <RefreshCw size={13} className={refreshing ? 'animate-spin' : ''} />
            {refreshing ? 'Refreshing...' : 'Refresh Intel'}
          </button>
          <button
            type="button"
            onClick={onClose}
            style={{
              padding: '6px',
              borderRadius: 6,
              background: '#0D1424',
              border: '1px solid #1E2D4A',
              color: 'var(--text-muted)',
              cursor: 'pointer',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
            }}
          >
            <X size={16} />
          </button>
        </div>
      </div>

      {/* Error state */}
      {error && (
        <div
          style={{
            margin: '16px',
            padding: '12px 16px',
            background: 'rgba(239, 68, 68, 0.1)',
            border: '1px solid rgba(239, 68, 68, 0.3)',
            borderRadius: 8,
            color: '#F87171',
            fontSize: 12,
            display: 'flex',
            alignItems: 'center',
            gap: 8,
          }}
        >
          <AlertTriangle size={15} />
          {error}
        </div>
      )}

      {/* Loading state */}
      {loading && (
        <div style={{ padding: '60px 20px', textAlign: 'center', color: 'var(--text-muted)', fontSize: 13 }}>
          <RefreshCw size={24} className="animate-spin" style={{ margin: '0 auto 12px', opacity: 0.6 }} />
          Computing Unified Threat Intelligence Context...
        </div>
      )}

      {/* Context loaded */}
      {!loading && context && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 16, padding: '16px 20px', maxHeight: 'calc(100vh - 180px)', overflowY: 'auto' }}>
          {/* Subsystem Navigation Tabs */}
          <div
            style={{
              display: 'flex',
              borderBottom: '1px solid #1E2D4A',
              gap: 8,
              paddingBottom: 8,
              flexWrap: 'wrap',
            }}
          >
            <button
              onClick={() => setActiveTab('assessment')}
              style={{
                display: 'flex',
                alignItems: 'center',
                gap: 6,
                padding: '6px 14px',
                borderRadius: 6,
                background: activeTab === 'assessment' ? '#3B82F622' : 'transparent',
                border: `1px solid ${activeTab === 'assessment' ? '#3B82F666' : 'transparent'}`,
                color: activeTab === 'assessment' ? '#60A5FA' : 'var(--text-muted)',
                fontSize: 12,
                fontWeight: 600,
                cursor: 'pointer',
              }}
            >
              <ShieldCheck size={14} />
              Threat Assessment &amp; Signals
            </button>

            <button
              onClick={() => setActiveTab('provider')}
              style={{
                display: 'flex',
                alignItems: 'center',
                gap: 6,
                padding: '6px 14px',
                borderRadius: 6,
                background: activeTab === 'provider' ? '#38BDF822' : 'transparent',
                border: `1px solid ${activeTab === 'provider' ? '#38BDF866' : 'transparent'}`,
                color: activeTab === 'provider' ? '#38BDF8' : 'var(--text-muted)',
                fontSize: 12,
                fontWeight: 600,
                cursor: 'pointer',
              }}
            >
              <Server size={14} />
              Provider Findings
            </button>

            <button
              onClick={() => setActiveTab('correlations')}
              style={{
                display: 'flex',
                alignItems: 'center',
                gap: 6,
                padding: '6px 14px',
                borderRadius: 6,
                background: activeTab === 'correlations' ? '#8B5CF622' : 'transparent',
                border: `1px solid ${activeTab === 'correlations' ? '#8B5CF666' : 'transparent'}`,
                color: activeTab === 'correlations' ? '#A78BFA' : 'var(--text-muted)',
                fontSize: 12,
                fontWeight: 600,
                cursor: 'pointer',
              }}
            >
              <GitFork size={14} />
              Correlation Graph ({context.correlations.length})
            </button>

            <button
              onClick={() => setActiveTab('timeline')}
              style={{
                display: 'flex',
                alignItems: 'center',
                gap: 6,
                padding: '6px 14px',
                borderRadius: 6,
                background: activeTab === 'timeline' ? '#10B98122' : 'transparent',
                border: `1px solid ${activeTab === 'timeline' ? '#10B98166' : 'transparent'}`,
                color: activeTab === 'timeline' ? '#34D399' : 'var(--text-muted)',
                fontSize: 12,
                fontWeight: 600,
                cursor: 'pointer',
              }}
            >
              <Clock size={14} />
              Investigation Timeline
            </button>

            <button
              onClick={() => setActiveTab('objects')}
              style={{
                display: 'flex',
                alignItems: 'center',
                gap: 6,
                padding: '6px 14px',
                borderRadius: 6,
                background: activeTab === 'objects' ? '#EF444422' : 'transparent',
                border: `1px solid ${activeTab === 'objects' ? '#EF444466' : 'transparent'}`,
                color: activeTab === 'objects' ? '#F87171' : 'var(--text-muted)',
                fontSize: 12,
                fontWeight: 600,
                cursor: 'pointer',
              }}
            >
              <Layers size={14} />
              Related Security Objects
            </button>
          </div>

          {/* Tab 1: Threat Assessment & Signals */}
          {activeTab === 'assessment' && (
            <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
              <ThreatAssessmentCard
                assessment={context.threat_assessment}
                analystStatus={context.analyst_status}
                correlationConfidence={context.overall_correlation_confidence}
              />
              {context.threat_assessment?.contributing_signals && (
                <ThreatSignalsPanel
                  signals={context.threat_assessment.contributing_signals}
                  threatScore={context.threat_assessment.threat_score}
                />
              )}
            </div>
          )}

          {/* Tab 2: Provider Findings */}
          {activeTab === 'provider' && (
            <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
              <ProviderFindingsPanel result={context.threat_intel_result} />
            </div>
          )}

          {/* Tab 3: Correlation Graph */}
          {activeTab === 'correlations' && (
            <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
              <ThreatCorrelationGraph
                iocValue={context.normalized_value}
                correlations={context.correlations}
              />
            </div>
          )}

          {/* Tab 4: Timeline */}
          {activeTab === 'timeline' && (
            <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
              <ThreatCorrelationTimeline
                correlations={context.correlations}
                assessment={context.threat_assessment}
              />
            </div>
          )}

          {/* Tab 5: Related Objects */}
          {activeTab === 'objects' && (
            <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
              <RelatedSecurityObjectsPanel context={context} />
            </div>
          )}
        </div>
      )}
    </div>
  );
}

