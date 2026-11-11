'use client';

import React, { useState } from 'react';
import Link from 'next/link';
import type { UnifiedThreatContext } from '@/types';
import { FileText, AlertTriangle, ShieldAlert, GitFork, ExternalLink, CheckCircle2, AlertCircle } from 'lucide-react';

interface RelatedSecurityObjectsPanelProps {
  context: UnifiedThreatContext;
}

export function RelatedSecurityObjectsPanel({ context }: RelatedSecurityObjectsPanelProps) {
  const [activeTab, setActiveTab] = useState<'events' | 'anomalies' | 'incidents' | 'chains'>('incidents');

  const { related_events, related_anomalies, related_incidents, related_attack_chains } = context;

  return (
    <div
      style={{
        background: 'rgba(13, 20, 36, 0.7)',
        border: '1px solid #1E2D4A',
        borderRadius: 12,
        padding: '16px 20px',
        display: 'flex',
        flexDirection: 'column',
        gap: 14,
      }}
    >
      {/* Tab Switcher */}
      <div style={{ display: 'flex', borderBottom: '1px solid #1E2D4A', gap: 6, paddingBottom: 8, flexWrap: 'wrap' }}>
        <button
          onClick={() => setActiveTab('incidents')}
          style={{
            display: 'flex',
            alignItems: 'center',
            gap: 6,
            padding: '6px 12px',
            borderRadius: 6,
            background: activeTab === 'incidents' ? '#EF444422' : 'transparent',
            border: `1px solid ${activeTab === 'incidents' ? '#EF444466' : 'transparent'}`,
            color: activeTab === 'incidents' ? '#EF4444' : 'var(--text-muted)',
            fontSize: 12,
            fontWeight: 600,
            cursor: 'pointer',
          }}
        >
          <ShieldAlert size={13} />
          Incidents ({related_incidents.length})
        </button>

        <button
          onClick={() => setActiveTab('chains')}
          style={{
            display: 'flex',
            alignItems: 'center',
            gap: 6,
            padding: '6px 12px',
            borderRadius: 6,
            background: activeTab === 'chains' ? '#8B5CF622' : 'transparent',
            border: `1px solid ${activeTab === 'chains' ? '#8B5CF666' : 'transparent'}`,
            color: activeTab === 'chains' ? '#A78BFA' : 'var(--text-muted)',
            fontSize: 12,
            fontWeight: 600,
            cursor: 'pointer',
          }}
        >
          <GitFork size={13} />
          Attack Chains ({related_attack_chains.length})
        </button>

        <button
          onClick={() => setActiveTab('anomalies')}
          style={{
            display: 'flex',
            alignItems: 'center',
            gap: 6,
            padding: '6px 12px',
            borderRadius: 6,
            background: activeTab === 'anomalies' ? '#F59E0B22' : 'transparent',
            border: `1px solid ${activeTab === 'anomalies' ? '#F59E0B66' : 'transparent'}`,
            color: activeTab === 'anomalies' ? '#F59E0B' : 'var(--text-muted)',
            fontSize: 12,
            fontWeight: 600,
            cursor: 'pointer',
          }}
        >
          <AlertTriangle size={13} />
          Anomalies ({related_anomalies.length})
        </button>

        <button
          onClick={() => setActiveTab('events')}
          style={{
            display: 'flex',
            alignItems: 'center',
            gap: 6,
            padding: '6px 12px',
            borderRadius: 6,
            background: activeTab === 'events' ? '#06B6D422' : 'transparent',
            border: `1px solid ${activeTab === 'events' ? '#06B6D466' : 'transparent'}`,
            color: activeTab === 'events' ? '#22D3EE' : 'var(--text-muted)',
            fontSize: 12,
            fontWeight: 600,
            cursor: 'pointer',
          }}
        >
          <FileText size={13} />
          Log Events ({related_events.length})
        </button>
      </div>

      {/* Tab Content */}
      <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
        {/* Incidents */}
        {activeTab === 'incidents' && (
          related_incidents.length === 0 ? (
            <div style={{ color: 'var(--text-muted)', fontSize: 12, padding: '12px 0' }}>No incidents correlated with this IOC.</div>
          ) : (
            related_incidents.map((inc) => (
              <div
                key={inc.incident_id}
                style={{
                  background: 'rgba(10, 14, 26, 0.8)',
                  border: '1px solid #1A253C',
                  borderRadius: 8,
                  padding: '12px 14px',
                  display: 'flex',
                  flexDirection: 'column',
                  gap: 6,
                }}
              >
                <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                    <ShieldAlert size={14} color="#EF4444" />
                    <span style={{ fontSize: 12, fontWeight: 700, fontFamily: 'var(--font-mono)', color: '#F8FAFC' }}>
                      {inc.incident_id}
                    </span>
                  </div>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                    <span
                      style={{
                        fontSize: 10,
                        fontWeight: 700,
                        padding: '1px 6px',
                        borderRadius: 4,
                        background: inc.confirmed ? 'rgba(16, 185, 129, 0.15)' : 'rgba(148, 163, 184, 0.15)',
                        color: inc.confirmed ? '#10B981' : '#94A3B8',
                      }}
                    >
                      {inc.confirmed ? 'CONFIRMED' : 'UNCONFIRMED'} ({(inc.confidence * 100).toFixed(0)}% conf)
                    </span>
                    <Link
                      href={`/incidents`}
                      style={{
                        display: 'flex',
                        alignItems: 'center',
                        gap: 3,
                        color: '#38BDF8',
                        fontSize: 11,
                        textDecoration: 'none',
                      }}
                    >
                      Investigate <ExternalLink size={11} />
                    </Link>
                  </div>
                </div>
                <div style={{ fontSize: 11, color: 'var(--text-muted)', lineHeight: 1.4 }}>
                  {inc.evidence[0] || 'Correlated via anomaly incident bridge'}
                </div>
              </div>
            ))
          )
        )}

        {/* Attack Chains */}
        {activeTab === 'chains' && (
          related_attack_chains.length === 0 ? (
            <div style={{ color: 'var(--text-muted)', fontSize: 12, padding: '12px 0' }}>No attack chains correlated with this IOC.</div>
          ) : (
            related_attack_chains.map((chain) => (
              <div
                key={chain.chain_id}
                style={{
                  background: 'rgba(10, 14, 26, 0.8)',
                  border: '1px solid #1A253C',
                  borderRadius: 8,
                  padding: '12px 14px',
                  display: 'flex',
                  flexDirection: 'column',
                  gap: 6,
                }}
              >
                <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                    <GitFork size={14} color="#8B5CF6" />
                    <span style={{ fontSize: 12, fontWeight: 700, fontFamily: 'var(--font-mono)', color: '#F8FAFC' }}>
                      {chain.chain_id}
                    </span>
                  </div>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                    <span
                      style={{
                        fontSize: 10,
                        fontWeight: 700,
                        padding: '1px 6px',
                        borderRadius: 4,
                        background: chain.confirmed ? 'rgba(16, 185, 129, 0.15)' : 'rgba(148, 163, 184, 0.15)',
                        color: chain.confirmed ? '#10B981' : '#94A3B8',
                      }}
                    >
                      {chain.confirmed ? 'CONFIRMED' : 'UNCONFIRMED'} ({(chain.confidence * 100).toFixed(0)}% conf)
                    </span>
                    <Link
                      href={`/attack-chains?chain_id=${chain.chain_id}`}
                      style={{
                        display: 'flex',
                        alignItems: 'center',
                        gap: 3,
                        color: '#A78BFA',
                        fontSize: 11,
                        textDecoration: 'none',
                      }}
                    >
                      Open Chain <ExternalLink size={11} />
                    </Link>
                  </div>
                </div>
                <div style={{ fontSize: 11, color: 'var(--text-muted)', lineHeight: 1.4 }}>
                  {chain.evidence[0] || 'Correlated via chain events or forensic entity'}
                </div>
              </div>
            ))
          )
        )}

        {/* Anomalies */}
        {activeTab === 'anomalies' && (
          related_anomalies.length === 0 ? (
            <div style={{ color: 'var(--text-muted)', fontSize: 12, padding: '12px 0' }}>No anomalies correlated with this IOC.</div>
          ) : (
            related_anomalies.map((anom) => (
              <div
                key={anom.anomaly_id}
                style={{
                  background: 'rgba(10, 14, 26, 0.8)',
                  border: '1px solid #1A253C',
                  borderRadius: 8,
                  padding: '12px 14px',
                  display: 'flex',
                  flexDirection: 'column',
                  gap: 6,
                }}
              >
                <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                    <AlertTriangle size={14} color="#F59E0B" />
                    <span style={{ fontSize: 12, fontWeight: 700, fontFamily: 'var(--font-mono)', color: '#F8FAFC' }}>
                      {anom.anomaly_id}
                    </span>
                  </div>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                    <span
                      style={{
                        fontSize: 10,
                        fontWeight: 700,
                        padding: '1px 6px',
                        borderRadius: 4,
                        background: anom.confirmed ? 'rgba(16, 185, 129, 0.15)' : 'rgba(148, 163, 184, 0.15)',
                        color: anom.confirmed ? '#10B981' : '#94A3B8',
                      }}
                    >
                      {anom.confirmed ? 'CONFIRMED' : 'UNCONFIRMED'} ({(anom.confidence * 100).toFixed(0)}% conf)
                    </span>
                    <Link
                      href={`/anomalies`}
                      style={{
                        display: 'flex',
                        alignItems: 'center',
                        gap: 3,
                        color: '#FBBF24',
                        fontSize: 11,
                        textDecoration: 'none',
                      }}
                    >
                      View Anomalies <ExternalLink size={11} />
                    </Link>
                  </div>
                </div>
                <div style={{ fontSize: 11, color: 'var(--text-muted)', lineHeight: 1.4 }}>
                  {anom.evidence[0] || 'Correlated via shared events'}
                </div>
              </div>
            ))
          )
        )}

        {/* Events */}
        {activeTab === 'events' && (
          related_events.length === 0 ? (
            <div style={{ color: 'var(--text-muted)', fontSize: 12, padding: '12px 0' }}>No log events extracted for this IOC.</div>
          ) : (
            related_events.map((ev) => (
              <div
                key={ev.event_id}
                style={{
                  background: 'rgba(10, 14, 26, 0.8)',
                  border: '1px solid #1A253C',
                  borderRadius: 8,
                  padding: '12px 14px',
                  display: 'flex',
                  flexDirection: 'column',
                  gap: 6,
                }}
              >
                <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                    <FileText size={14} color="#06B6D4" />
                    <span style={{ fontSize: 12, fontWeight: 700, fontFamily: 'var(--font-mono)', color: '#F8FAFC' }}>
                      Event: {ev.event_id}
                    </span>
                  </div>
                  <Link
                    href={`/logs`}
                    style={{
                      display: 'flex',
                      alignItems: 'center',
                      gap: 3,
                      color: '#22D3EE',
                      fontSize: 11,
                      textDecoration: 'none',
                    }}
                  >
                    Open Logs <ExternalLink size={11} />
                  </Link>
                </div>
                <div style={{ fontSize: 11, color: 'var(--text-muted)', lineHeight: 1.4 }}>
                  {ev.evidence[0] || 'Direct extraction from raw log line'}
                </div>
                {ev.evidence[1] && (
                  <div style={{ fontSize: 10, color: 'var(--text-muted)', fontFamily: 'var(--font-mono)' }}>
                    {ev.evidence[1]}
                  </div>
                )}
              </div>
            ))
          )
        )}
      </div>
    </div>
  );
}

