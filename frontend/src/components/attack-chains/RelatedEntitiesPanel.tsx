'use client';

import React, { useState, useEffect } from 'react';
import { motion } from 'framer-motion';
import {
  Network, Users, Server, HardDrive, Link2, AlertTriangle,
  ExternalLink, Shield, CheckCircle, Info, ArrowUpRight, Flame, Target
} from 'lucide-react';
import { getAttackChainRelated } from '@/lib/api';
import type { AttackChain, RelatedEntitiesResponse, RelatedChainLink } from '@/types';

interface Props {
  chain: AttackChain;
  onSelectChain?: (chainId: string) => void;
}

const SEV_COLORS: Record<string, string> = {
  CRITICAL: '#EF4444',
  HIGH:     '#F97316',
  MEDIUM:   '#EAB308',
  LOW:      '#10B981',
};

export function RelatedEntitiesPanel({ chain, onSelectChain }: Props) {
  const [data, setData] = useState<RelatedEntitiesResponse | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [activeTab, setActiveTab] = useState<'chains' | 'entities'>('chains');

  useEffect(() => {
    let isMounted = true;
    setLoading(true);
    setError(null);

    getAttackChainRelated(chain.id)
      .then(res => {
        if (isMounted) setData(res);
      })
      .catch(err => {
        if (isMounted) setError(err.message || 'Failed to fetch related entities');
      })
      .finally(() => {
        if (isMounted) setLoading(false);
      });

    return () => { isMounted = false; };
  }, [chain.id]);

  if (loading) {
    return (
      <div style={{
        background: 'rgba(10,14,26,0.95)',
        border: '1px solid rgba(30,41,59,0.8)',
        borderRadius: 16,
        padding: 32,
        textAlign: 'center',
        color: '#94A3B8',
        fontSize: 13,
      }}>
        <div style={{ width: 24, height: 24, borderRadius: '50%', border: '2px solid #3B82F6', borderTopColor: 'transparent', animation: 'spin 1s linear infinite', margin: '0 auto 12px' }} />
        Correlating forensic entities & cross-session linkages…
      </div>
    );
  }

  if (error) {
    return (
      <div style={{
        background: 'rgba(239,68,68,0.08)',
        border: '1px solid rgba(239,68,68,0.3)',
        borderRadius: 12,
        padding: 16,
        color: '#FCA5A5',
        fontSize: 13,
        display: 'flex',
        alignItems: 'center',
        gap: 8,
      }}>
        <AlertTriangle size={14} />
        {error}
      </div>
    );
  }

  const relatedChains = data?.related_chains || [];
  const relatedIps = data?.related_ips || [];
  const relatedHosts = data?.related_hosts || [];
  const relatedUsers = data?.related_users || [];
  const relatedSessions = data?.related_sessions || [];

  return (
    <div style={{
      background: 'rgba(10,14,26,0.95)',
      border: '1px solid rgba(59,130,246,0.25)',
      borderRadius: 16,
      padding: 24,
      boxShadow: '0 8px 32px rgba(0,0,0,0.4)',
    }}>
      {/* Header */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 20 }}>
        <div>
          <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 4 }}>
            <Network size={16} color="#3B82F6" />
            <h3 style={{ color: '#E2E8F0', fontSize: 15, fontWeight: 700, margin: 0 }}>
              Correlated Entities & Cross-Session Graph
            </h3>
          </div>
          <p style={{ color: '#64748B', fontSize: 11, margin: 0 }}>
            Forensic associations grounded in shared IPs, users, hosts, and multi-session telemetry
          </p>
        </div>

        {/* Tab switch */}
        <div style={{ display: 'flex', background: 'rgba(15,23,42,0.8)', border: '1px solid rgba(30,41,59,0.8)', borderRadius: 8, padding: 3 }}>
          <button
            onClick={() => setActiveTab('chains')}
            style={{
              background: activeTab === 'chains' ? 'rgba(59,130,246,0.2)' : 'transparent',
              border: activeTab === 'chains' ? '1px solid rgba(59,130,246,0.4)' : '1px solid transparent',
              color: activeTab === 'chains' ? '#60A5FA' : '#94A3B8',
              borderRadius: 6,
              padding: '4px 12px',
              fontSize: 12,
              fontWeight: 600,
              cursor: 'pointer',
              display: 'flex',
              alignItems: 'center',
              gap: 5,
            }}
          >
            <Link2 size={12} />
            Related Chains ({relatedChains.length})
          </button>
          <button
            onClick={() => setActiveTab('entities')}
            style={{
              background: activeTab === 'entities' ? 'rgba(59,130,246,0.2)' : 'transparent',
              border: activeTab === 'entities' ? '1px solid rgba(59,130,246,0.4)' : '1px solid transparent',
              color: activeTab === 'entities' ? '#60A5FA' : '#94A3B8',
              borderRadius: 6,
              padding: '4px 12px',
              fontSize: 12,
              fontWeight: 600,
              cursor: 'pointer',
              display: 'flex',
              alignItems: 'center',
              gap: 5,
            }}
          >
            <Users size={12} />
            Forensic Entities ({relatedIps.length + relatedHosts.length + relatedUsers.length})
          </button>
        </div>
      </div>

      {/* Tab: Related Chains */}
      {activeTab === 'chains' && (
        <div>
          {relatedChains.length > 0 ? (
            <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
              {relatedChains.map(link => {
                const sevColor = SEV_COLORS[link.severity] || '#3B82F6';
                return (
                  <div
                    key={link.chain_id}
                    style={{
                      background: 'rgba(15,23,42,0.8)',
                      border: '1px solid rgba(59,130,246,0.3)',
                      borderRadius: 12,
                      padding: 16,
                      boxShadow: '0 4px 16px rgba(0,0,0,0.3)',
                    }}
                  >
                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: 8 }}>
                      <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                        <span style={{
                          background: `${sevColor}18`,
                          border: `1px solid ${sevColor}50`,
                          color: sevColor,
                          fontSize: 10,
                          fontWeight: 800,
                          padding: '2px 8px',
                          borderRadius: 4,
                        }}>
                          {link.severity}
                        </span>
                        <h4 style={{ color: '#F1F5F9', fontSize: 13, fontWeight: 700, margin: 0 }}>
                          {link.title}
                        </h4>
                      </div>

                      <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
                        <span style={{
                          background: 'rgba(234,179,8,0.12)',
                          border: '1px solid rgba(234,179,8,0.3)',
                          color: '#EAB308',
                          fontSize: 10,
                          fontWeight: 700,
                          padding: '2px 8px',
                          borderRadius: 4,
                          textTransform: 'uppercase',
                        }}>
                          Suspected Association ({Math.round(link.confidence * 100)}%)
                        </span>

                        {onSelectChain && (
                          <button
                            onClick={() => onSelectChain(link.chain_id)}
                            style={{
                              background: 'rgba(59,130,246,0.15)',
                              border: '1px solid rgba(59,130,246,0.4)',
                              color: '#60A5FA',
                              borderRadius: 6,
                              padding: '4px 10px',
                              fontSize: 11,
                              fontWeight: 600,
                              cursor: 'pointer',
                              display: 'flex',
                              alignItems: 'center',
                              gap: 4,
                            }}
                          >
                            Open Chain <ArrowUpRight size={12} />
                          </button>
                        )}
                      </div>
                    </div>

                    {/* Shared Signals */}
                    <div style={{ marginBottom: 10 }}>
                      <span style={{ color: '#64748B', fontSize: 11, fontWeight: 600, display: 'block', marginBottom: 4 }}>
                        Corroborating Evidence Signals:
                      </span>
                      <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6 }}>
                        {link.shared_signals.map((sig, sIdx) => (
                          <span
                            key={sIdx}
                            style={{
                              background: 'rgba(30,41,59,0.7)',
                              border: '1px solid rgba(51,65,85,0.7)',
                              color: '#CBD5E1',
                              fontSize: 11,
                              borderRadius: 6,
                              padding: '2px 8px',
                              fontFamily: sig.includes('IP') ? 'monospace' : 'inherit',
                            }}
                          >
                            {sig}
                          </span>
                        ))}
                      </div>
                    </div>

                    {/* Explanation */}
                    <p style={{
                      color: '#94A3B8',
                      fontSize: 11,
                      lineHeight: 1.5,
                      margin: 0,
                      background: 'rgba(10,14,26,0.6)',
                      borderRadius: 6,
                      padding: '8px 10px',
                      borderLeft: '3px solid #3B82F6',
                    }}>
                      {link.correlation_explanation}
                    </p>
                  </div>
                );
              })}
            </div>
          ) : (
            <div style={{
              background: 'rgba(15,23,42,0.5)',
              border: '1px dashed rgba(30,41,59,0.8)',
              borderRadius: 12,
              padding: 24,
              textAlign: 'center',
              color: '#64748B',
              fontSize: 12,
            }}>
              <Info size={18} color="#475569" style={{ margin: '0 auto 8px' }} />
              No cross-session attack chains met the correlation threshold for this chain.
              Chains from different sessions remain isolated unless corroborated by multiple independent signals.
            </div>
          )}
        </div>
      )}

      {/* Tab: Forensic Entities */}
      {activeTab === 'entities' && (
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(240px, 1fr))', gap: 16 }}>
          {/* IPs */}
          <div style={{ background: 'rgba(15,23,42,0.6)', border: '1px solid rgba(30,41,59,0.8)', borderRadius: 10, padding: 14 }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 6, marginBottom: 10, color: '#EF4444', fontSize: 12, fontWeight: 700, textTransform: 'uppercase' }}>
              <Target size={13} /> Origin / Source IPs ({relatedIps.length})
            </div>
            {relatedIps.length > 0 ? (
              <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
                {relatedIps.map((e, idx) => (
                  <div key={idx} style={{ background: 'rgba(10,14,26,0.8)', borderRadius: 6, padding: '6px 10px', border: '1px solid rgba(239,68,68,0.2)' }}>
                    <div style={{ color: '#F1F5F9', fontSize: 12, fontFamily: 'monospace', fontWeight: 600 }}>{e.entity_value}</div>
                    <div style={{ color: '#64748B', fontSize: 10, marginTop: 2 }}>{e.relationship_type.replace(/_/g, ' ')}</div>
                  </div>
                ))}
              </div>
            ) : <span style={{ color: '#475569', fontSize: 11 }}>No IPs recorded</span>}
          </div>

          {/* Targets */}
          <div style={{ background: 'rgba(15,23,42,0.6)', border: '1px solid rgba(30,41,59,0.8)', borderRadius: 10, padding: 14 }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 6, marginBottom: 10, color: '#F97316', fontSize: 12, fontWeight: 700, textTransform: 'uppercase' }}>
              <Server size={13} /> Targeted Systems ({relatedHosts.length})
            </div>
            {relatedHosts.length > 0 ? (
              <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
                {relatedHosts.map((e, idx) => (
                  <div key={idx} style={{ background: 'rgba(10,14,26,0.8)', borderRadius: 6, padding: '6px 10px', border: '1px solid rgba(249,115,22,0.2)' }}>
                    <div style={{ color: '#F1F5F9', fontSize: 12, fontFamily: 'monospace', fontWeight: 600 }}>{e.entity_value}</div>
                    <div style={{ color: '#64748B', fontSize: 10, marginTop: 2 }}>{e.relationship_type.replace(/_/g, ' ')}</div>
                  </div>
                ))}
              </div>
            ) : <span style={{ color: '#475569', fontSize: 11 }}>No target systems recorded</span>}
          </div>

          {/* Users */}
          <div style={{ background: 'rgba(15,23,42,0.6)', border: '1px solid rgba(30,41,59,0.8)', borderRadius: 10, padding: 14 }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 6, marginBottom: 10, color: '#A78BFA', fontSize: 12, fontWeight: 700, textTransform: 'uppercase' }}>
              <Users size={13} /> Implicated Users ({relatedUsers.length})
            </div>
            {relatedUsers.length > 0 ? (
              <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
                {relatedUsers.map((e, idx) => (
                  <div key={idx} style={{ background: 'rgba(10,14,26,0.8)', borderRadius: 6, padding: '6px 10px', border: '1px solid rgba(167,139,250,0.2)' }}>
                    <div style={{ color: '#F1F5F9', fontSize: 12, fontWeight: 600 }}>{e.entity_value}</div>
                    <div style={{ color: '#64748B', fontSize: 10, marginTop: 2 }}>{e.relationship_type.replace(/_/g, ' ')}</div>
                  </div>
                ))}
              </div>
            ) : <span style={{ color: '#475569', fontSize: 11 }}>No specific accounts found</span>}
          </div>
        </div>
      )}
    </div>
  );
}
