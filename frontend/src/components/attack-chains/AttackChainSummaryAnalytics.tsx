'use client';

import React, { useMemo } from 'react';
import {
  ResponsiveContainer, BarChart, Bar, XAxis, YAxis, Tooltip, Cell,
  PieChart, Pie,
} from 'recharts';
import {
  ShieldAlert, ShieldCheck, AlertOctagon, CheckCircle2, AlertTriangle,
  Clock, Flame, Target, BarChart3, TrendingUp, Info
} from 'lucide-react';
import type { ChainSummary, AttackChain } from '@/types';

interface Props {
  summary: ChainSummary | null;
  loading: boolean;
  onSelectChain?: (chainId: string) => void;
}

const SEV_COLORS: Record<string, string> = {
  CRITICAL: '#EF4444',
  HIGH:     '#F97316',
  MEDIUM:   '#EAB308',
  LOW:      '#10B981',
};

const STAGE_COLORS: Record<string, string> = {
  'Reconnaissance':      '#06B6D4',
  'Initial Access':      '#F97316',
  'Credential Attack':   '#EF4444',
  'Privilege Escalation':'#DC2626',
  'Execution':           '#B91C1C',
  'Persistence':         '#7C3AED',
  'Command and Control': '#9333EA',
  'Lateral Movement':    '#8B5CF6',
  'Data Access':         '#3B82F6',
  'Exfiltration':        '#EC4899',
  'Unknown':             '#475569',
};

export function AttackChainSummaryAnalytics({ summary, loading, onSelectChain }: Props) {
  if (loading) {
    return (
      <div style={{
        background: 'rgba(15,23,42,0.6)',
        border: '1px solid rgba(30,41,59,0.8)',
        borderRadius: 16,
        padding: 24,
        marginBottom: 24,
      }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 16 }}>
          <div style={{ width: 16, height: 16, borderRadius: '50%', background: '#3B82F6', opacity: 0.5, animation: 'pulse 1.5s infinite' }} />
          <span style={{ color: '#94A3B8', fontSize: 13 }}>Loading SOC Analytics Summary…</span>
        </div>
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(140px, 1fr))', gap: 12 }}>
          {[...Array(6)].map((_, i) => (
            <div key={i} style={{ height: 68, borderRadius: 10, background: 'rgba(30,41,59,0.4)', animation: 'pulse 1.5s infinite' }} />
          ))}
        </div>
      </div>
    );
  }

  if (!summary || summary.total_chains === 0) {
    return null;
  }

  const newCount = summary.by_status?.NEW || 0;
  const investigatingCount = summary.by_status?.INVESTIGATING || 0;
  const confirmedCount = summary.by_status?.CONFIRMED || 0;
  const falsePositiveCount = summary.by_status?.FALSE_POSITIVE || 0;
  const resolvedCount = summary.by_status?.RESOLVED || 0;

  // Chart data: Severity
  const severityData = [
    { name: 'CRITICAL', count: summary.by_severity?.CRITICAL || 0, color: SEV_COLORS.CRITICAL },
    { name: 'HIGH',     count: summary.by_severity?.HIGH || 0,     color: SEV_COLORS.HIGH },
    { name: 'MEDIUM',   count: summary.by_severity?.MEDIUM || 0,   color: SEV_COLORS.MEDIUM },
    { name: 'LOW',      count: summary.by_severity?.LOW || 0,      color: SEV_COLORS.LOW },
  ].filter(d => d.count > 0);

  // Chart data: Stages
  const stageData = Object.entries(summary.by_stage || {})
    .map(([stage, count]) => ({ stage, count, color: STAGE_COLORS[stage] || '#3B82F6' }))
    .sort((a, b) => b.count - a.count)
    .slice(0, 7);

  return (
    <div style={{
      background: 'rgba(10,14,26,0.95)',
      border: '1px solid rgba(59,130,246,0.25)',
      borderRadius: 16,
      padding: 24,
      marginBottom: 28,
      boxShadow: '0 8px 32px rgba(0,0,0,0.4)',
    }}>
      {/* Title */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 20 }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
          <div style={{
            background: 'linear-gradient(135deg, rgba(59,130,246,0.2), rgba(124,58,237,0.2))',
            border: '1px solid rgba(59,130,246,0.4)',
            borderRadius: 8,
            padding: '6px 8px',
            display: 'flex',
          }}>
            <BarChart3 size={16} color="#60A5FA" />
          </div>
          <div>
            <h2 style={{ color: '#E2E8F0', fontSize: 16, fontWeight: 700, margin: 0 }}>
              SOC Threat Intelligence Overview
            </h2>
            <p style={{ color: '#64748B', fontSize: 11, margin: 0 }}>
              Telemetry aggregated across {summary.total_chains} reconstructed multi-stage attack chains
            </p>
          </div>
        </div>

        <div style={{ display: 'flex', alignItems: 'center', gap: 16 }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 6, color: '#94A3B8', fontSize: 12 }}>
            <TrendingUp size={14} color="#10B981" />
            <span>Avg Confidence: <strong style={{ color: '#F1F5F9' }}>{Math.round(summary.avg_confidence * 100)}%</strong></span>
          </div>
          <div style={{ display: 'flex', alignItems: 'center', gap: 6, color: '#94A3B8', fontSize: 12 }}>
            <Clock size={14} color="#60A5FA" />
            <span>Avg Duration: <strong style={{ color: '#F1F5F9' }}>{Math.round(summary.avg_duration_seconds)}s</strong></span>
          </div>
        </div>
      </div>

      {/* KPI Stat Cards */}
      <div style={{
        display: 'grid',
        gridTemplateColumns: 'repeat(auto-fit, minmax(150px, 1fr))',
        gap: 12,
        marginBottom: 24,
      }}>
        <div style={{ background: 'rgba(15,23,42,0.8)', border: '1px solid rgba(59,130,246,0.25)', borderRadius: 10, padding: '12px 16px' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 4 }}>
            <span style={{ color: '#64748B', fontSize: 11, fontWeight: 600, textTransform: 'uppercase' }}>Total Chains</span>
            <Flame size={14} color="#3B82F6" />
          </div>
          <div style={{ color: '#F1F5F9', fontSize: 24, fontWeight: 800 }}>{summary.total_chains}</div>
        </div>

        <div style={{ background: 'rgba(15,23,42,0.8)', border: '1px solid rgba(59,130,246,0.25)', borderRadius: 10, padding: '12px 16px' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 4 }}>
            <span style={{ color: '#60A5FA', fontSize: 11, fontWeight: 600, textTransform: 'uppercase' }}>New</span>
            <ShieldAlert size={14} color="#60A5FA" />
          </div>
          <div style={{ color: '#60A5FA', fontSize: 24, fontWeight: 800 }}>{newCount}</div>
        </div>

        <div style={{ background: 'rgba(15,23,42,0.8)', border: '1px solid rgba(234,179,8,0.25)', borderRadius: 10, padding: '12px 16px' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 4 }}>
            <span style={{ color: '#EAB308', fontSize: 11, fontWeight: 600, textTransform: 'uppercase' }}>Investigating</span>
            <AlertTriangle size={14} color="#EAB308" />
          </div>
          <div style={{ color: '#EAB308', fontSize: 24, fontWeight: 800 }}>{investigatingCount}</div>
        </div>

        <div style={{ background: 'rgba(15,23,42,0.8)', border: '1px solid rgba(239,68,68,0.25)', borderRadius: 10, padding: '12px 16px' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 4 }}>
            <span style={{ color: '#EF4444', fontSize: 11, fontWeight: 600, textTransform: 'uppercase' }}>Confirmed</span>
            <AlertOctagon size={14} color="#EF4444" />
          </div>
          <div style={{ color: '#EF4444', fontSize: 24, fontWeight: 800 }}>{confirmedCount}</div>
        </div>

        <div style={{ background: 'rgba(15,23,42,0.8)', border: '1px solid rgba(100,116,139,0.25)', borderRadius: 10, padding: '12px 16px' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 4 }}>
            <span style={{ color: '#94A3B8', fontSize: 11, fontWeight: 600, textTransform: 'uppercase' }}>False Positives</span>
            <ShieldCheck size={14} color="#94A3B8" />
          </div>
          <div style={{ color: '#94A3B8', fontSize: 24, fontWeight: 800 }}>{falsePositiveCount}</div>
        </div>

        <div style={{ background: 'rgba(15,23,42,0.8)', border: '1px solid rgba(16,185,129,0.25)', borderRadius: 10, padding: '12px 16px' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 4 }}>
            <span style={{ color: '#10B981', fontSize: 11, fontWeight: 600, textTransform: 'uppercase' }}>Resolved</span>
            <CheckCircle2 size={14} color="#10B981" />
          </div>
          <div style={{ color: '#10B981', fontSize: 24, fontWeight: 800 }}>{resolvedCount}</div>
        </div>
      </div>

      {/* Visual Analytics Grid */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))', gap: 20 }}>
        {/* Severity Breakdown */}
        <div style={{
          background: 'rgba(15,23,42,0.6)',
          border: '1px solid rgba(30,41,59,0.8)',
          borderRadius: 12,
          padding: 16,
        }}>
          <h4 style={{ color: '#CBD5E1', fontSize: 12, fontWeight: 700, margin: '0 0 12px', textTransform: 'uppercase', letterSpacing: 0.5 }}>
            Severity Distribution
          </h4>
          <div style={{ height: 140, display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
            {severityData.length > 0 ? (
              <ResponsiveContainer width="100%" height={140}>
                <BarChart data={severityData} margin={{ top: 10, right: 10, left: -25, bottom: 0 }}>
                  <XAxis dataKey="name" stroke="#64748B" fontSize={10} tickLine={false} />
                  <YAxis stroke="#64748B" fontSize={10} allowDecimals={false} />
                  <Tooltip
                    contentStyle={{ background: '#0F172A', border: '1px solid #334155', borderRadius: 8, fontSize: 12, color: '#F1F5F9' }}
                    cursor={{ fill: 'rgba(255,255,255,0.05)' }}
                  />
                  <Bar dataKey="count" radius={[4, 4, 0, 0]}>
                    {severityData.map((entry, index) => (
                      <Cell key={`sev-cell-${index}`} fill={entry.color} />
                    ))}
                  </Bar>
                </BarChart>
              </ResponsiveContainer>
            ) : (
              <div style={{ color: '#475569', fontSize: 12 }}>No severity data</div>
            )}
          </div>
        </div>

        {/* MITRE Stage Progression */}
        <div style={{
          background: 'rgba(15,23,42,0.6)',
          border: '1px solid rgba(30,41,59,0.8)',
          borderRadius: 12,
          padding: 16,
        }}>
          <h4 style={{ color: '#CBD5E1', fontSize: 12, fontWeight: 700, margin: '0 0 12px', textTransform: 'uppercase', letterSpacing: 0.5 }}>
            Top MITRE ATT&CK Stages
          </h4>
          <div style={{ height: 140 }}>
            {stageData.length > 0 ? (
              <ResponsiveContainer width="100%" height={140}>
                <BarChart data={stageData} layout="vertical" margin={{ top: 0, right: 15, left: 35, bottom: 0 }}>
                  <XAxis type="number" stroke="#64748B" fontSize={10} allowDecimals={false} />
                  <YAxis dataKey="stage" type="category" stroke="#64748B" fontSize={9} width={95} tickLine={false} />
                  <Tooltip
                    contentStyle={{ background: '#0F172A', border: '1px solid #334155', borderRadius: 8, fontSize: 12, color: '#F1F5F9' }}
                    cursor={{ fill: 'rgba(255,255,255,0.05)' }}
                  />
                  <Bar dataKey="count" radius={[0, 4, 4, 0]}>
                    {stageData.map((entry, index) => (
                      <Cell key={`stage-cell-${index}`} fill={entry.color} />
                    ))}
                  </Bar>
                </BarChart>
              </ResponsiveContainer>
            ) : (
              <div style={{ color: '#475569', fontSize: 12, display: 'flex', alignItems: 'center', justifyContent: 'center', height: '100%' }}>No stage data</div>
            )}
          </div>
        </div>

        {/* Top Attacker IPs */}
        <div style={{
          background: 'rgba(15,23,42,0.6)',
          border: '1px solid rgba(30,41,59,0.8)',
          borderRadius: 12,
          padding: 16,
        }}>
          <h4 style={{ color: '#CBD5E1', fontSize: 12, fontWeight: 700, margin: '0 0 12px', textTransform: 'uppercase', letterSpacing: 0.5 }}>
            Frequent Origin IPs
          </h4>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
            {summary.top_source_ips && summary.top_source_ips.length > 0 ? (
              summary.top_source_ips.slice(0, 4).map(([ip, count], i) => (
                <div key={ip} style={{
                  display: 'flex',
                  justifyContent: 'space-between',
                  alignItems: 'center',
                  background: 'rgba(15,23,42,0.8)',
                  border: '1px solid rgba(30,41,59,0.6)',
                  borderRadius: 6,
                  padding: '5px 10px',
                }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                    <Target size={11} color="#EF4444" />
                    <span style={{ color: '#E2E8F0', fontSize: 11, fontFamily: 'monospace' }}>{ip}</span>
                  </div>
                  <span style={{
                    color: '#EF4444',
                    background: 'rgba(239,68,68,0.12)',
                    fontSize: 10,
                    fontWeight: 700,
                    padding: '1px 6px',
                    borderRadius: 4,
                  }}>
                    {count} chain{count !== 1 ? 's' : ''}
                  </span>
                </div>
              ))
            ) : (
              <div style={{ color: '#475569', fontSize: 12 }}>No origin IPs recorded</div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}

