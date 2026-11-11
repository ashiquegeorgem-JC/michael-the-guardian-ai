'use client';

import Link from 'next/link';
import { motion, AnimatePresence } from 'framer-motion';
import type { AttackChain, AttackStage } from '@/types';
import { ChainStatusManager } from '@/components/attack-chains/ChainStatusManager';
import {
  Shield, Clock, Target, Users, Server, AlertTriangle,
  ChevronRight, FileText, AlertCircle, CheckCircle, Lightbulb,
  Layers, Activity, Fingerprint,
} from 'lucide-react';

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

const SEV_CONFIG: Record<string, { color: string; bg: string }> = {
  CRITICAL: { color: '#EF4444', bg: 'rgba(239,68,68,0.12)' },
  HIGH:     { color: '#F97316', bg: 'rgba(249,115,22,0.12)' },
  MEDIUM:   { color: '#EAB308', bg: 'rgba(234,179,8,0.12)' },
  LOW:      { color: '#10B981', bg: 'rgba(16,185,129,0.12)' },
};

function formatDuration(secs: number) {
  if (secs < 60) return `${Math.round(secs)}s`;
  if (secs < 3600) return `${Math.round(secs / 60)}m`;
  return `${(secs / 3600).toFixed(1)}h`;
}

function StagePill({ stage }: { stage: AttackStage }) {
  const color = STAGE_COLORS[stage] || '#475569';
  return (
    <div style={{
      background: color + '18',
      border: `1px solid ${color}40`,
      color,
      borderRadius: 6,
      padding: '3px 10px',
      fontSize: 10,
      fontWeight: 700,
      textTransform: 'uppercase',
      letterSpacing: 0.5,
      whiteSpace: 'nowrap',
    }}>
      {stage}
    </div>
  );
}

interface Props {
  chain: AttackChain;
  isExpanded?: boolean;
  onToggle?: () => void;
  onStatusUpdated?: (chain: AttackChain) => void;
  onStatusUpdate?: () => void;
  onEventConfirm?: (evt: any) => void;
}

export function ForensicInvestigationPanel({ chain, isExpanded = false, onToggle, onStatusUpdated }: Props) {
  const sevCfg = SEV_CONFIG[chain.severity] || SEV_CONFIG.LOW;

  return (
    <motion.div
      initial={{ opacity: 0, y: 16 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.35, ease: [0.4, 0, 0.2, 1] }}
      style={{
        background: 'rgba(10,14,26,0.95)',
        border: `1px solid ${sevCfg.color}30`,
        borderRadius: 16,
        overflow: 'hidden',
        boxShadow: `0 0 32px ${sevCfg.color}15`,
      }}
    >
      {/* Header */}
      <div
        onClick={onToggle}
        style={{
          display: 'flex',
          alignItems: 'flex-start',
          gap: 16,
          padding: '18px 20px',
          cursor: onToggle ? 'pointer' : 'default',
          borderBottom: isExpanded ? '1px solid rgba(30,41,59,0.8)' : 'none',
          transition: 'background 0.2s',
        }}
      >
        {/* Severity Badge */}
        <div style={{
          background: sevCfg.bg,
          border: `1px solid ${sevCfg.color}50`,
          borderRadius: 10,
          padding: '10px 14px',
          display: 'flex',
          flexDirection: 'column',
          alignItems: 'center',
          gap: 2,
          flexShrink: 0,
        }}>
          <Shield size={18} color={sevCfg.color} />
          <span style={{ color: sevCfg.color, fontSize: 9, fontWeight: 800, letterSpacing: 0.5 }}>
            {chain.severity}
          </span>
        </div>

        <div style={{ flex: 1, minWidth: 0 }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', gap: 8 }}>
            <div>
              <h3 style={{
                color: '#E2E8F0',
                fontSize: 14,
                fontWeight: 700,
                marginBottom: 4,
                lineHeight: 1.3,
              }}>
                {chain.title}
              </h3>
              <p style={{ color: '#64748B', fontSize: 11, lineHeight: 1.5 }}>{chain.summary}</p>
            </div>
            {onToggle && (
              <ChevronRight
                size={16}
                color="#64748B"
                style={{
                  transform: isExpanded ? 'rotate(90deg)' : 'rotate(0)',
                  transition: 'transform 0.2s',
                  flexShrink: 0,
                }}
              />
            )}
          </div>

          {/* Meta row */}
          <div style={{ display: 'flex', flexWrap: 'wrap', gap: 12, marginTop: 10 }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 5, color: '#64748B', fontSize: 11 }}>
              <Activity size={11} />
              <span>{chain.events.length} events</span>
            </div>
            <div style={{ display: 'flex', alignItems: 'center', gap: 5, color: '#64748B', fontSize: 11 }}>
              <Clock size={11} />
              <span>{formatDuration(chain.duration_seconds)}</span>
            </div>
            <div style={{ display: 'flex', alignItems: 'center', gap: 5, color: '#64748B', fontSize: 11 }}>
              <Target size={11} />
              <span>{chain.source_ips[0] || 'Unknown origin'}</span>
            </div>
            <div style={{
              background: 'rgba(59,130,246,0.1)',
              border: '1px solid rgba(59,130,246,0.3)',
              borderRadius: 4,
              padding: '1px 6px',
              color: '#60A5FA',
              fontSize: 10,
              fontWeight: 700,
            }}>
              {Math.round(chain.confidence_score * 100)}% confidence
            </div>
          </div>

          {/* Stage pills */}
          <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6, marginTop: 10 }}>
            {chain.stages_observed.map((s, i) => (
              <div key={s} style={{ display: 'flex', alignItems: 'center', gap: 4 }}>
                <StagePill stage={s} />
                {i < chain.stages_observed.length - 1 && (
                  <ChevronRight size={10} color="#334155" />
                )}
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* Expanded body */}
      <AnimatePresence>
        {isExpanded && (
          <motion.div
            initial={{ height: 0, opacity: 0 }}
            animate={{ height: 'auto', opacity: 1 }}
            exit={{ height: 0, opacity: 0 }}
            transition={{ duration: 0.25 }}
            style={{ overflow: 'hidden' }}
          >
            <div style={{ padding: 20, display: 'flex', flexDirection: 'column', gap: 20 }}>

              {/* Investigation Status Management */}
              {onStatusUpdated && (
                <ChainStatusManager
                  chain={chain}
                  onStatusUpdated={onStatusUpdated}
                />
              )}

              {/* Impact */}
              <Section title="Potential Impact" icon={<AlertTriangle size={13} color="#EF4444" />} color="#EF4444">
                <p style={{ color: '#94A3B8', fontSize: 12, lineHeight: 1.6 }}>{chain.potential_impact}</p>
              </Section>

              {/* Forensic Entities */}
              <Section title="Forensic Entities" icon={<Layers size={13} color="#3B82F6" />} color="#3B82F6">
                <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12 }}>
                  <EntityList label="Source IPs" items={chain.source_ips} color="#EF4444" linkToIoc />
                  <EntityList label="Target Systems" items={chain.target_systems} color="#F97316" />
                  <EntityList label="Affected Users" items={chain.affected_users} color="#8B5CF6" />
                  <EntityList label="Processes" items={chain.affected_processes} color="#06B6D4" />
                </div>
                <div style={{ marginTop: 12, paddingTop: 10, borderTop: '1px solid rgba(255,255,255,0.06)' }}>
                  <Link
                    href={`/iocs?attack_chain_id=${chain.id}`}
                    style={{
                      display: 'inline-flex',
                      alignItems: 'center',
                      gap: 6,
                      fontSize: 11,
                      color: '#60A5FA',
                      textDecoration: 'none',
                      fontWeight: 600,
                    }}
                  >
                    <Fingerprint size={13} />
                    Investigate IOCs in this Attack Chain →
                  </Link>
                </div>
              </Section>

              {/* Correlation Explanation */}
              <Section title="Correlation Rationale" icon={<FileText size={13} color="#10B981" />} color="#10B981">
                <p style={{ color: '#94A3B8', fontSize: 12, lineHeight: 1.6, fontStyle: 'italic' }}>
                  {chain.correlation_explanation}
                </p>
              </Section>

              {/* Evidence */}
              <Section title="Supporting Evidence" icon={<CheckCircle size={13} color="#22D3EE" />} color="#22D3EE">
                <div style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
                  {chain.supporting_evidence.slice(0, 6).map((ev, i) => (
                    <div
                      key={i}
                      style={{
                        background: 'rgba(2,6,23,0.7)',
                        borderRadius: 6,
                        padding: '5px 10px',
                        fontFamily: 'monospace',
                        fontSize: 10,
                        color: '#475569',
                        whiteSpace: 'nowrap',
                        overflow: 'hidden',
                        textOverflow: 'ellipsis',
                        borderLeft: '2px solid rgba(34,211,238,0.25)',
                      }}
                    >{ev}</div>
                  ))}
                </div>
              </Section>

              {/* Unconfirmed Hypotheses */}
              {chain.hypotheses_unconfirmed.length > 0 && (
                <Section title="Unconfirmed Hypotheses" icon={<Lightbulb size={13} color="#F59E0B" />} color="#F59E0B">
                  {chain.hypotheses_unconfirmed.map((h, i) => (
                    <div key={i} style={{ display: 'flex', gap: 8, marginBottom: 6 }}>
                      <AlertCircle size={12} color="#F59E0B" style={{ flexShrink: 0, marginTop: 1 }} />
                      <p style={{ color: '#94A3B8', fontSize: 12, lineHeight: 1.5 }}>{h}</p>
                    </div>
                  ))}
                </Section>
              )}

              {/* Unconfirmed stages */}
              {chain.stages_unconfirmed.length > 0 && (
                <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6 }}>
                  <span style={{ color: '#64748B', fontSize: 11, alignSelf: 'center' }}>Unconfirmed stages:</span>
                  {chain.stages_unconfirmed.map(s => (
                    <div
                      key={s}
                      style={{
                        background: 'rgba(71,85,105,0.15)',
                        border: '1px dashed rgba(71,85,105,0.5)',
                        color: '#64748B',
                        borderRadius: 6,
                        padding: '2px 8px',
                        fontSize: 10,
                      }}
                    >{s}</div>
                  ))}
                </div>
              )}

              {/* Recommended Actions */}
              <Section title="Recommended Actions" icon={<Shield size={13} color="#10B981" />} color="#10B981">
                <ol style={{ paddingLeft: 0, listStyle: 'none', display: 'flex', flexDirection: 'column', gap: 6 }}>
                  {chain.recommended_actions.map((action, i) => (
                    <li key={i} style={{ display: 'flex', gap: 10 }}>
                      <span style={{
                        background: 'rgba(16,185,129,0.15)',
                        color: '#10B981',
                        borderRadius: 4,
                        minWidth: 20,
                        height: 20,
                        display: 'flex',
                        alignItems: 'center',
                        justifyContent: 'center',
                        fontSize: 10,
                        fontWeight: 700,
                        flexShrink: 0,
                      }}>{i + 1}</span>
                      <p style={{ color: '#94A3B8', fontSize: 12, lineHeight: 1.5 }}>{action}</p>
                    </li>
                  ))}
                </ol>
              </Section>

              {/* Chain ID reference */}
              <div style={{ borderTop: '1px solid rgba(30,41,59,0.6)', paddingTop: 12 }}>
                <span style={{ color: '#334155', fontSize: 10, fontFamily: 'monospace' }}>
                  Chain ID: {chain.id}
                </span>
              </div>
            </div>
          </motion.div>
        )}
      </AnimatePresence>
    </motion.div>
  );
}

// ── Sub-components ─────────────────────────────────────────────────────────

function Section({
  title, icon, color, children,
}: {
  title: string;
  icon: React.ReactNode;
  color: string;
  children: React.ReactNode;
}) {
  return (
    <div>
      <div style={{ display: 'flex', alignItems: 'center', gap: 6, marginBottom: 10 }}>
        {icon}
        <h4 style={{ color, fontSize: 11, fontWeight: 700, letterSpacing: 0.5, textTransform: 'uppercase' }}>
          {title}
        </h4>
      </div>
      {children}
    </div>
  );
}

function EntityList({ label, items, color, linkToIoc }: { label: string; items: string[]; color: string; linkToIoc?: boolean }) {
  if (items.length === 0) return null;
  return (
    <div>
      <p style={{ color: '#475569', fontSize: 10, marginBottom: 4, textTransform: 'uppercase', letterSpacing: 0.5 }}>{label}</p>
      {items.map(item => (
        linkToIoc ? (
          <Link
            key={item}
            href={`/iocs?normalized_value=${encodeURIComponent(item)}`}
            style={{
              color,
              fontSize: 11,
              fontFamily: 'monospace',
              marginBottom: 2,
              textDecoration: 'none',
              display: 'inline-flex',
              alignItems: 'center',
              gap: 4,
            }}
            title="Investigate IOC in Intelligence Workspace"
          >
            {item}
            <span style={{ fontSize: 9, opacity: 0.7 }}>↗</span>
          </Link>
        ) : (
          <div
            key={item}
            style={{
              color,
              fontSize: 11,
              fontFamily: 'monospace',
              marginBottom: 2,
            }}
          >
            {item}
          </div>
        )
      ))}
    </div>
  );
}
