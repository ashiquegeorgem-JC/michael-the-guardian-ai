'use client';

import React, { useEffect, useState } from 'react';
import { motion } from 'framer-motion';
import {
  Shield, Globe, Hash, Mail, FileText, Server, Tag, X,
} from 'lucide-react';
import type { IOC, IOCType, IOCStatus } from '@/types';
import { formatDateTime } from '@/lib/utils';
import { IOCStatusManager } from './IOCStatusManager';
import { IOCEvidenceTimeline } from './IOCEvidenceTimeline';
import { IOCRelationshipsPanel } from './IOCRelationshipsPanel';

const TYPE_ICONS: Record<IOCType, React.ComponentType<{ size?: number; color?: string }>> = {
  ipv4: Globe, ipv6: Globe, domain: Globe, url: Globe,
  md5: Hash, sha1: Hash, sha256: Hash,
  email: Mail, file_path: FileText,
};

const TYPE_COLORS: Record<IOCType, string> = {
  ipv4: '#3B82F6', ipv6: '#6366F1', domain: '#8B5CF6', url: '#7C3AED',
  md5: '#F59E0B', sha1: '#F97316', sha256: '#EF4444',
  email: '#10B981', file_path: '#06B6D4',
};

const STATUS_CONFIG: Record<IOCStatus, { color: string; bg: string; label: string }> = {
  EXTRACTED:      { color: '#94A3B8', bg: 'rgba(148,163,184,0.12)', label: 'Extracted' },
  UNDER_REVIEW:   { color: '#EAB308', bg: 'rgba(234,179,8,0.12)',   label: 'Under Review' },
  CONFIRMED:      { color: '#3B82F6', bg: 'rgba(59,130,246,0.12)',  label: 'Confirmed Indicator' },
  FALSE_POSITIVE: { color: '#10B981', bg: 'rgba(16,185,129,0.12)',  label: 'False Positive' },
};

type DetailTab = 'identity' | 'evidence' | 'relationships' | 'status';

interface Props {
  ioc: IOC;
  onClose?: () => void;
  onStatusUpdated?: (ioc: IOC) => void;
}

export function IOCDetailPanel({ ioc: initialIoc, onClose, onStatusUpdated }: Props) {
  const [ioc, setIoc] = useState<IOC>(initialIoc);
  const [tab, setTab] = useState<DetailTab>('identity');

  useEffect(() => { setIoc(initialIoc); }, [initialIoc]);

  const statusCfg = STATUS_CONFIG[ioc.status] || STATUS_CONFIG.EXTRACTED;
  const TypeIcon = TYPE_ICONS[ioc.ioc_type] || Shield;
  const typeColor = TYPE_COLORS[ioc.ioc_type] || '#475569';

  const handleStatusUpdated = (updated: IOC) => {
    setIoc(updated);
    onStatusUpdated?.(updated);
  };

  const tabs: { key: DetailTab; label: string }[] = [
    { key: 'identity', label: 'Identity' },
    { key: 'evidence', label: `Evidence (${ioc.evidence_references?.length ?? 0})` },
    { key: 'relationships', label: 'Relationships' },
    { key: 'status', label: 'Review Status' },
  ];

  const rowStyle: React.CSSProperties = {
    display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start',
    padding: '8px 0', borderBottom: '1px solid #1A274430',
  };
  const labelStyle: React.CSSProperties = { fontSize: 11, color: 'var(--text-muted)', fontWeight: 500, flexShrink: 0, paddingRight: 12, paddingTop: 1 };
  const valueStyle: React.CSSProperties = { fontSize: 12, color: 'var(--text-primary)', fontFamily: 'var(--font-mono)', textAlign: 'right' as const, wordBreak: 'break-all' as const };

  return (
    <motion.div
      initial={{ opacity: 0, x: 16 }}
      animate={{ opacity: 1, x: 0 }}
      transition={{ duration: 0.25, ease: [0.4, 0, 0.2, 1] }}
      style={{
        background: 'rgba(10,14,26,0.97)',
        border: `1px solid ${typeColor}30`,
        borderRadius: 16,
        overflow: 'hidden',
        boxShadow: `0 0 32px ${typeColor}10`,
        display: 'flex',
        flexDirection: 'column',
        height: '100%',
      }}
    >
      {/* Header */}
      <div style={{ padding: '16px 20px', borderBottom: '1px solid #1E2D4A', display: 'flex', alignItems: 'flex-start', gap: 12 }}>
        <div style={{ width: 40, height: 40, background: typeColor + '20', border: `1px solid ${typeColor}40`, borderRadius: 10, display: 'flex', alignItems: 'center', justifyContent: 'center', flexShrink: 0 }}>
          <TypeIcon size={18} color={typeColor} />
        </div>
        <div style={{ flex: 1, minWidth: 0 }}>
          <div style={{ fontSize: 10, fontWeight: 700, letterSpacing: '0.08em', textTransform: 'uppercase', color: typeColor, marginBottom: 2 }}>
            {ioc.ioc_type.toUpperCase()}
          </div>
          <div style={{ fontFamily: 'var(--font-mono)', fontSize: 13, color: 'var(--text-primary)', wordBreak: 'break-all', fontWeight: 600 }}>
            {ioc.normalized_value}
          </div>
        </div>
        <div style={{ display: 'flex', alignItems: 'center', gap: 8, flexShrink: 0 }}>
          <span style={{ background: statusCfg.bg, border: `1px solid ${statusCfg.color}40`, color: statusCfg.color, fontSize: 10, fontWeight: 700, padding: '3px 8px', borderRadius: 5 }}>
            {statusCfg.label}
          </span>
          {onClose && (
            <button onClick={onClose} style={{ background: 'transparent', border: 'none', cursor: 'pointer', color: 'var(--text-muted)', padding: 4 }}>
              <X size={15} />
            </button>
          )}
        </div>
      </div>

      {/* Tabs */}
      <div style={{ display: 'flex', borderBottom: '1px solid #1E2D4A', flexShrink: 0, overflowX: 'auto' }}>
        {tabs.map(t => (
          <button
            key={t.key}
            onClick={() => setTab(t.key)}
            style={{
              padding: '10px 16px',
              fontSize: 12,
              fontWeight: tab === t.key ? 600 : 400,
              color: tab === t.key ? 'var(--primary)' : 'var(--text-muted)',
              background: 'transparent',
              border: 'none',
              borderBottom: tab === t.key ? '2px solid var(--primary)' : '2px solid transparent',
              cursor: 'pointer',
              transition: 'all 0.15s',
              marginBottom: -1,
              whiteSpace: 'nowrap',
            }}
          >
            {t.label}
          </button>
        ))}
      </div>

      {/* Tab Content */}
      <div style={{ flex: 1, overflowY: 'auto', padding: 20 }}>
        {tab === 'identity' && (
          <div>
            <div style={rowStyle}>
              <span style={labelStyle}>IOC ID</span>
              <span style={{ ...valueStyle, fontSize: 10, color: 'var(--text-muted)' }}>{ioc.id}</span>
            </div>
            <div style={rowStyle}>
              <span style={labelStyle}>Raw Value</span>
              <span style={valueStyle}>{ioc.raw_value}</span>
            </div>
            <div style={rowStyle}>
              <span style={labelStyle}>Normalized</span>
              <span style={valueStyle}>{ioc.normalized_value}</span>
            </div>
            <div style={rowStyle}>
              <span style={labelStyle}>Type</span>
              <span style={{ ...valueStyle, color: typeColor, fontWeight: 600 }}>{ioc.ioc_type.toUpperCase()}</span>
            </div>
            {ioc.validation_status && (
              <div style={rowStyle}>
                <span style={labelStyle}>Validation</span>
                <span style={{
                  ...valueStyle,
                  color: ioc.validation_status === 'VALID' ? '#10B981' : ioc.validation_status === 'SUSPICIOUS' ? '#F59E0B' : '#EF4444',
                  fontWeight: 600
                }}>
                  {ioc.validation_status}
                </span>
              </div>
            )}
            {ioc.ip_scope && (
              <div style={rowStyle}>
                <span style={labelStyle}>IP Scope</span>
                <span style={{ ...valueStyle, textTransform: 'capitalize' }}>{ioc.ip_scope}</span>
              </div>
            )}
            <div style={{ ...rowStyle, marginTop: 8 }}>
              <span style={labelStyle}>Confidence</span>
              <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                <div style={{ width: 80, height: 5, background: '#1E2D4A', borderRadius: 3 }}>
                  <div style={{ width: `${Math.round(ioc.confidence * 100)}%`, height: '100%', background: ioc.confidence >= 0.8 ? '#10B981' : ioc.confidence >= 0.6 ? '#F59E0B' : '#EF4444', borderRadius: 3 }} />
                </div>
                <span style={{ fontSize: 12, fontFamily: 'var(--font-mono)', color: 'var(--text-secondary)' }}>{Math.round(ioc.confidence * 100)}%</span>
              </div>
            </div>
            <div style={rowStyle}>
              <span style={labelStyle}>First Seen</span>
              <span style={{ ...valueStyle, color: 'var(--text-secondary)' }}>{ioc.first_seen ? formatDateTime(ioc.first_seen) : '—'}</span>
            </div>
            <div style={rowStyle}>
              <span style={labelStyle}>Last Seen</span>
              <span style={{ ...valueStyle, color: 'var(--text-secondary)' }}>{ioc.last_seen ? formatDateTime(ioc.last_seen) : '—'}</span>
            </div>
            <div style={rowStyle}>
              <span style={labelStyle}>Occurrences</span>
              <span style={{ ...valueStyle, color: 'var(--text-primary)', fontWeight: 700, fontFamily: 'var(--font-mono)' }}>{ioc.occurrence_count}</span>
            </div>

            {/* Sessions */}
            {ioc.source_sessions && ioc.source_sessions.length > 0 && (
              <div style={{ marginTop: 16 }}>
                <div style={{ fontSize: 10, fontWeight: 700, letterSpacing: '0.08em', textTransform: 'uppercase', color: 'var(--text-muted)', marginBottom: 8 }}>Source Sessions</div>
                {ioc.source_sessions.map(s => (
                  <div key={s} style={{ fontFamily: 'var(--font-mono)', fontSize: 11, color: '#60A5FA', marginBottom: 4, padding: '4px 8px', background: 'rgba(59,130,246,0.06)', borderRadius: 5, display: 'flex', alignItems: 'center', gap: 4 }}>
                    <Server size={10} />
                    {s}
                  </div>
                ))}
              </div>
            )}

            {/* Extraction Methods */}
            {ioc.extraction_methods && ioc.extraction_methods.length > 0 && (
              <div style={{ marginTop: 16 }}>
                <div style={{ fontSize: 10, fontWeight: 700, letterSpacing: '0.08em', textTransform: 'uppercase', color: 'var(--text-muted)', marginBottom: 8 }}>Extraction Methods</div>
                <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap' }}>
                  {ioc.extraction_methods.map(m => (
                    <span key={m} style={{ background: '#1E2D4A', border: '1px solid #2A3F6A', color: 'var(--text-secondary)', fontSize: 10, padding: '2px 8px', borderRadius: 4 }}>{m}</span>
                  ))}
                </div>
              </div>
            )}

            {/* Tags */}
            {ioc.tags && ioc.tags.length > 0 && (
              <div style={{ marginTop: 16 }}>
                <div style={{ fontSize: 10, fontWeight: 700, letterSpacing: '0.08em', textTransform: 'uppercase', color: 'var(--text-muted)', marginBottom: 8 }}>
                  <Tag size={10} style={{ display: 'inline', marginRight: 4 }} />Tags
                </div>
                <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap' }}>
                  {ioc.tags.map(t => (
                    <span key={t} style={{ background: '#7C3AED20', border: '1px solid #7C3AED30', color: '#A78BFA', fontSize: 10, padding: '2px 8px', borderRadius: 4 }}>{t}</span>
                  ))}
                </div>
              </div>
            )}

            {/* Analyst note */}
            {ioc.analyst_note && (
              <div style={{ marginTop: 16, padding: 12, background: 'rgba(234,179,8,0.06)', border: '1px solid rgba(234,179,8,0.2)', borderRadius: 8 }}>
                <div style={{ fontSize: 10, fontWeight: 700, color: '#EAB308', marginBottom: 4 }}>Analyst Note</div>
                <div style={{ fontSize: 12, color: 'var(--text-secondary)' }}>{ioc.analyst_note}</div>
              </div>
            )}
          </div>
        )}

        {tab === 'evidence' && (
          <IOCEvidenceTimeline iocId={ioc.id} inlineEvidence={ioc.evidence_references} />
        )}

        {tab === 'relationships' && (
          <IOCRelationshipsPanel iocId={ioc.id} />
        )}

        {tab === 'status' && (
          <IOCStatusManager ioc={ioc} onStatusUpdated={handleStatusUpdated} />
        )}
      </div>
    </motion.div>
  );
}

