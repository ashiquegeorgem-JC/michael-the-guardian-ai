'use client';

import React from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { Shield, Globe, Hash, Mail, FileText, Clock, Eye } from 'lucide-react';
import type { IOC, IOCType, IOCStatus } from '@/types';
import { formatDateTime } from '@/lib/utils';

const TYPE_CONFIG: Record<IOCType, { label: string; icon: React.ComponentType<{ size?: number; color?: string }>; color: string }> = {
  ipv4:      { label: 'IPv4',      icon: Globe,    color: '#3B82F6' },
  ipv6:      { label: 'IPv6',      icon: Globe,    color: '#6366F1' },
  domain:    { label: 'Domain',    icon: Globe,    color: '#8B5CF6' },
  url:       { label: 'URL',       icon: Globe,    color: '#7C3AED' },
  md5:       { label: 'MD5',       icon: Hash,     color: '#F59E0B' },
  sha1:      { label: 'SHA1',      icon: Hash,     color: '#F97316' },
  sha256:    { label: 'SHA256',    icon: Hash,     color: '#EF4444' },
  email:     { label: 'Email',     icon: Mail,     color: '#10B981' },
  file_path: { label: 'FilePath',  icon: FileText, color: '#06B6D4' },
};

const STATUS_CONFIG: Record<IOCStatus, { label: string; color: string; bg: string }> = {
  EXTRACTED:      { label: 'Extracted',      color: '#94A3B8', bg: 'rgba(148,163,184,0.12)' },
  UNDER_REVIEW:   { label: 'Under Review',   color: '#EAB308', bg: 'rgba(234,179,8,0.12)' },
  CONFIRMED:      { label: 'Confirmed',      color: '#3B82F6', bg: 'rgba(59,130,246,0.12)' },
  FALSE_POSITIVE: { label: 'False Positive', color: '#10B981', bg: 'rgba(16,185,129,0.12)' },
};

function TypeBadge({ type }: { type: IOCType }) {
  const cfg = TYPE_CONFIG[type] || { label: type, icon: Shield, color: '#475569' };
  const Icon = cfg.icon;
  return (
    <span style={{ display: 'inline-flex', alignItems: 'center', gap: 4, background: cfg.color + '15', border: `1px solid ${cfg.color}35`, color: cfg.color, fontSize: 10, fontWeight: 700, padding: '2px 7px', borderRadius: 5, letterSpacing: 0.4 }}>
      <Icon size={10} color={cfg.color} />
      {cfg.label}
    </span>
  );
}

function StatusBadge({ status }: { status: IOCStatus }) {
  const cfg = STATUS_CONFIG[status] || STATUS_CONFIG.EXTRACTED;
  return (
    <span style={{ background: cfg.bg, border: `1px solid ${cfg.color}40`, color: cfg.color, fontSize: 10, fontWeight: 700, padding: '2px 7px', borderRadius: 5, letterSpacing: 0.4, textTransform: 'uppercase' as const }}>
      {cfg.label}
    </span>
  );
}

function ConfidenceBar({ value }: { value: number }) {
  const pct = Math.round(value * 100);
  const color = pct >= 80 ? '#10B981' : pct >= 60 ? '#F59E0B' : '#EF4444';
  return (
    <div style={{ display: 'flex', alignItems: 'center', gap: 6, justifyContent: 'flex-end' }}>
      <div style={{ width: 44, height: 4, background: '#1E2D4A', borderRadius: 2, overflow: 'hidden' }}>
        <div style={{ width: `${pct}%`, height: '100%', background: color, borderRadius: 2 }} />
      </div>
      <span style={{ fontSize: 11, color: 'var(--text-muted)', fontFamily: 'var(--font-mono)' }}>{pct}%</span>
    </div>
  );
}

interface Props {
  iocs: IOC[];
  selectedId?: string | null;
  selectedIocId?: string | null;
  onSelect?: (ioc: IOC) => void;
  onSelectIoc?: (ioc: IOC) => void;
  loading?: boolean;
  pagination?: {
    page: number;
    page_size: number;
    total: number;
    total_pages: number;
  };
  onPageChange?: (newPage: number) => void;
}

export function IOCListTable({
  iocs,
  selectedId,
  selectedIocId,
  onSelect,
  onSelectIoc,
  loading,
  pagination,
  onPageChange,
}: Props) {
  const currentSelectedId = selectedId || selectedIocId;
  const handleSelect = (ioc: IOC) => {
    if (onSelect) onSelect(ioc);
    if (onSelectIoc) onSelectIoc(ioc);
  };
  const headerStyle: React.CSSProperties = {
    padding: '8px 12px',
    fontSize: 10,
    fontWeight: 700,
    letterSpacing: '0.08em',
    textTransform: 'uppercase',
    color: 'var(--text-muted)',
    borderBottom: '1px solid #1E2D4A',
    whiteSpace: 'nowrap' as const,
  };

  if (loading) {
    return (
      <div style={{ padding: 40, textAlign: 'center', color: 'var(--text-muted)' }}>
        <div className="animate-pulse" style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
          {[1, 2, 3, 4, 5].map(i => (
            <div key={i} style={{ height: 44, background: '#0F1629', borderRadius: 8 }} />
          ))}
        </div>
      </div>
    );
  }

  if (iocs.length === 0) {
    return (
      <div style={{ padding: 56, textAlign: 'center', color: 'var(--text-muted)' }}>
        <Shield size={36} style={{ opacity: 0.3, display: 'block', margin: '0 auto 12px' }} />
        <div style={{ fontSize: 14, fontWeight: 500 }}>No Indicators Found</div>
        <div style={{ fontSize: 12, marginTop: 4 }}>Try clearing search filters or uploading log files for extraction</div>
      </div>
    );
  }

  return (
    <div style={{ overflowX: 'auto' }}>
      <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 12 }}>
        <thead>
          <tr style={{ background: 'rgba(10,14,26,0.6)' }}>
            <th style={{ ...headerStyle, textAlign: 'left' }}>Indicator</th>
            <th style={{ ...headerStyle, textAlign: 'left' }}>Type</th>
            <th style={{ ...headerStyle, textAlign: 'left' }}>Review Status</th>
            <th style={{ ...headerStyle, textAlign: 'right' }}>Confidence</th>
            <th style={{ ...headerStyle, textAlign: 'right' }}>Occurrences</th>
            <th style={{ ...headerStyle, textAlign: 'left' }}>First Seen</th>
            <th style={{ ...headerStyle, textAlign: 'center' }}>Inspect</th>
          </tr>
        </thead>
        <tbody>
          <AnimatePresence initial={false}>
            {iocs.map((ioc, idx) => {
              const isSelected = ioc.id === currentSelectedId;
              return (
                <motion.tr
                  key={ioc.id}
                  initial={{ opacity: 0, y: 4 }}
                  animate={{ opacity: 1, y: 0 }}
                  transition={{ delay: idx * 0.015, duration: 0.18 }}
                  onClick={() => handleSelect(ioc)}
                  style={{
                    borderBottom: '1px solid #1A2744',
                    background: isSelected ? 'rgba(59,130,246,0.08)' : 'transparent',
                    cursor: 'pointer',
                    transition: 'background 0.15s',
                  }}
                  onMouseEnter={e => { if (!isSelected) (e.currentTarget as HTMLElement).style.background = '#0F1629'; }}
                  onMouseLeave={e => { if (!isSelected) (e.currentTarget as HTMLElement).style.background = 'transparent'; }}
                >
                  <td style={{ padding: '10px 12px', maxWidth: 220 }}>
                    <div style={{ fontFamily: 'var(--font-mono)', fontSize: 12, color: isSelected ? 'var(--primary)' : 'var(--text-primary)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                      {ioc.normalized_value}
                    </div>
                    {ioc.tags.length > 0 && (
                      <div style={{ display: 'flex', gap: 4, marginTop: 3, flexWrap: 'wrap' }}>
                        {ioc.tags.slice(0, 2).map(t => (
                          <span key={t} style={{ background: '#7C3AED20', border: '1px solid #7C3AED30', color: '#A78BFA', fontSize: 9, padding: '1px 5px', borderRadius: 3 }}>
                            {t}
                          </span>
                        ))}
                      </div>
                    )}
                  </td>
                  <td style={{ padding: '10px 12px' }}>
                    <TypeBadge type={ioc.ioc_type} />
                  </td>
                  <td style={{ padding: '10px 12px' }}>
                    <StatusBadge status={ioc.status} />
                  </td>
                  <td style={{ padding: '10px 12px', textAlign: 'right' }}>
                    <ConfidenceBar value={ioc.confidence} />
                  </td>
                  <td style={{ padding: '10px 12px', textAlign: 'right', fontFamily: 'var(--font-mono)', color: 'var(--text-secondary)', fontSize: 12 }}>
                    {ioc.occurrence_count}
                  </td>
                  <td style={{ padding: '10px 12px', color: 'var(--text-muted)', whiteSpace: 'nowrap', fontSize: 11 }}>
                    <Clock size={11} style={{ display: 'inline', marginRight: 4 }} />
                    {ioc.first_seen ? formatDateTime(ioc.first_seen) : '—'}
                  </td>
                  <td style={{ padding: '10px 12px', textAlign: 'center' }}>
                    <button
                      onClick={e => { e.stopPropagation(); handleSelect(ioc); }}
                      style={{ background: 'transparent', border: 'none', cursor: 'pointer', color: 'var(--text-muted)', padding: 4, borderRadius: 6, display: 'inline-flex', alignItems: 'center' }}
                      title="Investigate IOC"
                    >
                      <Eye size={14} />
                    </button>
                  </td>
                </motion.tr>
              );
            })}
          </AnimatePresence>
        </tbody>
      </table>
    </div>
  );
}

