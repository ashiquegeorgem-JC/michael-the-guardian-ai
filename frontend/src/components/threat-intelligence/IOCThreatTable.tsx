'use client';

import React from 'react';
import type { IOC } from '@/types';
import { Eye, Shield, Globe, Hash, FileCode, Mail, Folder, ExternalLink } from 'lucide-react';

interface IOCThreatTableProps {
  iocs: IOC[];
  selectedId: string | null;
  onSelect: (ioc: IOC) => void;
  loading?: boolean;
}

export function IOCThreatTable({
  iocs,
  selectedId,
  onSelect,
  loading,
}: IOCThreatTableProps) {
  if (loading && iocs.length === 0) {
    return (
      <div style={{ padding: '40px', textAlign: 'center', color: 'var(--text-muted)', fontSize: 13 }}>
        Loading threat indicators...
      </div>
    );
  }

  if (iocs.length === 0) {
    return (
      <div style={{ padding: '40px', textAlign: 'center', color: 'var(--text-muted)', fontSize: 13 }}>
        No threat intelligence indicators match the current query criteria.
      </div>
    );
  }

  const getTypeIcon = (type: string) => {
    switch (type) {
      case 'ipv4':
      case 'ipv6':
        return <Globe size={13} color="#38BDF8" />;
      case 'domain':
      case 'url':
        return <ExternalLink size={13} color="#818CF8" />;
      case 'md5':
      case 'sha1':
      case 'sha256':
        return <Hash size={13} color="#F472B6" />;
      case 'email':
        return <Mail size={13} color="#FBBF24" />;
      case 'file_path':
        return <Folder size={13} color="#34D399" />;
      default:
        return <FileCode size={13} color="#94A3B8" />;
    }
  };

  const getAnalystBadge = (status: string) => {
    switch (status) {
      case 'CONFIRMED':
        return { bg: 'rgba(239, 68, 68, 0.15)', border: 'rgba(239, 68, 68, 0.4)', color: '#EF4444' };
      case 'UNDER_REVIEW':
        return { bg: 'rgba(245, 158, 11, 0.15)', border: 'rgba(245, 158, 11, 0.4)', color: '#F59E0B' };
      case 'FALSE_POSITIVE':
        return { bg: 'rgba(16, 185, 129, 0.15)', border: 'rgba(16, 185, 129, 0.4)', color: '#10B981' };
      case 'EXTRACTED':
      default:
        return { bg: 'rgba(100, 116, 139, 0.15)', border: 'rgba(100, 116, 139, 0.3)', color: '#94A3B8' };
    }
  };

  return (
    <div style={{ width: '100%', overflowX: 'auto' }}>
      <table
        style={{
          width: '100%',
          borderCollapse: 'collapse',
          fontSize: 12,
          textAlign: 'left',
        }}
      >
        <thead>
          <tr
            style={{
              borderBottom: '1px solid #1E2D4A',
              background: 'rgba(8, 12, 22, 0.6)',
              color: 'var(--text-muted)',
              fontSize: 11,
              fontWeight: 600,
              letterSpacing: '0.04em',
              textTransform: 'uppercase',
            }}
          >
            <th style={{ padding: '12px 16px' }}>Indicator Value</th>
            <th style={{ padding: '12px 14px' }}>Type</th>
            <th style={{ padding: '12px 14px' }}>Triage State</th>
            <th style={{ padding: '12px 14px' }}>Validation</th>
            <th style={{ padding: '12px 14px', textAlign: 'center' }}>Occurrences</th>
            <th style={{ padding: '12px 14px' }}>Correlated Entities</th>
            <th style={{ padding: '12px 16px', textAlign: 'right' }}>Actions</th>
          </tr>
        </thead>
        <tbody>
          {iocs.map((ioc) => {
            const isSelected = selectedId === ioc.id;
            const analystBadge = getAnalystBadge(ioc.status);
            const totalCorrelations =
              (ioc.associated_chain_ids?.length || 0) +
              (ioc.associated_incident_ids?.length || 0) +
              (ioc.associated_anomaly_ids?.length || 0);

            return (
              <tr
                key={ioc.id}
                onClick={() => onSelect(ioc)}
                style={{
                  borderBottom: '1px solid #162036',
                  background: isSelected ? 'rgba(59, 130, 246, 0.1)' : 'transparent',
                  cursor: 'pointer',
                  transition: 'background 0.15s ease',
                }}
                onMouseEnter={(e) => {
                  if (!isSelected) e.currentTarget.style.background = 'rgba(15, 23, 42, 0.5)';
                }}
                onMouseLeave={(e) => {
                  if (!isSelected) e.currentTarget.style.background = 'transparent';
                }}
              >
                {/* Indicator Value */}
                <td style={{ padding: '12px 16px' }}>
                  <div style={{ display: 'flex', flexDirection: 'column', gap: 2 }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                      {getTypeIcon(ioc.ioc_type)}
                      <span
                        style={{
                          fontWeight: 700,
                          fontFamily: 'var(--font-mono)',
                          color: '#F8FAFC',
                          fontSize: 12,
                        }}
                      >
                        {ioc.normalized_value}
                      </span>
                    </div>
                    {ioc.raw_value !== ioc.normalized_value && (
                      <div
                        style={{
                          fontSize: 10,
                          color: 'var(--text-muted)',
                          fontFamily: 'var(--font-mono)',
                          paddingLeft: 19,
                        }}
                      >
                        raw: {ioc.raw_value}
                      </div>
                    )}
                  </div>
                </td>

                {/* Type */}
                <td style={{ padding: '12px 14px' }}>
                  <span
                    style={{
                      fontSize: 10,
                      fontWeight: 700,
                      textTransform: 'uppercase',
                      padding: '2px 6px',
                      borderRadius: 4,
                      background: '#1A253C',
                      color: '#94A3B8',
                      fontFamily: 'var(--font-mono)',
                    }}
                  >
                    {ioc.ioc_type}
                  </span>
                </td>

                {/* Analyst Status (Lifecycle) */}
                <td style={{ padding: '12px 14px' }}>
                  <span
                    style={{
                      fontSize: 10,
                      fontWeight: 700,
                      padding: '2px 8px',
                      borderRadius: 4,
                      background: analystBadge.bg,
                      border: `1px solid ${analystBadge.border}`,
                      color: analystBadge.color,
                      fontFamily: 'var(--font-mono)',
                    }}
                  >
                    {ioc.status}
                  </span>
                </td>

                {/* Validation Status */}
                <td style={{ padding: '12px 14px' }}>
                  <span
                    style={{
                      fontSize: 10,
                      fontWeight: 600,
                      color:
                        ioc.validation_status === 'VALID'
                          ? '#10B981'
                          : ioc.validation_status === 'SUSPICIOUS'
                          ? '#F59E0B'
                          : '#94A3B8',
                    }}
                  >
                    {ioc.validation_status || 'VALID'}
                  </span>
                </td>

                {/* Occurrences */}
                <td style={{ padding: '12px 14px', textAlign: 'center' }}>
                  <span
                    style={{
                      fontFamily: 'var(--font-mono)',
                      fontWeight: 700,
                      color: '#E2E8F0',
                      fontSize: 12,
                    }}
                  >
                    {ioc.occurrence_count}
                  </span>
                </td>

                {/* Correlated Entities count */}
                <td style={{ padding: '12px 14px' }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 6, fontSize: 11, color: 'var(--text-muted)' }}>
                    {ioc.associated_chain_ids?.length > 0 && (
                      <span style={{ color: '#A78BFA' }}>{ioc.associated_chain_ids.length} chains</span>
                    )}
                    {ioc.associated_incident_ids?.length > 0 && (
                      <span style={{ color: '#EF4444' }}>{ioc.associated_incident_ids.length} incs</span>
                    )}
                    {ioc.associated_anomaly_ids?.length > 0 && (
                      <span style={{ color: '#F59E0B' }}>{ioc.associated_anomaly_ids.length} anoms</span>
                    )}
                    {totalCorrelations === 0 && <span>None linked</span>}
                  </div>
                </td>

                {/* Actions */}
                <td style={{ padding: '12px 16px', textAlign: 'right' }}>
                  <button
                    type="button"
                    onClick={(e) => {
                      e.stopPropagation();
                      onSelect(ioc);
                    }}
                    style={{
                      display: 'inline-flex',
                      alignItems: 'center',
                      gap: 4,
                      padding: '4px 10px',
                      background: isSelected ? '#3B82F6' : '#1E2D4A',
                      border: 'none',
                      borderRadius: 6,
                      color: isSelected ? '#FFFFFF' : '#CBD5E1',
                      fontSize: 11,
                      fontWeight: 600,
                      cursor: 'pointer',
                    }}
                  >
                    <Eye size={12} />
                    {isSelected ? 'Active' : 'Inspect'}
                  </button>
                </td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}

