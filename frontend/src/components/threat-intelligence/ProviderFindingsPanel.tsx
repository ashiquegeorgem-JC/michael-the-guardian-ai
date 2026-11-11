'use client';

import React from 'react';
import type { ThreatIntelResult } from '@/types';
import { Server, Globe, ShieldAlert, CheckCircle2, Clock, Activity, Tag } from 'lucide-react';

interface ProviderFindingsPanelProps {
  result?: ThreatIntelResult | null;
  loading?: boolean;
}

export function ProviderFindingsPanel({ result, loading }: ProviderFindingsPanelProps) {
  if (loading) {
    return (
      <div style={{ padding: '24px', textAlign: 'center', color: 'var(--text-muted)', fontSize: 13 }}>
        Loading provider findings...
      </div>
    );
  }

  if (!result) {
    return (
      <div
        style={{
          background: 'rgba(13, 20, 36, 0.7)',
          border: '1px solid #1E2D4A',
          borderRadius: 12,
          padding: '20px',
          textAlign: 'center',
          color: 'var(--text-muted)',
          fontSize: 12,
        }}
      >
        No external provider intelligence has been attached to this indicator.
      </div>
    );
  }

  const getStatusBadge = (status: string) => {
    switch (status) {
      case 'MALICIOUS':
        return { bg: 'rgba(239, 68, 68, 0.15)', border: 'rgba(239, 68, 68, 0.4)', color: '#EF4444' };
      case 'SUSPICIOUS':
        return { bg: 'rgba(245, 158, 11, 0.15)', border: 'rgba(245, 158, 11, 0.4)', color: '#F59E0B' };
      case 'CLEAN':
        return { bg: 'rgba(16, 185, 129, 0.15)', border: 'rgba(16, 185, 129, 0.4)', color: '#10B981' };
      case 'ERROR':
        return { bg: 'rgba(239, 68, 68, 0.1)', border: 'rgba(239, 68, 68, 0.3)', color: '#F87171' };
      case 'UNKNOWN':
      default:
        return { bg: 'rgba(100, 116, 139, 0.15)', border: 'rgba(100, 116, 139, 0.3)', color: '#94A3B8' };
    }
  };

  const statusBadge = getStatusBadge(result.status);

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
      {/* Header */}
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: 8 }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
          <div
            style={{
              width: 32,
              height: 32,
              borderRadius: 8,
              background: '#1E2D4A',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
            }}
          >
            <Server size={16} color="#38BDF8" />
          </div>
          <div>
            <div style={{ fontSize: 13, fontWeight: 700, color: '#F8FAFC' }}>
              {result.provider_name.toUpperCase()} Threat Feed
            </div>
            <div style={{ fontSize: 10, color: 'var(--text-muted)', fontFamily: 'var(--font-mono)' }}>
              Source: {result.source} | Version: {result.provider_version || '1.0.0'}
            </div>
          </div>
        </div>

        <div
          style={{
            padding: '3px 10px',
            borderRadius: 6,
            background: statusBadge.bg,
            border: `1px solid ${statusBadge.border}`,
            color: statusBadge.color,
            fontSize: 11,
            fontWeight: 800,
            letterSpacing: '0.06em',
            fontFamily: 'var(--font-mono)',
          }}
        >
          {result.status}
        </div>
      </div>

      {/* Primary Telemetry Grid */}
      <div
        style={{
          display: 'grid',
          gridTemplateColumns: 'repeat(auto-fit, minmax(140px, 1fr))',
          gap: 10,
        }}
      >
        {/* Detection Ratio */}
        <div
          style={{
            background: 'rgba(10, 14, 26, 0.8)',
            border: '1px solid #1A253C',
            borderRadius: 8,
            padding: '10px 12px',
          }}
        >
          <div style={{ fontSize: 10, color: 'var(--text-muted)', fontWeight: 600, textTransform: 'uppercase' }}>
            Engine Detection
          </div>
          <div style={{ fontSize: 16, fontWeight: 800, fontFamily: 'var(--font-mono)', color: '#F8FAFC', marginTop: 2 }}>
            {result.detection_count !== null && result.detection_count !== undefined
              ? `${result.detection_count} / ${result.total_engines || '?'}`
              : 'N/A'}
          </div>
          {result.total_engines ? (
            <div style={{ fontSize: 10, color: 'var(--text-muted)', marginTop: 2 }}>
              {(((result.detection_count || 0) / result.total_engines) * 100).toFixed(1)}% detection ratio
            </div>
          ) : null}
        </div>

        {/* Reputation Score */}
        <div
          style={{
            background: 'rgba(10, 14, 26, 0.8)',
            border: '1px solid #1A253C',
            borderRadius: 8,
            padding: '10px 12px',
          }}
        >
          <div style={{ fontSize: 10, color: 'var(--text-muted)', fontWeight: 600, textTransform: 'uppercase' }}>
            Normalized Rep
          </div>
          <div style={{ fontSize: 16, fontWeight: 800, fontFamily: 'var(--font-mono)', color: '#38BDF8', marginTop: 2 }}>
            {result.reputation_score !== null && result.reputation_score !== undefined
              ? result.reputation_score.toFixed(2)
              : 'N/A'}
          </div>
          <div style={{ fontSize: 10, color: 'var(--text-muted)', marginTop: 2 }}>
            Scale: 0.0 (benign) - 1.0 (malicious)
          </div>
        </div>

        {/* Confidence */}
        <div
          style={{
            background: 'rgba(10, 14, 26, 0.8)',
            border: '1px solid #1A253C',
            borderRadius: 8,
            padding: '10px 12px',
          }}
        >
          <div style={{ fontSize: 10, color: 'var(--text-muted)', fontWeight: 600, textTransform: 'uppercase' }}>
            Feed Confidence
          </div>
          <div style={{ fontSize: 16, fontWeight: 800, fontFamily: 'var(--font-mono)', color: '#A78BFA', marginTop: 2 }}>
            {(result.confidence * 100).toFixed(0)}%
          </div>
          <div style={{ fontSize: 10, color: 'var(--text-muted)', marginTop: 2 }}>
            Intelligence integrity
          </div>
        </div>

        {/* ASN / Geo */}
        <div
          style={{
            background: 'rgba(10, 14, 26, 0.8)',
            border: '1px solid #1A253C',
            borderRadius: 8,
            padding: '10px 12px',
          }}
        >
          <div style={{ fontSize: 10, color: 'var(--text-muted)', fontWeight: 600, textTransform: 'uppercase' }}>
            Network / Origin
          </div>
          <div style={{ fontSize: 13, fontWeight: 700, fontFamily: 'var(--font-mono)', color: '#E2E8F0', marginTop: 4 }}>
            {result.asn || 'AS Unknown'}
          </div>
          <div style={{ fontSize: 10, color: 'var(--text-muted)', marginTop: 2 }}>
            Country: {result.country || 'Unknown'}
          </div>
        </div>
      </div>

      {/* Categories & Tags */}
      {(result.categories.length > 0 || result.tags.length > 0) && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
          <div style={{ fontSize: 11, fontWeight: 600, color: 'var(--text-muted)' }}>
            Threat Categories &amp; Behavioral Tags
          </div>
          <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6 }}>
            {result.categories.map((cat, idx) => (
              <span
                key={`cat-${idx}`}
                style={{
                  fontSize: 10,
                  fontWeight: 600,
                  fontFamily: 'var(--font-mono)',
                  padding: '2px 8px',
                  borderRadius: 4,
                  background: 'rgba(239, 68, 68, 0.12)',
                  border: '1px solid rgba(239, 68, 68, 0.3)',
                  color: '#F87171',
                }}
              >
                {cat}
              </span>
            ))}
            {result.tags.map((tag, idx) => (
              <span
                key={`tag-${idx}`}
                style={{
                  fontSize: 10,
                  fontWeight: 500,
                  fontFamily: 'var(--font-mono)',
                  padding: '2px 8px',
                  borderRadius: 4,
                  background: 'rgba(56, 189, 248, 0.1)',
                  border: '1px solid rgba(56, 189, 248, 0.25)',
                  color: '#38BDF8',
                }}
              >
                #{tag}
              </span>
            ))}
          </div>
        </div>
      )}

      {/* Timestamps footer */}
      <div
        style={{
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
          fontSize: 10,
          color: 'var(--text-muted)',
          borderTop: '1px solid #1A253C',
          paddingTop: 10,
          flexWrap: 'wrap',
          gap: 6,
        }}
      >
        <div>Queried At: {new Date(result.queried_at).toLocaleString()}</div>
        {result.lookup_latency_ms !== null && result.lookup_latency_ms !== undefined && (
          <div>Latency: {result.lookup_latency_ms.toFixed(1)}ms</div>
        )}
      </div>
    </div>
  );
}

