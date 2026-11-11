'use client';

import React from 'react';
import type { IOCSummary } from '@/types';
import { Fingerprint, ShieldAlert, AlertTriangle, ShieldCheck, HelpCircle, Clock, CheckCircle2, Shield } from 'lucide-react';
import { formatNumber } from '@/lib/utils';

interface ThreatIntelligenceMetricsProps {
  summary: IOCSummary | null;
  loading?: boolean;
}

export function ThreatIntelligenceMetrics({ summary, loading }: ThreatIntelligenceMetricsProps) {
  const cards = [
    {
      label: 'Total Indicators',
      value: summary?.total_iocs ?? 0,
      color: '#3B82F6',
      icon: Fingerprint,
      sub: 'Repository inventory',
    },
    {
      label: 'Confirmed Threats',
      value: summary?.confirmed_count ?? 0,
      color: '#EF4444',
      icon: ShieldAlert,
      sub: 'Analyst verified',
    },
    {
      label: 'Under Triage',
      value: summary?.under_review_count ?? 0,
      color: '#F59E0B',
      icon: Clock,
      sub: 'Active investigation',
    },
    {
      label: 'Suspicious Syntax',
      value: summary?.suspicious_count ?? 0,
      color: '#F97316',
      icon: AlertTriangle,
      sub: 'Format heuristics',
    },
    {
      label: 'False Positives',
      value: summary?.false_positive_count ?? 0,
      color: '#10B981',
      icon: Shield,
      sub: 'Cleared benign',
    },
    {
      label: 'Correlated Chains',
      value: summary?.chains_with_iocs ?? 0,
      color: '#8B5CF6',
      icon: ShieldCheck,
      sub: 'Multi-stage attacks',
    },
  ];

  return (
    <div
      style={{
        display: 'grid',
        gridTemplateColumns: 'repeat(auto-fit, minmax(170px, 1fr))',
        gap: 12,
      }}
    >
      {cards.map((card, idx) => {
        const Icon = card.icon;
        return (
          <div
            key={`kpi-${idx}`}
            style={{
              background: 'rgba(10, 14, 26, 0.9)',
              border: `1px solid ${card.color}25`,
              borderRadius: 12,
              padding: '14px 16px',
              display: 'flex',
              alignItems: 'center',
              gap: 12,
            }}
          >
            <div
              style={{
                width: 38,
                height: 38,
                borderRadius: 10,
                background: `${card.color}15`,
                border: `1px solid ${card.color}35`,
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                flexShrink: 0,
              }}
            >
              <Icon size={18} color={card.color} />
            </div>
            <div>
              <div
                style={{
                  fontSize: 10,
                  fontWeight: 600,
                  letterSpacing: '0.06em',
                  textTransform: 'uppercase',
                  color: 'var(--text-muted)',
                }}
              >
                {card.label}
              </div>
              <div
                style={{
                  fontSize: 20,
                  fontWeight: 800,
                  fontFamily: 'var(--font-mono)',
                  color: card.color,
                  lineHeight: 1.2,
                }}
              >
                {loading ? '—' : formatNumber(card.value)}
              </div>
              <div style={{ fontSize: 10, color: 'var(--text-muted)', marginTop: 1 }}>
                {card.sub}
              </div>
            </div>
          </div>
        );
      })}
    </div>
  );
}

