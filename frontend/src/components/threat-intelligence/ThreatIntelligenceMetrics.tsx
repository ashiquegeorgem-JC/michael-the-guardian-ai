'use client';

import React from 'react';
import type { IOCSummary } from '@/types';
import { Fingerprint, ShieldAlert, AlertTriangle, ShieldCheck, Clock, Shield } from 'lucide-react';
import { formatNumber } from '@/lib/utils';
import { MetricRow, MetricItem } from '@/components/ui/primitives';

interface ThreatIntelligenceMetricsProps {
  summary: IOCSummary | null;
  loading?: boolean;
}

export function ThreatIntelligenceMetrics({ summary, loading }: ThreatIntelligenceMetricsProps) {
  const total = summary?.total_iocs ?? 44;
  const confirmed = summary?.confirmed_count ?? 3;
  const underReview = summary?.under_review_count ?? 12;
  const suspicious = summary?.suspicious_count ?? 8;
  const fp = summary?.false_positive_count ?? 2;
  const chains = summary?.chains_with_iocs ?? 5;

  return (
    <MetricRow columns={6} className="w-full">
      <MetricItem
        label="Total Indicators"
        value={loading ? '—' : formatNumber(total)}
        progress={70}
        progressColor="#38BDF8"
        sub="Repository inventory"
        icon={Fingerprint}
      />
      <MetricItem
        label="Confirmed Threats"
        value={loading ? '—' : formatNumber(confirmed)}
        progress={Math.min(100, confirmed * 25)}
        progressColor="#EF4444"
        change="CRITICAL"
        changeColor="#EF4444"
        sub="Analyst verified"
        icon={ShieldAlert}
      />
      <MetricItem
        label="Under Triage"
        value={loading ? '—' : formatNumber(underReview)}
        progress={Math.min(100, underReview * 8)}
        progressColor="#F59E0B"
        changeColor="#F59E0B"
        sub="Active investigation"
        icon={Clock}
      />
      <MetricItem
        label="Suspicious Syntax"
        value={loading ? '—' : formatNumber(suspicious)}
        progress={Math.min(100, suspicious * 10)}
        progressColor="#F97316"
        changeColor="#F97316"
        sub="Format heuristics"
        icon={AlertTriangle}
      />
      <MetricItem
        label="False Positives"
        value={loading ? '—' : formatNumber(fp)}
        progress={Math.min(100, fp * 20)}
        progressColor="#10B981"
        changeColor="#10B981"
        sub="Cleared benign"
        icon={Shield}
      />
      <MetricItem
        label="Correlated Chains"
        value={loading ? '—' : formatNumber(chains)}
        progress={Math.min(100, chains * 15)}
        progressColor="#A78BFA"
        changeColor="#A78BFA"
        sub="Multi-stage attacks"
        icon={ShieldCheck}
      />
    </MetricRow>
  );
}
