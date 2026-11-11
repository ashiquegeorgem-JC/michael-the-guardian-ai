'use client';

import React from 'react';
import { ShieldAlert, Activity } from 'lucide-react';
import { Badge } from '@/components/ui/Badge';
import { Anomaly } from '@/types';
import { formatDate } from '@/lib/utils';

interface AnomalyCardProps {
  anomaly: Anomaly;
  onSelect?: () => void;
}

export function AnomalyCard({ anomaly, onSelect }: AnomalyCardProps) {
  const scorePercent = Math.round(anomaly.score * 100);

  const getMethodLabel = (m: string) => {
    switch (m) {
      case 'isolation_forest':
        return 'Isolation Forest ML';
      case 'tfidf':
        return 'TF-IDF Vector Outlier';
      case 'statistical':
        return 'Statistical Z-Score';
      case 'rule_based':
        return 'Heuristic Rule';
      default:
        return m;
    }
  };

  return (
    <div
      onClick={onSelect}
      style={{
        backgroundColor: '#0C1119',
        border: '1px solid rgba(255, 255, 255, 0.08)',
        borderRadius: '12px',
        padding: '20px',
      }}
      className="hover:border-blue-500/40 transition-all space-y-4 font-sans cursor-pointer group"
    >
      {/* Header */}
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div className="space-y-1">
          <div className="flex items-center gap-2">
            <Badge variant={anomaly.severity} dot size="sm">
              {anomaly.severity}
            </Badge>
            <Badge variant="cyan" size="sm">
              {getMethodLabel(anomaly.method)}
            </Badge>
          </div>
          <h4 className="text-sm font-semibold text-[#F5F7FA] mt-1 group-hover:text-[#3B82F6] transition-colors">
            {anomaly.reason}
          </h4>
        </div>

        {/* Score Meter */}
        <div className="text-right">
          <div className="text-xs text-[#A7B1C0]">Anomaly Score</div>
          <div className="text-base font-bold font-mono text-[#F5F7FA] flex items-center justify-end gap-1.5 mt-0.5">
            <Activity className="w-3.5 h-3.5 text-[#EF4444]" />
            {scorePercent}%
          </div>
        </div>
      </div>

      {/* Structured Details */}
      <div className="grid grid-cols-2 gap-3 p-3 rounded-lg bg-[#080C12] border border-white/[0.04] text-xs">
        <div>
          <span className="text-[#687589]">Source Entity:</span>
          <div className="font-mono text-[#F5F7FA] truncate mt-0.5">
            {(anomaly.source_ip as string | undefined) || (anomaly.host as string | undefined) || '127.0.0.1'}
          </div>
        </div>
        <div>
          <span className="text-[#687589]">Observed Time:</span>
          <div className="font-mono text-[#A7B1C0] mt-0.5">
            {formatDate((anomaly.timestamp as string | undefined) || anomaly.detected_at)}
          </div>
        </div>
      </div>
    </div>
  );
}
