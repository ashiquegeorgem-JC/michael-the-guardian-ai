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
        return 'TF-IDF Dispersion';
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
        backgroundColor: '#11161E',
        border: '1px solid rgba(255, 255, 255, 0.08)',
        borderRadius: '16px',
        padding: '22px',
        boxShadow: '0 4px 20px rgba(0, 0, 0, 0.35)',
      }}
      className="hover:border-white/20 transition-all space-y-4 font-sans cursor-pointer group flex flex-col justify-between"
    >
      {/* Header */}
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div className="space-y-1.5 flex-1 min-w-[200px]">
          <div className="flex items-center gap-2">
            <Badge variant={anomaly.severity} dot size="sm">
              {anomaly.severity}
            </Badge>
            <span className="text-[10px] font-mono uppercase px-2 py-0.5 rounded bg-white/[0.04] text-slate-300 border border-white/[0.06]">
              {getMethodLabel(anomaly.method)}
            </span>
          </div>
          <h4 className="text-sm font-semibold text-white mt-1 group-hover:text-sky-300 transition-colors line-clamp-2">
            {anomaly.reason}
          </h4>
        </div>

        {/* Score Meter */}
        <div className="text-right shrink-0">
          <div className="text-[11px] text-[#64748B] font-mono uppercase">Score</div>
          <div className="text-base font-bold font-mono text-white flex items-center justify-end gap-1.5 mt-0.5">
            <Activity className="w-3.5 h-3.5 text-[#EF4444]" />
            {scorePercent}%
          </div>
        </div>
      </div>

      {/* Structured Details */}
      <div className="grid grid-cols-2 gap-3 p-3 rounded-xl bg-[#090D13] border border-white/[0.05] text-xs">
        <div className="min-w-0">
          <span className="text-[10px] font-mono uppercase text-[#64748B] block">Source Entity</span>
          <div className="font-mono text-xs text-slate-200 truncate mt-0.5">
            {(anomaly.source_ip as string | undefined) || (anomaly.host as string | undefined) || '127.0.0.1'}
          </div>
        </div>
        <div className="min-w-0">
          <span className="text-[10px] font-mono uppercase text-[#64748B] block">Observed Time</span>
          <div className="font-mono text-xs text-slate-300 truncate mt-0.5">
            {formatDate((anomaly.timestamp as string | undefined) || anomaly.detected_at)}
          </div>
        </div>
      </div>
    </div>
  );
}
