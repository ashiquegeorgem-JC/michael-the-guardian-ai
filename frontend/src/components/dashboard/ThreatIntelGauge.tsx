'use client';

import React from 'react';
import { IOCSummary, IOC } from '@/types';

interface ThreatIntelGaugeProps {
  summary?: IOCSummary | null;
  recentIocs?: IOC[];
}

export function ThreatIntelGauge({ summary, recentIocs = [] }: ThreatIntelGaugeProps) {
  const threatScore = 20;
  const scoreColor = threatScore < 30 ? '#34D399' : threatScore < 60 ? '#FBBF24' : '#F87171';
  const scoreLabel = threatScore < 30 ? 'Normal Baseline' : threatScore < 60 ? 'Elevated' : 'High Risk';

  const totalIocs = summary?.total_iocs ?? recentIocs.length ?? 0;
  const ipCount = summary?.by_type?.ipv4 ?? 0;
  const domainCount = summary?.by_type?.domain ?? 0;
  const hashCount = summary?.by_type?.file_hash ?? 0;
  const confirmedBad = summary?.confirmed_count ?? 0;

  return (
    <div
      style={{
        backgroundColor: '#11161E',
        border: '1px solid rgba(255, 255, 255, 0.08)',
        borderRadius: 16,
        padding: '24px 28px',
        boxShadow: '0 4px 20px rgba(0, 0, 0, 0.35)',
      }}
      className="font-sans h-full flex flex-col"
    >
      {/* Header */}
      <div className="flex items-center justify-between border-b border-white/[0.06] pb-3 mb-4">
        <div>
          <h2 className="text-base font-semibold text-white font-heading">
            Threat Intelligence & IOCs
          </h2>
          <p className="text-xs text-[#94A3B8] font-subheading mt-0.5">
            External reputation feed correlation
          </p>
        </div>
        <div className="flex items-center gap-2">
          <span className="text-[11px] px-2 py-0.5 rounded bg-blue-500/10 text-blue-400 border border-blue-500/20 font-medium">
            Enriched
          </span>
          <span className="text-[11px] px-2 py-0.5 rounded bg-white/[0.05] text-[#94A3B8] border border-white/[0.08]">
            Intel Feed ↗
          </span>
        </div>
      </div>

      {/* Score + Provider Row */}
      <div className="flex items-center justify-between mb-5">
        <div>
          <div className="text-xs text-[#64748B] font-subheading mb-1">Enriched Threat Score</div>
          <div className="flex items-baseline gap-2">
            <span className="text-3xl font-bold font-mono" style={{ color: scoreColor }}>
              {threatScore}
            </span>
            <span className="text-sm text-[#64748B]">/ 100</span>
          </div>
          <div className="text-xs mt-1" style={{ color: scoreColor }}>{scoreLabel}</div>
        </div>

        <div className="text-right text-xs text-[#94A3B8] font-subheading">
          <div className="text-[11px] text-[#64748B] mb-1">Primary Provider</div>
          <div className="flex items-center gap-1.5 justify-end">
            <span className="w-1.5 h-1.5 rounded-full bg-emerald-400" />
            <span className="text-white font-medium">VirusTotal v3</span>
          </div>
          <div className="text-[11px] text-[#64748B] mt-1">Confidence: 96.4%</div>
        </div>
      </div>

      {/* Divider */}
      <div className="border-t border-white/[0.05] mb-4" />

      {/* IOC Breakdown Grid */}
      <div className="text-xs text-[#64748B] font-subheading mb-3">
        Extracted Indicators ({totalIocs} Total)
      </div>
      <div className="grid grid-cols-2 gap-x-6 gap-y-2.5 text-sm flex-1">
        {[
          { label: 'IPv4 Addresses', value: ipCount },
          { label: 'Domains & URLs', value: domainCount },
          { label: 'File Hashes', value: hashCount },
          { label: 'Confirmed Bad', value: confirmedBad, alert: confirmedBad > 0 },
        ].map((row) => (
          <div key={row.label} className="flex items-center justify-between border-b border-white/[0.04] pb-2">
            <span className="text-[#94A3B8] text-xs">{row.label}</span>
            <span
              className="font-mono font-semibold text-xs"
              style={{ color: row.alert ? '#F87171' : '#FFFFFF' }}
            >
              {row.value}
            </span>
          </div>
        ))}
      </div>
    </div>
  );
}
