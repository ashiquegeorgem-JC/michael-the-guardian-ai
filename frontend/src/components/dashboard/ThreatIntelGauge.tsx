'use client';

import React from 'react';
import { IOCSummary, IOC } from '@/types';

interface ThreatIntelGaugeProps {
  summary?: IOCSummary | null;
  recentIocs?: IOC[];
}

export function ThreatIntelGauge({ summary, recentIocs = [] }: ThreatIntelGaugeProps) {
  const threatScore = 82;

  return (
    <div
      style={{
        backgroundColor: '#1C242B',
        border: '1px solid rgba(212, 175, 55, 0.14)',
        borderRadius: '14px',
        padding: '24px',
        boxShadow: '0 4px 16px rgba(0, 0, 0, 0.4)',
      }}
      className="space-y-4 font-sans h-full flex flex-col justify-between"
    >
      {/* Header */}
      <div className="flex items-center justify-between border-b border-[rgba(212,175,55,0.1)] pb-4">
        <div>
          <h2 className="text-base font-semibold text-[#FAF9F5] font-heading">
            Threat Intelligence
          </h2>
        </div>

        <span className="px-2.5 py-0.5 rounded-full text-[10px] font-semibold bg-amber-500/15 text-[#F59E0B] border border-amber-500/30 font-subheading">
          Suspicious
        </span>
      </div>

      {/* Radial Gauge & Details */}
      <div className="flex flex-col sm:flex-row items-center justify-between gap-6 my-auto">
        {/* Radial Circle in Celestial Gold */}
        <div className="relative w-28 h-28 flex items-center justify-center shrink-0">
          <svg className="w-full h-full -rotate-90" viewBox="0 0 100 100">
            <circle
              cx="50"
              cy="50"
              r="40"
              fill="transparent"
              stroke="#141A1F"
              strokeWidth="9"
            />
            <circle
              cx="50"
              cy="50"
              r="40"
              fill="transparent"
              stroke="#D4AF37"
              strokeWidth="9"
              strokeDasharray={2 * Math.PI * 40}
              strokeDashoffset={2 * Math.PI * 40 * (1 - threatScore / 100)}
              strokeLinecap="round"
              style={{
                filter: 'drop-shadow(0 0 6px rgba(212, 175, 55, 0.7))',
              }}
            />
          </svg>

          <div className="absolute inset-0 flex flex-col items-center justify-center text-center">
            <span className="text-2xl font-bold font-mono text-[#FAF9F5] leading-none">
              {threatScore}
            </span>
            <span className="text-[9px] uppercase tracking-wider text-[#D4AF37] font-subheading font-medium mt-1">
              Threat Score
            </span>
          </div>
        </div>

        {/* Threat Context Breakdown */}
        <div className="grid grid-cols-2 gap-x-6 gap-y-3 text-xs flex-1 w-full font-subheading">
          <div>
            <div className="text-[10px] text-[#8E877D]">Provider</div>
            <div className="text-[#FAF9F5] font-medium mt-0.5">VirusTotal</div>
          </div>
          <div>
            <div className="text-[10px] text-[#8E877D]">Detection Ratio</div>
            <div className="text-[#FAF9F5] font-mono font-medium mt-0.5">18 / 62</div>
          </div>
          <div>
            <div className="text-[10px] text-[#8E877D]">Reputation</div>
            <div className="text-[#EF4444] font-medium mt-0.5">Malicious</div>
          </div>
          <div>
            <div className="text-[10px] text-[#8E877D]">Taxonomy</div>
            <div className="text-[#D4AF37] font-medium mt-0.5">C2, Malware</div>
          </div>
        </div>
      </div>
    </div>
  );
}
