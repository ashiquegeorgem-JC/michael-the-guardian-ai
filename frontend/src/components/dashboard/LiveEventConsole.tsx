'use client';

import React from 'react';

interface LiveEventConsoleProps {
  events: string[];
  wsConnected: boolean;
}

const BADGE_CONFIG: Record<string, { bg: string; text: string; label: string }> = {
  CRITICAL: { bg: 'rgba(248, 113, 113, 0.12)', text: '#F87171', label: 'CRIT' },
  IOC:      { bg: 'rgba(251, 191, 36, 0.12)',  text: '#FBBF24', label: 'IOC'  },
  INCIDENT: { bg: 'rgba(167, 139, 250, 0.12)', text: '#A78BFA', label: 'INC'  },
  TEMPORAL: { bg: 'rgba(96, 165, 250, 0.12)',  text: '#60A5FA', label: 'TIME' },
  INTEL:    { bg: 'rgba(52, 211, 153, 0.12)',  text: '#34D399', label: 'INTEL'},
};

const TEXT_COLORS: Record<string, string> = {
  CRITICAL: '#F87171',
  IOC:      '#FBBF24',
  INCIDENT: '#A78BFA',
  TEMPORAL: '#94A3B8',
  INTEL:    '#34D399',
};

const SAMPLE_EVENTS = [
  { time: '12:00:00', type: 'CRITICAL', msg: '[ERROR] Authentication failed for user admin from 10.0.0.7' },
  { time: '12:00:00', type: 'TEMPORAL', msg: '[WARNING] High memory usage detected: 82.7%' },
  { time: '12:00:00', type: 'TEMPORAL', msg: '[WARNING] High memory usage detected: 82.8%' },
  { time: '12:00:00', type: 'CRITICAL', msg: '[ERROR] Authentication failed for user admin from 10.0.0.50' },
  { time: '12:00:00', type: 'CRITICAL', msg: '[ERROR] Authentication failed for user admin from 10.0.0.80' },
  { time: '12:00:00', type: 'IOC',      msg: '[CRITICAL] Disk space low on /dev/sda1: 86% used' },
];

export function LiveEventConsole({ events, wsConnected }: LiveEventConsoleProps) {
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
      <div className="flex flex-wrap items-center justify-between gap-3 border-b border-white/[0.06] pb-3 mb-3">
        <div>
          <div className="flex items-center gap-2">
            <h2 className="text-base font-semibold text-white font-heading">
              Live Security Events
            </h2>
            <span className="text-[10px] uppercase font-mono px-2 py-0.5 rounded bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
              SOC Feed
            </span>
          </div>
          <p className="text-xs text-[#94A3B8] font-subheading mt-0.5">
            Real-time ingested system logs and alert triggers
          </p>
        </div>

        <div className="flex items-center gap-1.5 text-[11px]">
          <span
            className="w-1.5 h-1.5 rounded-full"
            style={{ backgroundColor: wsConnected ? '#34D399' : '#FBBF24' }}
          />
          <span style={{ color: wsConnected ? '#34D399' : '#FBBF24' }}>
            {wsConnected ? 'Streaming Live' : 'Polling'}
          </span>
        </div>
      </div>

      {/* Event Log — monospaced, clean */}
      <div className="flex-1 overflow-y-auto space-y-1 font-mono text-[12px]">
        {SAMPLE_EVENTS.map((item, idx) => {
          const cfg = BADGE_CONFIG[item.type] || BADGE_CONFIG.CRITICAL;
          const textColor = TEXT_COLORS[item.type] || '#94A3B8';

          return (
            <div
              key={idx}
              className="flex items-start gap-3 py-1 border-b border-white/[0.03] hover:bg-white/[0.015] transition-colors"
            >
              <span className="text-[#64748B] text-[11px] shrink-0 mt-0.5">{item.time}</span>
              <span
                style={{ backgroundColor: cfg.bg, color: cfg.text }}
                className="text-[9px] px-1.5 py-0.5 rounded font-bold uppercase shrink-0 mt-0.5 w-9 text-center"
              >
                {cfg.label}
              </span>
              <span style={{ color: textColor }} className="leading-snug">
                {item.msg}
              </span>
            </div>
          );
        })}
      </div>

      {/* Footer Status */}
      <div className="flex items-center justify-between pt-3 mt-2 border-t border-white/[0.05] text-[11px] text-[#64748B]">
        <span className="flex items-center gap-1.5">
          <span className="w-1.5 h-1.5 rounded-full bg-emerald-400" />
          Status: Streaming Live
        </span>
        <span className="font-mono">Buffer: {SAMPLE_EVENTS.length} events</span>
      </div>
    </div>
  );
}
