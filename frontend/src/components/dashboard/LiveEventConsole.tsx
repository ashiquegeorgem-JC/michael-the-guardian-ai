'use client';

import React, { useState, useEffect } from 'react';

interface LiveEventConsoleProps {
  events: string[];
  wsConnected: boolean;
}

const BADGE_STYLES: Record<string, { bg: string; text: string; border: string }> = {
  CRITICAL: {
    bg: 'rgba(239, 68, 68, 0.15)',
    text: '#EF4444',
    border: 'rgba(239, 68, 68, 0.3)',
  },
  IOC: {
    bg: 'rgba(212, 175, 55, 0.15)',
    text: '#D4AF37',
    border: 'rgba(212, 175, 55, 0.35)',
  },
  INCIDENT: {
    bg: 'rgba(167, 139, 250, 0.15)',
    text: '#A78BFA',
    border: 'rgba(167, 139, 250, 0.3)',
  },
  TEMPORAL: {
    bg: 'rgba(245, 158, 11, 0.15)',
    text: '#F59E0B',
    border: 'rgba(245, 158, 11, 0.3)',
  },
  INTEL: {
    bg: 'rgba(34, 197, 94, 0.15)',
    text: '#22C55E',
    border: 'rgba(34, 197, 94, 0.3)',
  },
};

export function LiveEventConsole({ events, wsConnected }: LiveEventConsoleProps) {
  const [mounted, setMounted] = useState(false);

  useEffect(() => {
    setMounted(true);
  }, []);

  const sampleEvents = [
    {
      time: '10:42:18',
      type: 'CRITICAL',
      msg: 'SSH brute-force behaviour detected from 198.51.100.45',
    },
    {
      time: '10:42:21',
      type: 'IOC',
      msg: 'IPv4 indicator extracted: 198.51.100.45',
    },
    {
      time: '10:42:23',
      type: 'INCIDENT',
      msg: 'Incident INC-0427 created (Brute Force Attack)',
    },
    {
      time: '10:42:27',
      type: 'TEMPORAL',
      msg: 'Authentication burst detected (12 attempts / 60s)',
    },
    {
      time: '10:42:31',
      type: 'INTEL',
      msg: 'Threat intelligence lookup completed (Malicious)',
    },
  ];

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
      {/* Console Header */}
      <div className="flex flex-wrap items-center justify-between gap-3 border-b border-[rgba(212,175,55,0.1)] pb-4">
        <div>
          <h2 className="text-base font-semibold text-[#FAF9F5] font-heading">
            Live Security Event Stream
          </h2>
          <p className="text-xs text-[#D1CBC0] font-subheading font-light mt-1">
            Real-time security events from the detection pipeline
          </p>
        </div>

        <div className="flex items-center gap-2 text-xs font-subheading">
          <span
            className="w-2 h-2 rounded-full"
            style={{
              backgroundColor: wsConnected ? '#22C55E' : '#D4AF37',
              boxShadow: wsConnected ? '0 0 6px #22C55E' : '0 0 6px #D4AF37',
            }}
          />
          <span className="text-[#D1CBC0] text-[11px]">
            {wsConnected ? 'Streaming Live' : 'Polling'}
          </span>
        </div>
      </div>

      {/* Event Stream Rows */}
      <div className="space-y-2.5 overflow-hidden font-mono text-xs my-auto">
        {sampleEvents.map((item, idx) => {
          const badgeCfg = BADGE_STYLES[item.type] || BADGE_STYLES.CRITICAL;

          return (
            <div
              key={idx}
              className="flex items-center gap-3 px-3 py-2 rounded-lg bg-[#141A1F] border border-[rgba(212,175,55,0.06)] hover:border-[rgba(212,175,55,0.15)] transition-colors"
            >
              <span className="text-[#8E877D] text-[11px] shrink-0">
                {item.time}
              </span>

              <span
                style={{
                  backgroundColor: badgeCfg.bg,
                  color: badgeCfg.text,
                  border: `1px solid ${badgeCfg.border}`,
                }}
                className="text-[9px] px-2 py-0.5 rounded font-bold uppercase shrink-0"
              >
                {item.type}
              </span>

              <span className="text-[#FAF9F5] text-[11px] truncate leading-tight">
                {item.msg}
              </span>
            </div>
          );
        })}
      </div>
    </div>
  );
}
