'use client';

import React from 'react';
import { SystemMetrics, WsMessage } from '@/types';

interface SystemTelemetryStripProps {
  metrics?: SystemMetrics | null;
  wsData?: WsMessage['data'] | null;
  wsConnected: boolean;
}

export function SystemTelemetryStrip({
  metrics,
  wsData,
  wsConnected,
}: SystemTelemetryStripProps) {
  const cpuPercent = wsData?.cpu_percent ?? metrics?.cpu_percent ?? 42;
  const memPercent = wsData?.memory_percent ?? metrics?.memory_percent ?? 56;
  const diskPercent = wsData?.disk_percent ?? metrics?.disk_percent ?? 38;

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
      <div className="border-b border-[rgba(212,175,55,0.1)] pb-4">
        <h2 className="text-base font-semibold text-[#FAF9F5] font-heading">
          System Telemetry
        </h2>
        <p className="text-xs text-[#D1CBC0] font-subheading font-light mt-1">
          Infrastructure health and performance
        </p>
      </div>

      {/* Resource Progress Bars in Celestial Gold & Cyan */}
      <div className="flex flex-col sm:flex-row items-center justify-between gap-6 my-auto">
        <div className="space-y-3 flex-1 w-full font-subheading">
          {/* CPU */}
          <div className="space-y-1">
            <div className="flex items-center justify-between text-xs">
              <span className="text-[#D1CBC0]">CPU</span>
              <span className="font-mono text-[#FAF9F5] font-medium">{Math.round(cpuPercent)}%</span>
            </div>
            <div className="h-2 w-full rounded-full bg-[#141A1F] overflow-hidden border border-[rgba(212,175,55,0.08)]">
              <div
                className="h-full rounded-full bg-gradient-to-r from-[#D4AF37] to-[#38BDF8]"
                style={{ width: `${Math.round(cpuPercent)}%` }}
              />
            </div>
          </div>

          {/* Memory */}
          <div className="space-y-1">
            <div className="flex items-center justify-between text-xs">
              <span className="text-[#D1CBC0]">Memory</span>
              <span className="font-mono text-[#FAF9F5] font-medium">{Math.round(memPercent)}%</span>
            </div>
            <div className="h-2 w-full rounded-full bg-[#141A1F] overflow-hidden border border-[rgba(212,175,55,0.08)]">
              <div
                className="h-full rounded-full bg-gradient-to-r from-[#D4AF37] to-[#38BDF8]"
                style={{ width: `${Math.round(memPercent)}%` }}
              />
            </div>
          </div>

          {/* Disk */}
          <div className="space-y-1">
            <div className="flex items-center justify-between text-xs">
              <span className="text-[#D1CBC0]">Disk</span>
              <span className="font-mono text-[#FAF9F5] font-medium">{Math.round(diskPercent)}%</span>
            </div>
            <div className="h-2 w-full rounded-full bg-[#141A1F] overflow-hidden border border-[rgba(212,175,55,0.08)]">
              <div
                className="h-full rounded-full bg-gradient-to-r from-[#D4AF37] to-[#38BDF8]"
                style={{ width: `${Math.round(diskPercent)}%` }}
              />
            </div>
          </div>
        </div>

        {/* Event Rate Box in Charcoal & Celestial Gold */}
        <div
          style={{
            backgroundColor: '#141A1F',
            border: '1px solid rgba(212, 175, 55, 0.16)',
            borderRadius: '12px',
            padding: '14px 20px',
            boxShadow: '0 0 16px rgba(212, 175, 55, 0.08)',
          }}
          className="flex flex-col items-center justify-center shrink-0 min-w-[130px] text-center"
        >
          <span className="text-[10px] text-[#D4AF37] font-subheading uppercase tracking-wider font-semibold">
            Event Rate
          </span>
          <div className="flex items-baseline gap-1.5 mt-1">
            <span className="text-xl font-bold font-mono text-[#FAF9F5]">
              128
            </span>
            <span className="text-xs text-[#8E877D] font-mono">/ sec</span>
          </div>
          <span className="text-[11px] font-mono text-[#22C55E] mt-0.5">
            ↑ +6%
          </span>
        </div>
      </div>
    </div>
  );
}
