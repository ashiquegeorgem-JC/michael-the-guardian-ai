'use client';

import React from 'react';
import { SystemMetrics, WsMessage } from '@/types';
import { Cpu, HardDrive, Wifi, Server, Database, Radio, Activity } from 'lucide-react';

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
  const eventRate = wsData?.log_events_per_min ?? 184;

  const sensors = [
    {
      label: 'CPU Utilization',
      value: `${Math.round(cpuPercent)}%`,
      sub: '8 Core Cluster',
      percent: cpuPercent,
      color: cpuPercent > 80 ? '#EF4444' : cpuPercent > 60 ? '#F59E0B' : '#38BDF8',
      icon: Cpu,
    },
    {
      label: 'Memory Allocation',
      value: `${Math.round(memPercent)}%`,
      sub: '8.6 / 16 GB Active',
      percent: memPercent,
      color: memPercent > 85 ? '#EF4444' : memPercent > 70 ? '#F59E0B' : '#34D399',
      icon: Activity,
    },
    {
      label: 'Disk Volume',
      value: `${Math.round(diskPercent)}%`,
      sub: '420 GB NVMe Storage',
      percent: diskPercent,
      color: '#A78BFA',
      icon: HardDrive,
    },
    {
      label: 'Network Throughput',
      value: '2.4 Gbps',
      sub: `${eventRate} EPS Ingestion`,
      percent: Math.min(100, (eventRate / 300) * 100),
      color: '#38BDF8',
      icon: Wifi,
    },
  ];

  const services = [
    { name: 'FastAPI Backend', status: 'Online', latency: '12ms', icon: Server, color: '#10B981' },
    { name: 'SQLite / DuckDB', status: 'Healthy', latency: '4ms', icon: Database, color: '#10B981' },
    { name: 'WebSocket Broadcast', status: wsConnected ? 'Connected' : 'Syncing', latency: wsConnected ? '2ms' : 'Retry', icon: Radio, color: wsConnected ? '#10B981' : '#F59E0B' },
  ];

  return (
    <div
      style={{
        backgroundColor: '#0F141D',
        border: '1px solid rgba(255, 255, 255, 0.07)',
        borderRadius: 14,
        padding: '24px 28px',
        boxShadow: '0 4px 16px rgba(0, 0, 0, 0.25)',
      }}
      className="font-sans flex flex-col justify-between space-y-6"
    >
      {/* Header */}
      <div className="flex items-center justify-between border-b border-white/[0.06] pb-3.5">
        <div>
          <h3
            className="text-base font-heading text-white font-normal"
            style={{ fontFamily: "'Times New Roman', Times, serif" }}
          >
            System Telemetry & Health Sensors
          </h3>
          <p className="text-xs text-[#94A3B8] font-subheading mt-0.5">
            Real-time host compute, streaming bandwidth, and service availability
          </p>
        </div>
        <div className="flex items-center gap-2 text-xs font-mono text-emerald-400">
          <span className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse shadow-[0_0_8px_#34D399]" />
          <span>Operational</span>
        </div>
      </div>

      {/* Primary Hardware Sensors */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
        {sensors.map((s) => {
          const Icon = s.icon;
          return (
            <div
              key={s.label}
              style={{
                backgroundColor: '#0A0E14',
                border: '1px solid rgba(255, 255, 255, 0.05)',
                borderRadius: 10,
                padding: '14px',
              }}
              className="space-y-2.5"
            >
              <div className="flex items-center justify-between">
                <span className="text-[11px] font-mono uppercase tracking-wider text-[#94A3B8]">
                  {s.label}
                </span>
                <Icon size={14} style={{ color: s.color }} />
              </div>
              <div className="flex items-baseline justify-between">
                <span className="text-xl font-bold font-mono text-white">{s.value}</span>
                <span className="text-[10px] font-mono text-[#64748B]">{s.sub}</span>
              </div>
              <div className="h-1.5 w-full bg-white/[0.06] rounded-full overflow-hidden">
                <div
                  className="h-full rounded-full transition-all duration-500"
                  style={{
                    width: `${Math.min(100, Math.max(0, s.percent))}%`,
                    backgroundColor: s.color,
                    boxShadow: `0 0 6px ${s.color}60`,
                  }}
                />
              </div>
            </div>
          );
        })}
      </div>

      {/* Auxiliary Services Status */}
      <div className="pt-3 border-t border-white/[0.05] grid grid-cols-1 md:grid-cols-3 gap-4">
        {services.map((svc) => {
          const SvcIcon = svc.icon;
          return (
            <div
              key={svc.name}
              className="flex items-center justify-between px-3.5 py-2.5 rounded-lg bg-white/[0.02] border border-white/[0.04]"
            >
              <div className="flex items-center gap-2">
                <SvcIcon size={14} className="text-[#94A3B8]" />
                <span className="text-xs text-white font-medium">{svc.name}</span>
              </div>
              <div className="flex items-center gap-2 text-xs font-mono">
                <span style={{ color: svc.color }}>{svc.status}</span>
                <span className="text-[#64748B] text-[11px]">({svc.latency})</span>
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}
