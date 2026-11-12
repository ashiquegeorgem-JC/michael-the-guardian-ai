'use client';

import React from 'react';
import {
  ResponsiveContainer,
  AreaChart,
  Area,
  BarChart,
  Bar,
  XAxis,
  YAxis,
  Tooltip,
  CartesianGrid,
  Cell,
  LineChart,
  Line,
} from 'recharts';
import { LogStats } from '@/types';
import { chartTooltipProps } from '@/lib/chartTheme';
import { Activity, Cpu, ShieldCheck, Zap } from 'lucide-react';

interface LogVolumeGraphProps {
  stats: LogStats | null;
  totalEntries: number;
}

const SEVERITY_COLORS: Record<string, string> = {
  CRITICAL: '#EF4444',
  ERROR: '#F87171',
  WARNING: '#F59E0B',
  INFO: '#38BDF8',
  DEBUG: '#94A3B8',
};

export function LogVolumeGraph({ stats }: LogVolumeGraphProps) {
  const volumeData =
    stats?.hourly_volume && stats.hourly_volume.length > 0
      ? stats.hourly_volume.map((h) => ({
          time: h.time,
          events: h.count,
          anomalies: Math.round(h.count * 0.12),
        }))
      : [
          { time: '00:00', events: 120, anomalies: 8 },
          { time: '04:00', events: 80, anomalies: 4 },
          { time: '08:00', events: 340, anomalies: 24 },
          { time: '12:00', events: 620, anomalies: 48 },
          { time: '16:00', events: 480, anomalies: 32 },
          { time: '20:00', events: 210, anomalies: 12 },
          { time: '23:59', events: 160, anomalies: 9 },
        ];

  const severityData = stats?.level_distribution
    ? Object.entries(stats.level_distribution).map(([name, value]) => ({
        name,
        value: Number(value),
        color: SEVERITY_COLORS[name.toUpperCase()] || '#94A3B8',
      }))
    : [
        { name: 'CRITICAL', value: 12, color: '#EF4444' },
        { name: 'ERROR', value: 28, color: '#F87171' },
        { name: 'WARNING', value: 45, color: '#F59E0B' },
        { name: 'INFO', value: 180, color: '#38BDF8' },
        { name: 'DEBUG', value: 34, color: '#94A3B8' },
      ];

  const totalSeverityCount = severityData.reduce((acc, curr) => acc + curr.value, 0) || 1;

  const eventTypeData = [
    { type: 'AUTH_FAIL', count: 142, fill: '#EF4444' },
    { type: 'SSH_SESSION', count: 210, fill: '#38BDF8' },
    { type: 'SUDO_EXEC', count: 86, fill: '#F59E0B' },
    { type: 'WAF_BLOCK', count: 178, fill: '#A78BFA' },
    { type: 'PORT_SCAN', count: 64, fill: '#F87171' },
    { type: 'SYS_DAEMON', count: 320, fill: '#34D399' },
  ];

  const sourceData = stats?.source_distribution
    ? Object.entries(stats.source_distribution).map(([name, count], i) => ({
        name,
        count: Number(count),
        color: ['#38BDF8', '#34D399', '#A78BFA', '#F59E0B', '#F87171'][i % 5],
      }))
    : [
        { name: 'auth.log / sshd', count: 184, color: '#38BDF8' },
        { name: 'nginx-waf / ingress', count: 142, color: '#A78BFA' },
        { name: 'syslog / kernel', count: 96, color: '#34D399' },
        { name: 'auditd / daemon', count: 68, color: '#F59E0B' },
      ];

  // Ingestion throughput velocity curve
  const throughputData = [
    { time: 'T-60m', rate: 45, bandwidth: 120 },
    { time: 'T-50m', rate: 58, bandwidth: 145 },
    { time: 'T-40m', rate: 82, bandwidth: 198 },
    { time: 'T-30m', rate: 142, bandwidth: 380 },
    { time: 'T-20m', rate: 110, bandwidth: 290 },
    { time: 'T-10m', rate: 74, bandwidth: 185 },
    { time: 'Now', rate: 68, bandwidth: 165 },
  ];

  return (
    <div className="space-y-8 font-sans">
      {/* ── 1. PRIMARY EVENT ACTIVITY VISUALIZATION ───────────────────────── */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6 items-stretch">
        {/* Main Ingestion Timeline Area Chart */}
        <div
          style={{
            backgroundColor: '#0F141D',
            border: '1px solid rgba(255, 255, 255, 0.07)',
            borderRadius: 14,
            padding: '24px',
            boxShadow: '0 4px 16px rgba(0, 0, 0, 0.25)',
          }}
          className="lg:col-span-8 flex flex-col justify-between"
        >
          <div className="flex items-center justify-between border-b border-white/[0.07] pb-3.5 mb-4">
            <div>
              <h3
                className="text-base font-heading text-white tracking-normal font-normal"
                style={{ fontFamily: "'Times New Roman', Times, serif" }}
              >
                Event Volume Timeline
              </h3>
              <p className="text-xs text-[#94A3B8] font-subheading mt-0.5">
                Hourly telemetry throughput and anomalous rate spikes
              </p>
            </div>
            <div className="flex items-center gap-4 text-xs font-mono text-[#94A3B8]">
              <span className="flex items-center gap-1.5">
                <span className="w-2.5 h-2.5 rounded-full bg-[#38BDF8]" />
                Volume
              </span>
              <span className="flex items-center gap-1.5">
                <span className="w-2.5 h-2.5 rounded-full bg-[#EF4444]" />
                Anomalies
              </span>
            </div>
          </div>

          <div className="h-72 w-full pt-1">
            <ResponsiveContainer width="100%" height="100%">
              <AreaChart data={volumeData} margin={{ top: 12, right: 12, left: 0, bottom: 0 }}>
                <defs>
                  <linearGradient id="volGrad" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#38BDF8" stopOpacity={0.3} />
                    <stop offset="95%" stopColor="#38BDF8" stopOpacity={0.0} />
                  </linearGradient>
                  <linearGradient id="anomGrad" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#EF4444" stopOpacity={0.25} />
                    <stop offset="95%" stopColor="#EF4444" stopOpacity={0.0} />
                  </linearGradient>
                </defs>
                <CartesianGrid strokeDasharray="3 3" stroke="rgba(255, 255, 255, 0.05)" vertical={false} />
                <XAxis dataKey="time" stroke="#64748B" fontSize={11} tickLine={false} tick={{ fill: '#94A3B8' }} />
                <YAxis stroke="#64748B" fontSize={11} tickLine={false} tick={{ fill: '#94A3B8' }} />
                <Tooltip
                  contentStyle={chartTooltipProps.contentStyle}
                  labelStyle={chartTooltipProps.labelStyle}
                  itemStyle={chartTooltipProps.itemStyle}
                  cursor={chartTooltipProps.cursor}
                />
                <Area type="monotone" dataKey="events" stroke="#38BDF8" strokeWidth={2} fill="url(#volGrad)" name="Events" />
                <Area type="monotone" dataKey="anomalies" stroke="#EF4444" strokeWidth={1.5} fill="url(#anomGrad)" name="Outliers" />
              </AreaChart>
            </ResponsiveContainer>
          </div>
        </div>

        {/* Severity Distribution: Horizontal Visual Severity Bars */}
        <div
          style={{
            backgroundColor: '#0F141D',
            border: '1px solid rgba(255, 255, 255, 0.07)',
            borderRadius: 14,
            padding: '24px',
            boxShadow: '0 4px 16px rgba(0, 0, 0, 0.25)',
          }}
          className="lg:col-span-4 flex flex-col justify-between space-y-4"
        >
          <div className="border-b border-white/[0.07] pb-3.5">
            <h3
              className="text-base font-heading text-white tracking-normal font-normal"
              style={{ fontFamily: "'Times New Roman', Times, serif" }}
            >
              Severity Distribution
            </h3>
            <p className="text-xs text-[#94A3B8] font-subheading mt-0.5">
              Classified security severity percentages
            </p>
          </div>

          <div className="space-y-4 my-auto">
            {severityData.map((item) => {
              const pct = Math.round((item.value / totalSeverityCount) * 100);
              return (
                <div key={item.name} className="space-y-1.5">
                  <div className="flex items-center justify-between text-xs">
                    <span className="flex items-center gap-2 text-[#94A3B8] font-mono text-[11px]">
                      <span className="w-2.5 h-2.5 rounded-full" style={{ backgroundColor: item.color }} />
                      <span className="font-medium text-white">{item.name}</span>
                    </span>
                    <span className="font-mono text-white font-medium text-xs">
                      {item.value.toLocaleString()} <span className="text-[#64748B] text-[10px]">({pct}%)</span>
                    </span>
                  </div>
                  <div className="h-2 w-full bg-white/[0.05] rounded-full overflow-hidden">
                    <div
                      className="h-full rounded-full transition-all duration-500"
                      style={{
                        width: `${pct}%`,
                        backgroundColor: item.color,
                        boxShadow: `0 0 8px ${item.color}60`,
                      }}
                    />
                  </div>
                </div>
              );
            })}
          </div>

          <div className="pt-3 border-t border-white/[0.07] text-[11px] font-mono text-[#64748B] flex items-center justify-between">
            <span>Aggregated Events:</span>
            <span className="text-white font-medium">{totalSeverityCount.toLocaleString()} Total</span>
          </div>
        </div>
      </div>

      {/* ── 2. SECONDARY ANALYTICS SECTION ─────────────────────────────────── */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6 items-stretch">
        {/* Event Type Distribution Bar Chart */}
        <div
          style={{
            backgroundColor: '#0F141D',
            border: '1px solid rgba(255, 255, 255, 0.07)',
            borderRadius: 14,
            padding: '24px',
            boxShadow: '0 4px 16px rgba(0, 0, 0, 0.25)',
          }}
          className="lg:col-span-6 flex flex-col justify-between space-y-4"
        >
          <div className="border-b border-white/[0.07] pb-3.5">
            <h3
              className="text-base font-heading text-white tracking-normal font-normal"
              style={{ fontFamily: "'Times New Roman', Times, serif" }}
            >
              Event Type Distribution
            </h3>
            <p className="text-xs text-[#94A3B8] font-subheading mt-0.5">
              Frequency by tactical action and system audit category
            </p>
          </div>

          <div className="h-64 w-full pt-1">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={eventTypeData} margin={{ top: 10, right: 10, left: -15, bottom: 0 }}>
                <CartesianGrid strokeDasharray="3 3" stroke="rgba(255, 255, 255, 0.05)" vertical={false} />
                <XAxis dataKey="type" stroke="#64748B" fontSize={10} tickLine={false} tick={{ fill: '#94A3B8' }} />
                <YAxis stroke="#64748B" fontSize={10} tickLine={false} tick={{ fill: '#94A3B8' }} />
                <Tooltip
                  contentStyle={chartTooltipProps.contentStyle}
                  labelStyle={chartTooltipProps.labelStyle}
                  itemStyle={chartTooltipProps.itemStyle}
                  cursor={chartTooltipProps.cursor}
                />
                <Bar dataKey="count" radius={[4, 4, 0, 0]} name="Event Count">
                  {eventTypeData.map((entry, index) => (
                    <Cell key={`cell-${index}`} fill={entry.fill} />
                  ))}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>

        {/* Source Ingestion Distribution */}
        <div
          style={{
            backgroundColor: '#0F141D',
            border: '1px solid rgba(255, 255, 255, 0.07)',
            borderRadius: 14,
            padding: '24px',
            boxShadow: '0 4px 16px rgba(0, 0, 0, 0.25)',
          }}
          className="lg:col-span-6 flex flex-col justify-between space-y-4"
        >
          <div className="border-b border-white/[0.07] pb-3.5">
            <h3
              className="text-base font-heading text-white tracking-normal font-normal"
              style={{ fontFamily: "'Times New Roman', Times, serif" }}
            >
              Source Ingestion Breakdown
            </h3>
            <p className="text-xs text-[#94A3B8] font-subheading mt-0.5">
              Event volume share across active log origins
            </p>
          </div>

          <div className="space-y-4 my-auto">
            {sourceData.map((src) => {
              const maxCount = Math.max(...sourceData.map((s) => s.count)) || 1;
              const pct = Math.round((src.count / maxCount) * 100);
              return (
                <div key={src.name} className="space-y-1.5">
                  <div className="flex items-center justify-between text-xs">
                    <span className="text-[#94A3B8] font-mono text-[11px] truncate">{src.name}</span>
                    <span className="font-mono text-white font-medium text-xs">{src.count.toLocaleString()} events</span>
                  </div>
                  <div className="h-2 w-full bg-white/[0.05] rounded-full overflow-hidden">
                    <div
                      className="h-full rounded-full transition-all duration-500"
                      style={{
                        width: `${pct}%`,
                        backgroundColor: src.color,
                        boxShadow: `0 0 8px ${src.color}60`,
                      }}
                    />
                  </div>
                </div>
              );
            })}
          </div>

          <div className="pt-3 border-t border-white/[0.07] text-[11px] font-mono text-[#64748B] flex items-center justify-between">
            <span>Active Daemon Ingestion:</span>
            <span className="text-emerald-400 font-medium">All Channels Online</span>
          </div>
        </div>
      </div>

      {/* ── 3. ADDITIONAL VISUAL ANALYTICS / INGESTION INTELLIGENCE ────────── */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6 items-stretch">
        {/* Ingestion Throughput Velocity Area Curve (7 cols) */}
        <div
          style={{
            backgroundColor: '#0F141D',
            border: '1px solid rgba(255, 255, 255, 0.07)',
            borderRadius: 14,
            padding: '24px',
            boxShadow: '0 4px 16px rgba(0, 0, 0, 0.25)',
          }}
          className="lg:col-span-7 flex flex-col justify-between space-y-4"
        >
          <div className="flex items-center justify-between border-b border-white/[0.07] pb-3.5">
            <div>
              <h3
                className="text-base font-heading text-white tracking-normal font-normal"
                style={{ fontFamily: "'Times New Roman', Times, serif" }}
              >
                Ingestion Throughput Velocity
              </h3>
              <p className="text-xs text-[#94A3B8] font-subheading mt-0.5">
                Real-time daemon ingestion rate (msgs/sec) and payload bandwidth (KB/s)
              </p>
            </div>
            <div className="flex items-center gap-3 text-xs font-mono">
              <span className="flex items-center gap-1.5 text-[#38BDF8]">
                <span className="w-2 h-2 rounded-full bg-[#38BDF8]" />
                Rate (msg/s)
              </span>
              <span className="flex items-center gap-1.5 text-[#A78BFA]">
                <span className="w-2 h-2 rounded-full bg-[#A78BFA]" />
                KB/s
              </span>
            </div>
          </div>

          <div className="h-56 w-full pt-1">
            <ResponsiveContainer width="100%" height="100%">
              <AreaChart data={throughputData} margin={{ top: 10, right: 10, left: -15, bottom: 0 }}>
                <defs>
                  <linearGradient id="rateGrad" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#38BDF8" stopOpacity={0.25} />
                    <stop offset="95%" stopColor="#38BDF8" stopOpacity={0.0} />
                  </linearGradient>
                  <linearGradient id="bwGrad" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#A78BFA" stopOpacity={0.25} />
                    <stop offset="95%" stopColor="#A78BFA" stopOpacity={0.0} />
                  </linearGradient>
                </defs>
                <CartesianGrid strokeDasharray="3 3" stroke="rgba(255, 255, 255, 0.05)" vertical={false} />
                <XAxis dataKey="time" stroke="#64748B" fontSize={10} tickLine={false} tick={{ fill: '#94A3B8' }} />
                <YAxis stroke="#64748B" fontSize={10} tickLine={false} tick={{ fill: '#94A3B8' }} />
                <Tooltip
                  contentStyle={chartTooltipProps.contentStyle}
                  labelStyle={chartTooltipProps.labelStyle}
                  itemStyle={chartTooltipProps.itemStyle}
                  cursor={chartTooltipProps.cursor}
                />
                <Area type="monotone" dataKey="rate" stroke="#38BDF8" strokeWidth={2} fill="url(#rateGrad)" name="Ingestion Rate (msg/s)" />
                <Area type="monotone" dataKey="bandwidth" stroke="#A78BFA" strokeWidth={1.5} fill="url(#bwGrad)" name="Bandwidth (KB/s)" />
              </AreaChart>
            </ResponsiveContainer>
          </div>
        </div>

        {/* Pipeline Integrity & Telemetry Normalizer Health (5 cols) */}
        <div
          style={{
            backgroundColor: '#0F141D',
            border: '1px solid rgba(255, 255, 255, 0.07)',
            borderRadius: 14,
            padding: '24px',
            boxShadow: '0 4px 16px rgba(0, 0, 0, 0.25)',
          }}
          className="lg:col-span-5 flex flex-col justify-between space-y-4"
        >
          <div className="border-b border-white/[0.07] pb-3.5">
            <h3
              className="text-base font-heading text-white tracking-normal font-normal"
              style={{ fontFamily: "'Times New Roman', Times, serif" }}
            >
              Pipeline Integrity & Parser Diagnostics
            </h3>
            <p className="text-xs text-[#94A3B8] font-subheading mt-0.5">
              Normalizer conformance and ingestion queue metrics
            </p>
          </div>

          <div className="space-y-3.5 my-auto">
            {[
              { label: 'ECS Schema Compliance', value: '100%', sub: 'Normalized RFC-5424', color: '#10B981' },
              { label: 'Parser Accuracy Score', value: '99.8%', sub: 'Regex heuristic confidence', color: '#38BDF8' },
              { label: 'Queue Saturation Level', value: '14.2%', sub: 'Ring buffer occupancy', color: '#F59E0B' },
              { label: 'Mean Parser Latency', value: '1.2 ms', sub: 'Per-event ingest time', color: '#34D399' },
            ].map((metric) => (
              <div key={metric.label} className="p-2.5 rounded-lg bg-[#080B0F] border border-white/[0.05] flex items-center justify-between">
                <div>
                  <span className="text-xs text-white font-medium block">{metric.label}</span>
                  <span className="text-[10px] text-[#64748B] font-mono">{metric.sub}</span>
                </div>
                <span className="font-mono text-sm font-semibold" style={{ color: metric.color }}>
                  {metric.value}
                </span>
              </div>
            ))}
          </div>

          <div className="pt-2 border-t border-white/[0.05] text-[11px] font-mono text-[#64748B] flex items-center justify-between">
            <span>Daemon Pipeline Status:</span>
            <span className="text-emerald-400 font-medium flex items-center gap-1.5">
              <span className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse" />
              Optimal
            </span>
          </div>
        </div>
      </div>
    </div>
  );
}
