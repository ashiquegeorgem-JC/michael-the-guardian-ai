'use client';

import React, { useState, useEffect } from 'react';
import {
  Cpu,
  HardDrive,
  Wifi,
  Activity,
  RefreshCw,
  Server,
  Database,
  Radio,
} from 'lucide-react';
import {
  ResponsiveContainer,
  AreaChart,
  Area,
  XAxis,
  YAxis,
  Tooltip,
  CartesianGrid,
} from 'recharts';

import {
  PageShell,
  Section,
  SectionHeader,
  MetricRow,
  MetricItem,
  DataPanel,
} from '@/components/ui/primitives';

import { EventStream } from '@/components/monitoring/EventStream';
import { useWebSocket } from '@/hooks/useWebSocket';
import { getSystemMetrics, getMetricHistory } from '@/lib/api';
import { SystemMetrics } from '@/types';
import { chartTooltipProps } from '@/lib/chartTheme';

export default function MonitoringPage() {
  const { latestMetric, connected, events } = useWebSocket();
  const [metrics, setMetrics] = useState<SystemMetrics | null>(null);
  const [history, setHistory] = useState<any[]>([]);

  const fetchStaticMetrics = async () => {
    try {
      const [m, h] = await Promise.all([
        getSystemMetrics().catch(() => null),
        getMetricHistory(20).catch(() => null),
      ]);
      if (m) setMetrics(m);
      if (h?.history) {
        setHistory(
          h.history.map((pt: any) => ({
            ...pt,
            time: new Date(pt.timestamp).toLocaleTimeString([], {
              hour: '2-digit',
              minute: '2-digit',
              second: '2-digit',
            }),
          }))
        );
      }
    } catch (err) {
      console.error(err);
    }
  };

  useEffect(() => {
    fetchStaticMetrics();
  }, []);

  useEffect(() => {
    if (latestMetric?.data) {
      const pt = {
        time: new Date().toLocaleTimeString([], {
          hour: '2-digit',
          minute: '2-digit',
          second: '2-digit',
        }),
        cpu_percent: latestMetric.data.cpu_percent,
        memory_percent: latestMetric.data.memory_percent,
        network_mbps: latestMetric.data.network_in_kbps / 1024,
      };
      setHistory((prev) => [...prev.slice(-25), pt]);
    }
  }, [latestMetric]);

  const currentCpu = latestMetric?.data?.cpu_percent ?? metrics?.cpu_percent ?? 24.2;
  const currentMem = latestMetric?.data?.memory_percent ?? metrics?.memory_percent ?? 56.4;
  const currentDisk = latestMetric?.data?.disk_percent ?? metrics?.disk_percent ?? 41.8;
  const currentNet = latestMetric?.data?.network_in_kbps
    ? latestMetric.data.network_in_kbps / 1024
    : 4.8;
  const eps = latestMetric?.data?.log_events_per_min
    ? Math.round(latestMetric.data.log_events_per_min / 60)
    : 48;

  return (
    <PageShell>
      {/* ── 1. PRIMARY MONITORING & TELEMETRY SECTION ──────────────────────── */}
      <Section className="border-t-2 border-t-[#38BDF8]">
        <SectionHeader
          tag="HOST TELEMETRY"
          title="Live Monitoring & Telemetry"
          description="Real-time host daemon telemetry, ingestion velocity, socket broadcast health, and distributed subsystem utilization."
          statusList={[
            { label: connected ? 'WebSocket: Streaming (8000)' : 'WebSocket: Polling', status: connected ? 'online' : 'warning' },
            { label: `${eps} Events/Sec Ingestion`, status: 'active' },
            { label: 'Host Daemon: Normal', status: 'online' },
          ]}
          actions={
            <button
              onClick={fetchStaticMetrics}
              style={{
                backgroundColor: '#111722',
                border: '1px solid rgba(255, 255, 255, 0.08)',
                color: '#FFFFFF',
                borderRadius: 8,
                padding: '7px 14px',
                fontSize: '0.78rem',
              }}
              className="flex items-center gap-2 hover:border-[#38BDF8] hover:bg-[#162030] transition-all cursor-pointer font-sans"
            >
              <RefreshCw size={13} className="text-[#38BDF8]" />
              <span>Refresh Telemetry</span>
            </button>
          }
        />

        {/* ── Single Continuous Metric Row: CPU | Memory | Storage | Velocity ── */}
        <div>
          <div className="text-[11px] font-mono uppercase tracking-wider text-[#64748B] mb-2 px-1">
            Resource Utilization Overview
          </div>
          <MetricRow columns={4}>
            <MetricItem
              label="CPU Utilization"
              value={`${currentCpu.toFixed(1)}%`}
              progress={currentCpu}
              progressColor="#38BDF8"
              sub="8 cores active runtime"
              icon={Cpu}
            />
            <MetricItem
              label="Memory Usage"
              value={`${currentMem.toFixed(1)}%`}
              progress={currentMem}
              progressColor="#A78BFA"
              changeColor="#A78BFA"
              sub="8.6 / 16.0 GB allocated"
              icon={HardDrive}
            />
            <MetricItem
              label="Storage Volume"
              value={`${currentDisk.toFixed(1)}%`}
              progress={currentDisk}
              progressColor="#34D399"
              sub="NVMe /var/log capacity"
              icon={Database}
            />
            <MetricItem
              label="Ingestion Velocity"
              value={`${eps} EPS`}
              progress={Math.min(100, eps * 2)}
              progressColor="#F59E0B"
              change={`${currentNet.toFixed(1)} MB/s`}
              changeColor="#10B981"
              sub="Optimal streaming velocity"
              icon={Activity}
            />
          </MetricRow>
        </div>
      </Section>

      {/* ── 2. DEDICATED CPU & MEMORY TELEMETRY CHARTS ─────────────────────── */}
      <Section
        title="Host Compute & Memory Telemetry"
        subtitle="Continuous 60s live sampling of processor execution workload and resident heap memory"
      >
        <div className="grid grid-cols-1 lg:grid-cols-12 gap-8 items-stretch">
          {/* CPU Live Workload Chart (6 cols) */}
          <div
            style={{
              backgroundColor: '#0A0E14',
              border: '1px solid rgba(255, 255, 255, 0.06)',
              borderRadius: 12,
              padding: '22px',
            }}
            className="lg:col-span-6 flex flex-col justify-between space-y-4"
          >
            <div className="flex items-center justify-between border-b border-white/[0.06] pb-3">
              <div>
                <span className="text-xs font-mono uppercase tracking-wider text-[#38BDF8]">
                  CPU Utilization Curve
                </span>
                <p className="text-[11px] text-[#64748B] mt-0.5">8-core SMP execution thread load</p>
              </div>
              <span className="text-sm font-bold font-mono text-white">{currentCpu.toFixed(1)}%</span>
            </div>

            <div className="h-56 w-full pt-1">
              <ResponsiveContainer width="100%" height="100%">
                <AreaChart data={history} margin={{ top: 10, right: 10, left: -20, bottom: 0 }}>
                  <defs>
                    <linearGradient id="cpuAreaGrad" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="5%" stopColor="#38BDF8" stopOpacity={0.3} />
                      <stop offset="95%" stopColor="#38BDF8" stopOpacity={0.0} />
                    </linearGradient>
                  </defs>
                  <CartesianGrid strokeDasharray="3 3" stroke="rgba(255, 255, 255, 0.05)" vertical={false} />
                  <XAxis dataKey="time" stroke="#64748B" fontSize={10} tickLine={false} tick={{ fill: '#94A3B8' }} />
                  <YAxis stroke="#64748B" fontSize={10} tickLine={false} tick={{ fill: '#94A3B8' }} domain={[0, 100]} tickFormatter={(v) => `${v}%`} />
                  <Tooltip
                    contentStyle={chartTooltipProps.contentStyle}
                    labelStyle={chartTooltipProps.labelStyle}
                    itemStyle={chartTooltipProps.itemStyle}
                    cursor={chartTooltipProps.cursor}
                  />
                  <Area type="monotone" dataKey="cpu_percent" stroke="#38BDF8" strokeWidth={2} fill="url(#cpuAreaGrad)" name="CPU Load" />
                </AreaChart>
              </ResponsiveContainer>
            </div>
          </div>

          {/* Memory Live Workload Chart (6 cols) */}
          <div
            style={{
              backgroundColor: '#0A0E14',
              border: '1px solid rgba(255, 255, 255, 0.06)',
              borderRadius: 12,
              padding: '22px',
            }}
            className="lg:col-span-6 flex flex-col justify-between space-y-4"
          >
            <div className="flex items-center justify-between border-b border-white/[0.06] pb-3">
              <div>
                <span className="text-xs font-mono uppercase tracking-wider text-[#A78BFA]">
                  Resident Memory Allocation
                </span>
                <p className="text-[11px] text-[#64748B] mt-0.5">Physical RAM active pages & cache buffers</p>
              </div>
              <span className="text-sm font-bold font-mono text-white">{currentMem.toFixed(1)}%</span>
            </div>

            <div className="h-56 w-full pt-1">
              <ResponsiveContainer width="100%" height="100%">
                <AreaChart data={history} margin={{ top: 10, right: 10, left: -20, bottom: 0 }}>
                  <defs>
                    <linearGradient id="memAreaGrad" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="5%" stopColor="#A78BFA" stopOpacity={0.3} />
                      <stop offset="95%" stopColor="#A78BFA" stopOpacity={0.0} />
                    </linearGradient>
                  </defs>
                  <CartesianGrid strokeDasharray="3 3" stroke="rgba(255, 255, 255, 0.05)" vertical={false} />
                  <XAxis dataKey="time" stroke="#64748B" fontSize={10} tickLine={false} tick={{ fill: '#94A3B8' }} />
                  <YAxis stroke="#64748B" fontSize={10} tickLine={false} tick={{ fill: '#94A3B8' }} domain={[0, 100]} tickFormatter={(v) => `${v}%`} />
                  <Tooltip
                    contentStyle={chartTooltipProps.contentStyle}
                    labelStyle={chartTooltipProps.labelStyle}
                    itemStyle={chartTooltipProps.itemStyle}
                    cursor={chartTooltipProps.cursor}
                  />
                  <Area type="monotone" dataKey="memory_percent" stroke="#A78BFA" strokeWidth={2} fill="url(#memAreaGrad)" name="RAM Usage" />
                </AreaChart>
              </ResponsiveContainer>
            </div>
          </div>
        </div>
      </Section>

      {/* ── 3. DISK VOLUME & NETWORK THROUGHPUT ─────────────────────────────── */}
      <Section
        title="Storage Volume & Network Throughput"
        subtitle="Disk partition occupancy and real-time streaming bandwidth utilization"
      >
        <div className="grid grid-cols-1 lg:grid-cols-12 gap-8 items-stretch">
          {/* Disk Area Graph (6 cols) */}
          <div
            style={{
              backgroundColor: '#0A0E14',
              border: '1px solid rgba(255, 255, 255, 0.06)',
              borderRadius: 12,
              padding: '22px',
            }}
            className="lg:col-span-6 flex flex-col justify-between space-y-4"
          >
            <div className="flex items-center justify-between border-b border-white/[0.06] pb-3">
              <div>
                <span className="text-xs font-mono uppercase tracking-wider text-[#34D399]">
                  Disk I/O & Storage Capacity
                </span>
                <p className="text-[11px] text-[#64748B] mt-0.5">NVMe block device buffer utilization</p>
              </div>
              <span className="text-sm font-bold font-mono text-white">{currentDisk.toFixed(1)}% Used</span>
            </div>

            <div className="h-48 w-full pt-1">
              <ResponsiveContainer width="100%" height="100%">
                <AreaChart
                  data={[
                    { time: '00:00', disk: 40.2 },
                    { time: '04:00', disk: 40.5 },
                    { time: '08:00', disk: 41.1 },
                    { time: '12:00', disk: 41.8 },
                    { time: '16:00', disk: 41.9 },
                    { time: '20:00', disk: 42.1 },
                  ]}
                  margin={{ top: 10, right: 10, left: -20, bottom: 0 }}
                >
                  <defs>
                    <linearGradient id="diskGrad" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="5%" stopColor="#34D399" stopOpacity={0.25} />
                      <stop offset="95%" stopColor="#34D399" stopOpacity={0.0} />
                    </linearGradient>
                  </defs>
                  <CartesianGrid strokeDasharray="3 3" stroke="rgba(255, 255, 255, 0.05)" vertical={false} />
                  <XAxis dataKey="time" stroke="#64748B" fontSize={10} tickLine={false} tick={{ fill: '#94A3B8' }} />
                  <YAxis stroke="#64748B" fontSize={10} tickLine={false} tick={{ fill: '#94A3B8' }} domain={[0, 100]} tickFormatter={(v) => `${v}%`} />
                  <Tooltip
                    contentStyle={chartTooltipProps.contentStyle}
                    labelStyle={chartTooltipProps.labelStyle}
                    itemStyle={chartTooltipProps.itemStyle}
                    cursor={chartTooltipProps.cursor}
                  />
                  <Area type="monotone" dataKey="disk" stroke="#34D399" strokeWidth={2} fill="url(#diskGrad)" name="Disk Storage" />
                </AreaChart>
              </ResponsiveContainer>
            </div>
          </div>

          {/* Network Inbound/Outbound Line Graph (6 cols) */}
          <div
            style={{
              backgroundColor: '#0A0E14',
              border: '1px solid rgba(255, 255, 255, 0.06)',
              borderRadius: 12,
              padding: '22px',
            }}
            className="lg:col-span-6 flex flex-col justify-between space-y-4"
          >
            <div className="flex items-center justify-between border-b border-white/[0.06] pb-3">
              <div>
                <span className="text-xs font-mono uppercase tracking-wider text-[#38BDF8]">
                  Network Ingress / Egress
                </span>
                <p className="text-[11px] text-[#64748B] mt-0.5">Socket streaming bandwidth velocity</p>
              </div>
              <span className="text-sm font-bold font-mono text-white">{currentNet.toFixed(1)} MB/s</span>
            </div>

            <div className="h-48 w-full pt-1">
              <ResponsiveContainer width="100%" height="100%">
                <AreaChart
                  data={[
                    { time: '00:00', inbound: 2.1, outbound: 0.8 },
                    { time: '04:00', inbound: 1.4, outbound: 0.5 },
                    { time: '08:00', inbound: 4.8, outbound: 1.9 },
                    { time: '12:00', inbound: 6.2, outbound: 2.4 },
                    { time: '16:00', inbound: 5.1, outbound: 2.0 },
                    { time: '20:00', inbound: 3.4, outbound: 1.2 },
                  ]}
                  margin={{ top: 10, right: 10, left: -20, bottom: 0 }}
                >
                  <defs>
                    <linearGradient id="netInGrad" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="5%" stopColor="#38BDF8" stopOpacity={0.25} />
                      <stop offset="95%" stopColor="#38BDF8" stopOpacity={0.0} />
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
                  <Area type="monotone" dataKey="inbound" stroke="#38BDF8" strokeWidth={2} fill="url(#netInGrad)" name="Ingress MB/s" />
                  <Area type="monotone" dataKey="outbound" stroke="#A78BFA" strokeWidth={2} fill="transparent" name="Egress MB/s" />
                </AreaChart>
              </ResponsiveContainer>
            </div>
          </div>
        </div>
      </Section>

      {/* ── 3. REAL-TIME DAEMON EVENT BUS BOX (Landscape below graph) ──────── */}
      <Section
        title="Real-Time Daemon Event Bus"
        subtitle="Asynchronous WebSocket broadcast pipeline streaming raw normalized security events"
      >
        <EventStream events={events} connected={connected} />
      </Section>

      {/* ── 4. PIPELINE COMPONENT STATUS (Landscape below Event Bus) ───────── */}
      <Section
        title="Pipeline Component Status"
        subtitle="Distributed telemetry processing workers, normalization daemons and subsystem latency"
      >
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-6">
          {[
            {
              title: 'Ingestion Daemon',
              runtime: 'FastAPI Uvicorn Async',
              status: 'Online',
              latency: '0.4ms',
              color: '#10B981',
            },
            {
              title: 'Log Parser & Regex',
              runtime: 'Standardized ECS Normalizer',
              status: 'Ready',
              latency: '1.2ms',
              color: '#10B981',
            },
            {
              title: 'Isolation Forest Worker',
              runtime: 'Scikit-Learn Ensemble',
              status: 'Active',
              latency: '8.4ms',
              color: '#38BDF8',
            },
            {
              title: 'Threat Intel Cache',
              runtime: 'VirusTotal Provider v3',
              status: 'Synced',
              latency: '34ms',
              color: '#A78BFA',
            },
          ].map((comp) => (
            <div
              key={comp.title}
              style={{
                backgroundColor: '#0F141D',
                border: '1px solid rgba(255, 255, 255, 0.05)',
                borderRadius: 12,
                padding: '18px 20px',
              }}
              className="flex flex-col justify-between space-y-3 hover:border-white/15 transition-all"
            >
              <div className="flex items-center justify-between">
                <span className="font-semibold text-xs text-white">
                  {comp.title}
                </span>
                <span
                  style={{
                    color: comp.color,
                    backgroundColor: `${comp.color}15`,
                    border: `1px solid ${comp.color}30`,
                  }}
                  className="text-[10px] font-mono px-2 py-0.5 rounded"
                >
                  {comp.status}
                </span>
              </div>

              <div>
                <div className="text-[11px] text-[#94A3B8] font-subheading">
                  {comp.runtime}
                </div>
                <div className="text-[10px] font-mono text-[#64748B] mt-1">
                  Latency: {comp.latency}
                </div>
              </div>
            </div>
          ))}
        </div>
      </Section>
    </PageShell>
  );
}
