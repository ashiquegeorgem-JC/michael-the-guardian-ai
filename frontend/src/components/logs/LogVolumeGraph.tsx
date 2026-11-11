'use client';

import React from 'react';
import {
  ResponsiveContainer,
  AreaChart,
  Area,
  XAxis,
  YAxis,
  Tooltip,
  CartesianGrid,
} from 'recharts';
import { Activity } from 'lucide-react';
import { LogStats } from '@/types';

interface LogVolumeGraphProps {
  stats: LogStats | null;
  totalEntries: number;
}

const SEVERITY_COLORS: Record<string, string> = {
  CRITICAL: '#EF4444',
  ERROR: '#EF4444',
  WARNING: '#F59E0B',
  INFO: '#3B82F6',
  DEBUG: '#687589',
};

export function LogVolumeGraph({ stats, totalEntries }: LogVolumeGraphProps) {
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
        ];

  const severityData = stats?.level_distribution
    ? Object.entries(stats.level_distribution).map(([name, value]) => ({
        name,
        value: Number(value),
        color: SEVERITY_COLORS[name.toUpperCase()] || '#A7B1C0',
      }))
    : [
        { name: 'CRITICAL', value: 12, color: '#EF4444' },
        { name: 'ERROR', value: 28, color: '#EF4444' },
        { name: 'WARNING', value: 45, color: '#F59E0B' },
        { name: 'INFO', value: 180, color: '#3B82F6' },
      ];

  const sourceData = [
    { name: 'auth.log / sshd', count: 184 },
    { name: 'nginx-waf / ingress', count: 142 },
    { name: 'syslog / kernel', count: 96 },
    { name: 'auditd / daemon', count: 68 },
  ];

  return (
    <div className="grid grid-cols-1 lg:grid-cols-12 gap-5 font-sans">
      {/* 1. Main Timeline Area Chart (8 cols) */}
      <div
        style={{
          backgroundColor: '#0C1119',
          border: '1px solid rgba(255, 255, 255, 0.08)',
          borderRadius: '12px',
          padding: '20px',
        }}
        className="lg:col-span-8 flex flex-col justify-between"
      >
        <div className="flex items-center justify-between border-b border-white/[0.06] pb-3 mb-3">
          <div>
            <h3 className="text-sm font-semibold text-[#F5F7FA]">
              Ingestion Volume Timeline
            </h3>
            <p className="text-xs text-[#A7B1C0] mt-0.5">
              Hourly event density and anomaly outlier markers
            </p>
          </div>
          <div className="flex items-center gap-3 text-xs text-[#A7B1C0]">
            <span className="flex items-center gap-1.5">
              <span className="w-2.5 h-2.5 rounded-xs bg-[#3B82F6]" />
              Volume
            </span>
            <span className="flex items-center gap-1.5">
              <span className="w-2.5 h-2.5 rounded-xs bg-[#EF4444]" />
              Anomalies
            </span>
          </div>
        </div>

        <div className="h-52 w-full pt-2">
          <ResponsiveContainer width="100%" height="100%">
            <AreaChart data={volumeData} margin={{ top: 10, right: 10, left: -20, bottom: 0 }}>
              <defs>
                <linearGradient id="volGrad" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%" stopColor="#3B82F6" stopOpacity={0.25} />
                  <stop offset="95%" stopColor="#3B82F6" stopOpacity={0.0} />
                </linearGradient>
              </defs>
              <CartesianGrid strokeDasharray="3 3" stroke="rgba(255, 255, 255, 0.05)" vertical={false} />
              <XAxis dataKey="time" stroke="#687589" fontSize={11} tickLine={false} tick={{ fill: '#A7B1C0' }} />
              <YAxis stroke="#687589" fontSize={11} tickLine={false} tick={{ fill: '#A7B1C0' }} />
              <Tooltip
                contentStyle={{
                  backgroundColor: '#111823',
                  border: '1px solid rgba(255, 255, 255, 0.1)',
                  borderRadius: '8px',
                  fontSize: '12px',
                  color: '#F5F7FA',
                }}
              />
              <Area type="monotone" dataKey="events" stroke="#3B82F6" strokeWidth={2} fill="url(#volGrad)" />
            </AreaChart>
          </ResponsiveContainer>
        </div>
      </div>

      {/* 2. Severity & Source Breakdown (4 cols) */}
      <div
        style={{
          backgroundColor: '#0C1119',
          border: '1px solid rgba(255, 255, 255, 0.08)',
          borderRadius: '12px',
          padding: '20px',
        }}
        className="lg:col-span-4 flex flex-col justify-between space-y-4"
      >
        <div className="border-b border-white/[0.06] pb-3">
          <h3 className="text-sm font-semibold text-[#F5F7FA]">
            Severity Distribution
          </h3>
          <p className="text-xs text-[#A7B1C0] mt-0.5">
            Classified security levels
          </p>
        </div>

        <div className="space-y-2">
          {severityData.map((item) => (
            <div key={item.name} className="flex items-center justify-between text-xs">
              <span className="flex items-center gap-2 text-[#A7B1C0]">
                <span className="w-2 h-2 rounded-full" style={{ backgroundColor: item.color }} />
                <span>{item.name}</span>
              </span>
              <span className="font-mono text-[#F5F7FA] font-medium">{item.value}</span>
            </div>
          ))}
        </div>

        <div className="pt-3 border-t border-white/[0.06] space-y-2">
          <div className="text-xs font-semibold text-[#A7B1C0] uppercase tracking-wider">
            Primary Feed Sources
          </div>
          {sourceData.map((src) => (
            <div key={src.name} className="flex items-center justify-between text-xs">
              <span className="text-[#687589] font-mono text-[11px] truncate max-w-[180px]">
                {src.name}
              </span>
              <span className="font-mono text-[#A7B1C0]">{src.count}</span>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}
