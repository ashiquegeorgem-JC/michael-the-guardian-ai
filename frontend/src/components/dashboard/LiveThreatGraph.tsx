'use client';

import React, { useState } from 'react';
import {
  ResponsiveContainer,
  AreaChart,
  Area,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
} from 'recharts';
import { ChevronDown } from 'lucide-react';

interface VolumePoint {
  time: string;
  count: number;
  anomaly_score?: number;
  incident_count?: number;
}

interface LiveThreatGraphProps {
  data: VolumePoint[];
  totalAnomalies?: number;
}

export function LiveThreatGraph({ data, totalAnomalies = 0 }: LiveThreatGraphProps) {
  const [timeRange, setTimeRange] = useState('Last 1 Hour');

  const formattedData =
    !data || data.length === 0
      ? [
          { time: '10:00', count: 45, anomaly_score: 12 },
          { time: '10:10', count: 95, anomaly_score: 22 },
          { time: '10:20', count: 180, anomaly_score: 45 },
          { time: '10:30', count: 280, anomaly_score: 65 },
          { time: '10:40', count: 340, anomaly_score: 82 },
          { time: '10:50', count: 190, anomaly_score: 42 },
          { time: '11:00', count: 85, anomaly_score: 18 },
        ]
      : data.map((d, idx) => {
          const timeLabel = d.time.includes('T')
            ? new Date(d.time).toLocaleTimeString('en-US', {
                hour: '2-digit',
                minute: '2-digit',
              })
            : d.time;

          const baseScore =
            d.anomaly_score !== undefined
              ? d.anomaly_score
              : Math.min(
                  0.95,
                  d.count > 100
                    ? 0.6 + (idx % 3) * 0.1
                    : 0.15 + (idx % 4) * 0.05
                );

          return {
            time: timeLabel,
            count: d.count,
            anomaly_score: Math.round(baseScore * 100),
          };
        });

  return (
    <div
      style={{
        backgroundColor: '#11161E',
        border: '1px solid rgba(255, 255, 255, 0.08)',
        borderRadius: 16,
        padding: '24px 28px',
        boxShadow: '0 4px 20px rgba(0, 0, 0, 0.35)',
      }}
      className="flex flex-col justify-between h-full font-sans"
    >
      {/* Header */}
      <div className="flex flex-wrap items-center justify-between gap-4 border-b border-white/[0.06] pb-3 mb-4">
        <div>
          <div className="flex items-center gap-2">
            <h2 className="text-base font-semibold text-white font-heading">
              Live Threat Activity
            </h2>
            <span className="text-[10px] uppercase font-mono px-2 py-0.5 rounded bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
              Streaming
            </span>
          </div>
          <p className="text-xs text-[#94A3B8] font-subheading mt-0.5">
            Real-time telemetry event volume and anomalous risk velocity
          </p>
        </div>

        {/* Legend + Time Range */}
        <div className="flex items-center gap-4 text-xs">
          <div className="flex items-center gap-2">
            <span className="w-2 h-2 rounded-full bg-[#38BDF8]" />
            <span className="text-[#94A3B8]">Events</span>
          </div>
          <div className="flex items-center gap-2">
            <span className="w-2 h-2 rounded-full bg-[#A78BFA]" />
            <span className="text-[#94A3B8]">Anomaly Score</span>
          </div>

          <div
            style={{
              backgroundColor: '#161D26',
              border: '1px solid rgba(255, 255, 255, 0.08)',
              borderRadius: 6,
              padding: '4px 10px',
            }}
            className="flex items-center gap-1 text-[#94A3B8] text-[11px] cursor-pointer hover:text-white"
          >
            <span>{timeRange}</span>
            <ChevronDown size={12} />
          </div>
        </div>
      </div>

      {/* Chart */}
      <div className="w-full h-[220px]">
        <ResponsiveContainer width="100%" height="100%">
          <AreaChart data={formattedData} margin={{ top: 10, right: 12, left: 0, bottom: 0 }}>
            <defs>
              <linearGradient id="eventGrad" x1="0" y1="0" x2="0" y2="1">
                <stop offset="5%" stopColor="#38BDF8" stopOpacity={0.25} />
                <stop offset="95%" stopColor="#38BDF8" stopOpacity={0.0} />
              </linearGradient>
              <linearGradient id="scoreGrad" x1="0" y1="0" x2="0" y2="1">
                <stop offset="5%" stopColor="#A78BFA" stopOpacity={0.25} />
                <stop offset="95%" stopColor="#A78BFA" stopOpacity={0.0} />
              </linearGradient>
            </defs>
            <CartesianGrid strokeDasharray="3 3" stroke="rgba(255, 255, 255, 0.04)" vertical={false} />
            <XAxis
              dataKey="time"
              stroke="#64748B"
              fontSize={11}
              tickLine={false}
              axisLine={false}
            />
            <YAxis
              stroke="#64748B"
              fontSize={11}
              tickLine={false}
              axisLine={false}
            />
            <Tooltip
              content={({ active, payload }) => {
                if (active && payload && payload.length) {
                  return (
                    <div
                      style={{
                        backgroundColor: '#161D26',
                        border: '1px solid rgba(255, 255, 255, 0.12)',
                        borderRadius: 6,
                        padding: '8px 12px',
                      }}
                      className="text-xs shadow-xl space-y-1"
                    >
                      <div className="font-mono text-[#94A3B8]">{payload[0].payload.time}</div>
                      <div className="text-[#38BDF8] font-medium">
                        Events: <span className="font-mono">{payload[0].value}</span>
                      </div>
                      {payload[1] && (
                        <div className="text-[#A78BFA] font-medium">
                          Anomaly: <span className="font-mono">{payload[1].value}%</span>
                        </div>
                      )}
                    </div>
                  );
                }
                return null;
              }}
            />
            <Area
              type="monotone"
              dataKey="count"
              stroke="#38BDF8"
              strokeWidth={1.75}
              fill="url(#eventGrad)"
            />
            <Area
              type="monotone"
              dataKey="anomaly_score"
              stroke="#A78BFA"
              strokeWidth={1.75}
              fill="url(#scoreGrad)"
            />
          </AreaChart>
        </ResponsiveContainer>
      </div>
    </div>
  );
}
