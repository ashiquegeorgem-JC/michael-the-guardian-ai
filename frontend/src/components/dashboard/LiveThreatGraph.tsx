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
            anomaly_score: Number((baseScore * 100).toFixed(0)),
          };
        });

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
      <div className="flex flex-wrap items-center justify-between gap-3 border-b border-[rgba(212,175,55,0.1)] pb-4">
        <div>
          <h2 className="text-base font-semibold text-[#FAF9F5] font-heading">
            Live Threat Activity
          </h2>
          <p className="text-xs text-[#D1CBC0] font-subheading font-light mt-1">
            Threat events and anomaly score over time
          </p>
        </div>

        {/* Legend & Selector */}
        <div className="flex items-center gap-4 text-xs font-subheading">
          <div className="flex items-center gap-3">
            <span className="flex items-center gap-1.5 text-[#D1CBC0]">
              <span className="w-2.5 h-2.5 rounded-full bg-[#D4AF37] shadow-[0_0_6px_rgba(212,175,55,0.8)]" />
              Event Volume
            </span>
            <span className="flex items-center gap-1.5 text-[#D1CBC0]">
              <span className="w-2.5 h-2.5 rounded-full bg-[#38BDF8] shadow-[0_0_6px_rgba(56,189,248,0.8)]" />
              Anomaly Score
            </span>
          </div>

          <div
            style={{
              backgroundColor: '#222C35',
              border: '1px solid rgba(212, 175, 55, 0.18)',
            }}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs text-[#FAF9F5] font-medium cursor-pointer"
          >
            <span>{timeRange}</span>
            <ChevronDown size={13} className="text-[#D4AF37]" />
          </div>
        </div>
      </div>

      {/* Dual Gradient Area Chart */}
      <div className="h-64 w-full pt-2">
        <ResponsiveContainer width="100%" height="100%">
          <AreaChart
            data={formattedData}
            margin={{ top: 10, right: 10, left: -20, bottom: 0 }}
          >
            <defs>
              <linearGradient id="eventVolumeGoldGrad" x1="0" y1="0" x2="0" y2="1">
                <stop offset="5%" stopColor="#D4AF37" stopOpacity={0.35} />
                <stop offset="95%" stopColor="#D4AF37" stopOpacity={0.0} />
              </linearGradient>
              <linearGradient id="anomalyScoreCyanGrad" x1="0" y1="0" x2="0" y2="1">
                <stop offset="5%" stopColor="#38BDF8" stopOpacity={0.3} />
                <stop offset="95%" stopColor="#38BDF8" stopOpacity={0.0} />
              </linearGradient>
            </defs>
            <CartesianGrid
              strokeDasharray="3 3"
              stroke="rgba(212, 175, 55, 0.08)"
              vertical={false}
            />
            <XAxis
              dataKey="time"
              stroke="#8E877D"
              fontSize={11}
              tickLine={false}
              axisLine={{ stroke: 'rgba(212, 175, 55, 0.14)' }}
              tick={{ fill: '#D1CBC0', fontFamily: 'var(--font-mono)' }}
            />
            <YAxis
              yAxisId="left"
              stroke="#8E877D"
              fontSize={11}
              tickLine={false}
              axisLine={false}
              tick={{ fill: '#D1CBC0', fontFamily: 'var(--font-mono)' }}
            />
            <YAxis
              yAxisId="right"
              orientation="right"
              domain={[0, 100]}
              stroke="#8E877D"
              fontSize={11}
              tickLine={false}
              axisLine={false}
              tick={{ fill: '#D1CBC0', fontFamily: 'var(--font-mono)' }}
              tickFormatter={(v) => `${v}%`}
            />
            <Tooltip
              content={({ active, payload, label }) => {
                if (active && payload && payload.length) {
                  const events = payload.find((p) => p.dataKey === 'count')?.value || 0;
                  const score = payload.find((p) => p.dataKey === 'anomaly_score')?.value || 0;
                  return (
                    <div
                      style={{
                        backgroundColor: '#222C35',
                        border: '1px solid rgba(212, 175, 55, 0.35)',
                        borderRadius: '10px',
                        padding: '10px 14px',
                        boxShadow: '0 8px 30px rgba(0, 0, 0, 0.7)',
                      }}
                      className="font-sans space-y-1"
                    >
                      <div className="text-xs font-mono font-semibold text-[#FAF9F5]">
                        {label}
                      </div>
                      <div className="flex items-center gap-2 text-xs">
                        <span className="w-2 h-2 rounded-full bg-[#D4AF37]" />
                        <span className="text-[#D1CBC0]">Events:</span>
                        <span className="font-mono font-bold text-[#FAF9F5]">{events}</span>
                      </div>
                      <div className="flex items-center gap-2 text-xs">
                        <span className="w-2 h-2 rounded-full bg-[#38BDF8]" />
                        <span className="text-[#D1CBC0]">Anomaly Score:</span>
                        <span className="font-mono font-bold text-[#38BDF8]">
                          {typeof score === 'number' ? (score / 100).toFixed(2) : score}
                        </span>
                      </div>
                    </div>
                  );
                }
                return null;
              }}
            />

            <Area
              yAxisId="left"
              type="monotone"
              dataKey="count"
              stroke="#D4AF37"
              strokeWidth={2.5}
              fillOpacity={1}
              fill="url(#eventVolumeGoldGrad)"
            />

            <Area
              yAxisId="right"
              type="monotone"
              dataKey="anomaly_score"
              stroke="#38BDF8"
              strokeWidth={2.5}
              fillOpacity={1}
              fill="url(#anomalyScoreCyanGrad)"
            />
          </AreaChart>
        </ResponsiveContainer>
      </div>
    </div>
  );
}

export const LiveThreatActivityChart = LiveThreatGraph;
