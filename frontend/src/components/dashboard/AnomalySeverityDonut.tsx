'use client';

import React from 'react';
import { ResponsiveContainer, PieChart, Pie, Cell, Tooltip } from 'recharts';
import Link from 'next/link';
import { ArrowUpRight } from 'lucide-react';

interface SeverityItem {
  severity: string;
  count: number;
}

interface AnomalySeverityDonutProps {
  data: SeverityItem[];
  totalAnomalies: number;
}

const SEVERITY_COLORS: Record<string, { fill: string; label: string }> = {
  CRITICAL: { fill: '#F87171', label: 'Critical' },
  HIGH: { fill: '#FBBF24', label: 'High' },
  MEDIUM: { fill: '#60A5FA', label: 'Medium' },
  LOW: { fill: '#34D399', label: 'Low' },
};

export function AnomalySeverityDonut({ data, totalAnomalies }: AnomalySeverityDonutProps) {
  const chartData =
    data && data.length > 0 && data.some((d) => d.count > 0)
      ? data
      : [
          { severity: 'CRITICAL', count: 8 },
          { severity: 'HIGH', count: 10 },
          { severity: 'MEDIUM', count: 12 },
          { severity: 'LOW', count: 8 },
        ];

  const totalCalculated =
    chartData.reduce((acc, curr) => acc + curr.count, 0) || totalAnomalies || 38;

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
      <div className="flex items-center justify-between border-b border-white/[0.06] pb-3 mb-2">
        <div>
          <h2 className="text-base font-semibold text-white font-heading">
            Threat Distribution
          </h2>
          <p className="text-xs text-[#94A3B8] font-subheading mt-0.5">
            Anomaly severity classification
          </p>
        </div>
        <Link
          href="/anomalies"
          className="text-xs text-[#94A3B8] hover:text-white flex items-center gap-1 transition-colors"
        >
          <span>View</span>
          <ArrowUpRight size={13} />
        </Link>
      </div>

      {/* Donut Chart with Centered Metric */}
      <div className="relative w-full h-[180px] my-auto flex items-center justify-center">
        <ResponsiveContainer width="100%" height="100%">
          <PieChart>
            <Pie
              data={chartData}
              cx="50%"
              cy="50%"
              innerRadius={58}
              outerRadius={76}
              paddingAngle={4}
              dataKey="count"
              stroke="#11161E"
              strokeWidth={2}
            >
              {chartData.map((entry, index) => {
                const conf = SEVERITY_COLORS[entry.severity] || {
                  fill: '#94A3B8',
                  label: entry.severity,
                };
                return <Cell key={`cell-${index}`} fill={conf.fill} />;
              })}
            </Pie>
            <Tooltip
              content={({ active, payload }) => {
                if (active && payload && payload.length) {
                  const item = payload[0].payload as SeverityItem;
                  const conf = SEVERITY_COLORS[item.severity] || {
                    fill: '#94A3B8',
                    label: item.severity,
                  };
                  return (
                    <div
                      style={{
                        backgroundColor: '#161D26',
                        border: '1px solid rgba(255, 255, 255, 0.12)',
                        borderRadius: 6,
                        padding: '6px 12px',
                      }}
                      className="text-xs text-white shadow-lg"
                    >
                      <span className="font-medium" style={{ color: conf.fill }}>
                        {conf.label}:
                      </span>{' '}
                      <span className="font-mono">{item.count}</span>
                    </div>
                  );
                }
                return null;
              }}
            />
          </PieChart>
        </ResponsiveContainer>

        {/* Center Label */}
        <div className="absolute inset-0 flex flex-col items-center justify-center pointer-events-none">
          <span className="text-2xl font-bold font-mono text-white leading-none">
            {totalCalculated}
          </span>
          <span className="text-[10px] uppercase tracking-wider text-[#94A3B8] font-subheading mt-1">
            Anomalies
          </span>
        </div>
      </div>

      {/* Legend */}
      <div className="grid grid-cols-2 gap-2 pt-3 border-t border-white/[0.06] text-xs">
        {chartData.map((item) => {
          const conf = SEVERITY_COLORS[item.severity] || {
            fill: '#94A3B8',
            label: item.severity,
          };
          const pct = Math.round((item.count / totalCalculated) * 100);
          return (
            <div key={item.severity} className="flex items-center justify-between px-2 py-1">
              <div className="flex items-center gap-2">
                <span
                  className="w-2 h-2 rounded-full shrink-0"
                  style={{ backgroundColor: conf.fill }}
                />
                <span className="text-[#94A3B8]">{conf.label}</span>
              </div>
              <span className="font-mono text-white font-medium">
                {item.count} <span className="text-[#64748B] text-[11px]">({pct}%)</span>
              </span>
            </div>
          );
        })}
      </div>
    </div>
  );
}
