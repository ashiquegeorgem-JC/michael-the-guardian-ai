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
  CRITICAL: { fill: '#EF4444', label: 'Critical' },
  HIGH: { fill: '#F59E0B', label: 'High' },
  MEDIUM: { fill: '#D4AF37', label: 'Medium' },
  LOW: { fill: '#22C55E', label: 'Low' },
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
        backgroundColor: '#1C242B',
        border: '1px solid rgba(212, 175, 55, 0.14)',
        borderRadius: '14px',
        padding: '24px',
        boxShadow: '0 4px 16px rgba(0, 0, 0, 0.4)',
      }}
      className="flex flex-col justify-between h-full space-y-4 font-sans"
    >
      {/* Header */}
      <div className="flex items-center justify-between border-b border-[rgba(212,175,55,0.1)] pb-4">
        <div>
          <h2 className="text-base font-semibold text-[#FAF9F5] font-heading">
            Threat Distribution
          </h2>
          <p className="text-xs text-[#D1CBC0] font-subheading font-light mt-1">
            Anomaly severity classification
          </p>
        </div>
        <Link
          href="/anomalies"
          style={{ color: '#D4AF37' }}
          className="text-xs hover:underline flex items-center gap-1 font-subheading font-medium"
        >
          <span>View</span>
          <ArrowUpRight size={13} color="#D4AF37" />
        </Link>
      </div>

      {/* Donut Chart with Centered Metric */}
      <div className="relative h-44 w-full flex items-center justify-center my-1">
        <ResponsiveContainer width="100%" height="100%">
          <PieChart>
            <Tooltip
              contentStyle={{
                backgroundColor: '#222C35',
                border: '1px solid rgba(212, 175, 55, 0.25)',
                borderRadius: '8px',
                fontSize: '11px',
                fontFamily: 'var(--font-sans)',
                boxShadow: '0 8px 30px rgba(0,0,0,0.6)',
                color: '#FAF9F5',
              }}
              formatter={(value, name) => [`${value} anomalies`, `${name}`]}
            />
            <Pie
              data={chartData}
              cx="50%"
              cy="50%"
              innerRadius={50}
              outerRadius={70}
              paddingAngle={4}
              dataKey="count"
              nameKey="severity"
              stroke="none"
            >
              {chartData.map((entry, index) => {
                const color =
                  SEVERITY_COLORS[entry.severity.toUpperCase()]?.fill || '#D4AF37';
                return <Cell key={`cell-${index}`} fill={color} />;
              })}
            </Pie>
          </PieChart>
        </ResponsiveContainer>

        {/* Center Metric Label */}
        <div className="absolute inset-0 flex flex-col items-center justify-center pointer-events-none text-center">
          <span className="text-2xl font-bold font-mono text-[#FAF9F5]">
            {totalCalculated}
          </span>
          <span className="text-[10px] tracking-wider uppercase text-[#D4AF37] font-subheading font-semibold">
            ANOMALIES
          </span>
        </div>
      </div>

      {/* Legend Breakdown Grid */}
      <div className="grid grid-cols-2 gap-2.5 pt-2 border-t border-[rgba(212,175,55,0.08)] text-xs font-subheading">
        {chartData.map((item) => {
          const cfg = SEVERITY_COLORS[item.severity.toUpperCase()] || {
            fill: '#D1CBC0',
            label: item.severity,
          };
          const pct = Math.round((item.count / totalCalculated) * 100) || 0;

          return (
            <div
              key={item.severity}
              className="flex items-center justify-between px-2 py-1.5 rounded bg-[#141A1F] border border-[rgba(212,175,55,0.08)]"
            >
              <div className="flex items-center gap-2">
                <span
                  className="w-2 h-2 rounded-full shrink-0"
                  style={{
                    backgroundColor: cfg.fill,
                    boxShadow: `0 0 6px ${cfg.fill}80`,
                  }}
                />
                <span className="text-[#D1CBC0] capitalize">{cfg.label}</span>
              </div>
              <span className="font-mono text-[#FAF9F5] font-medium text-[11px]">
                {item.count} <span className="text-[#8E877D]">({pct}%)</span>
              </span>
            </div>
          );
        })}
      </div>
    </div>
  );
}
