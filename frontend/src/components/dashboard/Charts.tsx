'use client';

import {
  ResponsiveContainer, AreaChart, Area, XAxis, YAxis,
  CartesianGrid, Tooltip, BarChart, Bar, Cell,
} from 'recharts';
import { formatNumber } from '@/lib/utils';
import { chartTooltipProps } from '@/lib/chartTheme';

// ── Log Volume Area Chart ─────────────────────────────────────────────────

interface VolumePoint { time: string; count: number }

export function LogVolumeChart({ data }: { data: VolumePoint[] }) {
  if (!data || data.length === 0) {
    return (
      <div className="empty-state" style={{ minHeight: 200 }}>
        <p className="empty-state-desc">No timeline data available. Upload and analyse logs.</p>
      </div>
    );
  }
  const formatted = data.map((d) => ({
    ...d,
    label: new Date(d.time).toLocaleTimeString('en-US', { hour: '2-digit', minute: '2-digit' }),
  }));

  return (
    <ResponsiveContainer width="100%" height={180}>
      <AreaChart data={formatted} margin={{ top: 4, right: 4, bottom: 0, left: -20 }}>
        <defs>
          <linearGradient id="blueGrad" x1="0" y1="0" x2="0" y2="1">
            <stop offset="5%" stopColor="#3B82F6" stopOpacity={0.25} />
            <stop offset="95%" stopColor="#3B82F6" stopOpacity={0} />
          </linearGradient>
        </defs>
        <CartesianGrid strokeDasharray="3 3" stroke="rgba(30,45,74,0.8)" />
        <XAxis dataKey="label" tick={{ fontSize: 10, fill: '#64748B' }} tickLine={false} axisLine={false} interval="preserveStartEnd" />
        <YAxis tickFormatter={formatNumber} tick={{ fontSize: 10, fill: '#64748B' }} tickLine={false} axisLine={false} />
        <Tooltip
          contentStyle={chartTooltipProps.contentStyle}
          labelStyle={chartTooltipProps.labelStyle}
          itemStyle={chartTooltipProps.itemStyle}
          cursor={chartTooltipProps.cursor}
        />
        <Area type="monotone" dataKey="count" stroke="#3B82F6" strokeWidth={2} fill="url(#blueGrad)" dot={false} activeDot={{ r: 4, fill: '#3B82F6' }} />
      </AreaChart>
    </ResponsiveContainer>
  );
}

// ── Severity Distribution Bar Chart ─────────────────────────────────────

interface SevData { severity: string; count: number }
const SEV_COLORS: Record<string, string> = {
  CRITICAL: '#EF4444', HIGH: '#F59E0B', MEDIUM: '#F97316', LOW: '#10B981',
};

export function SeverityBar({ data }: { data: SevData[] }) {
  if (!data || data.length === 0) {
    return (
      <div className="empty-state" style={{ minHeight: 160 }}>
        <p className="empty-state-desc">No severity data yet. Run anomaly detection first.</p>
      </div>
    );
  }

  return (
    <ResponsiveContainer width="100%" height={160}>
      <BarChart data={data} margin={{ top: 4, right: 4, bottom: 0, left: -20 }}>
        <CartesianGrid strokeDasharray="3 3" stroke="rgba(30,45,74,0.8)" vertical={false} />
        <XAxis dataKey="severity" tick={{ fontSize: 11, fill: '#64748B' }} tickLine={false} axisLine={false} />
        <YAxis tick={{ fontSize: 10, fill: '#64748B' }} tickLine={false} axisLine={false} />
        <Tooltip
          contentStyle={chartTooltipProps.contentStyle}
          labelStyle={chartTooltipProps.labelStyle}
          itemStyle={chartTooltipProps.itemStyle}
          cursor={chartTooltipProps.cursor}
        />
        <Bar dataKey="count" radius={[4, 4, 0, 0]} maxBarSize={48}>
          {data.map((entry) => (
            <Cell key={entry.severity} fill={SEV_COLORS[entry.severity] ?? '#94A3B8'} />
          ))}
        </Bar>
      </BarChart>
    </ResponsiveContainer>
  );
}

// ── Level Distribution Bar Chart ─────────────────────────────────────────

interface LevelData { level: string; count: number }
const LEVEL_COLORS: Record<string, string> = {
  CRITICAL: '#EF4444', ERROR: '#F87171', WARNING: '#FCD34D',
  INFO: '#3B82F6', DEBUG: '#64748B', UNKNOWN: '#475569',
};

export function LevelDistBar({ data }: { data: LevelData[] }) {
  if (!data || data.length === 0) {
    return (
      <div className="empty-state" style={{ minHeight: 160 }}>
        <p className="empty-state-desc">Upload logs to see level distribution.</p>
      </div>
    );
  }

  return (
    <ResponsiveContainer width="100%" height={160}>
      <BarChart data={data} layout="vertical" margin={{ top: 0, right: 4, bottom: 0, left: 40 }}>
        <CartesianGrid strokeDasharray="3 3" stroke="rgba(30,45,74,0.8)" horizontal={false} />
        <XAxis type="number" tick={{ fontSize: 10, fill: '#64748B' }} tickLine={false} axisLine={false} tickFormatter={formatNumber} />
        <YAxis type="category" dataKey="level" tick={{ fontSize: 11, fill: '#94A3B8' }} tickLine={false} axisLine={false} width={56} />
        <Tooltip
          contentStyle={chartTooltipProps.contentStyle}
          labelStyle={chartTooltipProps.labelStyle}
          itemStyle={chartTooltipProps.itemStyle}
          cursor={chartTooltipProps.cursor}
        />
        <Bar dataKey="count" radius={[0, 4, 4, 0]} maxBarSize={20}>
          {data.map((entry) => (
            <Cell key={entry.level} fill={LEVEL_COLORS[entry.level] ?? '#94A3B8'} />
          ))}
        </Bar>
      </BarChart>
    </ResponsiveContainer>
  );
}

// ── Mini sparkline ────────────────────────────────────────────────────────
export function SparklineChart({ data, color = '#3B82F6' }: { data: number[]; color?: string }) {
  const d = data.map((v, i) => ({ i, v }));
  return (
    <ResponsiveContainer width="100%" height={48}>
      <AreaChart data={d} margin={{ top: 2, right: 0, bottom: 0, left: 0 }}>
        <defs>
          <linearGradient id={`spark-${color}`} x1="0" y1="0" x2="0" y2="1">
            <stop offset="5%" stopColor={color} stopOpacity={0.3} />
            <stop offset="95%" stopColor={color} stopOpacity={0} />
          </linearGradient>
        </defs>
        <Area type="monotone" dataKey="v" stroke={color} strokeWidth={1.5} fill={`url(#spark-${color})`} dot={false} />
      </AreaChart>
    </ResponsiveContainer>
  );
}
