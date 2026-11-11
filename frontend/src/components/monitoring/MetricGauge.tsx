'use client';

import React from 'react';
import { LucideIcon } from 'lucide-react';
import { Card } from '@/components/ui/Card';

interface MetricGaugeProps {
  label: string;
  value: number; // percentage (0 - 100)
  unit?: string;
  subValue?: string;
  icon: LucideIcon;
  variant?: 'blue' | 'purple' | 'emerald' | 'amber';
}

export function MetricGauge({
  label,
  value,
  unit = '%',
  subValue,
  icon: Icon,
  variant = 'blue',
}: MetricGaugeProps) {
  const clampedValue = Math.min(100, Math.max(0, value));

  const colors = {
    blue: {
      bar: 'bg-blue-500',
      text: 'text-blue-400',
      iconBg: 'bg-blue-500/10 border-blue-500/20 text-blue-400',
    },
    purple: {
      bar: 'bg-purple-500',
      text: 'text-purple-400',
      iconBg: 'bg-purple-500/10 border-purple-500/20 text-purple-400',
    },
    emerald: {
      bar: 'bg-emerald-500',
      text: 'text-emerald-400',
      iconBg: 'bg-emerald-500/10 border-emerald-500/20 text-emerald-400',
    },
    amber: {
      bar: 'bg-amber-500',
      text: 'text-amber-400',
      iconBg: 'bg-amber-500/10 border-amber-500/20 text-amber-400',
    },
  }[variant];

  // If high usage, warn with rose
  const isHigh = clampedValue > 85;
  const barClass = isHigh ? 'bg-rose-500 shadow-[0_0_12px_rgba(244,63,94,0.4)]' : colors.bar;
  const textClass = isHigh ? 'text-rose-400' : colors.text;

  return (
    <Card className="p-5 space-y-3">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2.5">
          <div className={`p-2 rounded-xl border ${colors.iconBg}`}>
            <Icon className="w-4 h-4" />
          </div>
          <span className="text-xs font-semibold uppercase tracking-wider text-slate-300">
            {label}
          </span>
        </div>
        <span className={`text-xl font-bold font-mono ${textClass}`}>
          {clampedValue.toFixed(1)}
          <span className="text-xs text-slate-500 ml-0.5">{unit}</span>
        </span>
      </div>

      {/* Progress Track */}
      <div className="w-full h-2 rounded-full bg-slate-800/80 overflow-hidden">
        <div
          className={`h-full rounded-full transition-all duration-500 ${barClass}`}
          style={{ width: `${clampedValue}%` }}
        />
      </div>

      {subValue && (
        <div className="text-[11px] text-slate-400 font-mono truncate">
          {subValue}
        </div>
      )}
    </Card>
  );
}
