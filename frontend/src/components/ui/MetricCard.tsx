import React from 'react';
import { cn } from '@/lib/utils';

interface MetricCardProps {
  label: string;
  value: React.ReactNode;
  subValue?: React.ReactNode;
  icon?: React.ComponentType<{ className?: string; size?: number; color?: string; strokeWidth?: number }>;
  accentColor?: string;
  trend?: { value: string; positive?: boolean };
  badge?: React.ReactNode;
  onClick?: () => void;
  className?: string;
}

export function MetricCard({
  label,
  value,
  subValue,
  icon: Icon,
  accentColor = '#38BDF8',
  trend,
  badge,
  onClick,
  className,
}: MetricCardProps) {
  return (
    <div
      onClick={onClick}
      className={cn(
        'rounded-2xl p-6 transition-all duration-150 select-none flex flex-col justify-between font-sans',
        onClick && 'cursor-pointer hover:border-white/20 hover:translate-y-[-1px]',
        className
      )}
      style={{
        backgroundColor: '#11161E',
        border: '1px solid rgba(255, 255, 255, 0.08)',
        boxShadow: '0 4px 20px rgba(0, 0, 0, 0.35)',
      }}
    >
      <div className="flex items-center justify-between mb-3.5">
        <div className="text-xs font-medium text-[#94A3B8] font-subheading tracking-wide">
          {label}
        </div>
        <div className="flex items-center gap-1.5">
          {badge}
          {Icon && (
            <div
              className="w-7 h-7 rounded-lg flex items-center justify-center shrink-0"
              style={{
                backgroundColor: `${accentColor}18`,
                border: `1px solid ${accentColor}28`,
                color: accentColor,
              }}
            >
              <Icon size={14} color={accentColor} strokeWidth={1.8} />
            </div>
          )}
        </div>
      </div>

      <div className="flex items-baseline justify-between gap-2">
        <div className="text-2xl font-bold tracking-tight text-white font-mono leading-none">
          {value}
        </div>
        {trend && (
          <span
            className={cn(
              'text-[10px] font-medium px-2 py-0.5 rounded font-mono',
              trend.positive
                ? 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/20'
                : 'bg-rose-500/10 text-rose-400 border border-rose-500/20'
            )}
          >
            {trend.value}
          </span>
        )}
      </div>

      {subValue && (
        <div className="text-[11px] text-[#64748B] font-subheading mt-3 pt-2.5 border-t border-white/[0.05] truncate">
          {subValue}
        </div>
      )}
    </div>
  );
}
