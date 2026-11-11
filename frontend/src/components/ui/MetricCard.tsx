import React from 'react';
import { cn } from '@/lib/utils';

interface MetricCardProps {
  label: string;
  value: React.ReactNode;
  subValue?: React.ReactNode;
  icon?: React.ComponentType<{ className?: string; size?: number; color?: string }>;
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
  accentColor = '#D4AF37',
  trend,
  badge,
  onClick,
  className,
}: MetricCardProps) {
  return (
    <div
      onClick={onClick}
      className={cn(
        'rounded-xl p-5 transition-all duration-150 select-none flex flex-col justify-between font-sans',
        onClick && 'cursor-pointer hover:border-[#D4AF37]/40 hover:translate-y-[-1px]',
        className
      )}
      style={{
        backgroundColor: '#1C242B',
        border: '1px solid rgba(212, 175, 55, 0.14)',
        boxShadow: '0 4px 16px rgba(0, 0, 0, 0.4)',
      }}
    >
      <div className="flex items-center justify-between mb-3">
        <div className="text-xs font-medium text-[#D1CBC0] font-subheading">
          {label}
        </div>
        <div className="flex items-center gap-1.5">
          {badge}
          {Icon && (
            <div
              className="w-7 h-7 rounded-lg flex items-center justify-center shrink-0"
              style={{
                backgroundColor: `${accentColor}18`,
                border: `1px solid ${accentColor}35`,
                color: accentColor,
              }}
            >
              <Icon size={14} color={accentColor} />
            </div>
          )}
        </div>
      </div>

      <div className="flex items-baseline justify-between gap-2">
        <div className="text-2xl font-bold tracking-tight text-[#FAF9F5]">
          {value}
        </div>
        {trend && (
          <span
            className={cn(
              'text-[11px] font-medium px-2 py-0.5 rounded-full font-mono',
              trend.positive
                ? 'bg-emerald-500/10 text-[#22C55E] border border-emerald-500/20'
                : 'bg-rose-500/10 text-[#EF4444] border border-rose-500/20'
            )}
          >
            {trend.value}
          </span>
        )}
      </div>

      {subValue && (
        <div className="text-xs text-[#8E877D] mt-2 pt-2 border-t border-[rgba(212,175,55,0.08)] font-subheading font-light">
          {subValue}
        </div>
      )}
    </div>
  );
}
