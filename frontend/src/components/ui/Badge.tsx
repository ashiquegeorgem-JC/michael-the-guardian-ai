import React from 'react';
import { cn } from '@/lib/utils';
import { LogLevel, Severity, IncidentStatus } from '@/types';

type BadgeVariant =
  | LogLevel
  | Severity
  | IncidentStatus
  | 'default'
  | 'cyan'
  | 'purple'
  | 'success'
  | 'blue'
  | 'red'
  | 'orange'
  | 'yellow';

interface BadgeProps extends React.HTMLAttributes<HTMLSpanElement> {
  variant?: BadgeVariant | string;
  size?: 'sm' | 'md' | 'lg';
  dot?: boolean;
  glow?: boolean;
  children: React.ReactNode;
}

const variantStyles: Record<string, { bg: string; text: string; border: string; dotColor: string }> = {
  // Severity & Alert Levels
  CRITICAL: { bg: 'rgba(239, 68, 68, 0.12)', text: '#EF4444', border: 'rgba(239, 68, 68, 0.3)', dotColor: '#EF4444' },
  ERROR: { bg: 'rgba(239, 68, 68, 0.12)', text: '#EF4444', border: 'rgba(239, 68, 68, 0.3)', dotColor: '#EF4444' },
  HIGH: { bg: 'rgba(245, 158, 11, 0.12)', text: '#F59E0B', border: 'rgba(245, 158, 11, 0.3)', dotColor: '#F59E0B' },
  WARNING: { bg: 'rgba(245, 158, 11, 0.12)', text: '#F59E0B', border: 'rgba(245, 158, 11, 0.3)', dotColor: '#F59E0B' },
  MEDIUM: { bg: 'rgba(34, 184, 255, 0.12)', text: '#22B8FF', border: 'rgba(34, 184, 255, 0.3)', dotColor: '#22B8FF' },
  INFO: { bg: 'rgba(59, 130, 246, 0.12)', text: '#3B82F6', border: 'rgba(59, 130, 246, 0.3)', dotColor: '#3B82F6' },
  LOW: { bg: 'rgba(59, 130, 246, 0.12)', text: '#3B82F6', border: 'rgba(59, 130, 246, 0.3)', dotColor: '#3B82F6' },
  DEBUG: { bg: 'rgba(104, 117, 137, 0.14)', text: '#A7B1C0', border: 'rgba(104, 117, 137, 0.25)', dotColor: '#A7B1C0' },
  UNKNOWN: { bg: 'rgba(104, 117, 137, 0.14)', text: '#A7B1C0', border: 'rgba(104, 117, 137, 0.25)', dotColor: '#A7B1C0' },

  // Incident Statuses
  open: { bg: 'rgba(239, 68, 68, 0.12)', text: '#EF4444', border: 'rgba(239, 68, 68, 0.3)', dotColor: '#EF4444' },
  investigating: { bg: 'rgba(245, 158, 11, 0.12)', text: '#F59E0B', border: 'rgba(245, 158, 11, 0.3)', dotColor: '#F59E0B' },
  resolved: { bg: 'rgba(34, 197, 94, 0.12)', text: '#22C55E', border: 'rgba(34, 197, 94, 0.3)', dotColor: '#22C55E' },
  false_positive: { bg: 'rgba(104, 117, 137, 0.14)', text: '#A7B1C0', border: 'rgba(104, 117, 137, 0.25)', dotColor: '#A7B1C0' },

  // Named Variant Presets
  default: { bg: 'rgba(255, 255, 255, 0.04)', text: '#A7B1C0', border: 'rgba(255, 255, 255, 0.08)', dotColor: '#A7B1C0' },
  cyan: { bg: 'rgba(34, 184, 255, 0.12)', text: '#22B8FF', border: 'rgba(34, 184, 255, 0.3)', dotColor: '#22B8FF' },
  purple: { bg: 'rgba(139, 92, 246, 0.12)', text: '#8B5CF6', border: 'rgba(139, 92, 246, 0.3)', dotColor: '#8B5CF6' },
  success: { bg: 'rgba(34, 197, 94, 0.12)', text: '#22C55E', border: 'rgba(34, 197, 94, 0.3)', dotColor: '#22C55E' },
  blue: { bg: 'rgba(59, 130, 246, 0.12)', text: '#3B82F6', border: 'rgba(59, 130, 246, 0.3)', dotColor: '#3B82F6' },
  red: { bg: 'rgba(239, 68, 68, 0.12)', text: '#EF4444', border: 'rgba(239, 68, 68, 0.3)', dotColor: '#EF4444' },
  orange: { bg: 'rgba(245, 158, 11, 0.12)', text: '#F59E0B', border: 'rgba(245, 158, 11, 0.3)', dotColor: '#F59E0B' },
  yellow: { bg: 'rgba(245, 158, 11, 0.12)', text: '#F59E0B', border: 'rgba(245, 158, 11, 0.3)', dotColor: '#F59E0B' },
};

export function Badge({
  variant = 'default',
  size = 'md',
  dot = false,
  glow = false,
  className,
  children,
  style,
  ...props
}: BadgeProps) {
  const cfg =
    variantStyles[variant.toUpperCase()] ||
    variantStyles[variant] ||
    variantStyles.default;

  const sizeClasses = {
    sm: 'text-[10px] px-2 py-0.5',
    md: 'text-xs px-2.5 py-0.5',
    lg: 'text-xs px-3 py-1 font-medium',
  }[size];

  return (
    <span
      className={cn(
        'inline-flex items-center gap-1.5 rounded-full font-sans font-medium transition-colors select-none',
        sizeClasses,
        className
      )}
      style={{
        backgroundColor: cfg.bg,
        color: cfg.text,
        border: `1px solid ${cfg.border}`,
        ...style,
      }}
      {...props}
    >
      {dot && (
        <span
          className="rounded-full shrink-0"
          style={{
            width: size === 'sm' ? 5 : 6,
            height: size === 'sm' ? 5 : 6,
            backgroundColor: cfg.dotColor,
          }}
        />
      )}
      {children}
    </span>
  );
}
