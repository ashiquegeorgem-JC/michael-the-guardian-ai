'use client';

import React from 'react';

// ── 1. PageShell ─────────────────────────────────────────────────────────────
export interface PageShellProps {
  children: React.ReactNode;
  className?: string;
}

export function PageShell({ children, className = '' }: PageShellProps) {
  return (
    <div
      className={`w-full max-w-[1600px] mx-auto space-y-8 pb-16 font-sans text-slate-100 ${className}`}
    >
      {children}
    </div>
  );
}

// ── 2. StatusIndicator ───────────────────────────────────────────────────────
export interface StatusIndicatorProps {
  label: string;
  status?: 'online' | 'warning' | 'critical' | 'active' | 'neutral';
  subLabel?: string;
  className?: string;
}

export function StatusIndicator({
  label,
  status = 'online',
  subLabel,
  className = '',
}: StatusIndicatorProps) {
  const colorMap = {
    online: '#10B981',
    active: '#38BDF8',
    warning: '#F59E0B',
    critical: '#EF4444',
    neutral: '#94A3B8',
  };

  const dotColor = colorMap[status];

  return (
    <div className={`inline-flex items-center gap-2 text-xs font-mono ${className}`}>
      <span
        style={{
          width: 7,
          height: 7,
          borderRadius: '50%',
          backgroundColor: dotColor,
          boxShadow: `0 0 8px ${dotColor}60`,
        }}
        className="shrink-0 animate-pulse-subtle"
      />
      <span className="text-white font-medium">{label}</span>
      {subLabel && <span className="text-[#64748B]">({subLabel})</span>}
    </div>
  );
}

// ── 3. SectionHeader ─────────────────────────────────────────────────────────
export interface SectionHeaderProps {
  title: string;
  description?: React.ReactNode;
  tag?: string;
  actions?: React.ReactNode;
  statusList?: Array<{ label: string; status?: 'online' | 'warning' | 'critical' | 'active' | 'neutral' }>;
  className?: string;
}

export function SectionHeader({
  title,
  description,
  tag,
  actions,
  statusList,
  className = '',
}: SectionHeaderProps) {
  return (
    <div
      className={`flex flex-col gap-3 pb-5 border-b border-white/[0.06] ${className}`}
    >
      <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4">
        <div>
          {tag && (
            <div className="flex items-center gap-2 mb-1.5">
              <span className="w-1.5 h-1.5 rounded-full bg-[#38BDF8]" />
              <span className="text-[11px] font-mono uppercase tracking-widest text-[#38BDF8] font-medium">
                {tag}
              </span>
            </div>
          )}
          <h1
            className="text-2xl md:text-3xl font-heading text-white tracking-normal font-normal"
            style={{ fontFamily: "'Times New Roman', Times, serif" }}
          >
            {title}
          </h1>
          {description && (
            <div className="text-xs md:text-sm text-[#94A3B8] font-subheading mt-1.5 max-w-4xl leading-relaxed">
              {description}
            </div>
          )}
        </div>

        {actions && (
          <div className="flex items-center gap-3 shrink-0 flex-wrap">
            {actions}
          </div>
        )}
      </div>

      {statusList && statusList.length > 0 && (
        <div className="flex items-center gap-5 pt-2 flex-wrap text-xs text-[#94A3B8] font-subheading border-t border-white/[0.04]">
          {statusList.map((st, i) => (
            <StatusIndicator
              key={i}
              label={st.label}
              status={st.status || 'online'}
            />
          ))}
        </div>
      )}
    </div>
  );
}

// ── 4. Section (The Large Primary Visual Container) ─────────────────────────
export interface SectionProps {
  children: React.ReactNode;
  title?: string;
  subtitle?: string;
  headerAction?: React.ReactNode;
  className?: string;
}

export function Section({
  children,
  title,
  subtitle,
  headerAction,
  className = '',
}: SectionProps) {
  return (
    <section
      style={{
        backgroundColor: '#0C1017',
        border: '1px solid rgba(255, 255, 255, 0.06)',
        borderRadius: 16,
        padding: '28px',
        boxShadow: '0 4px 24px rgba(0, 0, 0, 0.45)',
      }}
      className={`space-y-6 ${className}`}
    >
      {(title || headerAction) && (
        <div className="flex items-center justify-between pb-3.5 border-b border-white/[0.06]">
          <div>
            {title && (
              <h2
                className="text-lg md:text-xl font-heading text-white tracking-normal font-normal"
                style={{ fontFamily: "'Times New Roman', Times, serif" }}
              >
                {title}
              </h2>
            )}
            {subtitle && (
              <p className="text-xs text-[#94A3B8] font-subheading mt-0.5">
                {subtitle}
              </p>
            )}
          </div>
          {headerAction && <div className="shrink-0">{headerAction}</div>}
        </div>
      )}
      {children}
    </section>
  );
}

// ── 5. MetricRow & MetricItem (Distinct Spaced Cards, Never Touching) ──────
export interface MetricItemProps {
  label: string;
  value: string | number;
  change?: string;
  changeColor?: string;
  badge?: string;
  badgeColor?: string;
  sub?: string;
  progress?: number; // 0 - 100 visual meter
  progressColor?: string;
  icon?: React.ComponentType<{ size?: number; className?: string; color?: string }>;
  className?: string;
  valueClassName?: string;
}

export function MetricItem({
  label,
  value,
  change,
  changeColor,
  badge,
  badgeColor = '#38BDF8',
  sub,
  progress,
  progressColor,
  icon: Icon,
  className = '',
  valueClassName = 'text-2xl sm:text-3xl',
}: MetricItemProps) {
  return (
    <div
      style={{
        backgroundColor: '#0F141D',
        border: '1px solid rgba(255, 255, 255, 0.07)',
        borderRadius: 14,
        boxShadow: '0 4px 16px rgba(0, 0, 0, 0.25)',
      }}
      className={`p-5 sm:p-6 flex flex-col justify-between gap-3 min-w-0 transition-all hover:border-white/[0.14] ${className}`}
    >
      <div className="flex items-center justify-between gap-2">
        <span className="text-[11px] text-[#94A3B8] font-mono tracking-wider uppercase font-medium truncate">
          {label}
        </span>
        {badge && (
          <span
            className="text-[10px] font-mono px-2 py-0.5 rounded font-medium shrink-0"
            style={{
              backgroundColor: `${badgeColor}18`,
              color: badgeColor,
              border: `1px solid ${badgeColor}30`,
            }}
          >
            {badge}
          </span>
        )}
      </div>

      <div className="flex items-baseline justify-between gap-3 my-0.5">
        <div className="flex items-baseline gap-2.5 min-w-0">
          <span className={`${valueClassName} font-mono font-bold text-white tracking-tight truncate`}>
            {value}
          </span>
          {change && (
            <span
              className="text-xs font-mono font-medium shrink-0"
              style={{ color: changeColor || '#38BDF8' }}
            >
              {change}
            </span>
          )}
        </div>
        {Icon && (
          <div
            className="w-8 h-8 rounded-lg flex items-center justify-center shrink-0"
            style={{
              backgroundColor: 'rgba(255, 255, 255, 0.03)',
              border: '1px solid rgba(255, 255, 255, 0.06)',
            }}
          >
            <Icon size={16} className="text-[#94A3B8]" />
          </div>
        )}
      </div>

      {progress !== undefined && (
        <div className="w-full bg-white/[0.06] rounded-full h-1.5 overflow-hidden my-1">
          <div
            className="h-full rounded-full transition-all duration-500"
            style={{
              width: `${Math.min(100, Math.max(0, progress))}%`,
              backgroundColor: progressColor || '#38BDF8',
              boxShadow: `0 0 6px ${progressColor || '#38BDF8'}80`,
            }}
          />
        </div>
      )}

      {sub && (
        <span className="text-[11px] text-[#64748B] font-sans truncate leading-normal">
          {sub}
        </span>
      )}
    </div>
  );
}

export interface MetricRowProps {
  children: React.ReactNode;
  columns?: number;
  className?: string;
}

export function MetricRow({ children, columns = 5, className = '' }: MetricRowProps) {
  const colClasses: Record<number, string> = {
    3: 'grid-cols-1 sm:grid-cols-3',
    4: 'grid-cols-1 sm:grid-cols-2 lg:grid-cols-4',
    5: 'grid-cols-1 sm:grid-cols-2 md:grid-cols-3 lg:grid-cols-5',
    6: 'grid-cols-1 sm:grid-cols-2 md:grid-cols-3 lg:grid-cols-6',
  };

  return (
    <div
      className={`grid ${colClasses[columns] || 'grid-cols-1 sm:grid-cols-2 lg:grid-cols-5'} gap-4 sm:gap-5 lg:gap-6 ${className}`}
    >
      {children}
    </div>
  );
}

// ── 6. DataPanel & ChartPanel ───────────────────────────────────────────────
export interface DataPanelProps {
  children: React.ReactNode;
  title?: string;
  subtitle?: string;
  headerAction?: React.ReactNode;
  className?: string;
}

export function DataPanel({
  children,
  title,
  subtitle,
  headerAction,
  className = '',
}: DataPanelProps) {
  return (
    <div
      style={{
        backgroundColor: '#0F141D',
        border: '1px solid rgba(255, 255, 255, 0.05)',
        borderRadius: 12,
        padding: '22px 26px',
      }}
      className={`flex flex-col justify-between ${className}`}
    >
      {(title || headerAction) && (
        <div className="flex items-center justify-between pb-3 mb-4 border-b border-white/[0.05]">
          <div>
            {title && (
              <h3
                className="text-base font-heading text-white font-normal"
                style={{ fontFamily: "'Times New Roman', Times, serif" }}
              >
                {title}
              </h3>
            )}
            {subtitle && (
              <p className="text-xs text-[#94A3B8] font-subheading mt-0.5">
                {subtitle}
              </p>
            )}
          </div>
          {headerAction && <div className="shrink-0">{headerAction}</div>}
        </div>
      )}
      {children}
    </div>
  );
}

// ── 7. Toolbar ──────────────────────────────────────────────────────────────
export interface ToolbarProps {
  children: React.ReactNode;
  className?: string;
}

export function Toolbar({ children, className = '' }: ToolbarProps) {
  return (
    <div
      style={{
        backgroundColor: '#0F141D',
        border: '1px solid rgba(255, 255, 255, 0.05)',
        borderRadius: 10,
        padding: '14px 18px',
      }}
      className={`flex flex-wrap items-center justify-between gap-4 ${className}`}
    >
      {children}
    </div>
  );
}

