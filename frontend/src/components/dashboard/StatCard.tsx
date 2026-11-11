'use client';

import { motion } from 'framer-motion';
import { LucideIcon } from 'lucide-react';

interface StatCardProps {
  title: string;
  value: string | number;
  subtitle?: string;
  icon: LucideIcon;
  trend?: { value: number; label: string };
  color?: 'blue' | 'red' | 'green' | 'amber' | 'violet';
  variant?: string;
  loading?: boolean;
  index?: number;
}

const COLOR_MAP: Record<string, { bg: string; border: string; icon: string; text: string }> = {
  blue: { bg: 'rgba(59, 130, 246, 0.1)', border: 'rgba(59, 130, 246, 0.2)', icon: '#3B82F6', text: '#93C5FD' },
  primary: { bg: 'rgba(59, 130, 246, 0.1)', border: 'rgba(59, 130, 246, 0.2)', icon: '#3B82F6', text: '#93C5FD' },
  red: { bg: 'rgba(239, 68, 68, 0.1)', border: 'rgba(239, 68, 68, 0.2)', icon: '#EF4444', text: '#FCA5A5' },
  danger: { bg: 'rgba(239, 68, 68, 0.1)', border: 'rgba(239, 68, 68, 0.2)', icon: '#EF4444', text: '#FCA5A5' },
  green: { bg: 'rgba(16, 185, 129, 0.1)', border: 'rgba(16, 185, 129, 0.2)', icon: '#10B981', text: '#6EE7B7' },
  success: { bg: 'rgba(16, 185, 129, 0.1)', border: 'rgba(16, 185, 129, 0.2)', icon: '#10B981', text: '#6EE7B7' },
  amber: { bg: 'rgba(245, 158, 11, 0.1)', border: 'rgba(245, 158, 11, 0.2)', icon: '#F59E0B', text: '#FCD34D' },
  warning: { bg: 'rgba(245, 158, 11, 0.1)', border: 'rgba(245, 158, 11, 0.2)', icon: '#F59E0B', text: '#FCD34D' },
  violet: { bg: 'rgba(124, 58, 237, 0.1)', border: 'rgba(124, 58, 237, 0.2)', icon: '#7C3AED', text: '#C4B5FD' },
  purple: { bg: 'rgba(124, 58, 237, 0.1)', border: 'rgba(124, 58, 237, 0.2)', icon: '#7C3AED', text: '#C4B5FD' },
};

export function StatCard({ title, value, subtitle, icon: Icon, trend, color = 'blue', variant, loading = false, index = 0 }: StatCardProps) {
  const chosenColor = (variant || color) as keyof typeof COLOR_MAP;
  const c = COLOR_MAP[chosenColor] || COLOR_MAP.blue;

  if (loading) {
    return (
      <div className="card" style={{ padding: 24 }}>
        <div className="skeleton" style={{ height: 14, width: '60%', marginBottom: 16 }} />
        <div className="skeleton" style={{ height: 32, width: '40%', marginBottom: 8 }} />
        <div className="skeleton" style={{ height: 12, width: '70%' }} />
      </div>
    );
  }

  return (
    <motion.div
      initial={{ opacity: 0, y: 16 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.4, delay: index * 0.07, ease: [0.4, 0, 0.2, 1] }}
      className="card"
      style={{
        padding: 24,
        position: 'relative',
        overflow: 'hidden',
        transition: 'border-color 0.2s, box-shadow 0.2s',
        cursor: 'default',
      }}
      whileHover={{ y: -2 }}
    >
      {/* Background accent */}
      <div style={{
        position: 'absolute',
        top: -20,
        right: -20,
        width: 100,
        height: 100,
        background: c.bg,
        borderRadius: '50%',
        filter: 'blur(20px)',
        pointerEvents: 'none',
      }} />

      {/* Header */}
      <div style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', marginBottom: 16 }}>
        <div style={{
          width: 40,
          height: 40,
          background: c.bg,
          border: `1px solid ${c.border}`,
          borderRadius: 10,
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
        }}>
          <Icon size={18} color={c.icon} strokeWidth={2} />
        </div>
        {trend && (
          <div style={{
            padding: '2px 8px',
            borderRadius: 99,
            fontSize: '0.7rem',
            fontWeight: 600,
            background: trend.value >= 0 ? 'rgba(16, 185, 129, 0.1)' : 'rgba(239, 68, 68, 0.1)',
            color: trend.value >= 0 ? 'var(--success)' : 'var(--danger)',
          }}>
            {trend.value >= 0 ? '+' : ''}{trend.value}% {trend.label}
          </div>
        )}
      </div>

      {/* Value */}
      <motion.div
        key={String(value)}
        initial={{ opacity: 0, y: 8 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.3 }}
        style={{ fontSize: '2rem', fontWeight: 800, letterSpacing: '-0.03em', lineHeight: 1, marginBottom: 6, color: c.text }}
      >
        {value}
      </motion.div>

      {/* Title */}
      <div style={{ fontSize: '0.8rem', fontWeight: 600, color: 'var(--text-secondary)', marginBottom: 2 }}>
        {title}
      </div>
      {subtitle && (
        <div style={{ fontSize: '0.72rem', color: 'var(--text-muted)' }}>{subtitle}</div>
      )}
    </motion.div>
  );
}
