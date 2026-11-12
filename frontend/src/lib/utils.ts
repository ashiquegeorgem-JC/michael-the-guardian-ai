import { type ClassValue, clsx } from 'clsx';
import { twMerge } from 'tailwind-merge';

export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs));
}

export function formatBytes(bytes: number): string {
  if (bytes === 0) return '0 B';
  const k = 1024;
  const sizes = ['B', 'KB', 'MB', 'GB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return `${parseFloat((bytes / Math.pow(k, i)).toFixed(1))} ${sizes[i]}`;
}

export function formatNumber(n: number): string {
  if (n >= 1_000_000) return `${(n / 1_000_000).toFixed(1)}M`;
  if (n >= 1_000) return `${(n / 1_000).toFixed(1)}K`;
  return n.toString();
}

export function formatRelativeTime(dateStr: string): string {
  const date = new Date(dateStr);
  const now = new Date();
  const diff = now.getTime() - date.getTime();
  const mins = Math.floor(diff / 60000);
  if (mins < 1) return 'just now';
  if (mins < 60) return `${mins}m ago`;
  const hours = Math.floor(mins / 60);
  if (hours < 24) return `${hours}h ago`;
  const days = Math.floor(hours / 24);
  return `${days}d ago`;
}

export function formatDateTime(dateStr: string | null): string {
  if (!dateStr) return '—';
  return new Date(dateStr).toLocaleString('en-US', {
    month: 'short', day: 'numeric',
    hour: '2-digit', minute: '2-digit', second: '2-digit',
  });
}

export const formatDate = formatDateTime;

export function severityColor(severity: string): string {
  const map: Record<string, string> = {
    CRITICAL: '#EF4444',
    HIGH: '#F59E0B',
    MEDIUM: '#F97316',
    LOW: '#10B981',
  };
  return map[severity] ?? '#94A3B8';
}

export function levelColor(level: string): string {
  const map: Record<string, string> = {
    CRITICAL: '#EF4444',
    ERROR: '#F87171',
    WARNING: '#FCD34D',
    INFO: '#93C5FD',
    DEBUG: '#64748B',
    UNKNOWN: '#64748B',
  };
  return map[level] ?? '#94A3B8';
}

export function methodLabel(method: string): string {
  const map: Record<string, string> = {
    isolation_forest: 'Isolation Forest',
    tfidf: 'TF-IDF',
    statistical: 'Statistical',
    rule_based: 'Rule-Based',
  };
  return map[method] ?? method;
}

export function truncate(str: string, max = 80): string {
  return str.length > max ? str.slice(0, max) + '…' : str;
}
