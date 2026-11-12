'use client';

import React from 'react';
import { usePathname } from 'next/navigation';
import {
  Bell,
  Calendar,
  Radio,
} from 'lucide-react';
import { useWebSocket } from '@/hooks/useWebSocket';

const PAGE_META: Record<string, { title: string; subtitle: string }> = {
  '/dashboard': {
    title: 'Command Centre',
    subtitle: 'Real-time security intelligence and operations overview',
  },
  '/logs': {
    title: 'Log Explorer',
    subtitle: 'Search, filter, ingest and investigate raw structured system events',
  },
  '/anomalies': {
    title: 'Anomaly Detection',
    subtitle: 'Unsupervised ML clustering, Isolation Forest outliers and temporal heuristics',
  },
  '/incidents': {
    title: 'Incident Centre',
    subtitle: 'Correlated security alerts, root cause hypotheses and triage response',
  },
  '/attack-chains': {
    title: 'Attack Chains',
    subtitle: 'MITRE ATT&CK multi-stage adversary progression reconstruction',
  },
  '/iocs': {
    title: 'IOC Intelligence',
    subtitle: 'Extracted indicators of compromise, validation status and entity graphs',
  },
  '/threat-intelligence': {
    title: 'Threat Intelligence',
    subtitle: 'Enriched external reputation scoring, provider signals and IOC correlation',
  },
  '/monitoring': {
    title: 'Live Monitoring',
    subtitle: 'Host telemetry, event ingestion velocity and WebSocket broadcast streams',
  },
  '/reports': {
    title: 'Report Centre',
    subtitle: 'Compliance documentation, NIST CSF audit logs and PDF/JSON export',
  },
  '/settings': {
    title: 'System Settings',
    subtitle: 'Security configurations, ML hyperparameters and provider credentials',
  },
};

interface TopbarProps {
  isCollapsed?: boolean;
  onToggleSidebar?: () => void;
}

export function Topbar({ isCollapsed = false, onToggleSidebar }: TopbarProps) {
  const pathname = usePathname();
  const { connected } = useWebSocket();

  const page = PAGE_META[pathname] || {
    title: 'Command Centre',
    subtitle: 'Real-time security intelligence and operations overview',
  };

  return (
    <header
      style={{
        height: 64,
        backgroundColor: '#0A0E13',
        borderBottom: '1px solid rgba(255, 255, 255, 0.06)',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'space-between',
        padding: '0 32px',
        position: 'sticky',
        top: 0,
        zIndex: 30,
        flexShrink: 0,
      }}
    >
      {/* ── Left: Heading (Times New Roman) & Subheading (Inter) ─────────── */}
      <div>
        <h1
          className="font-heading"
          style={{
            fontFamily: "'Times New Roman', Times, serif",
            fontSize: '1.35rem',
            fontWeight: 400,
            color: '#FFFFFF',
            letterSpacing: '0.01em',
            margin: 0,
            lineHeight: 1.2,
          }}
        >
          {page.title}
        </h1>
        <p
          className="font-subheading"
          style={{
            fontSize: '0.78rem',
            color: 'var(--text-secondary)',
            margin: 0,
            marginTop: 2,
            lineHeight: 1.3,
          }}
        >
          {page.subtitle}
        </p>
      </div>

      {/* ── Right: Minimalist Controls, Date Pill, Live State ─────────────── */}
      <div style={{ display: 'flex', alignItems: 'center', gap: 14 }}>
        {/* Minimalist Date Pill */}
        <div
          style={{
            display: 'flex',
            alignItems: 'center',
            gap: 8,
            backgroundColor: '#11161E',
            border: '1px solid rgba(255, 255, 255, 0.08)',
            borderRadius: 6,
            padding: '5px 12px',
            fontSize: '0.76rem',
            color: 'var(--text-secondary)',
          }}
          className="hidden sm:flex"
        >
          <Calendar size={13} color="var(--text-muted)" />
          <span style={{ color: '#FFFFFF', fontWeight: 500 }}>Live Session</span>
          <span style={{ color: 'var(--text-muted)' }}>|</span>
          <span style={{ fontSize: '0.72rem' }}>Past 24 Hours</span>
        </div>

        {/* WebSocket Live Status */}
        <div
          style={{
            display: 'flex',
            alignItems: 'center',
            gap: 6,
            padding: '4px 10px',
            borderRadius: 6,
            backgroundColor: connected ? 'rgba(52, 211, 153, 0.08)' : 'rgba(248, 113, 113, 0.08)',
            border: connected ? '1px solid rgba(52, 211, 153, 0.2)' : '1px solid rgba(248, 113, 113, 0.2)',
            fontSize: '0.72rem',
            color: connected ? '#34D399' : '#F87171',
          }}
        >
          <Radio size={12} className={connected ? 'animate-pulse' : ''} />
          <span>{connected ? 'Live Stream' : 'Connecting'}</span>
        </div>

        {/* Notification Bell */}
        <button
          style={{
            position: 'relative',
            background: 'transparent',
            border: '1px solid rgba(255, 255, 255, 0.08)',
            borderRadius: 6,
            width: 32,
            height: 32,
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            color: 'var(--text-secondary)',
            cursor: 'pointer',
          }}
          className="hover:text-white hover:border-white/20"
          title="Notifications"
        >
          <Bell size={14} />
          <span
            style={{
              position: 'absolute',
              top: 7,
              right: 7,
              width: 5,
              height: 5,
              borderRadius: '50%',
              backgroundColor: '#34D399',
            }}
          />
        </button>

        {/* User Avatar Circle */}
        <div
          style={{
            width: 32,
            height: 32,
            borderRadius: '50%',
            backgroundColor: '#161D26',
            border: '1px solid rgba(255, 255, 255, 0.12)',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            fontSize: '0.75rem',
            fontWeight: 600,
            color: '#FFFFFF',
          }}
        >
          M
        </div>
      </div>
    </header>
  );
}
