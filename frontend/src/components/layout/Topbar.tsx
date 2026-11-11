'use client';

import React from 'react';
import { usePathname } from 'next/navigation';
import {
  Bell,
  Radio,
  ChevronDown,
  Menu,
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
  '/copilot': {
    title: 'AI Copilot',
    subtitle: 'Context-aware LLM security analyst and automated incident investigation',
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
        height: 68,
        backgroundColor: '#171E24',
        borderBottom: '1px solid rgba(212, 175, 55, 0.14)',
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
      {/* Left: Sidebar Toggle + Page Title & Subtitle */}
      <div style={{ display: 'flex', alignItems: 'center', gap: 14 }}>
        {isCollapsed && onToggleSidebar && (
          <button
            onClick={onToggleSidebar}
            title="Expand sidebar"
            style={{
              background: 'rgba(212, 175, 55, 0.08)',
              border: '1px solid rgba(212, 175, 55, 0.2)',
              borderRadius: 8,
              padding: '6px',
              color: '#D4AF37',
              cursor: 'pointer',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
            }}
          >
            <Menu size={16} />
          </button>
        )}

        <div style={{ display: 'flex', flexDirection: 'column', gap: 1 }}>
          <h1
            className="font-heading font-semibold"
            style={{
              fontSize: '1.25rem',
              letterSpacing: '-0.01em',
              color: '#FAF9F5',
              lineHeight: 1.2,
              margin: 0,
            }}
          >
            {page.title}
          </h1>
          <p
            className="font-subheading font-light"
            style={{
              fontSize: '0.8rem',
              color: '#D1CBC0',
              margin: 0,
              letterSpacing: '0.01em',
            }}
          >
            {page.subtitle}
          </p>
        </div>
      </div>

      {/* Right: Live Telemetry Indicators & Profile Pill */}
      <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
        {/* Status: Live Indicator Pill */}
        <div
          style={{
            display: 'flex',
            alignItems: 'center',
            gap: 7,
            padding: '5px 12px',
            backgroundColor: 'rgba(34, 197, 94, 0.08)',
            border: '1px solid rgba(34, 197, 94, 0.28)',
            borderRadius: 99,
            fontSize: '0.74rem',
            fontWeight: 600,
            color: '#22C55E',
            fontFamily: 'var(--font-subheading)',
          }}
        >
          <span
            style={{
              width: 7,
              height: 7,
              backgroundColor: '#22C55E',
              borderRadius: '50%',
              display: 'inline-block',
              boxShadow: '0 0 8px rgba(34, 197, 94, 0.8)',
            }}
          />
          Live
        </div>

        {/* Status: WebSocket Pill in Celestial Gold */}
        <div
          style={{
            display: 'flex',
            alignItems: 'center',
            gap: 7,
            padding: '5px 12px',
            backgroundColor: connected
              ? 'rgba(212, 175, 55, 0.08)'
              : 'rgba(245, 158, 11, 0.08)',
            border: connected
              ? '1px solid rgba(212, 175, 55, 0.3)'
              : '1px solid rgba(245, 158, 11, 0.3)',
            borderRadius: 99,
            fontSize: '0.74rem',
            fontWeight: 500,
            color: connected ? '#D4AF37' : '#F59E0B',
            fontFamily: 'var(--font-subheading)',
          }}
        >
          <Radio size={13} color={connected ? '#D4AF37' : '#F59E0B'} />
          <span>{connected ? 'WebSocket Connected' : 'WebSocket Polling'}</span>
        </div>

        {/* Notifications Icon Button */}
        <button
          title="Security Notifications"
          style={{
            position: 'relative',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            width: 36,
            height: 36,
            backgroundColor: '#1C242B',
            border: '1px solid rgba(212, 175, 55, 0.15)',
            borderRadius: 10,
            color: '#D1CBC0',
            cursor: 'pointer',
            transition: 'all 0.15s ease',
          }}
          onMouseEnter={(e) => {
            e.currentTarget.style.color = '#FAF9F5';
            e.currentTarget.style.borderColor = 'rgba(212, 175, 55, 0.4)';
            e.currentTarget.style.backgroundColor = '#222C35';
          }}
          onMouseLeave={(e) => {
            e.currentTarget.style.color = '#D1CBC0';
            e.currentTarget.style.borderColor = 'rgba(212, 175, 55, 0.15)';
            e.currentTarget.style.backgroundColor = '#1C242B';
          }}
        >
          <Bell size={16} />
          <span
            style={{
              position: 'absolute',
              top: 8,
              right: 8,
              width: 6,
              height: 6,
              borderRadius: '50%',
              backgroundColor: '#D4AF37',
              boxShadow: '0 0 6px rgba(212, 175, 55, 0.8)',
            }}
          />
        </button>

        {/* User / SOC Pill with Archangel Michael Avatar */}
        <div
          style={{
            display: 'flex',
            alignItems: 'center',
            gap: 9,
            padding: '5px 12px 5px 6px',
            backgroundColor: '#1C242B',
            border: '1px solid rgba(212, 175, 55, 0.18)',
            borderRadius: 99,
            cursor: 'pointer',
            transition: 'all 0.15s ease',
          }}
          onMouseEnter={(e) => {
            e.currentTarget.style.borderColor = 'rgba(212, 175, 55, 0.5)';
            e.currentTarget.style.backgroundColor = '#222C35';
          }}
          onMouseLeave={(e) => {
            e.currentTarget.style.borderColor = 'rgba(212, 175, 55, 0.18)';
            e.currentTarget.style.backgroundColor = '#1C242B';
          }}
        >
          <div
            style={{
              width: 26,
              height: 26,
              borderRadius: '50%',
              overflow: 'hidden',
              border: '1px solid rgba(212, 175, 55, 0.6)',
              boxShadow: '0 0 8px rgba(212, 175, 55, 0.4)',
              flexShrink: 0,
            }}
          >
            <img
              src="/michael-logo.png"
              alt="Michael Avatar"
              style={{ width: '100%', height: '100%', objectFit: 'cover' }}
            />
          </div>
          <span
            className="font-subheading"
            style={{
              fontSize: '0.78rem',
              fontWeight: 600,
              color: '#FAF9F5',
              letterSpacing: '0.02em',
            }}
          >
            MICHAEL v1.0
          </span>
          <ChevronDown size={13} color="#D4AF37" />
        </div>
      </div>
    </header>
  );
}
