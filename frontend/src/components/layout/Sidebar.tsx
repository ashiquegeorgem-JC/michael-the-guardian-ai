'use client';

import React from 'react';
import Link from 'next/link';
import { usePathname } from 'next/navigation';
import {
  LayoutDashboard,
  FileText,
  AlertTriangle,
  ShieldAlert,
  GitFork,
  Fingerprint,
  Radar,
  Activity,
  FileBarChart2,
  Settings,
  ChevronLeft,
  ChevronRight,
} from 'lucide-react';

interface NavItem {
  href: string;
  icon: React.ComponentType<{ size?: number; className?: string; strokeWidth?: number; color?: string }>;
  label: string;
}

const NAV_ITEMS: NavItem[] = [
  { href: '/dashboard', icon: LayoutDashboard, label: 'Command Centre' },
  { href: '/logs', icon: FileText, label: 'Log Explorer' },
  { href: '/anomalies', icon: AlertTriangle, label: 'Anomaly Detection' },
  { href: '/incidents', icon: ShieldAlert, label: 'Incident Centre' },
  { href: '/attack-chains', icon: GitFork, label: 'Attack Chains' },
  { href: '/iocs', icon: Fingerprint, label: 'IOC Intelligence' },
  { href: '/threat-intelligence', icon: Radar, label: 'Threat Intelligence' },
  { href: '/monitoring', icon: Activity, label: 'Live Monitoring' },
  { href: '/reports', icon: FileBarChart2, label: 'Reports' },
  { href: '/settings', icon: Settings, label: 'Settings' },
];

interface SidebarProps {
  isCollapsed?: boolean;
  onToggleCollapse?: () => void;
}

export function Sidebar({ isCollapsed = false, onToggleCollapse }: SidebarProps) {
  const pathname = usePathname();

  return (
    <aside
      style={{
        width: isCollapsed ? 76 : 248,
        backgroundColor: '#07090E',
        borderRight: '1px solid rgba(255, 255, 255, 0.05)',
        height: '100%',
        display: 'flex',
        flexDirection: 'column',
        flexShrink: 0,
        overflow: 'hidden',
        zIndex: 40,
        transition: 'width 0.22s cubic-bezier(0.2, 0, 0, 1)',
      }}
    >
      {/* ── Brand Header (Clean, spacious, Times New Roman typography) ─────── */}
      <div
        style={{
          padding: isCollapsed ? '24px 14px' : '28px 20px',
          display: 'flex',
          alignItems: 'center',
          gap: 12,
          flexShrink: 0,
        }}
      >
        <div
          style={{
            width: 36,
            height: 36,
            borderRadius: '50%',
            overflow: 'hidden',
            flexShrink: 0,
            border: '1px solid rgba(255, 255, 255, 0.12)',
            backgroundColor: '#0F141D',
          }}
        >
          <img
            src="/michael-logo.png"
            alt="Michael Guardian AI"
            style={{ width: '100%', height: '100%', objectFit: 'cover' }}
          />
        </div>

        {!isCollapsed && (
          <div style={{ display: 'flex', flexDirection: 'column', minWidth: 0, overflow: 'hidden' }}>
            <span
              className="font-heading"
              style={{
                fontFamily: "'Times New Roman', Times, serif",
                fontSize: '1.1rem',
                fontWeight: 400,
                color: '#FFFFFF',
                letterSpacing: '0.04em',
                lineHeight: 1.1,
              }}
            >
              MICHAEL
            </span>
            <span
              className="font-subheading"
              style={{
                fontSize: '0.7rem',
                color: '#64748B',
                letterSpacing: '0.05em',
                textTransform: 'uppercase',
                marginTop: 2,
              }}
            >
              The Guardian AI
            </span>
          </div>
        )}
      </div>

      {/* ── Navigation List (Generous vertical spacing, no crowding) ────────── */}
      <nav
        style={{
          flex: 1,
          overflowY: 'auto',
          overflowX: 'hidden',
          padding: isCollapsed ? '16px 8px' : '16px 14px',
          display: 'flex',
          flexDirection: 'column',
          gap: 6,
        }}
      >
        {NAV_ITEMS.map((item) => {
          const isActive = pathname === item.href;
          const Icon = item.icon;

          return (
            <Link
              key={item.href}
              href={item.href}
              style={{ textDecoration: 'none' }}
              title={isCollapsed ? item.label : undefined}
            >
              <div
                style={{
                  display: 'flex',
                  alignItems: 'center',
                  gap: 12,
                  padding: isCollapsed ? '10px 0' : '9px 14px',
                  justifyContent: isCollapsed ? 'center' : 'flex-start',
                  borderRadius: 8,
                  backgroundColor: isActive
                    ? '#111722'
                    : 'transparent',
                  border: isActive
                    ? '1px solid rgba(56, 189, 248, 0.25)'
                    : '1px solid transparent',
                  color: isActive ? '#FFFFFF' : '#94A3B8',
                  transition: 'all 0.15s ease',
                  position: 'relative',
                }}
                className="hover:bg-white/[0.04] hover:text-white"
              >
                {isActive && (
                  <div
                    style={{
                      position: 'absolute',
                      left: 0,
                      top: '25%',
                      bottom: '25%',
                      width: 2.5,
                      borderRadius: 2,
                      backgroundColor: '#38BDF8',
                    }}
                  />
                )}
                <Icon
                  size={16}
                  strokeWidth={isActive ? 2 : 1.5}
                  color={isActive ? '#38BDF8' : 'currentColor'}
                />
                {!isCollapsed && (
                  <span
                    style={{
                      fontSize: '0.84rem',
                      fontWeight: isActive ? 500 : 400,
                      letterSpacing: '0.01em',
                      whiteSpace: 'nowrap',
                    }}
                  >
                    {item.label}
                  </span>
                )}
              </div>
            </Link>
          );
        })}
      </nav>

      {/* ── Collapse Toggle Footer ────────────────────────────────────────── */}
      {onToggleCollapse && (
        <div
          style={{
            padding: '16px 14px',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            flexShrink: 0,
          }}
        >
          <button
            onClick={onToggleCollapse}
            title={isCollapsed ? 'Expand sidebar' : 'Collapse sidebar'}
            style={{
              background: 'transparent',
              border: 'none',
              color: '#64748B',
              cursor: 'pointer',
              padding: 6,
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              borderRadius: 6,
            }}
            className="hover:text-white hover:bg-white/[0.06] transition-colors"
          >
            {isCollapsed ? <ChevronRight size={17} /> : <ChevronLeft size={17} />}
          </button>
        </div>
      )}
    </aside>
  );
}
