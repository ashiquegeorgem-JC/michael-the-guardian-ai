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
  Bot,
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

interface NavGroup {
  title: string;
  items: NavItem[];
}

const NAV_GROUPS: NavGroup[] = [
  {
    title: 'CORE',
    items: [
      { href: '/dashboard', icon: LayoutDashboard, label: 'Command Centre' },
      { href: '/logs', icon: FileText, label: 'Log Explorer' },
      { href: '/anomalies', icon: AlertTriangle, label: 'Anomaly Detection' },
      { href: '/incidents', icon: ShieldAlert, label: 'Incident Centre' },
      { href: '/attack-chains', icon: GitFork, label: 'Attack Chains' },
      { href: '/iocs', icon: Fingerprint, label: 'IOC Intelligence' },
      { href: '/threat-intelligence', icon: Radar, label: 'Threat Intelligence' },
    ],
  },
  {
    title: 'INTELLIGENCE',
    items: [
      { href: '/copilot', icon: Bot, label: 'AI Copilot' },
      { href: '/monitoring', icon: Activity, label: 'Live Monitoring' },
    ],
  },
  {
    title: 'TOOLS',
    items: [
      { href: '/reports', icon: FileBarChart2, label: 'Reports' },
      { href: '/settings', icon: Settings, label: 'Settings' },
    ],
  },
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
        width: isCollapsed ? 76 : 260,
        backgroundColor: '#151B21',
        borderRight: '1px solid rgba(212, 175, 55, 0.14)',
        height: '100%',
        display: 'flex',
        flexDirection: 'column',
        flexShrink: 0,
        overflow: 'hidden',
        zIndex: 40,
        fontFamily: 'var(--font-sans)',
        transition: 'width 0.28s cubic-bezier(0.2, 0, 0, 1)',
        boxShadow: '4px 0 24px rgba(0, 0, 0, 0.45)',
      }}
    >
      {/* 1. Brand Header */}
      <div
        style={{
          padding: isCollapsed ? '20px 14px' : '22px 20px',
          borderBottom: '1px solid rgba(212, 175, 55, 0.1)',
          display: 'flex',
          flexDirection: 'column',
          gap: 10,
          flexShrink: 0,
          position: 'relative',
        }}
      >
        <div
          style={{
            display: 'flex',
            alignItems: 'center',
            justifyContent: isCollapsed ? 'center' : 'space-between',
            gap: 12,
          }}
        >
          <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
            {/* Archangel Michael Logo with Celestial Gold Halo */}
            <div
              style={{
                position: 'relative',
                width: isCollapsed ? 42 : 46,
                height: isCollapsed ? 42 : 46,
                borderRadius: '50%',
                overflow: 'hidden',
                flexShrink: 0,
                border: '1.5px solid rgba(212, 175, 55, 0.55)',
                boxShadow: '0 0 16px rgba(212, 175, 55, 0.35)',
                background: '#1C242B',
              }}
            >
              <img
                src="/michael-logo.png"
                alt="MICHAEL — The Guardian AI"
                style={{
                  width: '100%',
                  height: '100%',
                  objectFit: 'cover',
                  display: 'block',
                }}
              />
            </div>

            {/* Brand Title & Subtitle */}
            {!isCollapsed && (
              <div style={{ minWidth: 0, overflow: 'hidden' }}>
                <div
                  className="font-heading font-bold"
                  style={{
                    fontSize: '1.15rem',
                    letterSpacing: '-0.01em',
                    color: '#FAF9F5',
                    lineHeight: 1.1,
                  }}
                >
                  MICHAEL
                </div>
                <div
                  className="font-subheading font-bold"
                  style={{
                    fontSize: '0.68rem',
                    color: '#D4AF37',
                    letterSpacing: '0.14em',
                    textTransform: 'uppercase',
                    marginTop: 2,
                  }}
                >
                  THE GUARDIAN AI
                </div>
              </div>
            )}
          </div>

          {/* Collapse Toggle Button */}
          {onToggleCollapse && !isCollapsed && (
            <button
              onClick={onToggleCollapse}
              title="Collapse sidebar"
              style={{
                background: 'rgba(212, 175, 55, 0.06)',
                border: '1px solid rgba(212, 175, 55, 0.15)',
                borderRadius: 6,
                padding: '5px',
                color: '#D1CBC0',
                cursor: 'pointer',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                transition: 'all 0.15s ease',
              }}
              onMouseEnter={(e) => {
                e.currentTarget.style.backgroundColor = 'rgba(212, 175, 55, 0.15)';
                e.currentTarget.style.color = '#D4AF37';
              }}
              onMouseLeave={(e) => {
                e.currentTarget.style.backgroundColor = 'rgba(212, 175, 55, 0.06)';
                e.currentTarget.style.color = '#D1CBC0';
              }}
            >
              <ChevronLeft size={15} />
            </button>
          )}
        </div>

        {/* Tagline */}
        {!isCollapsed && (
          <div
            className="font-subheading font-light"
            style={{
              fontSize: '0.72rem',
              lineHeight: 1.35,
              color: '#8E877D',
              paddingLeft: 2,
            }}
          >
            <div>Intelligence That Watches.</div>
            <div>AI That Protects.</div>
          </div>
        )}

        {/* Expand Toggle when collapsed */}
        {isCollapsed && onToggleCollapse && (
          <button
            onClick={onToggleCollapse}
            title="Expand sidebar"
            style={{
              marginTop: 4,
              background: 'rgba(212, 175, 55, 0.08)',
              border: '1px solid rgba(212, 175, 55, 0.22)',
              borderRadius: 6,
              padding: '4px',
              color: '#D4AF37',
              cursor: 'pointer',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              width: '100%',
              transition: 'all 0.15s ease',
            }}
          >
            <ChevronRight size={14} />
          </button>
        )}
      </div>

      {/* 2. Navigation List */}
      <nav
        style={{
          flex: 1,
          overflowY: 'auto',
          overflowX: 'hidden',
          padding: isCollapsed ? '16px 8px' : '18px 12px',
          display: 'flex',
          flexDirection: 'column',
          gap: isCollapsed ? 14 : 20,
        }}
      >
        {NAV_GROUPS.map((group) => (
          <div key={group.title}>
            {isCollapsed ? (
              <div
                style={{
                  height: 1,
                  background: 'rgba(212, 175, 55, 0.08)',
                  margin: '4px 8px 8px 8px',
                }}
              />
            ) : (
              <div
                className="font-subheading font-bold"
                style={{
                  fontSize: '0.66rem',
                  letterSpacing: '0.1em',
                  color: '#8E877D',
                  padding: '0 10px 8px 10px',
                  textTransform: 'uppercase',
                }}
              >
                {group.title}
              </div>
            )}

            <div style={{ display: 'flex', flexDirection: 'column', gap: 3 }}>
              {group.items.map((item) => {
                const isActive =
                  pathname === item.href ||
                  (item.href !== '/dashboard' && pathname.startsWith(item.href));
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
                        position: 'relative',
                        display: 'flex',
                        alignItems: 'center',
                        justifyContent: isCollapsed ? 'center' : 'flex-start',
                        gap: isCollapsed ? 0 : 12,
                        padding: isCollapsed ? '10px 0' : '9px 12px',
                        borderRadius: 8,
                        fontSize: '0.84rem',
                        fontWeight: isActive ? 600 : 400,
                        color: isActive ? '#FAF9F5' : '#D1CBC0',
                        backgroundColor: isActive
                          ? 'rgba(212, 175, 55, 0.12)'
                          : 'transparent',
                        transition: 'all 0.15s ease',
                        cursor: 'pointer',
                      }}
                      onMouseEnter={(e) => {
                        if (!isActive) {
                          e.currentTarget.style.backgroundColor =
                            'rgba(212, 175, 55, 0.05)';
                          e.currentTarget.style.color = '#FAF9F5';
                        }
                      }}
                      onMouseLeave={(e) => {
                        if (!isActive) {
                          e.currentTarget.style.backgroundColor = 'transparent';
                          e.currentTarget.style.color = '#D1CBC0';
                        }
                      }}
                    >
                      {/* Active Indicator Bar */}
                      {isActive && (
                        <div
                          style={{
                            position: 'absolute',
                            left: 0,
                            top: '15%',
                            bottom: '15%',
                            width: 3,
                            backgroundColor: '#D4AF37',
                            borderRadius: '0 2px 2px 0',
                            boxShadow: '0 0 10px rgba(212, 175, 55, 0.85)',
                          }}
                        />
                      )}

                      <Icon
                        size={18}
                        strokeWidth={isActive ? 2.2 : 1.8}
                        color={isActive ? '#D4AF37' : '#D1CBC0'}
                      />

                      {!isCollapsed && (
                        <span
                          className="font-subheading"
                          style={{
                            lineHeight: 1,
                            whiteSpace: 'nowrap',
                            overflow: 'hidden',
                            textOverflow: 'ellipsis',
                          }}
                        >
                          {item.label}
                        </span>
                      )}
                    </div>
                  </Link>
                );
              })}
            </div>
          </div>
        ))}
      </nav>

      {/* 3. Footer Status Indicator */}
      <div
        style={{
          padding: isCollapsed ? '14px 10px' : '16px 18px',
          borderTop: '1px solid rgba(212, 175, 55, 0.1)',
          backgroundColor: '#12171B',
          display: 'flex',
          alignItems: 'center',
          justifyContent: isCollapsed ? 'center' : 'space-between',
          flexShrink: 0,
        }}
      >
        <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
          <span
            style={{
              width: 8,
              height: 8,
              borderRadius: '50%',
              backgroundColor: '#22C55E',
              display: 'inline-block',
              boxShadow: '0 0 8px rgba(34, 197, 94, 0.75)',
            }}
          />
          {!isCollapsed && (
            <div>
              <div
                className="font-subheading font-bold"
                style={{
                  fontSize: '0.74rem',
                  color: '#FAF9F5',
                  lineHeight: 1.1,
                }}
              >
                Guardian Active
              </div>
              <div
                className="font-subheading font-light"
                style={{
                  fontSize: '0.66rem',
                  color: '#8E877D',
                }}
              >
                All systems operational
              </div>
            </div>
          )}
        </div>

        {!isCollapsed && (
          <div
            className="font-mono"
            style={{
              fontSize: '0.64rem',
              fontWeight: 600,
              color: '#D4AF37',
              backgroundColor: 'rgba(212, 175, 55, 0.08)',
              border: '1px solid rgba(212, 175, 55, 0.22)',
              padding: '2px 7px',
              borderRadius: 4,
            }}
          >
            SOC
          </div>
        )}
      </div>
    </aside>
  );
}
