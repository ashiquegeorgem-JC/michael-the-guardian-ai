'use client';

import React, { useState, useEffect } from 'react';
import { Sidebar } from './Sidebar';
import { Topbar } from './Topbar';
import { ShieldCheck } from 'lucide-react';

export function AppShell({ children }: { children: React.ReactNode }) {
  const [isCollapsed, setIsCollapsed] = useState(false);

  useEffect(() => {
    try {
      const saved = localStorage.getItem('michael_sidebar_collapsed');
      if (saved !== null) {
        setIsCollapsed(saved === 'true');
      }
    } catch {
      // ignore
    }
  }, []);

  const handleToggle = () => {
    setIsCollapsed((prev) => {
      const next = !prev;
      try {
        localStorage.setItem('michael_sidebar_collapsed', String(next));
      } catch {
        // ignore
      }
      return next;
    });
  };

  return (
    <div
      style={{
        display: 'flex',
        flexDirection: 'column',
        height: '100vh',
        width: '100vw',
        overflow: 'hidden',
        background: 'var(--bg-primary)',
        color: 'var(--text-primary)',
      }}
    >
      {/* ── Minimalist Top Status Ticker ──────────────────────────────────── */}
      <div
        style={{
          height: 28,
          backgroundColor: '#0A0E13',
          borderBottom: '1px solid rgba(255, 255, 255, 0.05)',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
          padding: '0 24px',
          fontSize: '0.72rem',
          color: 'var(--text-secondary)',
          flexShrink: 0,
          zIndex: 50,
        }}
      >
        <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
          <span
            style={{
              width: 6,
              height: 6,
              borderRadius: '50%',
              backgroundColor: '#34D399',
              display: 'inline-block',
            }}
          />
          <span className="font-subheading" style={{ fontWeight: 500, color: 'var(--text-primary)', letterSpacing: '0.02em' }}>
            MICHAEL GUARDIAN
          </span>
          <span style={{ color: 'var(--text-muted)' }}>•</span>
          <span style={{ color: 'var(--text-secondary)', fontWeight: 400 }}>
            Autonomous Surveillance & Behavioral Telemetry Active
          </span>
        </div>

        <div style={{ display: 'flex', alignItems: 'center', gap: 14, color: 'var(--text-muted)', fontSize: '0.7rem' }}>
          <span style={{ display: 'flex', alignItems: 'center', gap: 5 }}>
            <ShieldCheck size={12} color="#34D399" />
            <span style={{ color: 'var(--text-secondary)' }}>Threat Level: Guarded (14%)</span>
          </span>
          <span style={{ opacity: 0.3 }}>|</span>
          <span className="font-mono" style={{ color: 'var(--text-muted)' }}>v1.0.0</span>
        </div>
      </div>

      {/* ── Main Workspace Body with Sidebar & Content ────────────────────── */}
      <div
        style={{
          flex: 1,
          display: 'flex',
          overflow: 'hidden',
          minHeight: 0,
        }}
      >
        {/* Left Sidebar */}
        <Sidebar isCollapsed={isCollapsed} onToggleCollapse={handleToggle} />

        {/* Right Main Content Area */}
        <div
          style={{
            flex: 1,
            display: 'flex',
            flexDirection: 'column',
            overflow: 'hidden',
            minWidth: 0,
            backgroundColor: 'var(--bg-primary)',
          }}
        >
          {/* Topbar */}
          <Topbar isCollapsed={isCollapsed} onToggleSidebar={handleToggle} />

          {/* Scrollable Viewport with Minimalist Breathing Room */}
          <main
            id="main-content"
            style={{
              flex: 1,
              overflowY: 'auto',
              overflowX: 'hidden',
              padding: '32px 32px 64px 32px',
              backgroundColor: 'var(--bg-primary)',
            }}
          >
            <div style={{ maxWidth: 1600, margin: '0 auto', width: '100%' }}>
              {children}
            </div>
          </main>
        </div>
      </div>
    </div>
  );
}
