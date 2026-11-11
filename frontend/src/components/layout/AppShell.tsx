'use client';

import React, { useState, useEffect } from 'react';
import { Sidebar } from './Sidebar';
import { Topbar } from './Topbar';
import { ShieldCheck, Sparkles } from 'lucide-react';

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
        background: 'var(--background)',
      }}
    >
      {/* ── Signature Bethesda-Style Announcement & Defense Ribbon ──────────── */}
      <div
        style={{
          height: 32,
          backgroundColor: '#171E24',
          borderBottom: '1px solid rgba(212, 175, 55, 0.18)',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
          padding: '0 24px',
          fontSize: '0.74rem',
          fontFamily: 'var(--font-subheading)',
          color: '#FAF9F5',
          flexShrink: 0,
          zIndex: 50,
        }}
      >
        <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
          <span
            style={{
              width: 7,
              height: 7,
              borderRadius: '50%',
              backgroundColor: '#D4AF37',
              boxShadow: '0 0 8px rgba(212, 175, 55, 0.8)',
              display: 'inline-block',
            }}
            className="animate-pulse"
          />
          <span style={{ fontWeight: 600, color: '#D4AF37', letterSpacing: '0.04em' }}>
            MICHAEL DEFENSE POSTURE:
          </span>
          <span style={{ color: '#D1CBC0', fontWeight: 400 }}>
            Guardian Surveillance & Autonomous ML Heuristics Active
          </span>
        </div>

        <div style={{ display: 'flex', alignItems: 'center', gap: 16, color: '#8E877D', fontSize: '0.7rem' }}>
          <span style={{ display: 'flex', alignItems: 'center', gap: 4 }}>
            <ShieldCheck size={13} color="#D4AF37" />
            <span style={{ color: '#D1CBC0' }}>Threat Posture: Guarded (14%)</span>
          </span>
          <span style={{ opacity: 0.4 }}>|</span>
          <span style={{ color: '#D4AF37', fontWeight: 600 }}>v1.0.0 Production</span>
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
        <Sidebar isCollapsed={isCollapsed} onToggleCollapse={handleToggle} />
        <div
          style={{
            flex: 1,
            display: 'flex',
            flexDirection: 'column',
            overflow: 'hidden',
            minWidth: 0,
            transition: 'all 0.28s cubic-bezier(0.2, 0, 0, 1)',
          }}
        >
          <Topbar isCollapsed={isCollapsed} onToggleSidebar={handleToggle} />
          <main
            style={{
              flex: 1,
              overflowY: 'auto',
              overflowX: 'hidden',
              background: 'var(--background)',
              padding: '28px 36px',
            }}
          >
            {children}
          </main>
        </div>
      </div>
    </div>
  );
}
