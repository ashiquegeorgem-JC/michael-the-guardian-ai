'use client';

import React from 'react';
import Link from 'next/link';
import {
  Shield, Radio, Cpu, Database, Activity, RefreshCw,
  ArrowUpRight, Sparkles
} from 'lucide-react';

interface TopCommandStripProps {
  wsConnected: boolean;
  totalAnomalies: number;
  criticalIncidents: number;
  activeSessionId?: string | null;
  onRefresh: () => void;
  isLoading: boolean;
}

export function TopCommandStrip({
  wsConnected,
  totalAnomalies,
  criticalIncidents,
  activeSessionId,
  onRefresh,
  isLoading,
}: TopCommandStripProps) {
  // Threat posture
  const threatLevel = criticalIncidents > 0
    ? { label: 'CRITICAL', bg: 'rgba(255, 59, 48, 0.15)', text: '#FF3B30', border: 'rgba(255, 59, 48, 0.4)', dot: '#FF3B30' }
    : totalAnomalies > 5
    ? { label: 'ELEVATED', bg: 'rgba(255, 179, 0, 0.15)', text: '#FFB300', border: 'rgba(255, 179, 0, 0.4)', dot: '#FFB300' }
    : { label: 'GUARDED', bg: 'rgba(0, 230, 118, 0.12)', text: '#00E676', border: 'rgba(0, 230, 118, 0.35)', dot: '#00E676' };

  return (
    <div
      style={{
        background: '#070B14',
        border: '1px solid rgba(255, 255, 255, 0.08)',
        borderRadius: '12px',
        padding: '10px 16px',
        boxShadow: '0 8px 32px rgba(0, 0, 0, 0.6)',
      }}
      className="backdrop-blur-xl"
    >
      <div className="flex flex-wrap items-center justify-between gap-3">
        {/* Left: Brand Identity & Status Rails */}
        <div className="flex flex-wrap items-center gap-3">
          {/* Logo badge */}
          <div className="flex items-center gap-2 pr-3 border-r border-white/10">
            <div
              style={{
                width: 28,
                height: 28,
                background: 'linear-gradient(135deg, #00B8FF, #7C3AED)',
                borderRadius: 8,
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                boxShadow: '0 0 12px rgba(0, 184, 255, 0.4)',
              }}
            >
              <Shield size={15} color="white" />
            </div>
            <div>
              <span className="text-xs font-black tracking-wider text-white font-mono">MICHAEL SOC</span>
              <span className="hidden sm:inline-block ml-1.5 text-[9px] font-mono tracking-widest text-slate-400 uppercase">
                / COMMAND CENTRE
              </span>
            </div>
          </div>

          {/* Status Indicators Strip */}
          <div className="flex flex-wrap items-center gap-2 text-[10px] font-mono">
            {/* Guardian Status */}
            <div
              style={{
                background: 'rgba(0, 230, 118, 0.08)',
                border: '1px solid rgba(0, 230, 118, 0.3)',
                color: '#00E676',
              }}
              className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-md font-semibold tracking-wider"
            >
              <span
                style={{
                  display: 'inline-block',
                  width: 6,
                  height: 6,
                  borderRadius: '50%',
                  background: '#00E676',
                  boxShadow: '0 0 8px #00E676',
                }}
              />
              <span>GUARDIAN ONLINE</span>
            </div>

            {/* WebSocket Stream */}
            <div
              style={{
                background: wsConnected ? 'rgba(0, 184, 255, 0.08)' : 'rgba(255, 179, 0, 0.08)',
                border: wsConnected ? '1px solid rgba(0, 184, 255, 0.3)' : '1px solid rgba(255, 179, 0, 0.3)',
                color: wsConnected ? '#00B8FF' : '#FFB300',
              }}
              className="hidden md:inline-flex items-center gap-1.5 px-2.5 py-1 rounded-md"
            >
              <Radio size={12} className={wsConnected ? 'animate-pulse text-[#00B8FF]' : 'text-[#FFB300]'} />
              <span>WS: {wsConnected ? 'CONNECTED' : 'POLLING'}</span>
            </div>

            {/* ML Engine */}
            <div
              style={{
                background: 'rgba(124, 58, 237, 0.08)',
                border: '1px solid rgba(124, 58, 237, 0.25)',
                color: '#C4B5FD',
              }}
              className="hidden lg:inline-flex items-center gap-1.5 px-2.5 py-1 rounded-md"
            >
              <Cpu size={12} color="#C4B5FD" />
              <span>ML ENGINE ACTIVE</span>
            </div>

            {/* Log Pipeline */}
            <div
              style={{
                background: 'rgba(255, 255, 255, 0.03)',
                border: '1px solid rgba(255, 255, 255, 0.08)',
                color: '#94A3B8',
              }}
              className="hidden xl:inline-flex items-center gap-1.5 px-2.5 py-1 rounded-md"
            >
              <Activity size={12} color="#00B8FF" />
              <span>PIPELINE: HEALTHY</span>
            </div>

            {/* Database */}
            <div
              style={{
                background: 'rgba(255, 255, 255, 0.03)',
                border: '1px solid rgba(255, 255, 255, 0.08)',
                color: '#94A3B8',
              }}
              className="hidden 2xl:inline-flex items-center gap-1.5 px-2.5 py-1 rounded-md"
            >
              <Database size={12} color="#00E676" />
              <span>DB: READY</span>
            </div>
          </div>
        </div>

        {/* Right: Threat Posture & SOC Action Controls */}
        <div className="flex items-center gap-2.5 ml-auto">
          {/* Threat Level Badge */}
          <div
            style={{
              background: threatLevel.bg,
              border: `1px solid ${threatLevel.border}`,
              color: threatLevel.text,
            }}
            className="flex items-center gap-1.5 px-3 py-1 rounded-md text-[10px] font-mono font-bold tracking-widest uppercase"
          >
            <span
              style={{
                display: 'inline-block',
                width: 6,
                height: 6,
                borderRadius: '50%',
                background: threatLevel.dot,
                boxShadow: `0 0 8px ${threatLevel.dot}`,
              }}
            />
            <span>THREAT: {threatLevel.label}</span>
          </div>

          {/* Action Buttons with explicit dark styling */}
          <div className="flex items-center gap-2">
            <Link
              href="/logs"
              style={{
                background: 'linear-gradient(135deg, rgba(0, 184, 255, 0.2), rgba(0, 184, 255, 0.08))',
                border: '1px solid rgba(0, 184, 255, 0.45)',
                color: '#FFFFFF',
                borderRadius: '8px',
                padding: '6px 12px',
                fontSize: '11px',
                fontWeight: 600,
                letterSpacing: '0.04em',
                display: 'inline-flex',
                alignItems: 'center',
                gap: '6px',
                textDecoration: 'none',
                boxShadow: '0 0 14px rgba(0, 184, 255, 0.2)',
                transition: 'all 0.15s ease',
              }}
              className="hover:border-cyan-400 hover:shadow-cyan-500/30"
            >
              <span>INGEST LOGS</span>
              <ArrowUpRight size={13} color="#00B8FF" />
            </Link>

            <Link
              href="/copilot"
              style={{
                background: 'linear-gradient(135deg, rgba(124, 58, 237, 0.2), rgba(124, 58, 237, 0.08))',
                border: '1px solid rgba(124, 58, 237, 0.45)',
                color: '#FFFFFF',
                borderRadius: '8px',
                padding: '6px 12px',
                fontSize: '11px',
                fontWeight: 600,
                letterSpacing: '0.04em',
                display: 'inline-flex',
                alignItems: 'center',
                gap: '6px',
                textDecoration: 'none',
                boxShadow: '0 0 14px rgba(124, 58, 237, 0.2)',
                transition: 'all 0.15s ease',
              }}
              className="hover:border-purple-400 hover:shadow-purple-500/30"
            >
              <Sparkles size={13} color="#C4B5FD" />
              <span className="hidden sm:inline">AI COPILOT</span>
            </Link>

            <button
              onClick={onRefresh}
              disabled={isLoading}
              title="Refresh SOC Telemetry"
              style={{
                background: '#0D1320',
                border: '1px solid rgba(255, 255, 255, 0.12)',
                color: '#94A3B8',
                borderRadius: '8px',
                width: 30,
                height: 30,
                display: 'inline-flex',
                alignItems: 'center',
                justifyContent: 'center',
                cursor: 'pointer',
                transition: 'all 0.15s ease',
              }}
            >
              <RefreshCw size={13} className={isLoading ? 'animate-spin text-[#00B8FF]' : 'text-slate-300'} />
            </button>

            <span className="hidden sm:inline-block pl-2 border-l border-white/10 text-[10px] font-mono text-slate-400">
              v1.0 SOC
            </span>
          </div>
        </div>
      </div>
    </div>
  );
}
