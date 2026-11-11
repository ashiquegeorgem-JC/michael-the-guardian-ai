'use client';

import React from 'react';
import Link from 'next/link';
import {
  AlertTriangle, ShieldAlert, Fingerprint, FileText,
  Activity, ArrowUpRight, Zap, Shield, Sparkles
} from 'lucide-react';

interface ThreatStatusHeroProps {
  totalLogs: number;
  totalAnomalies: number;
  totalIncidents: number;
  criticalIncidents: number;
  openIncidents: number;
  totalIocs?: number;
  confidenceRate?: number;
  activeSessionId?: string | null;
}

export function ThreatStatusHero({
  totalLogs,
  totalAnomalies,
  totalIncidents,
  criticalIncidents,
  openIncidents,
  totalIocs = 0,
  confidenceRate = 94.2,
  activeSessionId,
}: ThreatStatusHeroProps) {
  // Threat score computation: base on criticals, anomalies, and active incidents
  const computedScore = Math.min(
    96,
    Math.max(
      12,
      criticalIncidents > 0
        ? 75 + Math.min(20, criticalIncidents * 8)
        : totalAnomalies > 0
        ? 45 + Math.min(30, totalAnomalies * 2)
        : 14
    )
  );

  const threatPosture = computedScore >= 75
    ? { level: 'CRITICAL', ringColor: '#FF3B30', textColor: '#FF3B30', badgeBg: 'rgba(255, 59, 48, 0.15)', badgeBorder: 'rgba(255, 59, 48, 0.4)' }
    : computedScore >= 45
    ? { level: 'ELEVATED', ringColor: '#FFB300', textColor: '#FFB300', badgeBg: 'rgba(255, 179, 0, 0.15)', badgeBorder: 'rgba(255, 179, 0, 0.4)' }
    : { level: 'GUARDED', ringColor: '#00E676', textColor: '#00E676', badgeBg: 'rgba(0, 230, 118, 0.15)', badgeBorder: 'rgba(0, 230, 118, 0.4)' };

  // Ring calculations
  const radius = 34;
  const circumference = 2 * Math.PI * radius;
  const strokeDashoffset = circumference - (computedScore / 100) * circumference;

  return (
    <div
      style={{
        background: '#070B14',
        border: '1px solid rgba(255, 255, 255, 0.08)',
        borderRadius: '12px',
        padding: '16px',
        boxShadow: '0 8px 32px rgba(0, 0, 0, 0.6)',
      }}
      className="space-y-3.5"
    >
      {/* 1. Command Center Headline Banner */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-3 pb-3 border-b border-white/10">
        <div>
          <div className="flex items-center gap-2">
            <span
              style={{
                width: 6,
                height: 6,
                borderRadius: '50%',
                background: '#00B8FF',
                boxShadow: '0 0 8px #00B8FF',
              }}
            />
            <span className="text-[10px] font-mono tracking-widest text-[#00B8FF] uppercase font-bold">
              MICHAEL CYBER DEFENSE NETWORK
            </span>
          </div>
          <h1 className="text-xl md:text-2xl font-black tracking-tight text-white mt-0.5">
            AUTONOMOUS SECURITY COMMAND CENTRE
          </h1>
          <p className="text-xs text-slate-400 font-mono mt-0.5">
            Real-time threat detection, behavioural intelligence and automated forensic analysis.
          </p>
        </div>

        {/* Action Pills */}
        <div className="flex items-center gap-2 shrink-0">
          <Link
            href="/logs"
            style={{
              background: '#0A1326',
              border: '1px solid rgba(0, 184, 255, 0.4)',
              color: '#00B8FF',
              borderRadius: '8px',
              padding: '6px 14px',
              fontSize: '11px',
              fontWeight: 600,
              letterSpacing: '0.04em',
              display: 'inline-flex',
              alignItems: 'center',
              gap: '6px',
              textDecoration: 'none',
              boxShadow: '0 0 12px rgba(0, 184, 255, 0.2)',
            }}
          >
            <ArrowUpRight size={13} color="#00B8FF" />
            <span>INGEST LOGS</span>
          </Link>

          <Link
            href="/copilot"
            style={{
              background: '#120E24',
              border: '1px solid rgba(124, 58, 237, 0.4)',
              color: '#C4B5FD',
              borderRadius: '8px',
              padding: '6px 14px',
              fontSize: '11px',
              fontWeight: 600,
              letterSpacing: '0.04em',
              display: 'inline-flex',
              alignItems: 'center',
              gap: '6px',
              textDecoration: 'none',
              boxShadow: '0 0 12px rgba(124, 58, 237, 0.2)',
            }}
          >
            <Sparkles size={13} color="#C4B5FD" />
            <span>OPEN AI COPILOT</span>
          </Link>
        </div>
      </div>

      {/* 2. Compact Status Modules Grid */}
      <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-5 gap-2 text-[10px] font-mono">
        <div style={{ background: '#090E1A', border: '1px solid rgba(255,255,255,0.06)' }} className="p-2 rounded-lg">
          <div className="text-slate-400">GUARDIAN STATUS</div>
          <div className="text-[#00E676] font-bold flex items-center gap-1.5 mt-0.5">
            <span style={{ width: 6, height: 6, borderRadius: '50%', background: '#00E676', boxShadow: '0 0 6px #00E676' }} />
            <span>ACTIVE DEFENSE</span>
          </div>
        </div>

        <div style={{ background: '#090E1A', border: '1px solid rgba(255,255,255,0.06)' }} className="p-2 rounded-lg">
          <div className="text-slate-400">ML ENGINE</div>
          <div className="text-[#C4B5FD] font-bold mt-0.5">ISOLATION FOREST + TF-IDF</div>
        </div>

        <div style={{ background: '#090E1A', border: '1px solid rgba(255,255,255,0.06)' }} className="p-2 rounded-lg">
          <div className="text-slate-400">LOG PIPELINE</div>
          <div className="text-[#00B8FF] font-bold mt-0.5">HEALTHY (AUTO-PARSE)</div>
        </div>

        <div style={{ background: '#090E1A', border: '1px solid rgba(255,255,255,0.06)' }} className="p-2 rounded-lg">
          <div className="text-slate-400">DATABASE</div>
          <div className="text-[#00E676] font-bold mt-0.5">READY (PERSISTENT)</div>
        </div>

        <div style={{ background: '#090E1A', border: '1px solid rgba(255,255,255,0.06)' }} className="p-2 rounded-lg col-span-2 sm:col-span-1">
          <div className="text-slate-400">WEBSOCKET TELEMETRY</div>
          <div className="text-[#00B8FF] font-bold mt-0.5">CONNECTED (LIVE)</div>
        </div>
      </div>

      {/* 3. Threat Overview & Key Metric Tiles */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-3 items-center pt-1">
        {/* Radial Threat Gauge (4 cols on lg) */}
        <div
          style={{ background: '#090E1A', border: '1px solid rgba(255,255,255,0.06)' }}
          className="lg:col-span-4 rounded-lg p-3 flex items-center gap-4"
        >
          <div className="relative flex h-20 w-20 shrink-0 items-center justify-center">
            <svg className="h-full w-full -rotate-90 transform" viewBox="0 0 80 80">
              <circle cx="40" cy="40" r={radius} stroke="#1A2333" strokeWidth="6" fill="transparent" />
              <circle
                cx="40"
                cy="40"
                r={radius}
                stroke={threatPosture.ringColor}
                strokeWidth="6"
                strokeDasharray={circumference}
                strokeDashoffset={strokeDashoffset}
                strokeLinecap="round"
                fill="transparent"
                style={{ transition: 'stroke-dashoffset 0.8s ease-in-out' }}
              />
            </svg>
            <div className="absolute inset-0 flex flex-col items-center justify-center text-center">
              <span className="text-lg font-black font-mono text-white leading-none">
                {computedScore}%
              </span>
              <span className="text-[8px] font-mono tracking-widest text-slate-400 uppercase mt-0.5">
                LEVEL
              </span>
            </div>
          </div>

          <div className="space-y-1">
            <div className="text-[10px] font-mono text-slate-400 uppercase tracking-widest">
              THREAT LEVEL POSTURE
            </div>
            <div className="flex items-center gap-2">
              <span style={{ color: threatPosture.textColor }} className="text-base font-black tracking-wider">
                {threatPosture.level}
              </span>
              <span
                style={{ background: threatPosture.badgeBg, border: `1px solid ${threatPosture.badgeBorder}`, color: threatPosture.textColor }}
                className="px-1.5 py-0.2 rounded text-[9px] font-mono font-bold"
              >
                LIVE
              </span>
            </div>
            <p className="text-[10px] text-slate-400 font-mono leading-tight">
              {criticalIncidents > 0
                ? `${criticalIncidents} critical security incident(s) open`
                : totalAnomalies > 0
                ? `${totalAnomalies} statistical log outliers detected`
                : 'Zero anomalous deviations detected'}
            </p>
          </div>
        </div>

        {/* Small Metric Tiles (8 cols on lg) */}
        <div className="lg:col-span-8 grid grid-cols-2 sm:grid-cols-4 gap-2">
          {/* Events Processed */}
          <Link
            href="/logs"
            style={{ background: '#090E1A', border: '1px solid rgba(255,255,255,0.06)' }}
            className="p-3 rounded-lg hover:border-cyan-500/40 transition-colors group text-decoration-none"
          >
            <div className="flex items-center justify-between text-slate-400 text-[10px] font-mono mb-1">
              <span>EVENTS PROCESSED</span>
              <FileText size={13} color="#00B8FF" className="group-hover:scale-110 transition-transform" />
            </div>
            <div className="text-xl font-bold font-mono text-white">
              {totalLogs.toLocaleString()}
            </div>
            <div className="text-[9px] font-mono text-[#00B8FF]">
              Indexed & Scored
            </div>
          </Link>

          {/* Anomalies */}
          <Link
            href="/anomalies"
            style={{ background: '#090E1A', border: '1px solid rgba(255,255,255,0.06)' }}
            className="p-3 rounded-lg hover:border-amber-500/40 transition-colors group text-decoration-none"
          >
            <div className="flex items-center justify-between text-slate-400 text-[10px] font-mono mb-1">
              <span>ANOMALIES</span>
              <AlertTriangle size={13} color="#FFB300" className="group-hover:scale-110 transition-transform" />
            </div>
            <div className="text-xl font-bold font-mono text-white">
              {totalAnomalies.toLocaleString()}
            </div>
            <div className="text-[9px] font-mono text-[#FFB300]">
              {totalAnomalies > 0 ? 'Outliers Flagged' : 'Baseline Normal'}
            </div>
          </Link>

          {/* Active Incidents */}
          <Link
            href="/incidents"
            style={{ background: '#090E1A', border: '1px solid rgba(255,255,255,0.06)' }}
            className="p-3 rounded-lg hover:border-purple-500/40 transition-colors group text-decoration-none"
          >
            <div className="flex items-center justify-between text-slate-400 text-[10px] font-mono mb-1">
              <span>ACTIVE INCIDENTS</span>
              <ShieldAlert size={13} color="#C4B5FD" className="group-hover:scale-110 transition-transform" />
            </div>
            <div className="text-xl font-bold font-mono text-white">
              {totalIncidents.toLocaleString()}
            </div>
            <div className="text-[9px] font-mono text-[#C4B5FD]">
              {openIncidents} Open Triage
            </div>
          </Link>

          {/* Suspicious IOCs */}
          <Link
            href="/iocs"
            style={{ background: '#090E1A', border: '1px solid rgba(255,255,255,0.06)' }}
            className="p-3 rounded-lg hover:border-rose-500/40 transition-colors group text-decoration-none"
          >
            <div className="flex items-center justify-between text-slate-400 text-[10px] font-mono mb-1">
              <span>SUSPICIOUS IOCs</span>
              <Fingerprint size={13} color="#FF3B30" className="group-hover:scale-110 transition-transform" />
            </div>
            <div className="text-xl font-bold font-mono text-white">
              {totalIocs.toLocaleString()}
            </div>
            <div className="text-[9px] font-mono text-[#FF3B30]">
              {criticalIncidents > 0 ? 'Threat Cluster' : 'Tracked'}
            </div>
          </Link>
        </div>
      </div>
    </div>
  );
}
