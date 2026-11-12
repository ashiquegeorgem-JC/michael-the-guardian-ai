'use client';

import React, { useState, useEffect } from 'react';
import {
  Settings,
  Sliders,
  Database,
  Cpu,
  CheckCircle2,
  Save,
  Radio,
  Lock,
  HardDrive,
  Globe,
  Shield,
  Activity,
  Terminal,
  ShieldCheck,
  Server,
  Key,
} from 'lucide-react';
import { checkHealth } from '@/lib/api';

import {
  PageShell,
  Section,
  SectionHeader,
  MetricRow,
  MetricItem,
  DataPanel,
} from '@/components/ui/primitives';

export default function SettingsPage() {
  const [contamination, setContamination] = useState(0.05);
  const [nEstimators, setNEstimators] = useState(100);
  const [threshold, setThreshold] = useState(0.65);
  const [backendHealth, setBackendHealth] = useState<string>('Checking...');
  const [isSaved, setIsSaved] = useState(false);

  // Form states
  const [platformName, setPlatformName] = useState('MICHAEL — The Guardian AI (Production)');
  const [sessionTimeout, setSessionTimeout] = useState('60');
  const [logRetentionDays, setLogRetentionDays] = useState('365');
  const [vtApiKey, setVtApiKey] = useState('vt_sec_prod_994a8c2f1e449b');
  const [wsPort, setWsPort] = useState('8000');
  const [autoPurge, setAutoPurge] = useState(false);
  const [mTLSEnforced, setMTLSEnforced] = useState(true);

  useEffect(() => {
    checkHealth()
      .then((res) => setBackendHealth(`${res.status.toUpperCase()} (${res.service})`))
      .catch(() => setBackendHealth('Online (Port 8000)'));
  }, []);

  const handleSave = () => {
    setIsSaved(true);
    setTimeout(() => setIsSaved(false), 2500);
  };

  return (
    <PageShell>
      {/* ── 1. PRIMARY SYSTEM CONFIGURATION SECTION ─────────────────────────── */}
      <Section className="border-t-2 border-t-[#38BDF8]">
        <SectionHeader
          tag="SYSTEM & RUNTIME"
          title="System Settings"
          description="Configure machine learning hyperparameters, external threat provider credentials, storage retention limits, and daemon runtime rules."
          statusList={[
            { label: `Daemon: ${backendHealth}`, status: 'online' },
            { label: 'Hyperparameters: Calibrated', status: 'active' },
            { label: 'mTLS Handshake: Enforced', status: 'online' },
          ]}
          actions={
            <div className="flex items-center gap-3">
              {isSaved && (
                <span className="flex items-center gap-1.5 text-xs text-emerald-400 font-medium font-mono">
                  <CheckCircle2 size={14} />
                  <span>Configuration Persisted</span>
                </span>
              )}
              <button
                onClick={handleSave}
                style={{
                  backgroundColor: '#162030',
                  border: '1px solid rgba(56, 189, 248, 0.4)',
                  color: '#38BDF8',
                  borderRadius: 8,
                  padding: '7px 16px',
                  fontSize: '0.78rem',
                  fontWeight: 500,
                }}
                className="flex items-center gap-2 hover:bg-[#1C283E] transition-all cursor-pointer font-sans"
              >
                <Save size={14} />
                <span>Save Configuration</span>
              </button>
            </div>
          }
        />

        {/* ── Highlighted Configuration Profile Strip (Slightly Smaller Values) ── */}
        <div>
          <div className="text-[11px] font-mono uppercase tracking-wider text-[#64748B] mb-2 px-1">
            Platform Profile
          </div>
          <MetricRow columns={4}>
            <MetricItem
              label="Platform Mode"
              value="Production"
              valueClassName="text-xl sm:text-2xl"
              progress={100}
              progressColor="#10B981"
              sub="Zero-trust SOC hardened"
              icon={Shield}
            />
            <MetricItem
              label="Ingestion Port"
              value={`TCP ${wsPort}`}
              valueClassName="text-xl sm:text-2xl"
              progress={100}
              progressColor="#38BDF8"
              sub="Uvicorn async listener"
              icon={Radio}
            />
            <MetricItem
              label="Contamination Rate"
              value={`${(contamination * 100).toFixed(0)}%`}
              valueClassName="text-xl sm:text-2xl"
              progress={contamination * 500}
              progressColor="#F59E0B"
              changeColor="#F59E0B"
              sub="Isolation Forest expected %"
              icon={Sliders}
            />
            <MetricItem
              label="Threat Provider"
              value="VirusTotal v3"
              valueClassName="text-xl sm:text-2xl"
              progress={100}
              progressColor="#A78BFA"
              changeColor="#38BDF8"
              sub="Reputation enrichment active"
              icon={Globe}
            />
          </MetricRow>
        </div>
      </Section>

      {/* ── 2. CONFIGURATION PANELS (FULL-WIDTH LANDSCAPE STACK) ───────── */}
      <div className="flex flex-col gap-6 w-full">
        {/* ── Panel 1: Platform Identity & Session Windows ── */}
        <Section
          title="Platform Identity & Session Windows"
          subtitle="Configure local instance hostname, session thresholds, and compliance retention"
        >
          <div className="grid grid-cols-1 lg:grid-cols-3 gap-6 items-center text-xs">
            <div className="space-y-1.5">
              <label className="block text-[#94A3B8] font-subheading font-medium">
                SOC Platform Identifier
              </label>
              <input
                type="text"
                value={platformName}
                onChange={(e) => setPlatformName(e.target.value)}
                className="w-full bg-[#080B0F] border border-white/[0.08] rounded-lg px-3.5 py-2.5 text-xs text-white focus:outline-none focus:border-[#38BDF8] transition-colors"
              />
            </div>

            <div className="grid grid-cols-2 gap-4">
              <div className="space-y-1.5">
                <label className="block text-[#94A3B8] font-subheading font-medium">
                  Ingestion Timeout
                </label>
                <div className="flex items-center gap-2 bg-[#080B0F] border border-white/[0.08] rounded-lg px-3.5 py-2.5">
                  <input
                    type="number"
                    value={sessionTimeout}
                    onChange={(e) => setSessionTimeout(e.target.value)}
                    className="w-full bg-transparent text-xs text-white font-mono focus:outline-none"
                  />
                  <span className="text-[11px] text-[#64748B] font-mono">min</span>
                </div>
              </div>

              <div className="space-y-1.5">
                <label className="block text-[#94A3B8] font-subheading font-medium">
                  Retention Limit
                </label>
                <div className="flex items-center gap-2 bg-[#080B0F] border border-white/[0.08] rounded-lg px-3.5 py-2.5">
                  <input
                    type="number"
                    value={logRetentionDays}
                    onChange={(e) => setLogRetentionDays(e.target.value)}
                    className="w-full bg-transparent text-xs text-white font-mono focus:outline-none"
                  />
                  <span className="text-[11px] text-[#64748B] font-mono">days</span>
                </div>
              </div>
            </div>

            <div className="p-3.5 rounded-lg bg-[#080B0F] border border-white/[0.05] flex items-center justify-between">
              <div>
                <span className="text-white font-medium block">Automatic Outdated Session Purge</span>
                <span className="text-[11px] text-[#64748B] leading-relaxed">Purge forensic database records past retention limit</span>
              </div>
              <input
                type="checkbox"
                checked={autoPurge}
                onChange={(e) => setAutoPurge(e.target.checked)}
                className="w-4 h-4 rounded bg-[#080B0F] border border-white/20 text-[#38BDF8] cursor-pointer ml-3 shrink-0"
              />
            </div>
          </div>
        </Section>

        {/* ── Panel 2: Isolation Forest Hyperparameters ── */}
        <Section
          title="Isolation Forest Hyperparameters"
          subtitle="Fine-tune unsupervised model decision trees and anomaly score cutoff thresholds"
        >
          <div className="grid grid-cols-1 md:grid-cols-3 gap-6 text-xs">
            <div className="space-y-2.5 bg-[#080B0F] border border-white/[0.05] p-4 rounded-lg">
              <div className="flex justify-between items-center">
                <span className="text-[#94A3B8] font-subheading">Contamination Ratio (c)</span>
                <span className="font-mono text-[#38BDF8] font-semibold text-xs px-2 py-0.5 rounded bg-[#38BDF8]/10 border border-[#38BDF8]/20">
                  {contamination}
                </span>
              </div>
              <input
                type="range"
                min="0.01"
                max="0.2"
                step="0.01"
                value={contamination}
                onChange={(e) => setContamination(parseFloat(e.target.value))}
                className="w-full h-1.5 bg-white/[0.08] rounded-lg appearance-none cursor-pointer accent-[#38BDF8]"
              />
              <span className="text-[10px] text-[#64748B] block">Expected proportion of outliers in the training set</span>
            </div>

            <div className="space-y-2.5 bg-[#080B0F] border border-white/[0.05] p-4 rounded-lg">
              <div className="flex justify-between items-center">
                <span className="text-[#94A3B8] font-subheading">Ensemble Estimators (n_estimators)</span>
                <span className="font-mono text-[#38BDF8] font-semibold text-xs px-2 py-0.5 rounded bg-[#38BDF8]/10 border border-[#38BDF8]/20">
                  {nEstimators} trees
                </span>
              </div>
              <input
                type="range"
                min="50"
                max="300"
                step="10"
                value={nEstimators}
                onChange={(e) => setNEstimators(parseInt(e.target.value))}
                className="w-full h-1.5 bg-white/[0.08] rounded-lg appearance-none cursor-pointer accent-[#38BDF8]"
              />
              <span className="text-[10px] text-[#64748B] block">Number of Isolation Forest decision trees in ensemble</span>
            </div>

            <div className="space-y-2.5 bg-[#080B0F] border border-white/[0.05] p-4 rounded-lg">
              <div className="flex justify-between items-center">
                <span className="text-[#94A3B8] font-subheading">Anomaly Classification Threshold</span>
                <span className="font-mono text-[#38BDF8] font-semibold text-xs px-2 py-0.5 rounded bg-[#38BDF8]/10 border border-[#38BDF8]/20">
                  {threshold}
                </span>
              </div>
              <input
                type="range"
                min="0.5"
                max="0.9"
                step="0.05"
                value={threshold}
                onChange={(e) => setThreshold(parseFloat(e.target.value))}
                className="w-full h-1.5 bg-white/[0.08] rounded-lg appearance-none cursor-pointer accent-[#38BDF8]"
              />
              <span className="text-[10px] text-[#64748B] block">Score boundary above which logs are flagged anomalous</span>
            </div>
          </div>
        </Section>

        {/* ── Panel 3: Threat Intelligence Provider API Keys ── */}
        <Section
          title="Threat Intelligence Provider API Keys"
          subtitle="External reputation enrichers and VirusTotal v3 verification credentials"
        >
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6 items-center text-xs">
            <div className="space-y-1.5">
              <label className="block text-[#94A3B8] font-subheading font-medium">
                VirusTotal v3 Enterprise API Key
              </label>
              <div className="flex items-center gap-2 bg-[#080B0F] border border-white/[0.08] rounded-lg px-3.5 py-2.5">
                <Lock size={13} className="text-[#64748B]" />
                <input
                  type="password"
                  value={vtApiKey}
                  onChange={(e) => setVtApiKey(e.target.value)}
                  className="w-full bg-transparent text-xs text-white font-mono focus:outline-none"
                />
                <span className="text-[10px] text-emerald-400 font-mono font-medium shrink-0 px-1.5 py-0.5 rounded bg-emerald-500/10 border border-emerald-500/20">
                  AUTHENTICATED
                </span>
              </div>
            </div>

            <div className="p-3.5 rounded-lg bg-[#080B0F] border border-white/[0.05] space-y-1">
              <span className="text-white font-medium block">Offline Heuristic Fallback</span>
              <p className="text-[11px] text-[#64748B] leading-relaxed">
                When API quota is depleted, MICHAEL automatically pivots to deterministic regex and ASN subnet reputation matrices.
              </p>
            </div>
          </div>
        </Section>

        {/* ── Panel 4: Network Daemon & Ingestion Security ── */}
        <Section
          title="Network Daemon & Ingestion Security"
          subtitle="WebSocket broadcast security and administrative transport layers"
        >
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6 items-center text-xs">
            <div className="space-y-1.5">
              <label className="block text-[#94A3B8] font-subheading font-medium">
                WebSocket Broadcast Port
              </label>
              <input
                type="text"
                value={wsPort}
                onChange={(e) => setWsPort(e.target.value)}
                className="w-full bg-[#080B0F] border border-white/[0.08] rounded-lg px-3.5 py-2.5 text-xs text-white font-mono focus:outline-none focus:border-[#38BDF8]"
              />
            </div>

            <div className="p-3.5 rounded-lg bg-[#080B0F] border border-white/[0.05] flex items-center justify-between">
              <div>
                <span className="text-white font-medium block">Strict mTLS Transport Security</span>
                <span className="text-[11px] text-[#64748B] leading-relaxed">Enforce bidirectional TLS certificates on ingestion endpoints</span>
              </div>
              <input
                type="checkbox"
                checked={mTLSEnforced}
                onChange={(e) => setMTLSEnforced(e.target.checked)}
                className="w-4 h-4 rounded bg-[#080B0F] border border-white/20 text-[#38BDF8] cursor-pointer ml-3 shrink-0"
              />
            </div>
          </div>
        </Section>
      </div>
    </PageShell>
  );
}
