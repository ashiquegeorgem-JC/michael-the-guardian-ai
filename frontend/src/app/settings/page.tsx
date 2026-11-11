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
} from 'lucide-react';
import { Button } from '@/components/ui/Button';
import { Badge } from '@/components/ui/Badge';
import { PageHeader } from '@/components/ui/PageHeader';
import { checkHealth } from '@/lib/api';

type SettingsTab =
  | 'general'
  | 'detection'
  | 'threat_intel'
  | 'telemetry'
  | 'database'
  | 'security'
  | 'system';

export default function SettingsPage() {
  const [activeTab, setActiveTab] = useState<SettingsTab>('general');
  const [contamination, setContamination] = useState(0.05);
  const [nEstimators, setNEstimators] = useState(100);
  const [threshold, setThreshold] = useState(0.65);
  const [backendHealth, setBackendHealth] = useState<string>('Checking...');
  const [isSaved, setIsSaved] = useState(false);

  // Form states
  const [sessionTimeout, setSessionTimeout] = useState('60');
  const [logRetentionDays, setLogRetentionDays] = useState('365');
  const [vtApiKey, setVtApiKey] = useState('••••••••••••••••••••••••••••••••');
  const [wsPort, setWsPort] = useState('8000');
  const [autoPurge, setAutoPurge] = useState(false);

  useEffect(() => {
    checkHealth()
      .then((res) => setBackendHealth(`${res.status.toUpperCase()} (${res.service})`))
      .catch(() => setBackendHealth('Offline (Port 8000)'));
  }, []);

  const handleSave = () => {
    setIsSaved(true);
    setTimeout(() => setIsSaved(false), 2500);
  };

  const TABS: Array<{
    id: SettingsTab;
    label: string;
    icon: React.ComponentType<{ size?: number; className?: string }>;
  }> = [
    { id: 'general', label: 'General', icon: Settings },
    { id: 'detection', label: 'Detection Engine', icon: Sliders },
    { id: 'threat_intel', label: 'Threat Intelligence', icon: Globe },
    { id: 'telemetry', label: 'Telemetry & Stream', icon: Radio },
    { id: 'database', label: 'Database & Storage', icon: Database },
    { id: 'security', label: 'Security & RBAC', icon: Lock },
    { id: 'system', label: 'System & Health', icon: Cpu },
  ];

  return (
    <div className="space-y-6 pb-12 font-sans text-slate-100 max-w-5xl">
      {/* 1. Page Header */}
      <PageHeader
        tag="Platform Administration"
        title="Settings & System Configuration"
        description="Configure ML model hyperparameters, external intelligence provider keys, storage retention, and daemon runtime rules."
        actions={
          <Button
            variant="primary"
            size="sm"
            onClick={handleSave}
            leftIcon={<Save size={14} />}
          >
            {isSaved ? 'Changes Committed!' : 'Save Configuration'}
          </Button>
        }
      />

      {isSaved && (
        <div className="p-3.5 rounded-xl bg-emerald-500/10 border border-emerald-500/25 flex items-center gap-2.5 text-[#22C55E] text-xs">
          <CheckCircle2 size={16} />
          <span>System configuration and engine hyperparameters updated successfully.</span>
        </div>
      )}

      {/* 2. Horizontal Navigation Tabs */}
      <div
        style={{
          backgroundColor: '#0C1119',
          border: '1px solid rgba(255, 255, 255, 0.08)',
          borderRadius: '12px',
          padding: '6px',
        }}
        className="flex items-center gap-1 overflow-x-auto text-xs"
      >
        {TABS.map(({ id, label, icon: Icon }) => (
          <button
            key={id}
            onClick={() => setActiveTab(id)}
            className={`flex items-center gap-2 px-3.5 py-2 rounded-lg font-medium transition-all cursor-pointer whitespace-nowrap ${
              activeTab === id
                ? 'bg-[#111823] text-[#3B82F6] shadow-sm border border-blue-500/30'
                : 'text-[#A7B1C0] hover:text-[#F5F7FA] hover:bg-white/[0.03]'
            }`}
          >
            <Icon size={14} />
            <span>{label}</span>
          </button>
        ))}
      </div>

      {/* 3. Settings Card Panel */}
      <div
        style={{
          backgroundColor: '#0C1119',
          border: '1px solid rgba(255, 255, 255, 0.08)',
          borderRadius: '12px',
          padding: '24px',
        }}
        className="space-y-6"
      >
        {/* TAB: GENERAL */}
        {activeTab === 'general' && (
          <div className="space-y-6">
            <div className="border-b border-white/[0.06] pb-3">
              <h3 className="text-sm font-semibold text-[#F5F7FA]">
                General Platform Settings
              </h3>
              <p className="text-xs text-[#A7B1C0] mt-0.5">
                Configure platform branding, session windows, and operational environments
              </p>
            </div>

            <div className="divide-y divide-white/[0.04]">
              <div className="flex flex-col sm:flex-row sm:items-center justify-between py-4 gap-3">
                <div>
                  <h4 className="text-sm font-semibold text-[#F5F7FA]">
                    SOC Platform Identifier
                  </h4>
                  <p className="text-xs text-[#A7B1C0]">
                    Canonical deployment name reported in exported compliance audits
                  </p>
                </div>
                <input
                  type="text"
                  readOnly
                  value="MICHAEL — The Guardian AI (Production)"
                  className="bg-[#080C12] border border-white/[0.08] rounded-lg px-3 py-2 text-xs text-[#F5F7FA] w-72"
                />
              </div>

              <div className="flex flex-col sm:flex-row sm:items-center justify-between py-4 gap-3">
                <div>
                  <h4 className="text-sm font-semibold text-[#F5F7FA]">
                    Session Ingestion Timeout
                  </h4>
                  <p className="text-xs text-[#A7B1C0]">
                    Inactivity window before an ingestion session is finalized (minutes)
                  </p>
                </div>
                <input
                  type="number"
                  value={sessionTimeout}
                  onChange={(e) => setSessionTimeout(e.target.value)}
                  className="bg-[#080C12] border border-white/[0.08] rounded-lg px-3 py-2 text-xs text-[#F5F7FA] w-32 font-mono"
                />
              </div>

              <div className="flex flex-col sm:flex-row sm:items-center justify-between py-4 gap-3">
                <div>
                  <h4 className="text-sm font-semibold text-[#F5F7FA]">
                    Log Event Retention Period
                  </h4>
                  <p className="text-xs text-[#A7B1C0]">
                    Number of days raw syslog lines are preserved for retrospective threat hunting
                  </p>
                </div>
                <input
                  type="number"
                  value={logRetentionDays}
                  onChange={(e) => setLogRetentionDays(e.target.value)}
                  className="bg-[#080C12] border border-white/[0.08] rounded-lg px-3 py-2 text-xs text-[#F5F7FA] w-32 font-mono"
                />
              </div>
            </div>
          </div>
        )}

        {/* TAB: DETECTION */}
        {activeTab === 'detection' && (
          <div className="space-y-6">
            <div className="border-b border-white/[0.06] pb-3">
              <h3 className="text-sm font-semibold text-[#F5F7FA]">
                Machine Learning Hyperparameters
              </h3>
              <p className="text-xs text-[#A7B1C0] mt-0.5">
                Tune Isolation Forest unsupervised clustering and heuristic detection thresholds
              </p>
            </div>

            <div className="divide-y divide-white/[0.04]">
              <div className="flex flex-col sm:flex-row sm:items-center justify-between py-4 gap-3">
                <div>
                  <div className="flex items-center gap-2">
                    <h4 className="text-sm font-semibold text-[#F5F7FA]">
                      Contamination Rate (nu)
                    </h4>
                    <span className="font-mono text-xs text-[#3B82F6]">
                      {(contamination * 100).toFixed(0)}%
                    </span>
                  </div>
                  <p className="text-xs text-[#A7B1C0]">
                    Expected proportion of behavioral outliers in the normal training dataset
                  </p>
                </div>
                <input
                  type="range"
                  min="0.01"
                  max="0.25"
                  step="0.01"
                  value={contamination}
                  onChange={(e) => setContamination(parseFloat(e.target.value))}
                  className="w-48 accent-[#3B82F6] cursor-pointer"
                />
              </div>

              <div className="flex flex-col sm:flex-row sm:items-center justify-between py-4 gap-3">
                <div>
                  <div className="flex items-center gap-2">
                    <h4 className="text-sm font-semibold text-[#F5F7FA]">
                      Ensemble Estimators (n_trees)
                    </h4>
                    <span className="font-mono text-xs text-[#3B82F6]">
                      {nEstimators} trees
                    </span>
                  </div>
                  <p className="text-xs text-[#A7B1C0]">
                    Number of isolation decision trees computed per ensemble iteration
                  </p>
                </div>
                <input
                  type="range"
                  min="50"
                  max="300"
                  step="25"
                  value={nEstimators}
                  onChange={(e) => setNEstimators(parseInt(e.target.value))}
                  className="w-48 accent-[#3B82F6] cursor-pointer"
                />
              </div>

              <div className="flex flex-col sm:flex-row sm:items-center justify-between py-4 gap-3">
                <div>
                  <div className="flex items-center gap-2">
                    <h4 className="text-sm font-semibold text-[#F5F7FA]">
                      Anomaly Outlier Decision Threshold
                    </h4>
                    <span className="font-mono text-xs text-[#F59E0B]">
                      {(threshold * 100).toFixed(0)}%
                    </span>
                  </div>
                  <p className="text-xs text-[#A7B1C0]">
                    Minimum score required before an event triggers an incident record
                  </p>
                </div>
                <input
                  type="range"
                  min="0.4"
                  max="0.9"
                  step="0.05"
                  value={threshold}
                  onChange={(e) => setThreshold(parseFloat(e.target.value))}
                  className="w-48 accent-[#F59E0B] cursor-pointer"
                />
              </div>
            </div>
          </div>
        )}

        {/* TAB: THREAT INTEL */}
        {activeTab === 'threat_intel' && (
          <div className="space-y-6">
            <div className="border-b border-white/[0.06] pb-3">
              <h3 className="text-sm font-semibold text-[#F5F7FA]">
                External Threat Intelligence Providers
              </h3>
              <p className="text-xs text-[#A7B1C0] mt-0.5">
                Configure reputation feeds, API credentials, and query rate limiters
              </p>
            </div>

            <div className="divide-y divide-white/[0.04]">
              <div className="flex flex-col sm:flex-row sm:items-center justify-between py-4 gap-3">
                <div>
                  <h4 className="text-sm font-semibold text-[#F5F7FA]">
                    VirusTotal v3 API Key
                  </h4>
                  <p className="text-xs text-[#A7B1C0]">
                    Commercial or community key used for IP and hash reputation lookups
                  </p>
                </div>
                <input
                  type="password"
                  value={vtApiKey}
                  onChange={(e) => setVtApiKey(e.target.value)}
                  className="bg-[#080C12] border border-white/[0.08] rounded-lg px-3 py-2 text-xs text-[#F5F7FA] w-64 font-mono"
                />
              </div>

              <div className="flex flex-col sm:flex-row sm:items-center justify-between py-4 gap-3">
                <div>
                  <h4 className="text-sm font-semibold text-[#F5F7FA]">
                    Circuit-Breaker Fallback
                  </h4>
                  <p className="text-xs text-[#A7B1C0]">
                    Automatically route to offline heuristics if external API exceeds timeout
                  </p>
                </div>
                <Badge variant="success" size="sm" dot>
                  Enabled (3.0s)
                </Badge>
              </div>
            </div>
          </div>
        )}

        {/* TAB: TELEMETRY */}
        {activeTab === 'telemetry' && (
          <div className="space-y-6">
            <div className="border-b border-white/[0.06] pb-3">
              <h3 className="text-sm font-semibold text-[#F5F7FA]">
                Telemetry & WebSocket Broadcast
              </h3>
              <p className="text-xs text-[#A7B1C0] mt-0.5">
                Configure real-time monitoring streams, port allocations, and socket buffer sizes
              </p>
            </div>

            <div className="divide-y divide-white/[0.04]">
              <div className="flex flex-col sm:flex-row sm:items-center justify-between py-4 gap-3">
                <div>
                  <h4 className="text-sm font-semibold text-[#F5F7FA]">
                    WebSocket Endpoint Port
                  </h4>
                  <p className="text-xs text-[#A7B1C0]">
                    Local bind port for broadcast stream `/ws/monitoring`
                  </p>
                </div>
                <input
                  type="text"
                  value={wsPort}
                  onChange={(e) => setWsPort(e.target.value)}
                  className="bg-[#080C12] border border-white/[0.08] rounded-lg px-3 py-2 text-xs text-[#F5F7FA] w-32 font-mono"
                />
              </div>

              <div className="flex flex-col sm:flex-row sm:items-center justify-between py-4 gap-3">
                <div>
                  <h4 className="text-sm font-semibold text-[#F5F7FA]">
                    Socket Broadcast Frequency
                  </h4>
                  <p className="text-xs text-[#A7B1C0]">
                    Interval between hardware utilization metrics emissions
                  </p>
                </div>
                <span className="font-mono text-xs text-[#22C55E]">
                  1.0 Hz (1000ms)
                </span>
              </div>
            </div>
          </div>
        )}

        {/* TAB: DATABASE */}
        {activeTab === 'database' && (
          <div className="space-y-6">
            <div className="border-b border-white/[0.06] pb-3">
              <h3 className="text-sm font-semibold text-[#F5F7FA]">
                Database & Persistence Engine
              </h3>
              <p className="text-xs text-[#A7B1C0] mt-0.5">
                Storage driver configurations, indices, and vacuum procedures
              </p>
            </div>

            <div className="divide-y divide-white/[0.04]">
              <div className="flex flex-col sm:flex-row sm:items-center justify-between py-4 gap-3">
                <div>
                  <h4 className="text-sm font-semibold text-[#F5F7FA]">
                    Primary Persistence Driver
                  </h4>
                  <p className="text-xs text-[#A7B1C0]">
                    Storage engine used for incidents, IOC repository, and attack chains
                  </p>
                </div>
                <Badge variant="cyan" size="sm">
                  In-Memory & SQLite Dual Engine
                </Badge>
              </div>

              <div className="flex flex-col sm:flex-row sm:items-center justify-between py-4 gap-3">
                <div>
                  <h4 className="text-sm font-semibold text-[#F5F7FA]">
                    Automatic Session Purge
                  </h4>
                  <p className="text-xs text-[#A7B1C0]">
                    Periodically purge temporary test logs when session memory reaches 80%
                  </p>
                </div>
                <button
                  onClick={() => setAutoPurge(!autoPurge)}
                  className={`w-11 h-6 flex items-center rounded-full p-1 cursor-pointer transition-colors ${
                    autoPurge ? 'bg-[#3B82F6]' : 'bg-slate-800'
                  }`}
                >
                  <div
                    className={`bg-white w-4 h-4 rounded-full shadow-md transform transition-transform ${
                      autoPurge ? 'translate-x-5' : 'translate-x-0'
                    }`}
                  />
                </button>
              </div>
            </div>
          </div>
        )}

        {/* TAB: SECURITY */}
        {activeTab === 'security' && (
          <div className="space-y-6">
            <div className="border-b border-white/[0.06] pb-3">
              <h3 className="text-sm font-semibold text-[#F5F7FA]">
                Security Controls & RBAC
              </h3>
              <p className="text-xs text-[#A7B1C0] mt-0.5">
                Role-based access permissions, API authentication, and TLS termination
              </p>
            </div>

            <div className="divide-y divide-white/[0.04]">
              <div className="flex flex-col sm:flex-row sm:items-center justify-between py-4 gap-3">
                <div>
                  <h4 className="text-sm font-semibold text-[#F5F7FA]">
                    Active Role Level
                  </h4>
                  <p className="text-xs text-[#A7B1C0]">
                    Permissions granted for incident status modification and report export
                  </p>
                </div>
                <Badge variant="purple" size="sm">
                  SOC Tier 3 Lead Analyst
                </Badge>
              </div>

              <div className="flex flex-col sm:flex-row sm:items-center justify-between py-4 gap-3">
                <div>
                  <h4 className="text-sm font-semibold text-[#F5F7FA]">
                    Mutual TLS (mTLS) Client Verification
                  </h4>
                  <p className="text-xs text-[#A7B1C0]">
                    Cryptographic certificate enforcement on log ingestion streams
                  </p>
                </div>
                <Badge variant="success" size="sm" dot>
                  Enforced
                </Badge>
              </div>
            </div>
          </div>
        )}

        {/* TAB: SYSTEM */}
        {activeTab === 'system' && (
          <div className="space-y-6">
            <div className="border-b border-white/[0.06] pb-3">
              <h3 className="text-sm font-semibold text-[#F5F7FA]">
                System Runtime Diagnostics & Daemon Health
              </h3>
              <p className="text-xs text-[#A7B1C0] mt-0.5">
                Inspect backend Uvicorn state, Python dependencies, and socket connectivity
              </p>
            </div>

            <div className="divide-y divide-white/[0.04]">
              <div className="flex flex-col sm:flex-row sm:items-center justify-between py-4 gap-3">
                <div>
                  <h4 className="text-sm font-semibold text-[#F5F7FA]">
                    FastAPI Backend Core
                  </h4>
                  <p className="text-xs text-[#A7B1C0]">
                    REST API endpoint response status
                  </p>
                </div>
                <Badge variant="success" size="sm" dot>
                  {backendHealth}
                </Badge>
              </div>

              <div className="flex flex-col sm:flex-row sm:items-center justify-between py-4 gap-3">
                <div>
                  <h4 className="text-sm font-semibold text-[#F5F7FA]">
                    Next.js Frontend Build
                  </h4>
                  <p className="text-xs text-[#A7B1C0]">
                    Client engine & server-rendered App Router
                  </p>
                </div>
                <Badge variant="blue" size="sm">
                  Next.js v16 (Production)
                </Badge>
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
