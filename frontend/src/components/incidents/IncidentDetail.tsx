'use client';

import React, { useState } from 'react';
import {
  Sparkles,
  Server,
  Globe,
  Copy,
  Check,
  Fingerprint,
  GitFork,
} from 'lucide-react';
import { Badge } from '@/components/ui/Badge';
import { Button } from '@/components/ui/Button';
import { InvestigationDrawer } from '@/components/ui/InvestigationDrawer';
import { Incident, IncidentStatus } from '@/types';
import { formatDate } from '@/lib/utils';
import { useRouter } from 'next/navigation';

interface IncidentDetailProps {
  incident: Incident | null;
  onClose: () => void;
  onStatusChange: (id: string, newStatus: IncidentStatus) => void;
}

export function IncidentDetail({ incident, onClose, onStatusChange }: IncidentDetailProps) {
  const router = useRouter();
  const [copiedLog, setCopiedLog] = useState<string | null>(null);

  if (!incident) return null;

  const handleCopy = (text: string) => {
    navigator.clipboard.writeText(text);
    setCopiedLog(text);
    setTimeout(() => setCopiedLog(null), 2000);
  };

  const handleAskCopilot = () => {
    const prompt = `Perform an in-depth forensic investigation of incident '${incident.title}'.
Category: ${incident.category}
Severity: ${incident.severity}
Root Cause Hypothesis: ${incident.root_cause_hypothesis}
Evidence logs:
${incident.evidence_log_lines?.slice(0, 5).join('\n')}
Provide a step-by-step mitigation strategy and threat actor attribution.`;
    router.push(`/copilot?prompt=${encodeURIComponent(prompt)}`);
  };

  return (
    <InvestigationDrawer
      isOpen={!!incident}
      onClose={onClose}
      title={incident.title}
      subtitle={`ID: ${incident.id.slice(0, 12)} • ${formatDate(incident.created_at)}`}
      width={600}
    >
      <div className="space-y-6 text-xs font-sans">
        {/* Status & Severity Bar */}
        <div className="flex flex-wrap items-center justify-between gap-3 p-4 rounded-xl bg-[#080C12] border border-white/[0.06]">
          <div className="flex items-center gap-2">
            <Badge variant={incident.severity} dot size="sm">
              {incident.severity}
            </Badge>
            <Badge variant="cyan" size="sm">
              {incident.category}
            </Badge>
          </div>

          <div className="flex items-center gap-2">
            <span className="text-[#A7B1C0] text-xs">Status:</span>
            <select
              value={incident.status}
              onChange={(e) => onStatusChange(incident.id, e.target.value as IncidentStatus)}
              className="bg-[#0C1119] border border-white/[0.08] text-xs text-[#F5F7FA] rounded-lg px-2.5 py-1 focus:outline-none focus:border-[#3B82F6]"
            >
              <option value="open">Open</option>
              <option value="investigating">Investigating</option>
              <option value="resolved">Resolved</option>
              <option value="false_positive">False Positive</option>
            </select>
          </div>
        </div>

        {/* Root Cause Hypothesis */}
        <div>
          <label className="block text-xs font-semibold text-[#A7B1C0] mb-2 uppercase tracking-wider">
            Root Cause Hypothesis
          </label>
          <div className="p-4 rounded-xl bg-[#080C12] border border-white/[0.06] text-[#F5F7FA] leading-relaxed">
            {incident.root_cause_hypothesis || incident.description}
          </div>
        </div>

        {/* Affected Entities */}
        <div className="grid grid-cols-2 gap-3">
          <div className="p-3.5 rounded-xl bg-[#080C12] border border-white/[0.06] space-y-1">
            <span className="text-[#687589] flex items-center gap-1.5">
              <Globe size={13} className="text-[#3B82F6]" /> Affected IPs
            </span>
            <div className="font-mono text-xs text-[#F5F7FA]">
              {incident.affected_ips?.join(', ') || '127.0.0.1'}
            </div>
          </div>

          <div className="p-3.5 rounded-xl bg-[#080C12] border border-white/[0.06] space-y-1">
            <span className="text-[#687589] flex items-center gap-1.5">
              <Server size={13} className="text-[#8B5CF6]" /> Affected Hosts
            </span>
            <div className="font-mono text-xs text-[#F5F7FA]">
              {incident.affected_hosts?.join(', ') || 'security-gw-01'}
            </div>
          </div>
        </div>

        {/* Evidence Logs */}
        {incident.evidence_log_lines && incident.evidence_log_lines.length > 0 && (
          <div>
            <label className="block text-xs font-semibold text-[#A7B1C0] mb-2 uppercase tracking-wider">
              Forensic Evidence Logs ({incident.evidence_log_lines.length})
            </label>
            <div className="space-y-2 max-h-56 overflow-y-auto">
              {incident.evidence_log_lines.map((line, idx) => (
                <div
                  key={idx}
                  className="p-3 rounded-lg bg-[#05070B] border border-white/[0.04] flex items-start justify-between gap-2 font-mono text-[11px] text-slate-300"
                >
                  <span className="break-all">{line}</span>
                  <button
                    onClick={() => handleCopy(line)}
                    className="shrink-0 p-1 rounded text-[#687589] hover:text-[#3B82F6]"
                  >
                    {copiedLog === line ? (
                      <Check size={12} className="text-[#22C55E]" />
                    ) : (
                      <Copy size={12} />
                    )}
                  </button>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* Action Controls */}
        <div className="pt-2 flex gap-3">
          <Button
            variant="primary"
            size="md"
            onClick={handleAskCopilot}
            leftIcon={<Sparkles size={14} />}
            className="flex-1"
          >
            Investigate with AI Copilot
          </Button>
          <Button variant="secondary" size="md" onClick={onClose}>
            Close
          </Button>
        </div>
      </div>
    </InvestigationDrawer>
  );
}
