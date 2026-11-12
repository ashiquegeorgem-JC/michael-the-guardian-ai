'use client';

import React, { useState } from 'react';
import { Copy, Check, ShieldAlert, Terminal } from 'lucide-react';
import { Badge } from '@/components/ui/Badge';
import { Button } from '@/components/ui/Button';
import { InvestigationDrawer } from '@/components/ui/InvestigationDrawer';
import { LogEntry } from '@/types';
import { formatDate } from '@/lib/utils';
import { useRouter } from 'next/navigation';

interface LogInspectorProps {
  log: LogEntry | null;
  onClose: () => void;
}

export function LogInspector({ log, onClose }: LogInspectorProps) {
  const [copied, setCopied] = useState(false);
  const router = useRouter();

  if (!log) return null;

  const handleCopy = () => {
    navigator.clipboard.writeText(log.raw_line);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <InvestigationDrawer
      isOpen={!!log}
      onClose={onClose}
      title="Security Event Inspector"
      subtitle={`Line #${log.line_number} • ID: ${log.id.slice(0, 8)}`}
      width={520}
    >
      <div className="space-y-6 text-xs font-sans">
        {/* Anomaly banner if flagged */}
        {log.is_anomaly && (
          <div className="p-4 rounded-xl bg-amber-500/10 border border-amber-500/30 flex items-start gap-3">
            <ShieldAlert className="w-5 h-5 text-[#F59E0B] shrink-0 mt-0.5" />
            <div className="space-y-1">
              <div className="flex items-center gap-2">
                <span className="font-semibold text-[#F59E0B]">
                  Behavioral Anomaly Outlier
                </span>
                <span className="px-1.5 py-0.5 rounded text-[10px] bg-amber-500/20 text-[#F59E0B] font-mono">
                  SCORE: {((log.anomaly_score || 0.85) * 100).toFixed(0)}%
                </span>
              </div>
              <p className="text-[#A7B1C0] leading-relaxed">
                Isolation Forest outlier detected based on rare frequency or unauthorized access pattern.
              </p>
            </div>
          </div>
        )}

        {/* Structured Metadata Fields */}
        <div className="rounded-xl bg-[#080C12] border border-white/[0.06] divide-y divide-white/[0.04]">
          <div className="flex items-center justify-between p-3.5">
            <span className="text-[#A7B1C0]">Severity</span>
            <Badge variant={log.level} size="sm">
              {log.level}
            </Badge>
          </div>
          <div className="flex items-center justify-between p-3.5">
            <span className="text-[#A7B1C0]">Timestamp</span>
            <span className="font-mono text-[#F5F7FA]">
              {formatDate(log.timestamp)}
            </span>
          </div>
          <div className="flex items-center justify-between p-3.5">
            <span className="text-[#A7B1C0]">Source IP / Host</span>
            <span className="font-mono text-[#3B82F6]">
              {log.source_ip || log.host || log.source || '127.0.0.1'}
            </span>
          </div>
          {(log.service) && (
            <div className="flex items-center justify-between p-3.5">
              <span className="text-[#A7B1C0]">Service Daemon</span>
              <span className="font-mono text-[#F5F7FA]">{log.service}</span>
            </div>
          )}
          {log.session_id && (
            <div className="flex items-center justify-between p-3.5">
              <span className="text-[#A7B1C0]">Ingestion Session</span>
              <span className="font-mono text-[#687589]">
                {log.session_id.slice(0, 12)}
              </span>
            </div>
          )}
        </div>

        {/* Parsed Message */}
        <div>
          <label className="block text-xs font-semibold text-[#A7B1C0] mb-2 uppercase tracking-wider">
            Structured Message
          </label>
          <div className="p-3.5 rounded-xl bg-[#080C12] border border-white/[0.06] text-[#F5F7FA] font-mono text-[11px] leading-relaxed break-words">
            {log.message}
          </div>
        </div>

        {/* Raw Log Line */}
        <div>
          <div className="flex items-center justify-between mb-2">
            <label className="text-xs font-semibold text-[#A7B1C0] uppercase tracking-wider">
              Raw Syslog Payload
            </label>
            <button
              onClick={handleCopy}
              className="flex items-center gap-1.5 text-xs text-[#3B82F6] hover:text-[#22B8FF] transition-colors"
            >
              {copied ? (
                <>
                  <Check size={13} className="text-[#22C55E]" />
                  <span className="text-[#22C55E]">Copied</span>
                </>
              ) : (
                <>
                  <Copy size={13} />
                  <span>Copy Raw</span>
                </>
              )}
            </button>
          </div>
          <div className="p-3.5 rounded-xl bg-[#05070B] border border-white/[0.06] text-slate-300 font-mono text-[10px] leading-relaxed break-all select-all">
            {log.raw_line}
          </div>
        </div>

        {/* Actions */}
        <div className="pt-2 flex gap-3">
          <Button
            variant="primary"
            size="md"
            onClick={handleCopy}
            leftIcon={<Copy size={14} />}
            className="flex-1"
          >
            {copied ? 'Copied Raw Log' : 'Copy Raw Log'}
          </Button>
          <Button variant="secondary" size="md" onClick={onClose}>
            Close
          </Button>
        </div>
      </div>
    </InvestigationDrawer>
  );
}
