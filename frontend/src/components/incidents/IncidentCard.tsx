'use client';

import React from 'react';
import {
  Globe,
  Clock,
  ArrowUpRight,
} from 'lucide-react';
import { Badge } from '@/components/ui/Badge';
import { Incident, IncidentStatus } from '@/types';
import { formatDate } from '@/lib/utils';

interface IncidentCardProps {
  incident: Incident;
  onSelect: (incident: Incident) => void;
  onStatusChange: (id: string, newStatus: IncidentStatus) => void;
}

export function IncidentCard({ incident, onSelect, onStatusChange }: IncidentCardProps) {
  return (
    <div
      style={{
        backgroundColor: '#11161E',
        border: '1px solid rgba(255, 255, 255, 0.08)',
        borderRadius: '16px',
        padding: '24px',
        boxShadow: '0 4px 20px rgba(0, 0, 0, 0.35)',
      }}
      className="hover:border-white/20 transition-all space-y-4 font-sans cursor-pointer group flex flex-col justify-between"
      onClick={() => onSelect(incident)}
    >
      {/* Top Header */}
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div className="space-y-2 flex-1 min-w-[200px]">
          <div className="flex flex-wrap items-center gap-2">
            <Badge variant={incident.severity} dot size="sm">
              {incident.severity}
            </Badge>
            <span className="text-[10px] font-mono uppercase px-2 py-0.5 rounded bg-white/[0.04] text-slate-300 border border-white/[0.06]">
              {incident.category}
            </span>
            <Badge variant={incident.status} size="sm">
              {incident.status.replace('_', ' ')}
            </Badge>
          </div>
          <h3 className="text-base font-heading font-semibold text-white group-hover:text-sky-300 transition-colors">
            {incident.title}
          </h3>
        </div>

        {/* Status Dropdown */}
        <div className="flex items-center gap-2 shrink-0" onClick={(e) => e.stopPropagation()}>
          <select
            value={incident.status}
            onChange={(e) => onStatusChange(incident.id, e.target.value as IncidentStatus)}
            className="bg-[#090D13] border border-white/10 text-xs text-white rounded-lg px-2.5 py-1.5 focus:outline-none focus:border-white/30 font-sans cursor-pointer"
          >
            <option value="open">Open</option>
            <option value="investigating">Investigating</option>
            <option value="resolved">Resolved</option>
            <option value="false_positive">False Positive</option>
          </select>
        </div>
      </div>

      {/* Hypothesis */}
      <p className="text-xs text-[#94A3B8] font-subheading leading-relaxed line-clamp-2">
        {incident.root_cause_hypothesis || incident.description}
      </p>

      {/* Metadata Footer */}
      <div className="flex flex-wrap items-center justify-between gap-3 pt-3.5 border-t border-white/[0.05] text-xs text-[#64748B]">
        <div className="flex items-center gap-4">
          <span className="flex items-center gap-1.5 font-mono text-[11px] text-[#94A3B8]">
            <Clock size={13} className="text-[#64748B]" />
            {formatDate(incident.created_at)}
          </span>
          {incident.affected_ips && incident.affected_ips.length > 0 && (
            <span className="flex items-center gap-1.5 font-mono text-[11px] text-sky-400">
              <Globe size={13} />
              {incident.affected_ips[0]}
            </span>
          )}
        </div>

        <span className="text-white group-hover:text-sky-300 font-medium flex items-center gap-1 text-xs transition-colors">
          Investigate <ArrowUpRight size={13} />
        </span>
      </div>
    </div>
  );
}
