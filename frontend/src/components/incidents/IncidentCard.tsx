'use client';

import React from 'react';
import {
  Server,
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
        backgroundColor: '#0C1119',
        border: '1px solid rgba(255, 255, 255, 0.08)',
        borderRadius: '12px',
        padding: '20px',
      }}
      className="hover:border-blue-500/40 transition-all space-y-4 font-sans cursor-pointer group"
      onClick={() => onSelect(incident)}
    >
      {/* Top Header */}
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div className="space-y-1.5">
          <div className="flex flex-wrap items-center gap-2">
            <Badge variant={incident.severity} dot size="sm">
              {incident.severity}
            </Badge>
            <Badge variant="cyan" size="sm">
              {incident.category}
            </Badge>
            <Badge variant={incident.status} size="sm">
              {incident.status.replace('_', ' ')}
            </Badge>
          </div>
          <h3 className="text-base font-semibold text-[#F5F7FA] group-hover:text-[#3B82F6] transition-colors">
            {incident.title}
          </h3>
        </div>

        {/* Status Dropdown */}
        <div className="flex items-center gap-2" onClick={(e) => e.stopPropagation()}>
          <select
            value={incident.status}
            onChange={(e) => onStatusChange(incident.id, e.target.value as IncidentStatus)}
            className="bg-[#080C12] border border-white/[0.08] text-xs text-[#F5F7FA] rounded-lg px-2.5 py-1 focus:outline-none focus:border-[#3B82F6] font-sans"
          >
            <option value="open">Open</option>
            <option value="investigating">Investigating</option>
            <option value="resolved">Resolved</option>
            <option value="false_positive">False Positive</option>
          </select>
        </div>
      </div>

      {/* Hypothesis */}
      <p className="text-xs text-[#A7B1C0] leading-relaxed line-clamp-2">
        {incident.root_cause_hypothesis || incident.description}
      </p>

      {/* Metadata Footer */}
      <div className="flex flex-wrap items-center justify-between gap-3 pt-3 border-t border-white/[0.04] text-xs text-[#687589]">
        <div className="flex items-center gap-4">
          <span className="flex items-center gap-1.5 font-mono text-[11px] text-[#A7B1C0]">
            <Clock size={13} className="text-[#687589]" />
            {formatDate(incident.created_at)}
          </span>
          {incident.affected_ips && incident.affected_ips.length > 0 && (
            <span className="flex items-center gap-1.5 font-mono text-[11px] text-[#3B82F6]">
              <Globe size={13} />
              {incident.affected_ips[0]}
            </span>
          )}
        </div>

        <span className="text-[#3B82F6] group-hover:text-[#22B8FF] font-medium flex items-center gap-1">
          Investigate <ArrowUpRight size={13} />
        </span>
      </div>
    </div>
  );
}
