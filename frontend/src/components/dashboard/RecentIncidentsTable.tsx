'use client';

import React from 'react';
import Link from 'next/link';
import { ArrowRight, ShieldAlert } from 'lucide-react';
import { Incident } from '@/types';

interface RecentIncidentsTableProps {
  incidents: Incident[];
  isLoading?: boolean;
}

const SAMPLE_INCIDENTS = [
  {
    id: 'INC-0427',
    severity: 'Critical',
    title: 'SSH Brute Force Attack',
    source: '198.51.100.45',
    detection: 'Temporal + IF',
    status: 'Open',
    statusColor: '#F87171',
    time: '10:42 AM',
    dotColor: '#F87171',
  },
  {
    id: 'INC-0426',
    severity: 'High',
    title: 'C2 Outbound Beaconing',
    source: '203.0.113.15',
    detection: 'TI + IF',
    status: 'Open',
    statusColor: '#F87171',
    time: '10:28 AM',
    dotColor: '#FBBF24',
  },
  {
    id: 'INC-0425',
    severity: 'High',
    title: 'Data Exfiltration via DNS',
    source: '192.0.2.77',
    detection: 'Behavioural',
    status: 'Investigating',
    statusColor: '#FBBF24',
    time: '10:17 AM',
    dotColor: '#FBBF24',
  },
  {
    id: 'INC-0424',
    severity: 'Medium',
    title: 'Suspicious Domain Lookup',
    source: 'evil-c2.org',
    detection: 'TF-IDF',
    status: 'Resolved',
    statusColor: '#34D399',
    time: '10:05 AM',
    dotColor: '#60A5FA',
  },
];

export function RecentIncidentsTable({ incidents, isLoading = false }: RecentIncidentsTableProps) {
  const displayItems =
    incidents && incidents.length > 0
      ? incidents.slice(0, 4).map((inc, i) => ({
          id: inc.id || `INC-042${7 - i}`,
          severity: inc.severity ? inc.severity.charAt(0).toUpperCase() + inc.severity.slice(1).toLowerCase() : 'Medium',
          title: inc.title || 'Security Anomaly Detected',
          source: (inc.affected_ips && inc.affected_ips[0]) || (inc.affected_sources && inc.affected_sources[0]) || '198.51.100.45',
          detection: 'Isolation Forest',
          status: inc.status === 'resolved' ? 'Resolved' : inc.status === 'investigating' ? 'Investigating' : 'Open',
          statusColor: inc.status === 'resolved' ? '#34D399' : inc.status === 'investigating' ? '#FBBF24' : '#F87171',
          time: new Date(inc.created_at || Date.now()).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
          dotColor: inc.severity === 'CRITICAL' ? '#F87171' : inc.severity === 'HIGH' ? '#FBBF24' : '#60A5FA',
        }))
      : SAMPLE_INCIDENTS;

  return (
    <div
      style={{
        backgroundColor: '#11161E',
        border: '1px solid rgba(255, 255, 255, 0.08)',
        borderRadius: 16,
        padding: '24px 28px',
        boxShadow: '0 4px 20px rgba(0, 0, 0, 0.35)',
      }}
      className="font-sans h-full flex flex-col justify-between"
    >
      {/* Header */}
      <div className="flex items-center justify-between border-b border-white/[0.06] pb-3 mb-3">
        <div>
          <h2 className="text-base font-semibold text-white font-heading">
            Recent Incidents
          </h2>
          <p className="text-xs text-[#94A3B8] font-subheading mt-0.5">
            Active correlated incidents awaiting analyst review
          </p>
        </div>
        <Link
          href="/incidents"
          className="text-xs text-[#94A3B8] hover:text-white flex items-center gap-1 transition-colors"
        >
          <span>All Incidents</span>
          <ArrowRight size={13} />
        </Link>
      </div>

      {/* Disciplined, Non-colliding Item List */}
      <div className="space-y-2.5 flex-1 my-auto overflow-hidden">
        {displayItems.map((item) => (
          <div
            key={item.id}
            style={{
              backgroundColor: '#0D1117',
              border: '1px solid rgba(255, 255, 255, 0.04)',
              borderRadius: 8,
              padding: '10px 14px',
            }}
            className="flex items-center justify-between gap-3 hover:border-white/[0.12] transition-colors"
          >
            {/* Left: Severity indicator dot + Title + ID */}
            <div className="flex items-center gap-3 min-w-0 flex-1">
              <span
                className="w-2 h-2 rounded-full shrink-0"
                style={{ backgroundColor: item.dotColor }}
                title={item.severity}
              />
              <div className="min-w-0">
                <div className="text-xs font-medium text-white truncate leading-tight">
                  {item.title}
                </div>
                <div className="flex items-center gap-2 mt-1">
                  <span className="font-mono text-[11px] text-[#94A3B8]">{item.source}</span>
                  <span className="text-[#64748B] text-[10px]">•</span>
                  <span className="text-[10px] text-[#64748B] font-subheading">{item.detection}</span>
                </div>
              </div>
            </div>

            {/* Right: Status badge + Time */}
            <div className="flex items-center gap-3 shrink-0 text-right">
              <span
                style={{
                  color: item.statusColor,
                  backgroundColor: `${item.statusColor}14`,
                  border: `1px solid ${item.statusColor}28`,
                }}
                className="text-[10px] font-medium px-2 py-0.5 rounded"
              >
                {item.status}
              </span>
              <span className="font-mono text-[11px] text-[#64748B] w-16 text-right">
                {item.time}
              </span>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}
