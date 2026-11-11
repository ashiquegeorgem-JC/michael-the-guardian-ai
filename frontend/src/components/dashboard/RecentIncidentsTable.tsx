'use client';

import React from 'react';
import Link from 'next/link';
import { ArrowRight } from 'lucide-react';
import { Incident } from '@/types';

interface RecentIncidentsTableProps {
  incidents: Incident[];
  isLoading?: boolean;
}

const SAMPLE_INCIDENTS = [
  {
    severity: 'Critical',
    title: 'SSH Brute Force',
    source: '198.51.100.45',
    detection: 'Temporal + IF',
    status: 'Open',
    statusBg: 'rgba(239, 68, 68, 0.15)',
    statusColor: '#EF4444',
    time: '10:42',
    dotColor: '#EF4444',
  },
  {
    severity: 'High',
    title: 'C2 Communication',
    source: '203.0.113.15',
    detection: 'IF + TI',
    status: 'Open',
    statusBg: 'rgba(239, 68, 68, 0.15)',
    statusColor: '#EF4444',
    time: '10:28',
    dotColor: '#F97316',
  },
  {
    severity: 'High',
    title: 'Data Exfiltration',
    source: '192.0.2.77',
    detection: 'Behavioural',
    status: 'Investigating',
    statusBg: 'rgba(212, 175, 55, 0.15)',
    statusColor: '#D4AF37',
    time: '10:17',
    dotColor: '#F97316',
  },
  {
    severity: 'Medium',
    title: 'Suspicious DNS',
    source: 'evil-c2.org',
    detection: 'TF-IDF',
    status: 'Open',
    statusBg: 'rgba(239, 68, 68, 0.15)',
    statusColor: '#EF4444',
    time: '10:05',
    dotColor: '#D4AF37',
  },
];

export function RecentIncidentsTable({ incidents, isLoading = false }: RecentIncidentsTableProps) {
  const displayItems =
    incidents.length > 0
      ? incidents.slice(0, 4).map((inc) => ({
          severity: inc.severity || 'Medium',
          title: inc.title || 'Security Anomaly',
          source: (inc.affected_ips && inc.affected_ips[0]) || (inc.affected_sources && inc.affected_sources[0]) || '198.51.100.45',
          detection: 'Isolation Forest',
          status: inc.status === 'resolved' ? 'Resolved' : inc.status === 'investigating' ? 'Investigating' : 'Open',
          statusBg: inc.status === 'resolved' ? 'rgba(34, 197, 94, 0.15)' : inc.status === 'investigating' ? 'rgba(212, 175, 55, 0.15)' : 'rgba(239, 68, 68, 0.15)',
          statusColor: inc.status === 'resolved' ? '#22C55E' : inc.status === 'investigating' ? '#D4AF37' : '#EF4444',
          time: new Date(inc.created_at || Date.now()).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
          dotColor: inc.severity === 'CRITICAL' ? '#EF4444' : inc.severity === 'HIGH' ? '#F97316' : '#D4AF37',
        }))
      : SAMPLE_INCIDENTS;

  return (
    <div
      style={{
        backgroundColor: '#1C242B',
        border: '1px solid rgba(212, 175, 55, 0.14)',
        borderRadius: '14px',
        padding: '24px',
        boxShadow: '0 4px 16px rgba(0, 0, 0, 0.4)',
      }}
      className="space-y-4 font-sans h-full flex flex-col justify-between"
    >
      {/* Header */}
      <div className="flex items-center justify-between border-b border-[rgba(212,175,55,0.1)] pb-4">
        <div>
          <h2 className="text-base font-semibold text-[#FAF9F5] font-heading">
            Recent Incidents
          </h2>
          <p className="text-xs text-[#D1CBC0] font-subheading font-light mt-1">
            Latest security incidents requiring attention
          </p>
        </div>

        <Link
          href="/incidents"
          className="text-xs text-[#D4AF37] hover:text-[#E5C07B] flex items-center gap-1 font-subheading font-medium transition-colors"
        >
          <span>View All</span>
          <ArrowRight size={13} />
        </Link>
      </div>

      {/* Structured Table */}
      <div className="overflow-x-auto my-auto">
        <table className="w-full text-left text-xs font-sans">
          <thead>
            <tr className="text-[#8E877D] font-subheading uppercase text-[10px] tracking-wider border-b border-[rgba(212,175,55,0.08)]">
              <th className="pb-2.5 font-medium">Severity</th>
              <th className="pb-2.5 font-medium">Incident</th>
              <th className="pb-2.5 font-medium">Source</th>
              <th className="pb-2.5 font-medium">Detection</th>
              <th className="pb-2.5 font-medium">Status</th>
              <th className="pb-2.5 font-medium text-right">Time</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-[rgba(212,175,55,0.06)] text-[11px]">
            {displayItems.map((item, idx) => (
              <tr key={idx} className="hover:bg-white/[0.02] transition-colors">
                <td className="py-2.5 whitespace-nowrap">
                  <span className="flex items-center gap-1.5 font-subheading font-medium text-[#FAF9F5]">
                    <span
                      className="w-2 h-2 rounded-full"
                      style={{ backgroundColor: item.dotColor }}
                    />
                    {item.severity}
                  </span>
                </td>
                <td className="py-2.5 font-subheading font-medium text-[#FAF9F5] whitespace-nowrap">
                  {item.title}
                </td>
                <td className="py-2.5 font-mono text-[#D1CBC0] whitespace-nowrap">
                  {item.source}
                </td>
                <td className="py-2.5 font-subheading text-[#D1CBC0] whitespace-nowrap">
                  {item.detection}
                </td>
                <td className="py-2.5 whitespace-nowrap">
                  <span
                    style={{
                      backgroundColor: item.statusBg,
                      color: item.statusColor,
                    }}
                    className="px-2 py-0.5 rounded text-[10px] font-semibold"
                  >
                    {item.status}
                  </span>
                </td>
                <td className="py-2.5 font-mono text-[#8E877D] text-right whitespace-nowrap">
                  {item.time}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
