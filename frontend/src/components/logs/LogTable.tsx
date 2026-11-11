'use client';

import React, { useState } from 'react';
import {
  Search,
  ChevronLeft,
  ChevronRight,
  Eye,
  ShieldAlert,
} from 'lucide-react';
import { Badge } from '@/components/ui/Badge';
import { Button } from '@/components/ui/Button';
import { LogEntry } from '@/types';
import { formatDate } from '@/lib/utils';

interface LogTableProps {
  entries: LogEntry[];
  total: number;
  currentPage: number;
  pageSize: number;
  onPageChange: (page: number) => void;
  onLevelFilter: (level: string) => void;
  onSearchChange: (keyword: string) => void;
  onSelectLog: (log: LogEntry) => void;
  selectedLogLevel?: string;
  isLoading?: boolean;
}

const LOG_LEVELS: Array<{ label: string; value: string }> = [
  { label: 'ALL', value: '' },
  { label: 'CRITICAL', value: 'CRITICAL' },
  { label: 'ERROR', value: 'ERROR' },
  { label: 'WARNING', value: 'WARNING' },
  { label: 'INFO', value: 'INFO' },
  { label: 'DEBUG', value: 'DEBUG' },
];

export function LogTable({
  entries,
  total,
  currentPage,
  pageSize,
  onPageChange,
  onLevelFilter,
  onSearchChange,
  onSelectLog,
  selectedLogLevel = '',
  isLoading = false,
}: LogTableProps) {
  const [searchTerm, setSearchTerm] = useState('');
  const totalPages = Math.ceil(total / pageSize) || 1;

  const handleSearchSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    onSearchChange(searchTerm);
  };

  return (
    <div
      className="rounded-xl overflow-hidden flex flex-col font-sans"
      style={{
        backgroundColor: '#0C1119',
        border: '1px solid rgba(255, 255, 255, 0.08)',
        boxShadow: '0 4px 16px rgba(0, 0, 0, 0.35)',
      }}
    >
      {/* 1. Filter & Search Controls */}
      <div className="p-4 border-b border-white/[0.06] flex flex-wrap items-center justify-between gap-3 bg-[#080C12]">
        {/* Severity Tabs */}
        <div className="flex items-center gap-1.5 overflow-x-auto pb-1 sm:pb-0">
          {LOG_LEVELS.map((lvl) => (
            <button
              key={lvl.label}
              onClick={() => onLevelFilter(lvl.value)}
              className={`px-3 py-1.5 rounded-lg text-xs font-medium transition-all cursor-pointer ${
                selectedLogLevel === lvl.value
                  ? 'bg-[#3B82F6] text-white shadow-sm'
                  : 'bg-white/[0.03] text-[#A7B1C0] hover:text-[#F5F7FA] hover:bg-white/[0.06]'
              }`}
            >
              {lvl.label}
            </button>
          ))}
        </div>

        {/* Search Bar */}
        <form onSubmit={handleSearchSubmit} className="flex items-center gap-2">
          <div className="relative">
            <Search className="absolute left-3 top-2.5 h-3.5 w-3.5 text-[#687589]" />
            <input
              type="text"
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              placeholder="Search message, IP, host..."
              className="pl-9 pr-3 py-1.5 rounded-lg bg-[#0C1119] border border-white/[0.08] text-xs text-[#F5F7FA] placeholder-[#687589] focus:outline-none focus:border-[#3B82F6] w-56 md:w-64 transition-colors font-sans"
            />
          </div>
          <Button type="submit" variant="secondary" size="sm">
            Filter
          </Button>
        </form>
      </div>

      {/* 2. Structured Event Table */}
      <div className="overflow-x-auto">
        <table className="w-full text-left text-xs border-collapse">
          <thead>
            <tr className="border-b border-white/[0.06] text-[#A7B1C0] bg-[#080C12]/50 font-medium">
              <th className="py-3 px-4 w-14">#</th>
              <th className="py-3 px-4 w-28">Severity</th>
              <th className="py-3 px-4 w-44">Timestamp</th>
              <th className="py-3 px-4 w-36 hidden md:table-cell">Source / IP</th>
              <th className="py-3 px-4">Log Message</th>
              <th className="py-3 px-4 w-20 text-right">Inspect</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-white/[0.04]">
            {isLoading ? (
              Array.from({ length: 6 }).map((_, i) => (
                <tr key={i} className="animate-pulse">
                  <td colSpan={6} className="py-3.5 px-4">
                    <div className="h-4 bg-white/[0.04] rounded w-full" />
                  </td>
                </tr>
              ))
            ) : entries.length === 0 ? (
              <tr>
                <td colSpan={6} className="py-12 text-center text-[#687589]">
                  No matching log events found in this session.
                </td>
              </tr>
            ) : (
              entries.map((entry) => {
                const isCrit = entry.level === 'CRITICAL' || entry.level === 'ERROR';

                return (
                  <tr
                    key={entry.id}
                    onClick={() => onSelectLog(entry)}
                    className={`hover:bg-white/[0.02] cursor-pointer transition-colors group ${
                      entry.is_anomaly ? 'bg-amber-500/[0.03]' : ''
                    }`}
                  >
                    {/* Line Index */}
                    <td className="py-3 px-4 font-mono text-[11px] text-[#687589]">
                      {entry.line_number}
                    </td>

                    {/* Level Badge */}
                    <td className="py-3 px-4">
                      <div className="flex items-center gap-1.5">
                        <Badge variant={entry.level} size="sm">
                          {entry.level}
                        </Badge>
                        {entry.is_anomaly && (
                          <span title="Anomaly Detected">
                            <ShieldAlert size={13} className="text-[#F59E0B]" />
                          </span>
                        )}
                      </div>
                    </td>

                    {/* Timestamp */}
                    <td className="py-3 px-4 font-mono text-[11px] text-[#A7B1C0] whitespace-nowrap">
                      {formatDate(entry.timestamp)}
                    </td>

                    {/* Host / Source IP */}
                    <td className="py-3 px-4 font-mono text-[11px] text-[#F5F7FA] hidden md:table-cell">
                      {entry.source_ip || entry.host || entry.source || '127.0.0.1'}
                    </td>

                    {/* Message */}
                    <td className="py-3 px-4">
                      <div className="font-mono text-[11px] text-slate-200 truncate max-w-xl group-hover:text-white transition-colors">
                        {entry.message}
                      </div>
                    </td>

                    {/* Inspect Link */}
                    <td className="py-3 px-4 text-right">
                      <button
                        onClick={(e) => {
                          e.stopPropagation();
                          onSelectLog(entry);
                        }}
                        className="p-1 rounded text-[#687589] hover:text-[#3B82F6] hover:bg-white/[0.06] transition-colors"
                      >
                        <Eye size={14} />
                      </button>
                    </td>
                  </tr>
                );
              })
            )}
          </tbody>
        </table>
      </div>

      {/* 3. Pagination Footer */}
      <div className="p-4 border-t border-white/[0.06] flex items-center justify-between text-xs text-[#A7B1C0] bg-[#080C12]">
        <div>
          Showing {(currentPage - 1) * pageSize + 1} to{' '}
          {Math.min(currentPage * pageSize, total)} of {total.toLocaleString()} events
        </div>

        <div className="flex items-center gap-2">
          <Button
            variant="secondary"
            size="sm"
            disabled={currentPage <= 1}
            onClick={() => onPageChange(currentPage - 1)}
          >
            <ChevronLeft size={13} className="mr-1" />
            Prev
          </Button>

          <span className="font-mono text-xs px-2 text-[#F5F7FA]">
            {currentPage} / {totalPages}
          </span>

          <Button
            variant="secondary"
            size="sm"
            disabled={currentPage >= totalPages}
            onClick={() => onPageChange(currentPage + 1)}
          >
            Next
            <ChevronRight size={13} className="ml-1" />
          </Button>
        </div>
      </div>
    </div>
  );
}
