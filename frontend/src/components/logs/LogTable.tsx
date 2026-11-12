'use client';

import React, { useState } from 'react';
import {
  Search,
  ChevronLeft,
  ChevronRight,
  Eye,
  ShieldAlert,
  X,
  FileCode2,
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

const LOG_LEVELS: Array<{ label: string; value: string; color?: string }> = [
  { label: 'ALL', value: '' },
  { label: 'CRITICAL', value: 'CRITICAL', color: '#EF4444' },
  { label: 'ERROR', value: 'ERROR', color: '#F87171' },
  { label: 'WARNING', value: 'WARNING', color: '#F59E0B' },
  { label: 'INFO', value: 'INFO', color: '#38BDF8' },
  { label: 'DEBUG', value: 'DEBUG', color: '#94A3B8' },
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
  const totalPages = Math.max(1, Math.ceil(total / pageSize));

  const handleSearchSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    onSearchChange(searchTerm);
  };

  const handleClearSearch = () => {
    setSearchTerm('');
    onSearchChange('');
  };

  const startEntryIndex = total > 0 ? (currentPage - 1) * pageSize + 1 : 0;
  const endEntryIndex = Math.min(currentPage * pageSize, total);

  return (
    <div
      className="rounded-xl overflow-hidden flex flex-col font-sans"
      style={{
        backgroundColor: '#0F141D',
        border: '1px solid rgba(255, 255, 255, 0.07)',
        boxShadow: '0 4px 16px rgba(0, 0, 0, 0.25)',
      }}
    >
      {/* ── 1. Disciplined Top Filter & Search Controls ───────────────────────── */}
      <div className="p-4 sm:p-5 border-b border-white/[0.07] bg-[#0B0E14] flex flex-col lg:flex-row items-stretch lg:items-center justify-between gap-4">
        {/* Severity Tabs with clean pill styling */}
        <div className="flex items-center gap-1.5 overflow-x-auto pb-1 sm:pb-0 scrollbar-none">
          <span className="text-[11px] font-mono uppercase tracking-wider text-[#64748B] mr-1 hidden sm:inline-block">
            Level:
          </span>
          {LOG_LEVELS.map((lvl) => {
            const isActive = selectedLogLevel === lvl.value;
            return (
              <button
                key={lvl.label}
                type="button"
                onClick={() => onLevelFilter(lvl.value)}
                className={`px-3 py-1.5 rounded-lg text-xs font-mono font-medium transition-all shrink-0 cursor-pointer flex items-center gap-1.5 ${
                  isActive
                    ? 'bg-white/10 text-white border border-white/30 shadow-xs'
                    : 'bg-white/[0.02] text-[#94A3B8] border border-white/[0.05] hover:text-white hover:bg-white/[0.05]'
                }`}
              >
                {lvl.color && (
                  <span
                    className="w-1.5 h-1.5 rounded-full"
                    style={{ backgroundColor: lvl.color }}
                  />
                )}
                {lvl.label}
              </button>
            );
          })}
        </div>

        {/* Search Bar Form with clear submit button */}
        <form onSubmit={handleSearchSubmit} className="flex items-center gap-2.5">
          <div className="relative flex-1 sm:w-72">
            <Search className="absolute left-3 top-2.5 h-3.5 w-3.5 text-[#64748B]" />
            <input
              type="text"
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              placeholder="Search message, host, IP..."
              className="w-full pl-9 pr-8 py-1.5 rounded-lg bg-[#080B0F] border border-white/10 text-xs text-white placeholder-[#64748B] focus:outline-none focus:border-white/30 transition-colors font-sans"
            />
            {searchTerm && (
              <button
                type="button"
                onClick={handleClearSearch}
                className="absolute right-2.5 top-2 text-[#64748B] hover:text-white p-0.5 rounded cursor-pointer"
              >
                <X size={12} />
              </button>
            )}
          </div>
          <Button
            type="submit"
            variant="secondary"
            size="sm"
            className="shrink-0"
          >
            Filter
          </Button>
        </form>
      </div>

      {/* ── 2. Structured Event Table (Strict Bounds, No Overlap) ─────────────── */}
      <div className="overflow-x-auto">
        <table className="w-full text-left text-xs border-collapse">
          <thead>
            <tr className="border-b border-white/[0.07] text-[#94A3B8] bg-[#090D13] font-mono text-[11px] uppercase tracking-wider">
              <th className="py-3.5 px-4 w-16 text-center">#</th>
              <th className="py-3.5 px-4 w-32">Severity</th>
              <th className="py-3.5 px-4 w-44">Timestamp</th>
              <th className="py-3.5 px-4 w-40 hidden md:table-cell">Source / IP</th>
              <th className="py-3.5 px-4">Log Message</th>
              <th className="py-3.5 px-4 w-20 text-right">Inspect</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-white/[0.04]">
            {isLoading ? (
              Array.from({ length: 6 }).map((_, i) => (
                <tr key={i} className="animate-pulse">
                  <td colSpan={6} className="py-4 px-4">
                    <div className="h-4 bg-white/[0.04] rounded-md w-full" />
                  </td>
                </tr>
              ))
            ) : entries.length === 0 ? (
              <tr>
                <td colSpan={6} className="py-16 text-center">
                  <div className="max-w-md mx-auto flex flex-col items-center justify-center space-y-2.5 text-center">
                    <div className="w-10 h-10 rounded-xl bg-white/[0.03] border border-white/[0.07] flex items-center justify-center text-[#64748B]">
                      <FileCode2 size={20} />
                    </div>
                    <p className="text-sm font-medium text-slate-200">
                      No matching log events found
                    </p>
                    <p className="text-xs text-[#64748B] max-w-xs leading-relaxed">
                      {selectedLogLevel || searchTerm
                        ? 'Try clearing the active filter or keyword search to view available telemetry logs.'
                        : 'No log events have been recorded in this session yet. Upload or stream logs to begin.'}
                    </p>
                    {(selectedLogLevel || searchTerm) && (
                      <div className="pt-2">
                        <Button
                          variant="secondary"
                          size="sm"
                          onClick={() => {
                            onLevelFilter('');
                            handleClearSearch();
                          }}
                        >
                          Clear All Filters
                        </Button>
                      </div>
                    )}
                  </div>
                </td>
              </tr>
            ) : (
              entries.map((entry) => {
                return (
                  <tr
                    key={entry.id}
                    onClick={() => onSelectLog(entry)}
                    className={`hover:bg-white/[0.025] cursor-pointer transition-colors group ${
                      entry.is_anomaly ? 'bg-amber-500/[0.03]' : ''
                    }`}
                  >
                    {/* Line Index */}
                    <td className="py-3 px-4 font-mono text-[11px] text-[#64748B] text-center">
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
                    <td className="py-3 px-4 font-mono text-[11px] text-[#94A3B8] whitespace-nowrap">
                      {formatDate(entry.timestamp)}
                    </td>

                    {/* Host / Source IP */}
                    <td className="py-3 px-4 font-mono text-[11px] text-slate-300 hidden md:table-cell">
                      {entry.source_ip || entry.host || entry.source || '127.0.0.1'}
                    </td>

                    {/* Message */}
                    <td className="py-3 px-4">
                      <div className="font-mono text-[11px] text-slate-300 truncate max-w-xl group-hover:text-white transition-colors">
                        {entry.message}
                      </div>
                    </td>

                    {/* Inspect Link */}
                    <td className="py-3 px-4 text-right">
                      <button
                        type="button"
                        onClick={(e) => {
                          e.stopPropagation();
                          onSelectLog(entry);
                        }}
                        className="p-1.5 rounded-lg text-[#64748B] hover:text-white hover:bg-white/[0.06] transition-colors cursor-pointer"
                        title="Inspect event details"
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

      {/* ── 3. Clean Disciplined Pagination Footer ────────────────────────────── */}
      <div className="p-4 sm:px-6 border-t border-white/[0.07] flex flex-col sm:flex-row items-center justify-between gap-3 text-xs text-[#94A3B8] bg-[#090D13]">
        <div>
          Showing{' '}
          <span className="font-mono text-white font-medium">
            {startEntryIndex}
          </span>{' '}
          to{' '}
          <span className="font-mono text-white font-medium">
            {endEntryIndex}
          </span>{' '}
          of{' '}
          <span className="font-mono text-white font-medium">
            {total.toLocaleString()}
          </span>{' '}
          events
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

          <span className="font-mono text-xs px-2.5 text-white">
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
