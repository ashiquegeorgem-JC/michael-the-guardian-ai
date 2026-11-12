'use client';

import React, { useState, useRef, useEffect } from 'react';
import { Terminal, Pause, Play, Filter } from 'lucide-react';
import { Badge } from '@/components/ui/Badge';
import { Button } from '@/components/ui/Button';

interface EventStreamProps {
  events: string[];
  connected: boolean;
}

export function EventStream({ events, connected }: EventStreamProps) {
  const [isPaused, setIsPaused] = useState(false);
  const [filter, setFilter] = useState('');
  const [frozenEvents, setFrozenEvents] = useState<string[]>([]);
  const [mounted, setMounted] = useState(false);
  const containerRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    setMounted(true);
  }, []);

  const activeEvents = isPaused ? frozenEvents : events;

  const handleTogglePause = () => {
    if (!isPaused) {
      setFrozenEvents([...events]);
    }
    setIsPaused(!isPaused);
  };

  const filtered = activeEvents.filter((e) =>
    filter ? e.toLowerCase().includes(filter.toLowerCase()) : true
  );

  return (
    <div
      style={{
        backgroundColor: '#11161E',
        border: '1px solid rgba(255, 255, 255, 0.08)',
        borderRadius: '16px',
        boxShadow: '0 4px 20px rgba(0, 0, 0, 0.35)',
      }}
      className="h-[500px] flex flex-col font-sans overflow-hidden"
    >
      {/* Header */}
      <div className="p-4 sm:p-5 border-b border-white/[0.07] flex items-center justify-between bg-[#0D1117]">
        <div className="flex items-center gap-3">
          <div className="w-8 h-8 rounded-lg bg-sky-500/10 border border-sky-500/25 flex items-center justify-center text-[#38BDF8]">
            <Terminal size={16} />
          </div>
          <div>
            <h3 className="text-sm font-heading font-semibold text-white tracking-wide">
              Real-Time Daemon Event Bus
            </h3>
            <p className="text-xs text-[#94A3B8] font-subheading">
              Low-latency WebSocket event ingestion stream
            </p>
          </div>
        </div>

        <div className="flex items-center gap-2">
          <Badge variant={connected ? 'success' : 'default'} dot size="sm">
            {connected ? 'BROADCAST ACTIVE' : 'RECONNECTING'}
          </Badge>
          <Button
            variant="secondary"
            size="sm"
            onClick={handleTogglePause}
            leftIcon={isPaused ? <Play size={13} /> : <Pause size={13} />}
          >
            {isPaused ? 'Resume' : 'Pause'}
          </Button>
        </div>
      </div>

      {/* Filter Bar */}
      <div className="px-4 py-2 border-b border-white/[0.04] bg-[#0C1119] flex items-center justify-between">
        <div className="flex items-center gap-2 w-full max-w-xs">
          <Filter size={12} className="text-[#687589]" />
          <input
            type="text"
            value={filter}
            onChange={(e) => setFilter(e.target.value)}
            placeholder="Filter event log..."
            className="w-full bg-transparent border-none text-xs text-[#F5F7FA] placeholder-[#687589] focus:outline-none font-sans"
          />
        </div>
        <span className="text-[10px] text-[#687589] font-mono">
          Buffer: {filtered.length} events
        </span>
      </div>

      {/* Event List */}
      <div
        ref={containerRef}
        className="flex-1 overflow-y-auto p-4 space-y-1.5 font-mono text-[11px] bg-[#05070B]"
      >
        {filtered.length === 0 ? (
          <div className="h-full flex items-center justify-center text-[#687589] text-xs font-sans">
            No events match the current filter or buffer is synchronizing...
          </div>
        ) : (
          filtered.map((evt, idx) => {
            const isCrit = evt.includes('CRITICAL');
            const isWarn = evt.includes('WARNING') || evt.includes('ANOMALY');
            const isErr = evt.includes('ERROR');

            return (
              <div
                key={idx}
                className="flex items-start gap-2.5 leading-relaxed hover:bg-white/[0.02] px-2 py-1 rounded transition-colors"
              >
                <span className="text-[#687589] select-none text-[10px] shrink-0 font-mono">
                  {mounted ? '00:00:00' : '00:00:00'}
                </span>

                <span
                  className={`text-[9px] px-1.5 py-0.2 rounded font-bold shrink-0 ${
                    isCrit
                      ? 'bg-rose-500/10 text-[#EF4444] border border-rose-500/25'
                      : isErr
                      ? 'bg-rose-500/10 text-[#EF4444] border border-rose-500/25'
                      : isWarn
                      ? 'bg-amber-500/10 text-[#F59E0B] border border-amber-500/25'
                      : 'bg-blue-500/10 text-[#3B82F6] border border-blue-500/25'
                  }`}
                >
                  {isCrit ? 'CRIT' : isErr ? 'ERR' : isWarn ? 'WARN' : 'INFO'}
                </span>

                <span
                  className={`break-all ${
                    isCrit ? 'text-[#EF4444] font-medium' : 'text-slate-300'
                  }`}
                >
                  {evt}
                </span>
              </div>
            );
          })
        )}
      </div>
    </div>
  );
}
