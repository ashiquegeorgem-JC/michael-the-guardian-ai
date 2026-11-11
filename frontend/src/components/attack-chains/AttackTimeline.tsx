'use client';

import { motion } from 'framer-motion';
import type { ChainLinkEvent, AttackStage } from '@/types';
import { CheckCircle, AlertCircle, Clock, MapPin, CheckSquare } from 'lucide-react';

const STAGE_COLORS: Record<string, string> = {
  'Reconnaissance':      '#06B6D4',
  'Initial Access':      '#F97316',
  'Credential Attack':   '#EF4444',
  'Privilege Escalation':'#DC2626',
  'Execution':           '#B91C1C',
  'Persistence':         '#7C3AED',
  'Command and Control': '#9333EA',
  'Lateral Movement':    '#8B5CF6',
  'Data Access':         '#3B82F6',
  'Exfiltration':        '#EC4899',
  'Unknown':             '#475569',
};

function formatTs(ts: string | null) {
  if (!ts) return 'Timestamp N/A';
  try {
    return new Date(ts).toLocaleString('en-GB', {
      year: 'numeric', month: 'short', day: '2-digit',
      hour: '2-digit', minute: '2-digit', second: '2-digit',
    });
  } catch {
    return ts;
  }
}

interface AttackTimelineProps {
  events: ChainLinkEvent[];
  onConfirmEvent?: (event: ChainLinkEvent) => void;
}

export function AttackTimeline({ events, onConfirmEvent }: AttackTimelineProps) {
  if (events.length === 0) {
    return (
      <div style={{ textAlign: 'center', color: '#475569', padding: 40, fontSize: 14 }}>
        No timeline events available.
      </div>
    );
  }

  return (
    <div style={{ position: 'relative', paddingLeft: 32 }}>
      {/* Vertical line */}
      <div style={{
        position: 'absolute',
        left: 12,
        top: 0,
        bottom: 0,
        width: 2,
        background: 'linear-gradient(180deg, rgba(59,130,246,0.6) 0%, rgba(59,130,246,0.05) 100%)',
      }} />

      {events.map((ev, idx) => {
        const stageColor = STAGE_COLORS[ev.stage] || '#475569';
        return (
          <motion.div
            key={ev.id}
            initial={{ opacity: 0, x: -16 }}
            animate={{ opacity: 1, x: 0 }}
            transition={{ delay: idx * 0.04, duration: 0.3 }}
            style={{ position: 'relative', marginBottom: 20 }}
          >
            {/* Timeline dot */}
            <div style={{
              position: 'absolute',
              left: -26,
              top: 12,
              width: 12,
              height: 12,
              borderRadius: '50%',
              background: stageColor,
              border: '2px solid rgba(10,14,26,0.9)',
              boxShadow: `0 0 8px ${stageColor}80`,
            }} />

            {/* Event card */}
            <div style={{
              background: 'rgba(15,23,42,0.8)',
              border: `1px solid ${ev.is_confirmed ? stageColor + '40' : 'rgba(71,85,105,0.3)'}`,
              borderRadius: 10,
              padding: 14,
              marginLeft: 8,
            }}>
              {/* Header */}
              <div style={{ display: 'flex', justifyContent: 'space-between', flexWrap: 'wrap', gap: 6, marginBottom: 8 }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                  <span style={{
                    background: stageColor + '20',
                    color: stageColor,
                    fontSize: 10,
                    fontWeight: 700,
                    padding: '2px 8px',
                    borderRadius: 4,
                    textTransform: 'uppercase',
                    letterSpacing: 0.5,
                  }}>{ev.stage}</span>

                  {ev.is_confirmed ? (
                    <CheckCircle size={12} color="#10B981" />
                  ) : (
                    <AlertCircle size={12} color="#F59E0B" />
                  )}
                  <span style={{ color: ev.is_confirmed ? '#10B981' : '#F59E0B', fontSize: 10 }}>
                    {ev.is_confirmed ? 'Confirmed' : 'Suspected'}
                  </span>
                  <span style={{ color: '#64748B', fontSize: 10 }}>
                    {Math.round(ev.stage_confidence * 100)}% conf.
                  </span>

                  {onConfirmEvent && (
                    <button
                      onClick={() => onConfirmEvent(ev)}
                      style={{
                        background: 'rgba(59,130,246,0.1)',
                        border: '1px solid rgba(59,130,246,0.3)',
                        borderRadius: 4,
                        color: '#60A5FA',
                        fontSize: 9,
                        padding: '1px 6px',
                        cursor: 'pointer',
                        display: 'flex',
                        alignItems: 'center',
                        gap: 3,
                      }}
                      title="Analyst Confirmation & Review"
                    >
                      <CheckSquare size={9} />
                      Verify
                    </button>
                  )}
                </div>
                <div style={{ display: 'flex', alignItems: 'center', gap: 4, color: '#64748B', fontSize: 10 }}>
                  <Clock size={10} />
                  <span>{formatTs(ev.timestamp)}</span>
                  {ev.line_number && <span style={{ color: '#334155' }}>· Line {ev.line_number}</span>}
                </div>
              </div>

              {/* Message */}
              <p style={{ color: '#CBD5E1', fontSize: 12, marginBottom: 6, lineHeight: 1.5 }}>
                {ev.message}
              </p>

              {/* Entities */}
              <div style={{ display: 'flex', flexWrap: 'wrap', gap: 8, marginBottom: 8 }}>
                {ev.source_ip && (
                  <div style={{ display: 'flex', alignItems: 'center', gap: 4 }}>
                    <MapPin size={10} color="#EF4444" />
                    <span style={{ color: '#EF4444', fontSize: 10, fontFamily: 'monospace' }}>{ev.source_ip}</span>
                  </div>
                )}
                {ev.destination_ip && (
                  <div style={{ display: 'flex', alignItems: 'center', gap: 4 }}>
                    <span style={{ color: '#64748B', fontSize: 10 }}>→</span>
                    <span style={{ color: '#F97316', fontSize: 10, fontFamily: 'monospace' }}>{ev.destination_ip}</span>
                  </div>
                )}
                {ev.user && (
                  <span style={{ color: '#8B5CF6', fontSize: 10, fontFamily: 'monospace' }}>👤 {ev.user}</span>
                )}
                {ev.process && (
                  <span style={{ color: '#06B6D4', fontSize: 10, fontFamily: 'monospace' }}>⚙ {ev.process}</span>
                )}
              </div>

              {/* Raw log */}
              <div style={{
                background: 'rgba(2,6,23,0.6)',
                borderRadius: 6,
                padding: '6px 10px',
                fontFamily: 'monospace',
                fontSize: 10,
                color: '#475569',
                whiteSpace: 'nowrap',
                overflow: 'hidden',
                textOverflow: 'ellipsis',
              }}>
                {ev.raw_log.trim()}
              </div>

              {/* Rationale */}
              <p style={{ color: '#334155', fontSize: 10, marginTop: 6, fontStyle: 'italic' }}>
                {ev.correlation_reason}
              </p>
            </div>
          </motion.div>
        );
      })}
    </div>
  );
}
