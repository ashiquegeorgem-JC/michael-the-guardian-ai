'use client';

import React, { useState } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import {
  CheckCircle2, AlertOctagon, Shield, Clock, ArrowRight,
  History, User, ChevronDown, ChevronUp, AlertCircle,
} from 'lucide-react';
import { updateIOCStatus } from '@/lib/api';
import { Button } from '@/components/ui/Button';
import type { IOC, IOCStatus } from '@/types';
import { formatDateTime } from '@/lib/utils';

const STATUS_CONFIG: Record<IOCStatus, { label: string; color: string; bg: string; icon: React.ComponentType<{ size?: number; color?: string }> }> = {
  EXTRACTED:      { label: 'Extracted',          color: '#94A3B8', bg: 'rgba(148,163,184,0.12)', icon: Clock },
  UNDER_REVIEW:   { label: 'Under Review',        color: '#EAB308', bg: 'rgba(234,179,8,0.12)',   icon: AlertOctagon },
  CONFIRMED:      { label: 'Confirmed Indicator', color: '#3B82F6', bg: 'rgba(59,130,246,0.12)',  icon: CheckCircle2 },
  FALSE_POSITIVE: { label: 'False Positive',       color: '#10B981', bg: 'rgba(16,185,129,0.12)', icon: Shield },
};

const ALLOWED_TRANSITIONS: Record<IOCStatus, IOCStatus[]> = {
  EXTRACTED:      ['UNDER_REVIEW', 'CONFIRMED', 'FALSE_POSITIVE'],
  UNDER_REVIEW:   ['CONFIRMED', 'FALSE_POSITIVE', 'EXTRACTED'],
  CONFIRMED:      ['UNDER_REVIEW', 'FALSE_POSITIVE'],
  FALSE_POSITIVE: ['UNDER_REVIEW', 'CONFIRMED'],
};

interface Props {
  ioc: IOC;
  onStatusUpdated: (ioc: IOC) => void;
}

export function IOCStatusManager({ ioc, onStatusUpdated }: Props) {
  const [targetStatus, setTargetStatus] = useState<IOCStatus | ''>('');
  const [reason, setReason] = useState('');
  const [analystName, setAnalystName] = useState('');
  const [analystNote, setAnalystNote] = useState('');
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [success, setSuccess] = useState<string | null>(null);
  const [showHistory, setShowHistory] = useState(false);

  const current = ioc.status;
  const cfg = STATUS_CONFIG[current] || STATUS_CONFIG.EXTRACTED;
  const CurrentIcon = cfg.icon;
  const allowed = ALLOWED_TRANSITIONS[current] || [];
  const history = ioc.status_history || [];

  const handleSubmit = async () => {
    if (!targetStatus) { setError('Please select a target status.'); return; }
    if (reason.trim().length < 5) { setError('Reason must be at least 5 characters long.'); return; }
    setSubmitting(true);
    setError(null);
    setSuccess(null);
    try {
      const updated = await updateIOCStatus(ioc.id, {
        status: targetStatus,
        reason: reason.trim(),
        changed_by: analystName.trim() || undefined,
        analyst_note: analystNote.trim() || undefined,
      });
      onStatusUpdated(updated);
      setSuccess(`Status transitioned to ${STATUS_CONFIG[targetStatus]?.label}`);
      setReason('');
      setAnalystNote('');
      setTargetStatus('');
    } catch (e: unknown) {
      setError((e as Error).message || 'Status update rejected by backend');
    } finally {
      setSubmitting(false);
    }
  };

  const textareaStyle: React.CSSProperties = {
    width: '100%',
    background: '#0A0E1A',
    border: '1px solid #1E2D4A',
    borderRadius: 8,
    color: 'var(--text-primary)',
    padding: '9px 12px',
    fontSize: 12,
    fontFamily: 'var(--font-sans)',
    outline: 'none',
    resize: 'vertical' as const,
    minHeight: 65,
    marginBottom: 10,
  };

  const inputStyle: React.CSSProperties = {
    width: '100%',
    background: '#0A0E1A',
    border: '1px solid #1E2D4A',
    borderRadius: 8,
    color: 'var(--text-primary)',
    padding: '9px 12px',
    fontSize: 12,
    outline: 'none',
    marginBottom: 10,
  };

  return (
    <div>
      {/* Distinction banner */}
      <div style={{ background: 'rgba(59,130,246,0.06)', border: '1px solid rgba(59,130,246,0.2)', borderRadius: 8, padding: '10px 14px', marginBottom: 16 }}>
        <div style={{ fontSize: 11, color: '#93C5FD', fontWeight: 600, marginBottom: 3 }}>Analyst Review Status vs. Validation Status</div>
        <div style={{ fontSize: 11, color: 'var(--text-muted)', lineHeight: 1.5 }}>
          <strong style={{ color: 'var(--text-secondary)' }}>Review Status</strong> records human triage decisions (EXTRACTED, UNDER_REVIEW, CONFIRMED, FALSE_POSITIVE).<br/>
          <strong style={{ color: 'var(--text-secondary)' }}>Validation Status</strong> records machine-verified syntax correctness (VALID, INVALID, SUSPICIOUS) and is preserved immutable.
        </div>
      </div>

      {/* Current status indicator */}
      <div style={{ display: 'flex', alignItems: 'center', gap: 10, padding: '12px 14px', background: cfg.bg, border: `1px solid ${cfg.color}40`, borderRadius: 10, marginBottom: 18 }}>
        <CurrentIcon size={18} color={cfg.color} />
        <div>
          <div style={{ fontSize: 10, color: 'var(--text-muted)', fontWeight: 600, letterSpacing: '0.07em', textTransform: 'uppercase' }}>Current Review Status</div>
          <div style={{ fontSize: 14, color: cfg.color, fontWeight: 700 }}>{cfg.label}</div>
        </div>
      </div>

      {allowed.length > 0 ? (
        <div>
          <div style={{ fontSize: 11, fontWeight: 700, color: 'var(--text-muted)', letterSpacing: '0.08em', textTransform: 'uppercase', marginBottom: 10 }}>Available Transitions</div>

          <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap', marginBottom: 16 }}>
            {allowed.map(s => {
              const c = STATUS_CONFIG[s];
              const TIcon = c.icon;
              return (
                <button
                  key={s}
                  onClick={() => setTargetStatus(s)}
                  style={{
                    display: 'flex', alignItems: 'center', gap: 6,
                    padding: '7px 12px',
                    background: targetStatus === s ? c.bg : '#0A0E1A',
                    border: `1px solid ${targetStatus === s ? c.color : '#1E2D4A'}`,
                    borderRadius: 8,
                    color: targetStatus === s ? c.color : 'var(--text-muted)',
                    fontSize: 12, fontWeight: targetStatus === s ? 700 : 400,
                    cursor: 'pointer', transition: 'all 0.15s',
                  }}
                >
                  <TIcon size={12} color={c.color} />
                  {c.label}
                </button>
              );
            })}
          </div>

          {targetStatus && (
            <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 14, fontSize: 12, color: 'var(--text-muted)' }}>
              <span style={{ color: cfg.color }}>{cfg.label}</span>
              <ArrowRight size={13} />
              <span style={{ color: STATUS_CONFIG[targetStatus]?.color, fontWeight: 600 }}>{STATUS_CONFIG[targetStatus]?.label}</span>
            </div>
          )}

          <label style={{ fontSize: 11, fontWeight: 700, color: 'var(--text-muted)', display: 'block', marginBottom: 6 }}>
            Justification Reason <span style={{ color: '#EF4444' }}>*</span> (min 5 chars)
          </label>
          <textarea
            value={reason}
            onChange={e => setReason(e.target.value)}
            placeholder="Document reason for status transition…"
            style={textareaStyle}
          />

          <label style={{ fontSize: 11, fontWeight: 700, color: 'var(--text-muted)', display: 'block', marginBottom: 6 }}>Analyst Note (optional)</label>
          <textarea
            value={analystNote}
            onChange={e => setAnalystNote(e.target.value)}
            placeholder="Investigation findings or notes…"
            style={{ ...textareaStyle, minHeight: 48 }}
          />

          <label style={{ fontSize: 11, fontWeight: 700, color: 'var(--text-muted)', display: 'block', marginBottom: 6 }}>
            <User size={11} style={{ display: 'inline', marginRight: 4 }} />Analyst Identifier (optional)
          </label>
          <input
            value={analystName}
            onChange={e => setAnalystName(e.target.value)}
            placeholder="e.g. analyst-secops"
            style={inputStyle}
          />

          <AnimatePresence>
            {error && (
              <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }}
                style={{ display: 'flex', alignItems: 'center', gap: 6, padding: '8px 12px', background: 'rgba(239,68,68,0.08)', border: '1px solid rgba(239,68,68,0.3)', borderRadius: 8, marginBottom: 10, fontSize: 12, color: '#EF4444' }}>
                <AlertCircle size={13} />
                {error}
              </motion.div>
            )}
            {success && (
              <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }}
                style={{ display: 'flex', alignItems: 'center', gap: 6, padding: '8px 12px', background: 'rgba(16,185,129,0.08)', border: '1px solid rgba(16,185,129,0.3)', borderRadius: 8, marginBottom: 10, fontSize: 12, color: '#10B981' }}>
                <CheckCircle2 size={13} />
                {success}
              </motion.div>
            )}
          </AnimatePresence>

          <Button onClick={handleSubmit} isLoading={submitting} disabled={!targetStatus || reason.trim().length < 5}>
            Commit Status Transition
          </Button>
        </div>
      ) : (
        <div style={{ fontSize: 12, color: 'var(--text-muted)', padding: '12px', background: '#0A0E1A', borderRadius: 8 }}>
          No further transitions permitted from this terminal state.
        </div>
      )}

      {/* History audit trail */}
      {history.length > 0 && (
        <div style={{ marginTop: 24 }}>
          <button
            onClick={() => setShowHistory(v => !v)}
            style={{ display: 'flex', alignItems: 'center', gap: 6, fontSize: 11, fontWeight: 700, letterSpacing: '0.08em', textTransform: 'uppercase', color: 'var(--text-muted)', background: 'transparent', border: 'none', cursor: 'pointer', marginBottom: 8 }}
          >
            <History size={12} />
            Status History ({history.length})
            {showHistory ? <ChevronUp size={12} /> : <ChevronDown size={12} />}
          </button>
          <AnimatePresence>
            {showHistory && (
              <motion.div initial={{ opacity: 0, height: 0 }} animate={{ opacity: 1, height: 'auto' }} exit={{ opacity: 0, height: 0 }}>
                {[...history].reverse().map((h, i) => {
                  const fromCfg = STATUS_CONFIG[h.previous_status as IOCStatus];
                  const toCfg = STATUS_CONFIG[h.new_status as IOCStatus];
                  return (
                    <div key={i} style={{ padding: '10px 12px', background: '#060A14', border: '1px solid #1A2744', borderRadius: 8, marginBottom: 6 }}>
                      <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 4 }}>
                        <span style={{ fontSize: 11, color: fromCfg?.color }}>{fromCfg?.label}</span>
                        <ArrowRight size={11} color="var(--text-muted)" />
                        <span style={{ fontSize: 11, color: toCfg?.color, fontWeight: 600 }}>{toCfg?.label}</span>
                        {h.changed_by && <span style={{ fontSize: 10, color: 'var(--text-muted)', marginLeft: 'auto' }}>by {h.changed_by}</span>}
                      </div>
                      <div style={{ fontSize: 11, color: 'var(--text-secondary)', marginBottom: 3 }}>{h.reason}</div>
                      <div style={{ fontSize: 10, color: 'var(--text-muted)' }}>{formatDateTime(h.changed_at)}</div>
                    </div>
                  );
                })}
              </motion.div>
            )}
          </AnimatePresence>
        </div>
      )}
    </div>
  );
}

