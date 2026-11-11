'use client';

import React, { useState } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import {
  ShieldAlert, ShieldCheck, AlertOctagon, CheckCircle2, AlertTriangle,
  History, ArrowRight, X, Check, Clock, User, FileText, ChevronDown, ChevronUp
} from 'lucide-react';
import { updateAttackChainStatus } from '@/lib/api';
import type { AttackChain, ChainStatus, ChainStatusHistory } from '@/types';

interface Props {
  chain: AttackChain;
  onStatusUpdated: (updatedChain: AttackChain) => void;
}

const STATUS_CONFIG: Record<ChainStatus, { label: string; color: string; bg: string; icon: any }> = {
  NEW:            { label: 'New Alert',        color: '#60A5FA', bg: 'rgba(59,130,246,0.14)', icon: ShieldAlert },
  INVESTIGATING:  { label: 'Investigating',    color: '#EAB308', bg: 'rgba(234,179,8,0.14)',  icon: AlertTriangle },
  CONFIRMED:      { label: 'Confirmed Attack', color: '#EF4444', bg: 'rgba(239,68,68,0.14)',  icon: AlertOctagon },
  FALSE_POSITIVE: { label: 'False Positive',   color: '#94A3B8', bg: 'rgba(148,163,184,0.14)',icon: ShieldCheck },
  RESOLVED:       { label: 'Resolved / Closed',color: '#10B981', bg: 'rgba(16,185,129,0.14)', icon: CheckCircle2 },
};

// State transitions matching backend VALID_STATUS_TRANSITIONS
const ALLOWED_TRANSITIONS: Record<ChainStatus, ChainStatus[]> = {
  NEW:            ['INVESTIGATING', 'FALSE_POSITIVE'],
  INVESTIGATING:  ['CONFIRMED', 'FALSE_POSITIVE', 'RESOLVED'],
  CONFIRMED:      ['RESOLVED', 'INVESTIGATING'],
  FALSE_POSITIVE: ['INVESTIGATING'],
  RESOLVED:       ['INVESTIGATING'],
};

export function ChainStatusManager({ chain, onStatusUpdated }: Props) {
  const [isModalOpen, setIsModalOpen] = useState(false);
  const [isHistoryOpen, setIsHistoryOpen] = useState(false);
  const [targetStatus, setTargetStatus] = useState<ChainStatus | ''>('');
  const [reason, setReason] = useState('');
  const [analystName, setAnalystName] = useState('Analyst');
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const currentStatus: ChainStatus = chain.status || 'NEW';
  const cfg = STATUS_CONFIG[currentStatus] || STATUS_CONFIG.NEW;
  const CurrentIcon = cfg.icon;
  const allowed = ALLOWED_TRANSITIONS[currentStatus] || [];

  const handleOpenModal = () => {
    setTargetStatus(allowed[0] || '');
    setReason('');
    setError(null);
    setIsModalOpen(true);
  };

  const handleConfirmUpdate = async () => {
    if (!targetStatus) return;
    if (reason.trim().length < 5) {
      setError('A justification reason of at least 5 characters is required.');
      return;
    }

    setSubmitting(true);
    setError(null);
    try {
      const updated = await updateAttackChainStatus(chain.id, {
        status: targetStatus as ChainStatus,
        reason: reason.trim(),
        changed_by: analystName.trim() || undefined,
      });
      onStatusUpdated(updated);
      setIsModalOpen(false);
    } catch (err: unknown) {
      const e = err as Error;
      setError(e.message || 'Status transition rejected');
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
      {/* Current Status Bar */}
      <div style={{
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'space-between',
        background: 'rgba(15,23,42,0.85)',
        border: `1px solid ${cfg.color}40`,
        borderRadius: 12,
        padding: '10px 16px',
        boxShadow: `0 0 16px ${cfg.color}10`,
      }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
          <div style={{
            background: cfg.bg,
            border: `1px solid ${cfg.color}50`,
            borderRadius: 8,
            padding: 6,
            display: 'flex',
          }}>
            <CurrentIcon size={16} color={cfg.color} />
          </div>
          <div>
            <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
              <span style={{ color: '#94A3B8', fontSize: 11, textTransform: 'uppercase', letterSpacing: 0.5 }}>
                Investigation Status:
              </span>
              <span style={{
                color: cfg.color,
                fontWeight: 700,
                fontSize: 12,
                textTransform: 'uppercase',
                letterSpacing: 0.5,
              }}>
                {cfg.label}
              </span>
            </div>
            {chain.analyst_note && (
              <p style={{ color: '#CBD5E1', fontSize: 11, margin: '2px 0 0', fontStyle: 'italic' }}>
                &ldquo;{chain.analyst_note}&rdquo;
              </p>
            )}
          </div>
        </div>

        <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
          {/* Change Status Action */}
          <button
            onClick={handleOpenModal}
            style={{
              background: 'linear-gradient(135deg, rgba(59,130,246,0.2), rgba(124,58,237,0.2))',
              border: '1px solid rgba(59,130,246,0.4)',
              color: '#60A5FA',
              borderRadius: 8,
              padding: '6px 14px',
              fontSize: 12,
              fontWeight: 600,
              cursor: 'pointer',
              display: 'flex',
              alignItems: 'center',
              gap: 6,
            }}
          >
            Update Status
          </button>

          {/* Audit History Toggle */}
          {chain.status_history && chain.status_history.length > 0 && (
            <button
              onClick={() => setIsHistoryOpen(v => !v)}
              style={{
                background: isHistoryOpen ? 'rgba(59,130,246,0.15)' : 'rgba(30,41,59,0.7)',
                border: '1px solid rgba(51,65,85,0.8)',
                color: '#94A3B8',
                borderRadius: 8,
                padding: '6px 10px',
                fontSize: 12,
                cursor: 'pointer',
                display: 'flex',
                alignItems: 'center',
                gap: 5,
              }}
              title="View Status History"
            >
              <History size={13} />
              <span>{chain.status_history.length}</span>
              {isHistoryOpen ? <ChevronUp size={12} /> : <ChevronDown size={12} />}
            </button>
          )}
        </div>
      </div>

      {/* History Drawer */}
      <AnimatePresence>
        {isHistoryOpen && chain.status_history && (
          <motion.div
            initial={{ opacity: 0, height: 0 }}
            animate={{ opacity: 1, height: 'auto' }}
            exit={{ opacity: 0, height: 0 }}
            style={{
              background: 'rgba(10,14,26,0.95)',
              border: '1px solid rgba(30,41,59,0.9)',
              borderRadius: 10,
              padding: 12,
              overflow: 'hidden',
            }}
          >
            <div style={{ display: 'flex', alignItems: 'center', gap: 6, marginBottom: 8, color: '#94A3B8', fontSize: 11, fontWeight: 600, textTransform: 'uppercase' }}>
              <History size={12} />
              Investigation Audit Trail
            </div>
            <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
              {chain.status_history.map((h, i) => (
                <div
                  key={i}
                  style={{
                    display: 'flex',
                    alignItems: 'flex-start',
                    justifyContent: 'space-between',
                    background: 'rgba(15,23,42,0.6)',
                    border: '1px solid rgba(30,41,59,0.6)',
                    borderRadius: 6,
                    padding: '6px 10px',
                    fontSize: 11,
                  }}
                >
                  <div>
                    <div style={{ display: 'flex', alignItems: 'center', gap: 6, marginBottom: 2 }}>
                      <span style={{ color: STATUS_CONFIG[h.previous_status]?.color || '#94A3B8', fontWeight: 600 }}>
                        {h.previous_status}
                      </span>
                      <ArrowRight size={10} color="#64748B" />
                      <span style={{ color: STATUS_CONFIG[h.new_status]?.color || '#94A3B8', fontWeight: 600 }}>
                        {h.new_status}
                      </span>
                      {h.changed_by && (
                        <span style={{ color: '#64748B' }}>by {h.changed_by}</span>
                      )}
                    </div>
                    <p style={{ color: '#CBD5E1', margin: 0, fontSize: 11 }}>{h.reason}</p>
                  </div>
                  <span style={{ color: '#475569', fontSize: 10, flexShrink: 0 }}>
                    {new Date(h.changed_at).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}
                  </span>
                </div>
              ))}
            </div>
          </motion.div>
        )}
      </AnimatePresence>

      {/* Status Update Modal */}
      <AnimatePresence>
        {isModalOpen && (
          <div style={{
            position: 'fixed',
            inset: 0,
            background: 'rgba(0,0,0,0.7)',
            backdropFilter: 'blur(4px)',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            zIndex: 100,
            padding: 20,
          }}>
            <motion.div
              initial={{ scale: 0.95, opacity: 0 }}
              animate={{ scale: 1, opacity: 1 }}
              exit={{ scale: 0.95, opacity: 0 }}
              style={{
                background: '#0F172A',
                border: '1px solid rgba(59,130,246,0.3)',
                borderRadius: 16,
                padding: 24,
                width: '100%',
                maxWidth: 480,
                boxShadow: '0 20px 50px rgba(0,0,0,0.6)',
              }}
            >
              {/* Modal Header */}
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 16 }}>
                <h3 style={{ color: '#F1F5F9', fontSize: 16, fontWeight: 700, margin: 0 }}>
                  Update Investigation Status
                </h3>
                <button
                  onClick={() => setIsModalOpen(false)}
                  style={{ background: 'none', border: 'none', color: '#64748B', cursor: 'pointer' }}
                >
                  <X size={16} />
                </button>
              </div>

              {/* Current -> Target Preview */}
              <div style={{
                display: 'flex',
                alignItems: 'center',
                gap: 12,
                background: 'rgba(15,23,42,0.9)',
                border: '1px solid rgba(30,41,59,0.9)',
                borderRadius: 10,
                padding: '10px 14px',
                marginBottom: 16,
              }}>
                <span style={{ color: cfg.color, fontSize: 12, fontWeight: 700 }}>{currentStatus}</span>
                <ArrowRight size={14} color="#64748B" />
                <span style={{ color: targetStatus ? (STATUS_CONFIG[targetStatus]?.color || '#3B82F6') : '#64748B', fontSize: 12, fontWeight: 700 }}>
                  {targetStatus || 'Select below'}
                </span>
              </div>

              {/* Target Status Selection */}
              <div style={{ marginBottom: 16 }}>
                <label style={{ color: '#94A3B8', fontSize: 11, fontWeight: 600, display: 'block', marginBottom: 6 }}>
                  Select Next Status:
                </label>
                <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(130px, 1fr))', gap: 8 }}>
                  {allowed.map(st => {
                    const isSelected = targetStatus === st;
                    const stCfg = STATUS_CONFIG[st];
                    return (
                      <button
                        key={st}
                        onClick={() => setTargetStatus(st)}
                        style={{
                          background: isSelected ? `${stCfg.color}20` : 'rgba(30,41,59,0.5)',
                          border: `1px solid ${isSelected ? stCfg.color : 'rgba(51,65,85,0.7)'}`,
                          borderRadius: 8,
                          padding: '8px 10px',
                          color: isSelected ? stCfg.color : '#94A3B8',
                          fontSize: 12,
                          fontWeight: 600,
                          cursor: 'pointer',
                          display: 'flex',
                          alignItems: 'center',
                          gap: 6,
                          textAlign: 'left',
                        }}
                      >
                        <div style={{ width: 6, height: 6, borderRadius: '50%', background: stCfg.color }} />
                        {stCfg.label}
                      </button>
                    );
                  })}
                </div>
              </div>

              {/* Mandatory Reason Input */}
              <div style={{ marginBottom: 16 }}>
                <label style={{ color: '#94A3B8', fontSize: 11, fontWeight: 600, display: 'block', marginBottom: 6 }}>
                  Justification / Investigation Notes <span style={{ color: '#EF4444' }}>*</span>
                </label>
                <textarea
                  rows={3}
                  placeholder="Explain why this attack chain is being transitioned (e.g. Verified malicious C2 beaconing, FP confirmed via test traffic)…"
                  value={reason}
                  onChange={e => setReason(e.target.value)}
                  style={{
                    width: '100%',
                    background: 'rgba(15,23,42,0.9)',
                    border: '1px solid rgba(51,65,85,0.8)',
                    borderRadius: 8,
                    padding: '8px 10px',
                    color: '#F1F5F9',
                    fontSize: 12,
                    fontFamily: 'inherit',
                    outline: 'none',
                    resize: 'none',
                  }}
                />
              </div>

              {/* Analyst ID */}
              <div style={{ marginBottom: 20 }}>
                <label style={{ color: '#94A3B8', fontSize: 11, fontWeight: 600, display: 'block', marginBottom: 6 }}>
                  Analyst ID / Username
                </label>
                <input
                  type="text"
                  value={analystName}
                  onChange={e => setAnalystName(e.target.value)}
                  style={{
                    width: '100%',
                    background: 'rgba(15,23,42,0.9)',
                    border: '1px solid rgba(51,65,85,0.8)',
                    borderRadius: 8,
                    padding: '7px 10px',
                    color: '#F1F5F9',
                    fontSize: 12,
                  }}
                />
              </div>

              {/* Error message */}
              {error && (
                <div style={{
                  background: 'rgba(239,68,68,0.1)',
                  border: '1px solid rgba(239,68,68,0.3)',
                  borderRadius: 8,
                  padding: '8px 12px',
                  color: '#FCA5A5',
                  fontSize: 12,
                  marginBottom: 16,
                  display: 'flex',
                  alignItems: 'center',
                  gap: 6,
                }}>
                  <AlertTriangle size={12} />
                  {error}
                </div>
              )}

              {/* Actions */}
              <div style={{ display: 'flex', justifyContent: 'flex-end', gap: 10 }}>
                <button
                  onClick={() => setIsModalOpen(false)}
                  style={{
                    background: 'rgba(30,41,59,0.7)',
                    border: '1px solid rgba(51,65,85,0.8)',
                    borderRadius: 8,
                    padding: '8px 16px',
                    color: '#94A3B8',
                    fontSize: 13,
                    cursor: 'pointer',
                  }}
                >
                  Cancel
                </button>
                <button
                  onClick={handleConfirmUpdate}
                  disabled={submitting || !targetStatus || reason.trim().length < 5}
                  style={{
                    background: '#2563EB',
                    border: '1px solid #3B82F6',
                    borderRadius: 8,
                    padding: '8px 18px',
                    color: '#FFFFFF',
                    fontSize: 13,
                    fontWeight: 600,
                    cursor: submitting ? 'wait' : 'pointer',
                    opacity: submitting || !targetStatus || reason.trim().length < 5 ? 0.6 : 1,
                  }}
                >
                  {submitting ? 'Updating…' : 'Confirm Transition'}
                </button>
              </div>
            </motion.div>
          </div>
        )}
      </AnimatePresence>
    </div>
  );
}

