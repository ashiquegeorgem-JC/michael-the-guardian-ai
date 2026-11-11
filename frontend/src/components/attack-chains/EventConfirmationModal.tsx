'use client';

import React, { useState } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import {
  CheckCircle2, XCircle, AlertTriangle, X, Shield, FileText,
  User, Check, Info
} from 'lucide-react';
import { confirmAttackChainEvent } from '@/lib/api';
import type { ChainLinkEvent } from '@/types';

interface Props {
  chainId: string;
  event: ChainLinkEvent | null;
  isOpen: boolean;
  onClose: () => void;
  onConfirmed?: (eventId: string, isConfirmed: boolean, updatedReason: string) => void;
  onSuccess?: () => void;
}

export function EventConfirmationModal({ chainId, event, isOpen, onClose, onConfirmed, onSuccess }: Props) {
  const [isConfirmed, setIsConfirmed] = useState<boolean>(true);
  const [reason, setReason] = useState('');
  const [analystName, setAnalystName] = useState('Analyst');
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);

  if (!isOpen || !event) return null;

  const handleSubmit = async () => {
    if (reason.trim().length < 3) {
      setError('A justification reason of at least 3 characters is required.');
      return;
    }

    setSubmitting(true);
    setError(null);
    try {
      const res = await confirmAttackChainEvent(chainId, event.id, {
        is_confirmed: isConfirmed,
        reason: reason.trim(),
        changed_by: analystName.trim() || undefined,
      });
      if (onConfirmed) onConfirmed(event.id, res.is_confirmed, res.correlation_reason);
      if (onSuccess) onSuccess();
      onClose();
    } catch (err: unknown) {
      const e = err as Error;
      setError(e.message || 'Failed to update event confirmation');
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <AnimatePresence>
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
            maxWidth: 520,
            boxShadow: '0 20px 50px rgba(0,0,0,0.6)',
          }}
        >
          {/* Header */}
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 16 }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
              <Shield size={18} color="#3B82F6" />
              <h3 style={{ color: '#F1F5F9', fontSize: 16, fontWeight: 700, margin: 0 }}>
                Analyst Evidence Confirmation
              </h3>
            </div>
            <button
              onClick={onClose}
              style={{ background: 'none', border: 'none', color: '#64748B', cursor: 'pointer' }}
            >
              <X size={16} />
            </button>
          </div>

          {/* Event Context Card */}
          <div style={{
            background: 'rgba(15,23,42,0.9)',
            border: '1px solid rgba(30,41,59,0.9)',
            borderRadius: 10,
            padding: '12px 14px',
            marginBottom: 16,
          }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 6 }}>
              <span style={{
                background: 'rgba(59,130,246,0.15)',
                color: '#60A5FA',
                fontSize: 10,
                fontWeight: 700,
                padding: '2px 8px',
                borderRadius: 4,
                textTransform: 'uppercase',
              }}>
                {event.stage}
              </span>
              <span style={{ color: '#64748B', fontSize: 11 }}>
                Line {event.line_number ?? '?'} · {event.timestamp ? new Date(event.timestamp).toLocaleTimeString() : 'No timestamp'}
              </span>
            </div>

            <p style={{
              color: '#CBD5E1',
              fontFamily: 'monospace',
              fontSize: 11,
              lineHeight: 1.4,
              margin: '0 0 6px',
              wordBreak: 'break-all',
              background: 'rgba(0,0,0,0.3)',
              padding: '6px 8px',
              borderRadius: 6,
            }}>
              {event.raw_log}
            </p>

            <div style={{ color: '#94A3B8', fontSize: 11 }}>
              <strong>Current Attribution:</strong> {event.correlation_reason}
            </div>
          </div>

          {/* Decision Selection */}
          <div style={{ marginBottom: 16 }}>
            <label style={{ color: '#94A3B8', fontSize: 11, fontWeight: 600, display: 'block', marginBottom: 6 }}>
              Confirmation Decision:
            </label>
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 10 }}>
              <button
                type="button"
                onClick={() => setIsConfirmed(true)}
                style={{
                  background: isConfirmed ? 'rgba(16,185,129,0.15)' : 'rgba(30,41,59,0.5)',
                  border: `1px solid ${isConfirmed ? '#10B981' : 'rgba(51,65,85,0.7)'}`,
                  borderRadius: 8,
                  padding: '10px 14px',
                  color: isConfirmed ? '#10B981' : '#94A3B8',
                  fontSize: 12,
                  fontWeight: 600,
                  cursor: 'pointer',
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'center',
                  gap: 6,
                }}
              >
                <CheckCircle2 size={14} />
                Confirm Membership
              </button>

              <button
                type="button"
                onClick={() => setIsConfirmed(false)}
                style={{
                  background: !isConfirmed ? 'rgba(239,68,68,0.15)' : 'rgba(30,41,59,0.5)',
                  border: `1px solid ${!isConfirmed ? '#EF4444' : 'rgba(51,65,85,0.7)'}`,
                  borderRadius: 8,
                  padding: '10px 14px',
                  color: !isConfirmed ? '#EF4444' : '#94A3B8',
                  fontSize: 12,
                  fontWeight: 600,
                  cursor: 'pointer',
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'center',
                  gap: 6,
                }}
              >
                <XCircle size={14} />
                Reject / Mark Suspected
              </button>
            </div>
          </div>

          {/* Mandatory Reason */}
          <div style={{ marginBottom: 16 }}>
            <label style={{ color: '#94A3B8', fontSize: 11, fontWeight: 600, display: 'block', marginBottom: 6 }}>
              Analyst Reasoning <span style={{ color: '#EF4444' }}>*</span>
            </label>
            <textarea
              rows={3}
              placeholder="Provide evidence or justification (e.g. Verified SQL payload matches known CVE, False alarm caused by scanner)…"
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

          {/* Analyst Username */}
          <div style={{ marginBottom: 20 }}>
            <label style={{ color: '#94A3B8', fontSize: 11, fontWeight: 600, display: 'block', marginBottom: 6 }}>
              Analyst Identifier
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

          {/* Error */}
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
              onClick={onClose}
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
              onClick={handleSubmit}
              disabled={submitting || reason.trim().length < 3}
              style={{
                background: '#2563EB',
                border: '1px solid #3B82F6',
                borderRadius: 8,
                padding: '8px 18px',
                color: '#FFFFFF',
                fontSize: 13,
                fontWeight: 600,
                cursor: submitting ? 'wait' : 'pointer',
                opacity: submitting || reason.trim().length < 3 ? 0.6 : 1,
              }}
            >
              {submitting ? 'Saving…' : 'Record Decision'}
            </button>
          </div>
        </motion.div>
      </div>
    </AnimatePresence>
  );
}

