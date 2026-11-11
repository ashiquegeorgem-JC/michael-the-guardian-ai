'use client';

import React from 'react';
import type { ContributingSignal } from '@/types';
import { Layers, CheckCircle2, XCircle } from 'lucide-react';

interface ThreatSignalsPanelProps {
  signals: ContributingSignal[];
  threatScore: number;
}

export function ThreatSignalsPanel({ signals, threatScore }: ThreatSignalsPanelProps) {
  if (!signals || signals.length === 0) {
    return (
      <div style={{ padding: '16px', color: 'var(--text-muted)', fontSize: 12, textAlign: 'center' }}>
        No contributing signals telemetry available.
      </div>
    );
  }

  return (
    <div
      style={{
        background: 'rgba(13, 20, 36, 0.7)',
        border: '1px solid #1E2D4A',
        borderRadius: 12,
        padding: '16px 20px',
        display: 'flex',
        flexDirection: 'column',
        gap: 14,
      }}
    >
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
          <Layers size={15} color="#3B82F6" />
          <span style={{ fontSize: 13, fontWeight: 700, letterSpacing: '0.02em', color: '#F8FAFC' }}>
            Contributing Threat Signals
          </span>
        </div>
        <div style={{ fontSize: 11, color: 'var(--text-muted)', fontFamily: 'var(--font-mono)' }}>
          Total Score: <span style={{ color: '#F8FAFC', fontWeight: 700 }}>{threatScore.toFixed(1)} / 100</span>
        </div>
      </div>

      <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
        {signals.map((sig, idx) => {
          const contribPercentage = (sig.contribution / 100) * 100;
          return (
            <div
              key={`${sig.signal_name}-${idx}`}
              style={{
                background: 'rgba(10, 14, 26, 0.8)',
                border: '1px solid #1A253C',
                borderRadius: 8,
                padding: '10px 14px',
                display: 'flex',
                flexDirection: 'column',
                gap: 6,
              }}
            >
              <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                  {sig.available ? (
                    <CheckCircle2 size={13} color="#10B981" />
                  ) : (
                    <XCircle size={13} color="#64748B" />
                  )}
                  <span
                    style={{
                      fontSize: 12,
                      fontWeight: 600,
                      fontFamily: 'var(--font-mono)',
                      color: sig.available ? '#E2E8F0' : '#64748B',
                    }}
                  >
                    {sig.signal_name.replace(/_/g, ' ')}
                  </span>
                  <span
                    style={{
                      fontSize: 10,
                      color: 'var(--text-muted)',
                      background: '#162238',
                      padding: '1px 5px',
                      borderRadius: 4,
                    }}
                  >
                    Weight: {(sig.weight * 100).toFixed(0)}%
                  </span>
                </div>

                <div
                  style={{
                    fontSize: 12,
                    fontWeight: 700,
                    fontFamily: 'var(--font-mono)',
                    color: sig.contribution > 0 ? '#38BDF8' : '#64748B',
                  }}
                >
                  +{sig.contribution.toFixed(1)} pts
                </div>
              </div>

              {/* Progress bar */}
              <div
                style={{
                  height: 4,
                  background: '#1A2338',
                  borderRadius: 2,
                  overflow: 'hidden',
                  width: '100%',
                }}
              >
                <div
                  style={{
                    height: '100%',
                    width: `${Math.min(100, Math.max(0, contribPercentage * (1 / sig.weight)))}%`,
                    background: sig.contribution > 0 ? 'linear-gradient(90deg, #3B82F6, #38BDF8)' : '#334155',
                    borderRadius: 2,
                    transition: 'width 0.5s ease',
                  }}
                />
              </div>

              <div
                style={{
                  fontSize: 11,
                  color: 'var(--text-muted)',
                  lineHeight: 1.4,
                }}
              >
                {sig.explanation}
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}

