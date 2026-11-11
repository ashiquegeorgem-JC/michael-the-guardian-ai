'use client';

import React, { useState } from 'react';
import type { ThreatCorrelation } from '@/types';
import { GitFork, ShieldAlert, AlertTriangle, FileText, CheckCircle2, AlertCircle, Info } from 'lucide-react';

interface ThreatCorrelationGraphProps {
  iocValue: string;
  correlations: ThreatCorrelation[];
  onSelectCorrelation?: (corr: ThreatCorrelation) => void;
}

export function ThreatCorrelationGraph({
  iocValue,
  correlations,
  onSelectCorrelation,
}: ThreatCorrelationGraphProps) {
  const [selectedId, setSelectedId] = useState<string | null>(null);

  if (!correlations || correlations.length === 0) {
    return (
      <div
        style={{
          padding: '30px',
          textAlign: 'center',
          color: 'var(--text-muted)',
          fontSize: 12,
          background: 'rgba(10, 14, 26, 0.7)',
          borderRadius: 12,
          border: '1px solid #1E2D4A',
        }}
      >
        No correlation relationships have been established for this indicator.
      </div>
    );
  }

  const selectedCorr = correlations.find((c) => c.correlation_id === selectedId);

  // Group by target_type
  const events = correlations.filter((c) => c.target_type === 'event');
  const anomalies = correlations.filter((c) => c.target_type === 'anomaly');
  const incidents = correlations.filter((c) => c.target_type === 'incident');
  const chains = correlations.filter((c) => c.target_type === 'attack_chain');

  const getNodeColor = (type: string, confirmed: boolean) => {
    if (!confirmed) return '#94A3B8';
    switch (type) {
      case 'event':
        return '#06B6D4'; // Cyan
      case 'anomaly':
        return '#F59E0B'; // Amber
      case 'incident':
        return '#EF4444'; // Red
      case 'attack_chain':
        return '#8B5CF6'; // Violet
      default:
        return '#3B82F6';
    }
  };

  return (
    <div
      style={{
        background: 'rgba(13, 20, 36, 0.7)',
        border: '1px solid #1E2D4A',
        borderRadius: 12,
        padding: '18px 20px',
        display: 'flex',
        flexDirection: 'column',
        gap: 16,
      }}
    >
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
          <GitFork size={16} color="#8B5CF6" />
          <span style={{ fontSize: 13, fontWeight: 700, color: '#F8FAFC' }}>
            Investigation Correlation Graph
          </span>
        </div>
        <div style={{ display: 'flex', alignItems: 'center', gap: 12, fontSize: 10, color: 'var(--text-muted)' }}>
          <span style={{ display: 'flex', alignItems: 'center', gap: 4 }}>
            <span style={{ width: 8, height: 8, borderRadius: '50%', background: '#10B981' }} />
            Confirmed
          </span>
          <span style={{ display: 'flex', alignItems: 'center', gap: 4 }}>
            <span style={{ width: 8, height: 8, borderRadius: '50%', background: '#94A3B8' }} />
            Unconfirmed (Cross-Session/Temporal)
          </span>
        </div>
      </div>

      {/* Forensic Graph Layout (SVG + Flex Nodes) */}
      <div
        style={{
          background: 'rgba(8, 12, 22, 0.95)',
          border: '1px solid #162036',
          borderRadius: 10,
          padding: '24px 16px',
          display: 'flex',
          flexDirection: 'column',
          alignItems: 'center',
          gap: 24,
          position: 'relative',
          minHeight: 280,
        }}
      >
        {/* Root Node: IOC */}
        <div
          style={{
            padding: '10px 20px',
            background: 'linear-gradient(135deg, rgba(59, 130, 246, 0.2), rgba(124, 58, 237, 0.2))',
            border: '2px solid #3B82F6',
            borderRadius: 10,
            display: 'flex',
            flexDirection: 'column',
            alignItems: 'center',
            boxShadow: '0 0 15px rgba(59, 130, 246, 0.2)',
            zIndex: 2,
          }}
        >
          <span style={{ fontSize: 9, fontWeight: 700, letterSpacing: '0.08em', color: '#93C5FD', textTransform: 'uppercase' }}>
            Indicator of Compromise
          </span>
          <span style={{ fontSize: 14, fontWeight: 800, fontFamily: 'var(--font-mono)', color: '#F8FAFC', marginTop: 2 }}>
            {iocValue}
          </span>
        </div>

        {/* Target Columns */}
        <div
          style={{
            display: 'grid',
            gridTemplateColumns: 'repeat(auto-fit, minmax(130px, 1fr))',
            gap: 12,
            width: '100%',
            zIndex: 2,
          }}
        >
          {/* Events Column */}
          <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
            <div style={{ fontSize: 10, fontWeight: 700, color: '#06B6D4', textTransform: 'uppercase', letterSpacing: '0.05em' }}>
              Events ({events.length})
            </div>
            {events.map((c) => {
              const active = selectedId === c.correlation_id;
              const color = getNodeColor('event', c.confirmed);
              return (
                <div
                  key={c.correlation_id}
                  onClick={() => {
                    setSelectedId(active ? null : c.correlation_id);
                    onSelectCorrelation?.(c);
                  }}
                  style={{
                    padding: '8px 10px',
                    borderRadius: 6,
                    background: active ? `${color}25` : 'rgba(15, 23, 42, 0.8)',
                    border: `1px solid ${active ? color : color + '40'}`,
                    cursor: 'pointer',
                    display: 'flex',
                    flexDirection: 'column',
                    gap: 3,
                    transition: 'all 0.2s ease',
                  }}
                >
                  <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: 4 }}>
                      <FileText size={11} color={color} />
                      <span style={{ fontSize: 11, fontWeight: 600, color: '#F8FAFC', fontFamily: 'var(--font-mono)' }}>
                        {c.target_id.slice(0, 10)}
                      </span>
                    </div>
                    {c.confirmed ? <CheckCircle2 size={11} color="#10B981" /> : <AlertCircle size={11} color="#94A3B8" />}
                  </div>
                  <div style={{ fontSize: 9, color: 'var(--text-muted)', fontFamily: 'var(--font-mono)' }}>
                    Conf: {(c.confidence.score * 100).toFixed(0)}%
                  </div>
                </div>
              );
            })}
          </div>

          {/* Anomalies Column */}
          <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
            <div style={{ fontSize: 10, fontWeight: 700, color: '#F59E0B', textTransform: 'uppercase', letterSpacing: '0.05em' }}>
              Anomalies ({anomalies.length})
            </div>
            {anomalies.map((c) => {
              const active = selectedId === c.correlation_id;
              const color = getNodeColor('anomaly', c.confirmed);
              return (
                <div
                  key={c.correlation_id}
                  onClick={() => {
                    setSelectedId(active ? null : c.correlation_id);
                    onSelectCorrelation?.(c);
                  }}
                  style={{
                    padding: '8px 10px',
                    borderRadius: 6,
                    background: active ? `${color}25` : 'rgba(15, 23, 42, 0.8)',
                    border: `1px solid ${active ? color : color + '40'}`,
                    cursor: 'pointer',
                    display: 'flex',
                    flexDirection: 'column',
                    gap: 3,
                    transition: 'all 0.2s ease',
                  }}
                >
                  <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: 4 }}>
                      <AlertTriangle size={11} color={color} />
                      <span style={{ fontSize: 11, fontWeight: 600, color: '#F8FAFC', fontFamily: 'var(--font-mono)' }}>
                        {c.target_id.slice(0, 10)}
                      </span>
                    </div>
                    {c.confirmed ? <CheckCircle2 size={11} color="#10B981" /> : <AlertCircle size={11} color="#94A3B8" />}
                  </div>
                  <div style={{ fontSize: 9, color: 'var(--text-muted)', fontFamily: 'var(--font-mono)' }}>
                    Conf: {(c.confidence.score * 100).toFixed(0)}%
                  </div>
                </div>
              );
            })}
          </div>

          {/* Incidents Column */}
          <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
            <div style={{ fontSize: 10, fontWeight: 700, color: '#EF4444', textTransform: 'uppercase', letterSpacing: '0.05em' }}>
              Incidents ({incidents.length})
            </div>
            {incidents.map((c) => {
              const active = selectedId === c.correlation_id;
              const color = getNodeColor('incident', c.confirmed);
              return (
                <div
                  key={c.correlation_id}
                  onClick={() => {
                    setSelectedId(active ? null : c.correlation_id);
                    onSelectCorrelation?.(c);
                  }}
                  style={{
                    padding: '8px 10px',
                    borderRadius: 6,
                    background: active ? `${color}25` : 'rgba(15, 23, 42, 0.8)',
                    border: `1px solid ${active ? color : color + '40'}`,
                    cursor: 'pointer',
                    display: 'flex',
                    flexDirection: 'column',
                    gap: 3,
                    transition: 'all 0.2s ease',
                  }}
                >
                  <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: 4 }}>
                      <ShieldAlert size={11} color={color} />
                      <span style={{ fontSize: 11, fontWeight: 600, color: '#F8FAFC', fontFamily: 'var(--font-mono)' }}>
                        {c.target_id.slice(0, 10)}
                      </span>
                    </div>
                    {c.confirmed ? <CheckCircle2 size={11} color="#10B981" /> : <AlertCircle size={11} color="#94A3B8" />}
                  </div>
                  <div style={{ fontSize: 9, color: 'var(--text-muted)', fontFamily: 'var(--font-mono)' }}>
                    Conf: {(c.confidence.score * 100).toFixed(0)}%
                  </div>
                </div>
              );
            })}
          </div>

          {/* Attack Chains Column */}
          <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
            <div style={{ fontSize: 10, fontWeight: 700, color: '#8B5CF6', textTransform: 'uppercase', letterSpacing: '0.05em' }}>
              Attack Chains ({chains.length})
            </div>
            {chains.map((c) => {
              const active = selectedId === c.correlation_id;
              const color = getNodeColor('attack_chain', c.confirmed);
              return (
                <div
                  key={c.correlation_id}
                  onClick={() => {
                    setSelectedId(active ? null : c.correlation_id);
                    onSelectCorrelation?.(c);
                  }}
                  style={{
                    padding: '8px 10px',
                    borderRadius: 6,
                    background: active ? `${color}25` : 'rgba(15, 23, 42, 0.8)',
                    border: `1px solid ${active ? color : color + '40'}`,
                    cursor: 'pointer',
                    display: 'flex',
                    flexDirection: 'column',
                    gap: 3,
                    transition: 'all 0.2s ease',
                  }}
                >
                  <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: 4 }}>
                      <GitFork size={11} color={color} />
                      <span style={{ fontSize: 11, fontWeight: 600, color: '#F8FAFC', fontFamily: 'var(--font-mono)' }}>
                        {c.target_id.slice(0, 10)}
                      </span>
                    </div>
                    {c.confirmed ? <CheckCircle2 size={11} color="#10B981" /> : <AlertCircle size={11} color="#94A3B8" />}
                  </div>
                  <div style={{ fontSize: 9, color: 'var(--text-muted)', fontFamily: 'var(--font-mono)' }}>
                    Conf: {(c.confidence.score * 100).toFixed(0)}%
                  </div>
                </div>
              );
            })}
          </div>
        </div>
      </div>

      {/* Selected Correlation Evidence Box */}
      {selectedCorr && (
        <div
          style={{
            background: 'rgba(10, 14, 26, 0.9)',
            border: '1px solid #1A253C',
            borderRadius: 8,
            padding: '12px 16px',
            display: 'flex',
            flexDirection: 'column',
            gap: 6,
          }}
        >
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
            <span style={{ fontSize: 11, fontWeight: 700, color: '#F8FAFC' }}>
              Relationship: {selectedCorr.correlation_type} ({selectedCorr.target_id})
            </span>
            <span
              style={{
                fontSize: 10,
                fontWeight: 700,
                padding: '2px 6px',
                borderRadius: 4,
                background: selectedCorr.confirmed ? 'rgba(16, 185, 129, 0.15)' : 'rgba(148, 163, 184, 0.15)',
                color: selectedCorr.confirmed ? '#10B981' : '#94A3B8',
              }}
            >
              {selectedCorr.confirmed ? 'CONFIRMED' : 'UNCONFIRMED'} ({(selectedCorr.confidence.score * 100).toFixed(0)}% conf)
            </span>
          </div>
          <ul style={{ margin: 0, paddingLeft: 18, fontSize: 11, color: '#CBD5E1', lineHeight: 1.4 }}>
            {selectedCorr.evidence.map((ev, i) => (
              <li key={`ev-${i}`}>{ev}</li>
            ))}
          </ul>
        </div>
      )}
    </div>
  );
}

