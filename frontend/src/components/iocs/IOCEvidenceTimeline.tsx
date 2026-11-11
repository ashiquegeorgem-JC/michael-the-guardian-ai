'use client';

import React, { useEffect, useState } from 'react';
import { Clock, FileText, Hash, AlertCircle } from 'lucide-react';
import { getIOCEvidence } from '@/lib/api';
import type { IOCEvidence, IOCEvidenceResponse } from '@/types';
import { formatDateTime } from '@/lib/utils';

interface Props {
  iocId: string;
  inlineEvidence?: IOCEvidence[];
}

export function IOCEvidenceTimeline({ iocId, inlineEvidence }: Props) {
  const [data, setData] = useState<IOCEvidenceResponse | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    setLoading(true);
    setError(null);
    getIOCEvidence(iocId)
      .then(setData)
      .catch((e: Error) => setError(e.message))
      .finally(() => setLoading(false));
  }, [iocId]);

  const evidence = data?.evidence ?? inlineEvidence ?? [];

  if (loading) {
    return (
      <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
        {[1, 2, 3].map(i => (
          <div key={i} className="animate-pulse" style={{ height: 80, background: '#0F1629', borderRadius: 10 }} />
        ))}
      </div>
    );
  }

  if (error) {
    return (
      <div style={{ padding: 20, textAlign: 'center', color: '#EF4444' }}>
        <AlertCircle size={28} style={{ display: 'block', margin: '0 auto 8px', opacity: 0.6 }} />
        <div style={{ fontSize: 13 }}>Failed to load evidence</div>
        <div style={{ fontSize: 11, color: 'var(--text-muted)', marginTop: 4 }}>{error}</div>
      </div>
    );
  }

  if (evidence.length === 0) {
    return (
      <div style={{ padding: 40, textAlign: 'center', color: 'var(--text-muted)' }}>
        <FileText size={32} style={{ display: 'block', margin: '0 auto 10px', opacity: 0.3 }} />
        <div style={{ fontSize: 13 }}>No evidence records found</div>
      </div>
    );
  }

  return (
    <div>
      <div style={{ fontSize: 11, color: 'var(--text-muted)', marginBottom: 14 }}>
        {evidence.length} evidence record{evidence.length !== 1 ? 's' : ''} — read-only forensic data
      </div>
      <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
        {evidence.map((ev, idx) => (
          <div
            key={`${ev.event_id}-${idx}`}
            style={{
              background: '#0A0E1A',
              border: '1px solid #1E2D4A',
              borderRadius: 10,
              overflow: 'hidden',
            }}
          >
            {/* Evidence header */}
            <div style={{ padding: '10px 14px', borderBottom: '1px solid #1E2D4A', display: 'flex', alignItems: 'center', gap: 10, flexWrap: 'wrap' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 5, fontSize: 11, color: '#60A5FA' }}>
                <Hash size={10} />
                <span style={{ fontFamily: 'var(--font-mono)' }}>{ev.event_id}</span>
              </div>
              {ev.timestamp && (
                <div style={{ display: 'flex', alignItems: 'center', gap: 4, fontSize: 11, color: 'var(--text-muted)' }}>
                  <Clock size={10} />
                  {formatDateTime(ev.timestamp)}
                </div>
              )}
              {ev.line_number !== null && (
                <span style={{ fontSize: 10, color: '#8B5CF6', background: 'rgba(139,92,246,0.1)', padding: '1px 6px', borderRadius: 4, fontFamily: 'var(--font-mono)' }}>
                  Line {ev.line_number}
                </span>
              )}
              <span style={{ fontSize: 10, color: 'var(--text-muted)', background: '#1E2D4A', padding: '1px 6px', borderRadius: 4 }}>
                {ev.source_field}
              </span>
              <span style={{ fontSize: 11, fontFamily: 'var(--font-mono)', color: '#3B82F6', marginLeft: 'auto' }}>
                {ev.session_id.slice(0, 16)}…
              </span>
            </div>

            {/* Raw value */}
            <div style={{ padding: '8px 14px', display: 'flex', alignItems: 'center', gap: 8 }}>
              <span style={{ fontSize: 10, color: 'var(--text-muted)', flexShrink: 0 }}>Verbatim Match:</span>
              <code style={{ fontFamily: 'var(--font-mono)', fontSize: 12, color: '#FCD34D', background: 'rgba(252,211,77,0.08)', padding: '2px 6px', borderRadius: 4 }}>
                {ev.raw_value}
              </code>
            </div>

            {/* Context */}
            {ev.surrounding_context && (
              <div style={{ padding: '0 14px 12px' }}>
                <div style={{ fontSize: 10, color: 'var(--text-muted)', marginBottom: 4 }}>Surrounding Context:</div>
                <div style={{
                  fontFamily: 'var(--font-mono)',
                  fontSize: 11,
                  color: '#94A3B8',
                  background: '#060A14',
                  border: '1px solid #1A2744',
                  borderRadius: 6,
                  padding: '8px 10px',
                  whiteSpace: 'pre-wrap',
                  wordBreak: 'break-all',
                  lineHeight: 1.6,
                }}>
                  {ev.surrounding_context}
                </div>
              </div>
            )}
          </div>
        ))}
      </div>
    </div>
  );
}

