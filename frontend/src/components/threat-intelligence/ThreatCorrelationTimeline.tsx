'use client';

import React from 'react';
import type { ThreatCorrelation, ThreatAssessment } from '@/types';
import { Clock, CheckCircle2, AlertCircle, FileText, AlertTriangle, ShieldAlert, GitFork, ShieldCheck } from 'lucide-react';

interface ThreatCorrelationTimelineProps {
  correlations: ThreatCorrelation[];
  assessment?: ThreatAssessment | null;
}

interface TimelineEvent {
  id: string;
  timestamp: string;
  type: 'EVENT' | 'ANOMALY' | 'INCIDENT' | 'ATTACK_CHAIN' | 'ASSESSMENT';
  title: string;
  description: string;
  confidence?: number;
  confirmed: boolean;
  statusText: string;
}

export function ThreatCorrelationTimeline({ correlations, assessment }: ThreatCorrelationTimelineProps) {
  const eventsList: TimelineEvent[] = [];

  // Add correlations with timestamps
  for (const c of correlations) {
    const ts = c.first_seen || c.created_at;
    let type: TimelineEvent['type'] = 'EVENT';
    let title = `Correlated ${c.target_type}`;

    if (c.target_type === 'event') {
      type = 'EVENT';
      title = `Log Event ${c.target_id}`;
    } else if (c.target_type === 'anomaly') {
      type = 'ANOMALY';
      title = `Anomaly Detected ${c.target_id}`;
    } else if (c.target_type === 'incident') {
      type = 'INCIDENT';
      title = `Incident Correlated ${c.target_id}`;
    } else if (c.target_type === 'attack_chain') {
      type = 'ATTACK_CHAIN';
      title = `Attack Chain Linked ${c.target_id}`;
    }

    eventsList.push({
      id: c.correlation_id,
      timestamp: ts,
      type,
      title,
      description: c.evidence[0] || c.correlation_method,
      confidence: c.confidence.score,
      confirmed: c.confirmed,
      statusText: c.confirmed ? 'Confirmed Correlation' : 'Unconfirmed Link',
    });
  }

  // Add assessment if present
  if (assessment) {
    eventsList.push({
      id: assessment.assessment_id,
      timestamp: assessment.assessed_at,
      type: 'ASSESSMENT',
      title: `Threat Assessment: ${assessment.status}`,
      description: `Risk score evaluated at ${assessment.threat_score.toFixed(1)}/100 (${assessment.severity}).`,
      confidence: assessment.confidence,
      confirmed: true,
      statusText: 'Threat Assessment Generated',
    });
  }

  // Sort chronologically ascending
  eventsList.sort((a, b) => new Date(a.timestamp).getTime() - new Date(b.timestamp).getTime());

  if (eventsList.length === 0) {
    return (
      <div style={{ padding: '24px', textAlign: 'center', color: 'var(--text-muted)', fontSize: 12 }}>
        No chronological timeline data available for this indicator.
      </div>
    );
  }

  const getTypeIcon = (type: TimelineEvent['type']) => {
    switch (type) {
      case 'EVENT':
        return <FileText size={13} color="#06B6D4" />;
      case 'ANOMALY':
        return <AlertTriangle size={13} color="#F59E0B" />;
      case 'INCIDENT':
        return <ShieldAlert size={13} color="#EF4444" />;
      case 'ATTACK_CHAIN':
        return <GitFork size={13} color="#8B5CF6" />;
      case 'ASSESSMENT':
        return <ShieldCheck size={13} color="#10B981" />;
    }
  };

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
      <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
        <Clock size={15} color="#38BDF8" />
        <span style={{ fontSize: 13, fontWeight: 700, color: '#F8FAFC' }}>
          Chronological Threat Investigation Timeline
        </span>
      </div>

      <div style={{ display: 'flex', flexDirection: 'column', gap: 0, position: 'relative' }}>
        {eventsList.map((item, idx) => {
          const isLast = idx === eventsList.length - 1;
          return (
            <div
              key={item.id}
              style={{
                display: 'grid',
                gridTemplateColumns: '130px 24px 1fr',
                gap: 12,
                position: 'relative',
                paddingBottom: isLast ? 0 : 16,
              }}
            >
              {/* Timestamp column */}
              <div
                style={{
                  fontSize: 10,
                  fontFamily: 'var(--font-mono)',
                  color: 'var(--text-muted)',
                  textAlign: 'right',
                  paddingTop: 2,
                }}
              >
                {new Date(item.timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' })}
                <div style={{ fontSize: 9, opacity: 0.7 }}>
                  {new Date(item.timestamp).toLocaleDateString()}
                </div>
              </div>

              {/* Node connector */}
              <div
                style={{
                  display: 'flex',
                  flexDirection: 'column',
                  alignItems: 'center',
                  position: 'relative',
                }}
              >
                <div
                  style={{
                    width: 22,
                    height: 22,
                    borderRadius: '50%',
                    background: '#0D1424',
                    border: '1px solid #1E2D4A',
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'center',
                    zIndex: 2,
                  }}
                >
                  {getTypeIcon(item.type)}
                </div>
                {!isLast && (
                  <div
                    style={{
                      width: 2,
                      flexGrow: 1,
                      background: '#1E2D4A',
                      marginTop: 2,
                    }}
                  />
                )}
              </div>

              {/* Event content box */}
              <div
                style={{
                  background: 'rgba(10, 14, 26, 0.8)',
                  border: '1px solid #1A253C',
                  borderRadius: 8,
                  padding: '10px 14px',
                  display: 'flex',
                  flexDirection: 'column',
                  gap: 4,
                }}
              >
                <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: 4 }}>
                  <span style={{ fontSize: 12, fontWeight: 700, color: '#F8FAFC' }}>
                    {item.title}
                  </span>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                    <span
                      style={{
                        fontSize: 9,
                        fontWeight: 700,
                        padding: '1px 5px',
                        borderRadius: 4,
                        background: item.confirmed ? 'rgba(16, 185, 129, 0.15)' : 'rgba(148, 163, 184, 0.15)',
                        color: item.confirmed ? '#10B981' : '#94A3B8',
                      }}
                    >
                      {item.statusText}
                    </span>
                    {item.confidence !== undefined && (
                      <span style={{ fontSize: 10, color: 'var(--text-muted)', fontFamily: 'var(--font-mono)' }}>
                        {(item.confidence * 100).toFixed(0)}% conf
                      </span>
                    )}
                  </div>
                </div>
                <div style={{ fontSize: 11, color: '#94A3B8', lineHeight: 1.4 }}>
                  {item.description}
                </div>
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}

