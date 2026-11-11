'use client';

import React from 'react';
import type { ThreatAssessment, IOCStatus } from '@/types';
import { ThreatScoreGauge } from './ThreatScoreGauge';
import { ShieldCheck, AlertCircle, Info, Hash } from 'lucide-react';

interface ThreatAssessmentCardProps {
  assessment?: ThreatAssessment | null;
  analystStatus: IOCStatus;
  correlationConfidence?: number;
}

export function ThreatAssessmentCard({
  assessment,
  analystStatus,
  correlationConfidence,
}: ThreatAssessmentCardProps) {
  if (!assessment) {
    return (
      <div
        style={{
          background: 'rgba(13, 20, 36, 0.7)',
          border: '1px solid #1E2D4A',
          borderRadius: 12,
          padding: '24px',
          textAlign: 'center',
          color: 'var(--text-muted)',
          fontSize: 13,
        }}
      >
        No Threat Assessment has been evaluated for this indicator.
      </div>
    );
  }

  return (
    <div
      style={{
        background: 'rgba(13, 20, 36, 0.7)',
        border: '1px solid #1E2D4A',
        borderRadius: 12,
        padding: '20px',
        display: 'flex',
        flexDirection: 'column',
        gap: 16,
      }}
    >
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
          <ShieldCheck size={18} color="#38BDF8" />
          <span style={{ fontSize: 14, fontWeight: 700, color: '#F8FAFC' }}>
            Reputation Assessment &amp; Risk Metrics
          </span>
        </div>
        <span
          style={{
            fontSize: 10,
            color: 'var(--text-muted)',
            fontFamily: 'var(--font-mono)',
          }}
        >
          Engine v{assessment.engine_version}
        </span>
      </div>

      {/* Main Metric Row: Gauge + Disambiguated Metric Grid */}
      <div
        style={{
          display: 'grid',
          gridTemplateColumns: 'auto 1fr',
          gap: 20,
          alignItems: 'center',
          flexWrap: 'wrap',
        }}
      >
        {/* Visual Gauge */}
        <div style={{ display: 'flex', justifyContent: 'center' }}>
          <ThreatScoreGauge
            score={assessment.threat_score}
            severity={assessment.severity}
            confidence={assessment.confidence}
            size={130}
          />
        </div>

        {/* 4 Distinct Independent Metrics as requested by Section 7 */}
        <div
          style={{
            display: 'grid',
            gridTemplateColumns: 'repeat(auto-fit, minmax(130px, 1fr))',
            gap: 10,
          }}
        >
          {/* 1. Threat Score */}
          <div
            style={{
              background: 'rgba(10, 14, 26, 0.8)',
              border: '1px solid #1A253C',
              borderRadius: 8,
              padding: '10px 12px',
            }}
          >
            <div style={{ fontSize: 10, color: 'var(--text-muted)', fontWeight: 600, textTransform: 'uppercase' }}>
              Threat Score
            </div>
            <div style={{ fontSize: 16, fontWeight: 800, fontFamily: 'var(--font-mono)', color: '#F8FAFC', marginTop: 2 }}>
              {assessment.threat_score.toFixed(1)} <span style={{ fontSize: 11, color: 'var(--text-muted)' }}>/ 100</span>
            </div>
            <div style={{ fontSize: 10, color: 'var(--text-muted)', marginTop: 2 }}>
              Quantitative risk
            </div>
          </div>

          {/* 2. Threat Confidence */}
          <div
            style={{
              background: 'rgba(10, 14, 26, 0.8)',
              border: '1px solid #1A253C',
              borderRadius: 8,
              padding: '10px 12px',
            }}
          >
            <div style={{ fontSize: 10, color: 'var(--text-muted)', fontWeight: 600, textTransform: 'uppercase' }}>
              Threat Confidence
            </div>
            <div style={{ fontSize: 16, fontWeight: 800, fontFamily: 'var(--font-mono)', color: '#38BDF8', marginTop: 2 }}>
              {(assessment.confidence * 100).toFixed(0)}%
            </div>
            <div style={{ fontSize: 10, color: 'var(--text-muted)', marginTop: 2 }}>
              Intelligence accuracy
            </div>
          </div>

          {/* 3. Correlation Confidence */}
          <div
            style={{
              background: 'rgba(10, 14, 26, 0.8)',
              border: '1px solid #1A253C',
              borderRadius: 8,
              padding: '10px 12px',
            }}
          >
            <div style={{ fontSize: 10, color: 'var(--text-muted)', fontWeight: 600, textTransform: 'uppercase' }}>
              Correlation Conf
            </div>
            <div style={{ fontSize: 16, fontWeight: 800, fontFamily: 'var(--font-mono)', color: '#A78BFA', marginTop: 2 }}>
              {correlationConfidence !== undefined ? `${(correlationConfidence * 100).toFixed(0)}%` : '0%'}
            </div>
            <div style={{ fontSize: 10, color: 'var(--text-muted)', marginTop: 2 }}>
              Relationship certainty
            </div>
          </div>

          {/* 4. Analyst Lifecycle Status */}
          <div
            style={{
              background: 'rgba(10, 14, 26, 0.8)',
              border: '1px solid #1A253C',
              borderRadius: 8,
              padding: '10px 12px',
            }}
          >
            <div style={{ fontSize: 10, color: 'var(--text-muted)', fontWeight: 600, textTransform: 'uppercase' }}>
              Analyst Status
            </div>
            <div style={{ fontSize: 13, fontWeight: 800, fontFamily: 'var(--font-mono)', color: '#FBBF24', marginTop: 4 }}>
              {analystStatus}
            </div>
            <div style={{ fontSize: 10, color: 'var(--text-muted)', marginTop: 2 }}>
              Human triage state
            </div>
          </div>
        </div>
      </div>

      {/* Assessment Reasons / Evidence bullets */}
      {assessment.reasons && assessment.reasons.length > 0 && (
        <div
          style={{
            background: 'rgba(10, 14, 26, 0.6)',
            border: '1px solid #1A253C',
            borderRadius: 8,
            padding: '12px 14px',
            display: 'flex',
            flexDirection: 'column',
            gap: 6,
          }}
        >
          <div style={{ fontSize: 11, fontWeight: 600, color: 'var(--text-muted)', display: 'flex', alignItems: 'center', gap: 6 }}>
            <Info size={13} color="#38BDF8" />
            Evaluation Rationales
          </div>
          <ul style={{ margin: 0, paddingLeft: 18, fontSize: 11, color: '#CBD5E1', lineHeight: 1.5 }}>
            {assessment.reasons.map((reason, idx) => (
              <li key={`reason-${idx}`}>{reason}</li>
            ))}
          </ul>
        </div>
      )}
    </div>
  );
}

