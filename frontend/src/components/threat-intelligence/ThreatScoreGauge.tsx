'use client';

import React from 'react';
import type { ThreatSeverity } from '@/types';

interface ThreatScoreGaugeProps {
  score: number;
  severity: ThreatSeverity;
  confidence?: number;
  size?: number;
}

export function ThreatScoreGauge({
  score,
  severity,
  confidence,
  size = 140,
}: ThreatScoreGaugeProps) {
  const boundedScore = Math.max(0, Math.min(100, Math.round(score)));

  // Color mapping based on severity
  const getColor = (sev: ThreatSeverity) => {
    switch (sev) {
      case 'CRITICAL':
        return '#EF4444'; // Red
      case 'HIGH':
        return '#F97316'; // Orange
      case 'MEDIUM':
        return '#F59E0B'; // Amber
      case 'LOW':
        return '#10B981'; // Green
      case 'UNKNOWN':
      default:
        return '#64748B'; // Slate
    }
  };

  const color = getColor(severity);
  const strokeWidth = 10;
  const radius = (size - strokeWidth * 2) / 2;
  const circumference = 2 * Math.PI * radius;
  // Use a 270-degree arc for dashboard feel
  const arcPercentage = 0.75;
  const totalArc = circumference * arcPercentage;
  const strokeDashoffset = totalArc - (boundedScore / 100) * totalArc;

  return (
    <div
      style={{
        display: 'flex',
        flexDirection: 'column',
        alignItems: 'center',
        justifyContent: 'center',
        position: 'relative',
        width: size,
        height: size,
      }}
    >
      <svg
        width={size}
        height={size}
        viewBox={`0 0 ${size} ${size}`}
        style={{ transform: 'rotate(135deg)', overflow: 'visible' }}
      >
        {/* Background Track */}
        <circle
          cx={size / 2}
          cy={size / 2}
          r={radius}
          fill="none"
          stroke="#1E293B"
          strokeWidth={strokeWidth}
          strokeDasharray={`${totalArc} ${circumference}`}
          strokeLinecap="round"
        />
        {/* Progress Arc */}
        <circle
          cx={size / 2}
          cy={size / 2}
          r={radius}
          fill="none"
          stroke={color}
          strokeWidth={strokeWidth}
          strokeDasharray={`${totalArc} ${circumference}`}
          strokeDashoffset={strokeDashoffset}
          strokeLinecap="round"
          style={{
            transition: 'stroke-dashoffset 0.8s ease-in-out, stroke 0.4s ease',
            filter: `drop-shadow(0 0 6px ${color}55)`,
          }}
        />
      </svg>

      {/* Center Metrics Display */}
      <div
        style={{
          position: 'absolute',
          display: 'flex',
          flexDirection: 'column',
          alignItems: 'center',
          justifyContent: 'center',
          textAlign: 'center',
        }}
      >
        <span
          style={{
            fontSize: size * 0.24,
            fontWeight: 800,
            fontFamily: 'var(--font-mono)',
            color,
            lineHeight: 1,
            letterSpacing: '-0.03em',
          }}
        >
          {boundedScore}
        </span>
        <span
          style={{
            fontSize: 9,
            fontWeight: 700,
            letterSpacing: '0.08em',
            textTransform: 'uppercase',
            color: 'var(--text-muted)',
            marginTop: 4,
          }}
        >
          / 100
        </span>
        <div
          style={{
            marginTop: 4,
            fontSize: 9,
            fontWeight: 700,
            letterSpacing: '0.06em',
            padding: '1px 6px',
            borderRadius: 4,
            background: `${color}18`,
            border: `1px solid ${color}40`,
            color,
            textTransform: 'uppercase',
          }}
        >
          {severity}
        </div>
        {confidence !== undefined && (
          <span
            style={{
              fontSize: 9,
              color: 'var(--text-muted)',
              fontFamily: 'var(--font-mono)',
              marginTop: 2,
            }}
          >
            Conf: {(confidence * 100).toFixed(0)}%
          </span>
        )}
      </div>
    </div>
  );
}

