'use client';

import React from 'react';

interface DetectionIntelligenceBarsProps {
  totalAnomalies?: number;
  detectionMethods?: string[];
}

const ENGINES = [
  { name: 'Isolation Forest', weight: 92 },
  { name: 'TF-IDF (Log Semantics)', weight: 88 },
  { name: 'Temporal Behaviour', weight: 95 },
  { name: 'Statistical Analysis', weight: 84 },
  { name: 'Rule Engine', weight: 90 },
];

export function DetectionIntelligenceBars({
  totalAnomalies = 0,
  detectionMethods = [],
}: DetectionIntelligenceBarsProps) {
  return (
    <div
      style={{
        backgroundColor: '#11161E',
        border: '1px solid rgba(255, 255, 255, 0.08)',
        borderRadius: 16,
        padding: '24px 28px',
        boxShadow: '0 4px 20px rgba(0, 0, 0, 0.35)',
      }}
      className="flex flex-col h-full font-sans"
    >
      {/* Header */}
      <div className="border-b border-white/[0.06] pb-3 mb-4">
        <h2 className="text-base font-semibold text-white font-heading">
          Detection Intelligence
        </h2>
        <p className="text-xs text-[#94A3B8] font-subheading mt-0.5">
          ML and rule-based detection engine performance
        </p>
      </div>

      {/* Engine Contribution Bars */}
      <div className="space-y-4 flex-1">
        {ENGINES.map((eng) => (
          <div key={eng.name}>
            <div className="flex items-center justify-between text-xs mb-1.5">
              <span className="text-[#94A3B8] font-subheading">{eng.name}</span>
              <span className="font-mono text-white font-medium">{eng.weight}%</span>
            </div>
            <div className="h-1 w-full rounded-full bg-white/[0.06] overflow-hidden">
              <div
                className="h-full rounded-full transition-all duration-700"
                style={{
                  width: `${eng.weight}%`,
                  background: 'linear-gradient(90deg, #38BDF8 0%, #60A5FA 100%)',
                }}
              />
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}
