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
        backgroundColor: '#1C242B',
        border: '1px solid rgba(212, 175, 55, 0.14)',
        borderRadius: '14px',
        padding: '24px',
        boxShadow: '0 4px 16px rgba(0, 0, 0, 0.4)',
      }}
      className="flex flex-col justify-between h-full space-y-4 font-sans"
    >
      {/* Header */}
      <div className="border-b border-[rgba(212,175,55,0.1)] pb-4">
        <h2 className="text-base font-semibold text-[#FAF9F5] font-heading">
          Detection Intelligence
        </h2>
        <p className="text-xs text-[#D1CBC0] font-subheading font-light mt-1">
          ML and rule-based detection engines
        </p>
      </div>

      {/* Engine Contribution Bars in Celestial Gold */}
      <div className="space-y-3.5 my-auto">
        {ENGINES.map((eng) => (
          <div key={eng.name} className="space-y-1.5">
            <div className="flex items-center justify-between text-xs font-subheading">
              <span className="text-[#D1CBC0] font-medium">{eng.name}</span>
              <span className="text-[#FAF9F5] font-mono font-semibold">{eng.weight}%</span>
            </div>

            {/* Clean Progress track */}
            <div className="h-2 w-full rounded-full bg-[#141A1F] border border-[rgba(212,175,55,0.08)] overflow-hidden">
              <div
                className="h-full rounded-full transition-all duration-700"
                style={{
                  width: `${eng.weight}%`,
                  background: 'linear-gradient(90deg, #D4AF37 0%, #E8C868 100%)',
                  boxShadow: '0 0 8px rgba(212, 175, 55, 0.4)',
                }}
              />
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}
