'use client';

import React from 'react';
import { Cpu, Zap, Timer, CheckCircle, Database } from 'lucide-react';
import { Badge } from '@/components/ui/Badge';
import { ModelMetrics as ModelMetricsType } from '@/types';

interface ModelMetricsProps {
  metrics: ModelMetricsType | null;
}

export function ModelMetrics({ metrics }: ModelMetricsProps) {
  if (!metrics) {
    return (
      <div
        style={{
          backgroundColor: '#0C1119',
          border: '1px solid rgba(255, 255, 255, 0.08)',
          borderRadius: '12px',
          padding: '24px',
        }}
        className="text-center text-[#A7B1C0] text-xs font-sans"
      >
        No ML evaluation metrics available yet. Run anomaly detection to train and evaluate the pipeline.
      </div>
    );
  }

  return (
    <div
      style={{
        backgroundColor: '#11161E',
        border: '1px solid rgba(255, 255, 255, 0.08)',
        borderRadius: '16px',
        padding: '24px',
        boxShadow: '0 4px 20px rgba(0, 0, 0, 0.35)',
      }}
      className="space-y-4 font-sans"
    >
      <div className="flex items-center justify-between border-b border-white/[0.06] pb-3.5">
        <div className="flex items-center gap-2.5">
          <div className="w-8 h-8 rounded-lg bg-blue-500/10 border border-blue-500/20 flex items-center justify-center text-[#3B82F6]">
            <Cpu size={16} />
          </div>
          <div>
            <h3 className="text-sm font-semibold text-[#F5F7FA]">
              ML Engine Telemetry & Pipeline Parameters
            </h3>
            <p className="text-xs text-[#A7B1C0] mt-0.5">
              Unsupervised multi-model ensemble detection configuration
            </p>
          </div>
        </div>
        <Badge variant="purple" size="sm" dot>
          Scikit-Learn Ensemble
        </Badge>
      </div>

      {/* Core KPIs */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
        <div className="p-3 rounded-lg bg-[#080C12] border border-white/[0.06]">
          <div className="text-xs text-[#A7B1C0] flex items-center gap-1.5">
            <Database className="w-3.5 h-3.5 text-[#3B82F6]" /> Total Vectors
          </div>
          <div className="text-lg font-bold font-mono text-[#F5F7FA] mt-1">
            {metrics.total_logs}
          </div>
        </div>

        <div className="p-3 rounded-lg bg-[#080C12] border border-white/[0.06]">
          <div className="text-xs text-[#A7B1C0] flex items-center gap-1.5">
            <CheckCircle className="w-3.5 h-3.5 text-[#F59E0B]" /> Outliers Detected
          </div>
          <div className="text-lg font-bold font-mono text-[#F59E0B] mt-1">
            {metrics.anomalies_detected}
          </div>
        </div>

        <div className="p-3 rounded-lg bg-[#080C12] border border-white/[0.06]">
          <div className="text-xs text-[#A7B1C0] flex items-center gap-1.5">
            <Zap className="w-3.5 h-3.5 text-[#22B8FF]" /> Contamination
          </div>
          <div className="text-lg font-bold font-mono text-[#22B8FF] mt-1">
            {(metrics.contamination_rate * 100).toFixed(1)}%
          </div>
        </div>

        <div className="p-3 rounded-lg bg-[#080C12] border border-white/[0.06]">
          <div className="text-xs text-[#A7B1C0] flex items-center gap-1.5">
            <Timer className="w-3.5 h-3.5 text-[#22C55E]" /> Fit & Inference
          </div>
          <div className="text-lg font-bold font-mono text-[#22C55E] mt-1">
            {metrics.training_time_ms != null ? `${metrics.training_time_ms.toFixed(1)}ms` : `${(metrics.analysis_duration_seconds * 1000).toFixed(1)}ms`}
          </div>
        </div>
      </div>
    </div>
  );
}
