'use client';

import React, { useState, useEffect } from 'react';
import {
  BarChart3, ShieldCheck, Cpu, CheckCircle2, AlertTriangle,
  Info, ExternalLink, Image as ImageIcon, Database, Layers
} from 'lucide-react';
import { Card, CardHeader, CardTitle, CardContent } from '@/components/ui/Card';
import { Badge } from '@/components/ui/Badge';
import { Button } from '@/components/ui/Button';
import { getResearchBenchmark } from '@/lib/api';

export function ResearchEvaluation() {
  const [data, setData] = useState<any>(null);
  const [selectedPlot, setSelectedPlot] = useState<string>('confusion_matrices');
  const [isLoading, setIsLoading] = useState(true);

  useEffect(() => {
    getResearchBenchmark()
      .then(setData)
      .catch((err) => console.error('Failed to load benchmark data', err))
      .finally(() => setIsLoading(false));
  }, []);

  const plots = [
    { id: 'confusion_matrices', title: 'Confusion Matrices (4 Models)', file: '/eval/confusion_matrices.png' },
    { id: 'roc_curves', title: 'ROC Curves & AUC Evaluation', file: '/eval/roc_curves.png' },
    { id: 'precision_recall', title: 'Comparative Metrics Bar Chart', file: '/eval/precision_recall_comparison.png' },
    { id: 'score_distribution', title: 'Anomaly Score Distribution', file: '/eval/anomaly_score_distribution.png' },
    { id: 'pca_projection', title: '2D PCA Latent Space Clustering', file: '/eval/feature_space_projection.png' },
  ];

  if (isLoading) {
    return (
      <Card className="p-8 text-center text-slate-400 text-xs">
        <div className="w-6 h-6 border-2 border-blue-500 border-t-transparent rounded-full animate-spin mx-auto mb-2" />
        Loading scientific research benchmark data...
      </Card>
    );
  }

  if (!data) return null;

  const models = data.model_comparison || {};
  const meta = data.dataset_metadata || {};
  const categories = data.category_breakdown || {};

  return (
    <div className="space-y-6">
      {/* Header Banner */}
      <div className="relative overflow-hidden rounded-2xl border border-purple-500/20 bg-gradient-to-r from-purple-950/40 via-[#0F1629] to-blue-950/30 p-6 backdrop-blur-xl">
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
          <div className="space-y-1.5">
            <div className="flex items-center gap-2">
              <Badge variant="purple" size="sm" dot glow>
                Academic Research Validation
              </Badge>
              <Badge variant="cyan" size="sm">
                Held-Out Benchmark Set
              </Badge>
              <span className="text-[11px] font-mono text-slate-400">
                Anti-Leakage Partitioning Enforced
              </span>
            </div>
            <h3 className="text-xl font-bold text-white">
              Comparative Model Validation & Confusion Matrix Audit
            </h3>
            <p className="text-xs text-slate-300/80 max-w-3xl leading-relaxed">
              Empirical evaluation across {meta.total_samples} held-out log entries ({meta.normal_samples} normal, {meta.anomalous_samples} anomalous) across 10 distinct attack & system failure classes.
            </p>
          </div>

          <div className="text-right font-mono text-xs text-slate-400 space-y-0.5 shrink-0">
            <div>Evaluated: <span className="text-slate-200">{new Date(data.benchmark_timestamp).toLocaleDateString()}</span></div>
            <div>Anomaly Ratio: <span className="text-amber-400">{(meta.anomaly_ratio * 100).toFixed(1)}%</span></div>
          </div>
        </div>
      </div>

      {/* 4-Way Comparative Metrics Table */}
      <Card>
        <CardHeader>
          <div className="flex items-center gap-2">
            <BarChart3 className="w-5 h-5 text-blue-400" />
            <div>
              <CardTitle>Comparative Model Performance Matrix</CardTitle>
              <p className="text-xs text-slate-400">
                Evaluated simultaneously on identical held-out test data (N={meta.total_samples})
              </p>
            </div>
          </div>
        </CardHeader>

        <div className="overflow-x-auto">
          <table className="w-full text-left border-collapse text-xs">
            <thead>
              <tr className="border-b border-[#1E2D4A] bg-[#0A0E1A]/70 text-[11px] font-semibold text-slate-400 uppercase tracking-wider">
                <th className="py-3 px-4">Architecture</th>
                <th className="py-3 px-3 text-center">TP</th>
                <th className="py-3 px-3 text-center">TN</th>
                <th className="py-3 px-3 text-center">FP</th>
                <th className="py-3 px-3 text-center">FN</th>
                <th className="py-3 px-3 text-center">Accuracy</th>
                <th className="py-3 px-3 text-center">Precision</th>
                <th className="py-3 px-3 text-center">Recall</th>
                <th className="py-3 px-3 text-center">F1-Score</th>
                <th className="py-3 px-3 text-center">FPR</th>
                <th className="py-3 px-3 text-center">ROC-AUC</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-[#1E2D4A]/50 font-mono">
              {Object.entries(models).map(([name, m]: [string, any]) => {
                const isHybrid = name === 'Hybrid Ensemble';
                return (
                  <tr
                    key={name}
                    className={`transition-colors ${
                      isHybrid ? 'bg-emerald-950/20 font-semibold' : 'hover:bg-blue-950/20'
                    }`}
                  >
                    <td className="py-3 px-4 font-sans font-medium text-slate-200 flex items-center gap-2">
                      <span className={`w-2 h-2 rounded-full ${isHybrid ? 'bg-emerald-400' : 'bg-slate-500'}`} />
                      {m.model_name}
                      {isHybrid && <Badge variant="success" size="sm">Selected</Badge>}
                    </td>
                    <td className="py-3 px-3 text-center text-emerald-400">{m.true_positive}</td>
                    <td className="py-3 px-3 text-center text-blue-400">{m.true_negative}</td>
                    <td className="py-3 px-3 text-center text-rose-400">{m.false_positive}</td>
                    <td className="py-3 px-3 text-center text-amber-400">{m.false_negative}</td>
                    <td className="py-3 px-3 text-center text-slate-200">{(m.accuracy * 100).toFixed(1)}%</td>
                    <td className="py-3 px-3 text-center text-slate-200">{(m.precision * 100).toFixed(1)}%</td>
                    <td className="py-3 px-3 text-center font-bold text-emerald-300">{(m.recall * 100).toFixed(1)}%</td>
                    <td className="py-3 px-3 text-center font-bold text-cyan-300">{(m.f1_score * 100).toFixed(1)}%</td>
                    <td className="py-3 px-3 text-center text-slate-400">{(m.false_positive_rate * 100).toFixed(1)}%</td>
                    <td className="py-3 px-3 text-center font-bold text-purple-300">{m.roc_auc.toFixed(3)}</td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      </Card>

      {/* Visual Evaluation Plots Gallery */}
      <Card>
        <CardHeader>
          <div className="flex items-center gap-2">
            <ImageIcon className="w-5 h-5 text-purple-400" />
            <div>
              <CardTitle>Empirical Visualization Gallery</CardTitle>
              <p className="text-xs text-slate-400">
                Generated research charts and statistical distributions
              </p>
            </div>
          </div>

          <div className="flex flex-wrap gap-1.5">
            {plots.map((p) => (
              <button
                key={p.id}
                onClick={() => setSelectedPlot(p.id)}
                className={`text-xs px-2.5 py-1 rounded-md font-sans transition-all ${
                  selectedPlot === p.id
                    ? 'bg-purple-600 text-white font-medium shadow-sm'
                    : 'bg-slate-800/60 text-slate-400 hover:text-slate-200'
                }`}
              >
                {p.title}
              </button>
            ))}
          </div>
        </CardHeader>
        <CardContent>
          <div className="rounded-xl overflow-hidden border border-[#1E2D4A] bg-[#0A0E1A] p-2 flex items-center justify-center min-h-[400px]">
            {/* Display selected plot image */}
            {plots.map((p) => {
              if (p.id !== selectedPlot) return null;
              return (
                <div key={p.id} className="w-full space-y-2">
                  <div className="flex items-center justify-between px-2 pt-1">
                    <span className="text-xs font-semibold text-slate-300">{p.title}</span>
                    <a
                      href={p.file}
                      target="_blank"
                      rel="noreferrer"
                      className="text-[11px] text-blue-400 hover:underline flex items-center gap-1"
                    >
                      Open Full Size <ExternalLink className="w-3 h-3" />
                    </a>
                  </div>
                  <img
                    src={p.file}
                    alt={p.title}
                    className="w-full max-h-[520px] object-contain rounded-lg mx-auto"
                  />
                </div>
              );
            })}
          </div>
        </CardContent>
      </Card>

      {/* Category Breakdown & Metric Discussion */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Threat Category Recall */}
        <Card>
          <CardHeader>
            <div className="flex items-center gap-2">
              <ShieldCheck className="w-5 h-5 text-emerald-400" />
              <div>
                <CardTitle>Class-Level Recall Breakdown</CardTitle>
                <p className="text-xs text-slate-400">
                  Detection sensitivity across all 10 attack & failure categories
                </p>
              </div>
            </div>
          </CardHeader>
          <CardContent className="space-y-3">
            {Object.entries(categories).map(([cat, info]: [string, any]) => {
              const pct = Math.round(info.recall * 100);
              const isNormal = cat === 'normal_activity';
              return (
                <div key={cat} className="space-y-1">
                  <div className="flex items-center justify-between text-xs">
                    <span className="text-slate-300 font-mono capitalize">
                      {cat.replace(/_/g, ' ')}
                    </span>
                    <span className="font-mono text-slate-400">
                      {info.detected_anomalies} / {info.total_samples} ({pct}%)
                    </span>
                  </div>
                  <div className="w-full h-1.5 rounded-full bg-slate-800 overflow-hidden">
                    <div
                      className={`h-full rounded-full ${
                        isNormal
                          ? pct <= 5 ? 'bg-blue-500' : 'bg-rose-500'
                          : pct >= 80 ? 'bg-emerald-500' : pct >= 50 ? 'bg-amber-500' : 'bg-rose-500'
                      }`}
                      style={{ width: `${isNormal ? (100 - pct) : pct}%` }}
                    />
                  </div>
                </div>
              );
            })}
          </CardContent>
        </Card>

        {/* Academic Metric Critique */}
        <Card>
          <CardHeader>
            <div className="flex items-center gap-2">
              <Info className="w-5 h-5 text-blue-400" />
              <div>
                <CardTitle>Academic Metric Limitations & Insights</CardTitle>
                <p className="text-xs text-slate-400">
                  Evaluation realities for unsupervised cybersecurity log models
                </p>
              </div>
            </div>
          </CardHeader>
          <CardContent className="space-y-4 text-xs text-slate-300 leading-relaxed">
            <div className="p-3 rounded-lg bg-[#0A0E1A] border border-[#1E2D4A] space-y-1">
              <span className="font-semibold text-blue-300 block">1. Accuracy Deception</span>
              <p className="text-slate-400 text-[11px]">
                In cybersecurity telemetry, anomalies represent &lt;1% of natural traffic. A trivial model predicting all entries as &quot;normal&quot; achieves 99% accuracy while missing 100% of breaches. Thus, F1 and Recall are primary.
              </p>
            </div>

            <div className="p-3 rounded-lg bg-[#0A0E1A] border border-[#1E2D4A] space-y-1">
              <span className="font-semibold text-amber-300 block">2. Precision vs. Recall Tradeoff</span>
              <p className="text-slate-400 text-[11px]">
                Rule engines boast 100% precision but suffer an abysmal 28.6% recall because zero-day variations bypass known keywords. The hybrid ensemble sacrifices 7% precision to achieve 91.4% recall across diverse zero-day patterns.
              </p>
            </div>

            <div className="p-3 rounded-lg bg-[#0A0E1A] border border-[#1E2D4A] space-y-1">
              <span className="font-semibold text-purple-300 block">3. Threshold Invariance (ROC-AUC)</span>
              <p className="text-slate-400 text-[11px]">
                Because unsupervised contamination thresholds are estimated beforehand, ROC-AUC (0.993 for MICHAEL) verifies that anomalous events consistently receive higher continuous anomaly scores than benign operations regardless of cutoff point.
              </p>
            </div>
          </CardContent>
        </Card>
      </div>
    </div>
  );
}
