'use client';

import React from 'react';
import Link from 'next/link';
import {
  Laptop,
  Lock,
  Code2,
  Radio,
  Database,
  ArrowRight,
} from 'lucide-react';
import { AttackChain } from '@/types';

interface AttackChainFlowProps {
  chains: AttackChain[];
  isLoading?: boolean;
}

const STAGES_PIPELINE = [
  {
    code: 'T1190',
    title: 'Initial Access',
    icon: Laptop,
    accent: '#D4AF37',
    border: 'rgba(212, 175, 55, 0.4)',
    bg: 'rgba(212, 175, 55, 0.12)',
  },
  {
    code: 'T1110',
    title: 'Credential Access',
    icon: Lock,
    accent: '#E5C07B',
    border: 'rgba(229, 192, 123, 0.4)',
    bg: 'rgba(229, 192, 123, 0.12)',
  },
  {
    code: 'T1059',
    title: 'Execution',
    icon: Code2,
    accent: '#38BDF8',
    border: 'rgba(56, 189, 248, 0.4)',
    bg: 'rgba(56, 189, 248, 0.12)',
  },
  {
    code: 'T1071',
    title: 'Command & Control',
    icon: Radio,
    accent: '#A78BFA',
    border: 'rgba(167, 139, 250, 0.4)',
    bg: 'rgba(167, 139, 250, 0.12)',
  },
  {
    code: 'T1041',
    title: 'Exfiltration',
    icon: Database,
    accent: '#EF4444',
    border: 'rgba(239, 68, 68, 0.4)',
    bg: 'rgba(239, 68, 68, 0.12)',
  },
];

export function AttackChainFlow({ chains, isLoading = false }: AttackChainFlowProps) {
  return (
    <div
      style={{
        backgroundColor: '#1C242B',
        border: '1px solid rgba(212, 175, 55, 0.14)',
        borderRadius: '14px',
        padding: '24px',
        boxShadow: '0 4px 16px rgba(0, 0, 0, 0.4)',
      }}
      className="space-y-5 font-sans h-full flex flex-col justify-between"
    >
      {/* Header */}
      <div className="flex flex-wrap items-center justify-between gap-3 border-b border-[rgba(212,175,55,0.1)] pb-4">
        <div>
          <div className="flex items-center gap-2.5">
            <h2 className="text-base font-semibold text-[#FAF9F5] font-heading">
              Attack Chain Reconstruction
            </h2>
            <span
              style={{
                backgroundColor: 'rgba(212, 175, 55, 0.12)',
                border: '1px solid rgba(212, 175, 55, 0.3)',
                color: '#D4AF37',
              }}
              className="text-[10px] font-subheading px-2.5 py-0.5 rounded-full font-semibold"
            >
              MITRE ATT&CK
            </span>
          </div>
          <p className="text-xs text-[#D1CBC0] font-subheading font-light mt-1">
            Correlated event sequence and MITRE attack stages
          </p>
        </div>

        <Link
          href="/attack-chains"
          className="text-xs text-[#D4AF37] hover:text-[#E5C07B] flex items-center gap-1.5 transition-colors font-subheading font-medium"
        >
          <span>View Details</span>
          <ArrowRight className="h-3.5 w-3.5" />
        </Link>
      </div>

      {/* Connected 5-Stage Pipeline */}
      <div className="flex items-center justify-between gap-2 overflow-x-auto py-2">
        {STAGES_PIPELINE.map((stage, idx) => {
          const Icon = stage.icon;
          const isLast = idx === STAGES_PIPELINE.length - 1;

          return (
            <React.Fragment key={stage.code}>
              <div
                style={{
                  backgroundColor: stage.bg,
                  border: `1px solid ${stage.border}`,
                  boxShadow: `0 0 16px ${stage.accent}15`,
                }}
                className="flex-1 min-w-[120px] rounded-xl p-3.5 flex flex-col items-center justify-center text-center transition-all hover:scale-[1.02]"
              >
                <div
                  className="w-8 h-8 rounded-lg flex items-center justify-center mb-2"
                  style={{
                    backgroundColor: `${stage.accent}20`,
                    color: stage.accent,
                  }}
                >
                  <Icon size={16} color={stage.accent} />
                </div>

                <div className="text-xs font-semibold text-[#FAF9F5] font-subheading leading-snug">
                  {stage.title}
                </div>

                <div
                  className="font-mono text-[10px] mt-1 font-medium tracking-wider"
                  style={{ color: stage.accent }}
                >
                  {stage.code}
                </div>
              </div>

              {!isLast && (
                <div className="shrink-0 text-[#8E877D] px-0.5">
                  <ArrowRight size={14} className="opacity-60" />
                </div>
              )}
            </React.Fragment>
          );
        })}
      </div>
    </div>
  );
}

export const AttackChainReconstruction = AttackChainFlow;
