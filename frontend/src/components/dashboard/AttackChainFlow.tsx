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
  ExternalLink,
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
    accent: '#38BDF8',
  },
  {
    code: 'T1110',
    title: 'Credential Access',
    icon: Lock,
    accent: '#FBBF24',
  },
  {
    code: 'T1059',
    title: 'Execution',
    icon: Code2,
    accent: '#A78BFA',
  },
  {
    code: 'T1071',
    title: 'Command & Control',
    icon: Radio,
    accent: '#F472B6',
  },
  {
    code: 'T1041',
    title: 'Exfiltration',
    icon: Database,
    accent: '#F87171',
  },
];

export function AttackChainFlow({ chains, isLoading }: AttackChainFlowProps) {
  const activeChain = chains && chains.length > 0 ? chains[0] : null;

  return (
    <div
      style={{
        backgroundColor: '#11161E',
        border: '1px solid rgba(255, 255, 255, 0.08)',
        borderRadius: 16,
        padding: '24px 28px',
        boxShadow: '0 4px 20px rgba(0, 0, 0, 0.35)',
      }}
      className="flex flex-col justify-between font-sans w-full"
    >
      {/* Header */}
      <div className="flex items-center justify-between border-b border-white/[0.06] pb-3 mb-5">
        <div>
          <div className="flex items-center gap-2">
            <h2 className="text-base font-semibold text-white font-heading">
              Attack Chain Reconstruction
            </h2>
            <span className="text-[10px] font-mono uppercase px-2 py-0.5 rounded bg-white/[0.06] text-[#94A3B8] border border-white/[0.08]">
              MITRE ATT&CK
            </span>
          </div>
          <p className="text-xs text-[#94A3B8] font-subheading mt-0.5 leading-relaxed">
            Automated multi-stage temporal correlation<br />and adversary progression mapping
          </p>
        </div>

        <Link
          href="/attack-chains"
          className="text-xs text-[#94A3B8] hover:text-white flex items-center gap-1 transition-colors"
        >
          <span>Interactive Graph</span>
          <ExternalLink size={12} />
        </Link>
      </div>

      {/* 5-Stage Minimalist Progression */}
      <div className="grid grid-cols-1 md:grid-cols-5 gap-3 relative">
        {STAGES_PIPELINE.map((stage, idx) => {
          const Icon = stage.icon;
          const isTarget = activeChain ? idx <= ((activeChain.stages_observed?.length ?? 0) || 2) : idx < 3;

          return (
            <div
              key={stage.code}
              style={{
                backgroundColor: isTarget ? '#161D26' : '#0D1117',
                border: isTarget
                  ? '1px solid rgba(255, 255, 255, 0.12)'
                  : '1px solid rgba(255, 255, 255, 0.04)',
                borderRadius: 8,
                padding: '14px 16px',
              }}
              className="flex flex-col justify-between transition-colors relative"
            >
              <div className="flex items-center justify-between mb-2">
                <div
                  style={{
                    color: stage.accent,
                    backgroundColor: 'rgba(255, 255, 255, 0.05)',
                    padding: 6,
                    borderRadius: 6,
                  }}
                >
                  <Icon size={16} />
                </div>
                <span className="font-mono text-[11px] text-[#64748B]">{stage.code}</span>
              </div>

              <div>
                <h4 className="text-xs font-semibold text-white tracking-tight">
                  {stage.title}
                </h4>
                <div className="flex items-center gap-1.5 mt-1">
                  <span
                    className="w-1.5 h-1.5 rounded-full"
                    style={{ backgroundColor: isTarget ? stage.accent : '#475569' }}
                  />
                  <span className="text-[11px] font-subheading text-[#94A3B8]">
                    {isTarget ? 'Correlated' : 'Inactive'}
                  </span>
                </div>
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}
