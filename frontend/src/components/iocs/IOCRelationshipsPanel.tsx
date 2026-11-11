'use client';

import React, { useEffect, useState } from 'react';
import { Server, Activity, AlertTriangle, ShieldAlert, GitFork, AlertCircle, ExternalLink } from 'lucide-react';
import Link from 'next/link';
import { getIOCRelationships } from '@/lib/api';
import type { IOCRelationships } from '@/types';
import { formatDateTime } from '@/lib/utils';

interface Props {
  iocId: string;
}

export function IOCRelationshipsPanel({ iocId }: Props) {
  const [data, setData] = useState<IOCRelationships | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    setLoading(true);
    setError(null);
    getIOCRelationships(iocId)
      .then(setData)
      .catch((e: Error) => setError(e.message))
      .finally(() => setLoading(false));
  }, [iocId]);

  if (loading) {
    return (
      <div className="animate-pulse" style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
        {[1, 2, 3].map(i => <div key={i} style={{ height: 48, background: '#0F1629', borderRadius: 8 }} />)}
      </div>
    );
  }

  if (error) {
    return (
      <div style={{ padding: 20, textAlign: 'center', color: '#EF4444' }}>
        <AlertCircle size={28} style={{ display: 'block', margin: '0 auto 8px', opacity: 0.6 }} />
        <div style={{ fontSize: 13 }}>Failed to load relationships: {error}</div>
      </div>
    );
  }

  if (!data || data.relationship_count === 0) {
    return (
      <div style={{ padding: 40, textAlign: 'center', color: 'var(--text-muted)' }}>
        <GitFork size={32} style={{ display: 'block', margin: '0 auto 10px', opacity: 0.3 }} />
        <div style={{ fontSize: 13 }}>No linked investigation objects</div>
        <div style={{ fontSize: 11, marginTop: 4 }}>Relationships are only surfaced when evidence explicitly references them</div>
      </div>
    );
  }

  const Section = ({ title, icon: Icon, color, count, children }: { title: string; icon: React.ComponentType<{ size?: number; color?: string }>; color: string; count: number; children: React.ReactNode }) => count === 0 ? null : (
    <div style={{ marginBottom: 18 }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: 6, marginBottom: 8 }}>
        <Icon size={13} color={color} />
        <span style={{ fontSize: 11, fontWeight: 700, letterSpacing: '0.07em', textTransform: 'uppercase', color }}>{title}</span>
        <span style={{ fontSize: 10, background: color + '18', border: `1px solid ${color}35`, color, padding: '0px 5px', borderRadius: 10, fontFamily: 'var(--font-mono)' }}>{count}</span>
      </div>
      {children}
    </div>
  );

  const renderPill = (content: React.ReactNode, href?: string, key?: string | number) => {
    const inner = (
      <div style={{ background: '#0A0E1A', border: '1px solid #1E2D4A', borderRadius: 7, padding: '7px 12px', fontSize: 11, color: 'var(--text-secondary)', fontFamily: 'var(--font-mono)', display: 'flex', alignItems: 'center', gap: 6, marginBottom: 6, cursor: href ? 'pointer' : 'default' }}>
        {content}
        {href && <ExternalLink size={10} style={{ marginLeft: 'auto', color: 'var(--text-muted)' }} />}
      </div>
    );
    return href ? <Link key={key} href={href} style={{ textDecoration: 'none' }}>{inner}</Link> : <div key={key}>{inner}</div>;
  };

  return (
    <div>
      <div style={{ fontSize: 11, color: 'var(--text-muted)', marginBottom: 16 }}>
        {data.relationship_count} evidence-backed link{data.relationship_count !== 1 ? 's' : ''} across investigation objects
      </div>

      <Section title="Source Sessions" icon={Server} color="#60A5FA" count={data.sessions.length}>
        {data.sessions.map((s, idx) => renderPill(<><Server size={11} color="#60A5FA" /><span>{s.session_id}</span></>, undefined, idx))}
      </Section>

      <Section title="Log Events" icon={Activity} color="#A78BFA" count={data.events.length}>
        {data.events.map((e, idx) => renderPill(
          <>
            <Activity size={11} color="#A78BFA" />
            <span style={{ color: 'var(--text-primary)' }}>{e.event_id}</span>
            {e.line_number !== null && <span style={{ color: 'var(--text-muted)', fontSize: 10 }}>· Line {e.line_number}</span>}
            {e.timestamp && <span style={{ color: 'var(--text-muted)', fontSize: 10 }}>· {formatDateTime(e.timestamp)}</span>}
          </>,
          undefined,
          idx
        ))}
      </Section>

      <Section title="Anomalies" icon={AlertTriangle} color="#F59E0B" count={data.anomalies.length}>
        {data.anomalies.map((a, idx) => renderPill(
          <><AlertTriangle size={11} color="#F59E0B" /><span>{a.anomaly_id}</span></>,
          `/anomalies`,
          idx
        ))}
      </Section>

      <Section title="Incidents" icon={ShieldAlert} color="#EF4444" count={data.incidents.length}>
        {data.incidents.map((i, idx) => renderPill(
          <><ShieldAlert size={11} color="#EF4444" /><span>{i.incident_id}</span></>,
          `/incidents`,
          idx
        ))}
      </Section>

      <Section title="Attack Chains" icon={GitFork} color="#8B5CF6" count={data.attack_chains.length}>
        {data.attack_chains.map((c, idx) => renderPill(
          <><GitFork size={11} color="#8B5CF6" /><span>{c.chain_id}</span></>,
          `/attack-chains`,
          idx
        ))}
      </Section>
    </div>
  );
}

