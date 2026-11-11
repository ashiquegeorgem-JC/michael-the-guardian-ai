'use client';

import { useRef, useState, useCallback, useEffect } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import type { AttackGraphData, AttackGraphNode, AttackGraphEdge } from '@/types';
import { Shield, Server, User, Cpu, AlertTriangle, Activity } from 'lucide-react';

// ── Node Type Config ───────────────────────────────────────────────────────

const NODE_CONFIG: Record<string, { color: string; glow: string; icon: React.ElementType; bg: string }> = {
  source_ip:    { color: '#EF4444', glow: 'rgba(239,68,68,0.6)',    icon: AlertTriangle, bg: 'rgba(239,68,68,0.15)' },
  target_host:  { color: '#F97316', glow: 'rgba(249,115,22,0.6)',   icon: Server,        bg: 'rgba(249,115,22,0.15)' },
  user_account: { color: '#8B5CF6', glow: 'rgba(139,92,246,0.6)',   icon: User,          bg: 'rgba(139,92,246,0.15)' },
  process:      { color: '#06B6D4', glow: 'rgba(6,182,212,0.6)',    icon: Cpu,           bg: 'rgba(6,182,212,0.15)' },
  attack_stage: { color: '#3B82F6', glow: 'rgba(59,130,246,0.6)',   icon: Activity,      bg: 'rgba(59,130,246,0.15)' },
  incident:     { color: '#EC4899', glow: 'rgba(236,72,153,0.6)',   icon: Shield,        bg: 'rgba(236,72,153,0.15)' },
  endpoint:     { color: '#10B981', glow: 'rgba(16,185,129,0.6)',   icon: Server,        bg: 'rgba(16,185,129,0.15)' },
};

const NODE_W = 120;
const NODE_H = 60;
const PADDING = 80;

// ── Layout: force-like spiral placement ───────────────────────────────────

function computeLayout(nodes: AttackGraphNode[]): Record<string, { x: number; y: number }> {
  const positions: Record<string, { x: number; y: number }> = {};

  // Group by type for structured layout
  const stageNodes = nodes.filter(n => n.type === 'attack_stage');
  const ipNodes    = nodes.filter(n => n.type === 'source_ip');
  const otherNodes = nodes.filter(n => !['attack_stage', 'source_ip'].includes(n.type));

  const totalW = Math.max(900, nodes.length * (NODE_W + PADDING));
  const centerY = 320;

  // Stages in a top arc
  stageNodes.forEach((n, i) => {
    const t = stageNodes.length === 1 ? 0.5 : i / (stageNodes.length - 1);
    positions[n.id] = {
      x: PADDING + t * (totalW - NODE_W - PADDING * 2),
      y: 60,
    };
  });

  // Source IPs bottom-left cluster
  ipNodes.forEach((n, i) => {
    positions[n.id] = {
      x: PADDING + i * (NODE_W + 20),
      y: centerY + 160,
    };
  });

  // Other nodes spread in the middle
  const midNodes = otherNodes;
  const midStep = midNodes.length > 0 ? (totalW - NODE_W - PADDING * 2) / Math.max(1, midNodes.length - 1) : 0;
  midNodes.forEach((n, i) => {
    positions[n.id] = {
      x: PADDING + i * midStep,
      y: centerY + (i % 2 === 0 ? 0 : 80),
    };
  });

  return positions;
}

// ── Bezier edge path ─────────────────────────────────────────────────────

function edgePath(
  sx: number, sy: number, tx: number, ty: number
): string {
  const cx = (sx + tx) / 2;
  const cy1 = sy;
  const cy2 = ty;
  return `M ${sx + NODE_W / 2} ${sy + NODE_H / 2} C ${cx} ${cy1 + NODE_H / 2}, ${cx} ${cy2 + NODE_H / 2}, ${tx + NODE_W / 2} ${ty + NODE_H / 2}`;
}

// ── Inspector Panel ───────────────────────────────────────────────────────

function NodeInspector({
  node,
  onClose,
}: {
  node: AttackGraphNode;
  onClose: () => void;
}) {
  const cfg = NODE_CONFIG[node.type] || NODE_CONFIG.attack_stage;
  const Icon = cfg.icon;

  return (
    <motion.div
      initial={{ opacity: 0, x: 20 }}
      animate={{ opacity: 1, x: 0 }}
      exit={{ opacity: 0, x: 20 }}
      style={{
        position: 'absolute',
        top: 12,
        right: 12,
        width: 260,
        background: 'rgba(10,14,26,0.96)',
        border: `1px solid ${cfg.color}55`,
        borderRadius: 12,
        padding: 16,
        boxShadow: `0 0 24px ${cfg.glow}`,
        zIndex: 10,
      }}
    >
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 12 }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
          <div style={{ background: cfg.bg, borderRadius: 8, padding: 6, display: 'flex' }}>
            <Icon size={14} color={cfg.color} />
          </div>
          <span style={{ color: cfg.color, fontWeight: 700, fontSize: 12, textTransform: 'uppercase', letterSpacing: 1 }}>
            {node.type.replace('_', ' ')}
          </span>
        </div>
        <button
          onClick={onClose}
          style={{ background: 'none', border: 'none', color: '#64748B', cursor: 'pointer', fontSize: 18, lineHeight: 1 }}
        >×</button>
      </div>
      <p style={{ color: '#E2E8F0', fontWeight: 600, fontSize: 13, marginBottom: 8 }}>{node.label}</p>
      {Object.entries(node.details).map(([k, v]) => (
        <div key={k} style={{ display: 'flex', gap: 8, marginBottom: 4 }}>
          <span style={{ color: '#64748B', fontSize: 11, minWidth: 80 }}>{k}</span>
          <span style={{ color: '#94A3B8', fontSize: 11, wordBreak: 'break-all' }}>{String(v)}</span>
        </div>
      ))}
      {node.severity && (
        <div style={{ marginTop: 10, background: cfg.bg, borderRadius: 6, padding: '4px 8px', display: 'inline-block' }}>
          <span style={{ color: cfg.color, fontSize: 11, fontWeight: 700 }}>Severity: {node.severity}</span>
        </div>
      )}
    </motion.div>
  );
}

// ── Main Component ─────────────────────────────────────────────────────────

export function AttackGraph({ data }: { data: AttackGraphData }) {
  const svgRef = useRef<SVGSVGElement>(null);
  const [positions, setPositions] = useState<Record<string, { x: number; y: number }>>({});
  const [selected, setSelected] = useState<AttackGraphNode | null>(null);
  const [zoom, setZoom] = useState(1);
  const [pan, setPan] = useState({ x: 0, y: 0 });
  const [dragging, setDragging] = useState<string | null>(null);
  const [dragOffset, setDragOffset] = useState({ x: 0, y: 0 });

  // Compute initial layout
  useEffect(() => {
    if (data.nodes.length > 0) {
      setPositions(computeLayout(data.nodes));
    }
  }, [data.nodes]);

  const svgWidth = Math.max(900, data.nodes.length * (NODE_W + PADDING + 20));
  const svgHeight = 560;

  // Dragging nodes
  const onNodeMouseDown = useCallback((e: React.MouseEvent, nodeId: string) => {
    e.stopPropagation();
    const pos = positions[nodeId];
    if (!pos) return;
    const rect = svgRef.current?.getBoundingClientRect();
    if (!rect) return;
    setDragging(nodeId);
    setDragOffset({
      x: (e.clientX - rect.left) / zoom - pan.x - pos.x,
      y: (e.clientY - rect.top) / zoom - pan.y - pos.y,
    });
  }, [positions, zoom, pan]);

  const onMouseMove = useCallback((e: React.MouseEvent) => {
    if (!dragging || !svgRef.current) return;
    const rect = svgRef.current.getBoundingClientRect();
    const newX = (e.clientX - rect.left) / zoom - pan.x - dragOffset.x;
    const newY = (e.clientY - rect.top) / zoom - pan.y - dragOffset.y;
    setPositions(prev => ({ ...prev, [dragging]: { x: newX, y: newY } }));
  }, [dragging, zoom, pan, dragOffset]);

  const onMouseUp = useCallback(() => setDragging(null), []);

  if (data.nodes.length === 0) {
    return (
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', height: 300, color: '#475569', fontSize: 14 }}>
        No graph data available. Run analysis to generate attack chain graphs.
      </div>
    );
  }

  return (
    <div style={{ position: 'relative', width: '100%', overflow: 'hidden', borderRadius: 12, background: 'rgba(2,6,23,0.8)' }}>
      {/* Controls */}
      <div style={{ position: 'absolute', top: 12, left: 12, display: 'flex', gap: 8, zIndex: 5 }}>
        {[
          { label: '+', action: () => setZoom(z => Math.min(z + 0.2, 2.5)) },
          { label: '−', action: () => setZoom(z => Math.max(z - 0.2, 0.3)) },
          { label: '⊙', action: () => { setZoom(1); setPan({ x: 0, y: 0 }); } },
        ].map(btn => (
          <button
            key={btn.label}
            onClick={btn.action}
            style={{
              background: 'rgba(30,41,59,0.9)',
              border: '1px solid rgba(59,130,246,0.3)',
              color: '#94A3B8',
              borderRadius: 8,
              width: 32,
              height: 32,
              cursor: 'pointer',
              fontSize: 16,
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
            }}
          >{btn.label}</button>
        ))}
        <span style={{ color: '#475569', fontSize: 11, alignSelf: 'center', marginLeft: 4 }}>
          Drag nodes to rearrange
        </span>
      </div>

      {/* SVG Canvas */}
      <div style={{ overflow: 'auto', cursor: dragging ? 'grabbing' : 'default' }}>
        <svg
          ref={svgRef}
          width={svgWidth}
          height={svgHeight}
          onMouseMove={onMouseMove}
          onMouseUp={onMouseUp}
          onMouseLeave={onMouseUp}
          style={{ display: 'block', minWidth: '100%' }}
        >
          <defs>
            <marker id="arrowhead" markerWidth="10" markerHeight="7" refX="9" refY="3.5" orient="auto">
              <polygon points="0 0, 10 3.5, 0 7" fill="#3B82F6" opacity={0.8} />
            </marker>
            <filter id="glow-red">
              <feGaussianBlur stdDeviation="3" result="coloredBlur" />
              <feMerge><feMergeNode in="coloredBlur" /><feMergeNode in="SourceGraphic" /></feMerge>
            </filter>
            <filter id="glow-blue">
              <feGaussianBlur stdDeviation="2.5" result="coloredBlur" />
              <feMerge><feMergeNode in="coloredBlur" /><feMergeNode in="SourceGraphic" /></feMerge>
            </filter>
          </defs>

          <g transform={`translate(${pan.x}, ${pan.y}) scale(${zoom})`}>
            {/* Edges */}
            {data.edges.map(edge => {
              const sp = positions[edge.source];
              const tp = positions[edge.target];
              if (!sp || !tp) return null;
              return (
                <g key={edge.id}>
                  <path
                    d={edgePath(sp.x, sp.y, tp.x, tp.y)}
                    fill="none"
                    stroke="#3B82F6"
                    strokeWidth={1.5}
                    strokeOpacity={0.6}
                    strokeDasharray="6 3"
                    markerEnd="url(#arrowhead)"
                  />
                  {/* Edge label */}
                  {edge.label && (
                    <text
                      x={((sp.x + tp.x) / 2) + NODE_W / 2}
                      y={((sp.y + tp.y) / 2) + NODE_H / 2 - 6}
                      textAnchor="middle"
                      fill="#64748B"
                      fontSize={9}
                      fontFamily="monospace"
                    >{edge.label}</text>
                  )}
                </g>
              );
            })}

            {/* Nodes */}
            {data.nodes.map(node => {
              const pos = positions[node.id];
              if (!pos) return null;
              const cfg = NODE_CONFIG[node.type] || NODE_CONFIG.attack_stage;
              const Icon = cfg.icon;
              const isSelected = selected?.id === node.id;

              return (
                <g
                  key={node.id}
                  transform={`translate(${pos.x}, ${pos.y})`}
                  style={{ cursor: 'pointer' }}
                  onMouseDown={(e) => onNodeMouseDown(e, node.id)}
                  onClick={() => setSelected(isSelected ? null : node)}
                >
                  {/* Glow ring when selected */}
                  {isSelected && (
                    <rect
                      x={-4} y={-4}
                      width={NODE_W + 8} height={NODE_H + 8}
                      rx={14} ry={14}
                      fill="none"
                      stroke={cfg.color}
                      strokeWidth={2}
                      opacity={0.8}
                      filter={node.type === 'source_ip' ? 'url(#glow-red)' : 'url(#glow-blue)'}
                    />
                  )}
                  {/* Node body */}
                  <rect
                    width={NODE_W} height={NODE_H}
                    rx={10} ry={10}
                    fill={cfg.bg}
                    stroke={cfg.color}
                    strokeWidth={isSelected ? 2 : 1}
                    strokeOpacity={0.7}
                  />
                  {/* Icon + Label */}
                  <foreignObject x={8} y={10} width={NODE_W - 16} height={NODE_H - 16}>
                    <div
                      style={{
                        display: 'flex',
                        flexDirection: 'column',
                        alignItems: 'center',
                        gap: 4,
                        height: '100%',
                      }}
                    >
                      <div style={{ color: cfg.color, display: 'flex' }}>
                        <Icon size={12} />
                      </div>
                      <span style={{
                        color: '#CBD5E1',
                        fontSize: 9,
                        textAlign: 'center',
                        wordBreak: 'break-all',
                        lineHeight: 1.3,
                        fontFamily: 'monospace',
                        maxHeight: 28,
                        overflow: 'hidden',
                      }}>
                        {node.label}
                      </span>
                    </div>
                  </foreignObject>
                </g>
              );
            })}
          </g>
        </svg>
      </div>

      {/* Inspector */}
      <AnimatePresence>
        {selected && (
          <NodeInspector node={selected} onClose={() => setSelected(null)} />
        )}
      </AnimatePresence>

      {/* Legend */}
      <div style={{
        position: 'absolute',
        bottom: 12,
        left: 12,
        display: 'flex',
        gap: 12,
        flexWrap: 'wrap',
      }}>
        {Object.entries(NODE_CONFIG).map(([type, cfg]) => (
          <div key={type} style={{ display: 'flex', alignItems: 'center', gap: 4 }}>
            <div style={{ width: 8, height: 8, borderRadius: 2, background: cfg.color }} />
            <span style={{ color: '#64748B', fontSize: 10, textTransform: 'capitalize' }}>{type.replace('_', ' ')}</span>
          </div>
        ))}
      </div>
    </div>
  );
}
