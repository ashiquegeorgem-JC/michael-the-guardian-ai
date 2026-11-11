'use client';

import React, { useState, useEffect, useCallback } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import {
  Search, Filter, X, ChevronDown, ChevronUp, Clock, AlertTriangle,
  RotateCcw, Shield, Target, Users, Server, ArrowLeft, ArrowRight,
  SlidersHorizontal, CheckCircle2, AlertOctagon, HelpCircle,
} from 'lucide-react';
import { searchAttackChains } from '@/lib/api';
import type { AttackChain, ChainSearchParams, ChainStatus, AttackStage, Severity } from '@/types';

interface Props {
  onSelectChain: (chain: AttackChain) => void;
  selectedChainId?: string | null;
  onClearSearch?: () => void;
}

const STAGES: AttackStage[] = [
  'Reconnaissance',
  'Initial Access',
  'Credential Attack',
  'Privilege Escalation',
  'Execution',
  'Persistence',
  'Command and Control',
  'Lateral Movement',
  'Data Access',
  'Exfiltration',
  'Unknown',
];

const SEVERITIES: Severity[] = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'];

const STATUSES: ChainStatus[] = [
  'NEW',
  'INVESTIGATING',
  'CONFIRMED',
  'FALSE_POSITIVE',
  'RESOLVED',
];

const SEV_COLORS: Record<string, string> = {
  CRITICAL: '#EF4444',
  HIGH:     '#F97316',
  MEDIUM:   '#EAB308',
  LOW:      '#10B981',
};

const STATUS_COLORS: Record<string, string> = {
  NEW:            '#60A5FA',
  INVESTIGATING:  '#EAB308',
  CONFIRMED:      '#EF4444',
  FALSE_POSITIVE: '#94A3B8',
  RESOLVED:       '#10B981',
};

export function ChainSearchPanel({ onSelectChain, selectedChainId, onClearSearch }: Props) {
  const [keyword, setKeyword] = useState('');
  const [sourceIp, setSourceIp] = useState('');
  const [destIp, setDestIp] = useState('');
  const [username, setUsername] = useState('');
  const [selectedStage, setSelectedStage] = useState<string>('');
  const [selectedSeverity, setSelectedSeverity] = useState<string>('');
  const [selectedStatus, setSelectedStatus] = useState<string>('');
  const [startTime, setStartTime] = useState('');
  const [endTime, setEndTime] = useState('');
  const [eventId, setEventId] = useState('');

  const [isAdvancedOpen, setIsAdvancedOpen] = useState(false);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [results, setResults] = useState<AttackChain[]>([]);
  const [totalMatches, setTotalMatches] = useState<number | null>(null);
  const [page, setPage] = useState(1);
  const [hasSearched, setHasSearched] = useState(false);

  const activeFilterCount = [
    keyword, sourceIp, destIp, username, selectedStage,
    selectedSeverity, selectedStatus, startTime, endTime, eventId,
  ].filter(Boolean).length;

  const executeSearch = useCallback(async (targetPage = 1) => {
    setLoading(true);
    setError(null);
    setHasSearched(true);

    try {
      const params: ChainSearchParams = {
        keyword: keyword.trim() || undefined,
        source_ip: sourceIp.trim() || undefined,
        destination_ip: destIp.trim() || undefined,
        username: username.trim() || undefined,
        stage: selectedStage || undefined,
        severity: selectedSeverity || undefined,
        status: (selectedStatus as ChainStatus) || undefined,
        start_time: startTime ? new Date(startTime).toISOString() : undefined,
        end_time: endTime ? new Date(endTime).toISOString() : undefined,
        event_id: eventId.trim() || undefined,
        page: targetPage,
        page_size: 10,
        sort_by: 'first_seen',
        sort_desc: true,
      };

      const res = await searchAttackChains(params);
      setResults(res.chains);
      setTotalMatches(res.total);
      setPage(res.page);
    } catch (err: unknown) {
      const e = err as Error;
      setError(e.message || 'Search failed');
      setResults([]);
      setTotalMatches(0);
    } finally {
      setLoading(false);
    }
  }, [keyword, sourceIp, destIp, username, selectedStage, selectedSeverity, selectedStatus, startTime, endTime, eventId]);

  const handleResetFilters = () => {
    setKeyword('');
    setSourceIp('');
    setDestIp('');
    setUsername('');
    setSelectedStage('');
    setSelectedSeverity('');
    setSelectedStatus('');
    setStartTime('');
    setEndTime('');
    setEventId('');
    setResults([]);
    setTotalMatches(null);
    setHasSearched(false);
    setPage(1);
    if (onClearSearch) onClearSearch();
  };

  return (
    <div style={{
      background: 'rgba(10,14,26,0.95)',
      border: '1px solid rgba(59,130,246,0.25)',
      borderRadius: 16,
      padding: '16px 20px',
      marginBottom: 24,
      boxShadow: '0 8px 24px rgba(0,0,0,0.3)',
    }}>
      {/* Search Header Bar */}
      <div style={{ display: 'flex', gap: 10, alignItems: 'center', flexWrap: 'wrap' }}>
        {/* Main Search Input */}
        <div style={{
          flex: 1,
          minWidth: 220,
          position: 'relative',
          display: 'flex',
          alignItems: 'center',
        }}>
          <Search size={14} color="#64748B" style={{ position: 'absolute', left: 12 }} />
          <input
            type="text"
            placeholder="Search attack chains (IP, entity, payload keyword, CVE, stage)…"
            value={keyword}
            onChange={e => setKeyword(e.target.value)}
            onKeyDown={e => e.key === 'Enter' && executeSearch(1)}
            style={{
              width: '100%',
              background: 'rgba(15,23,42,0.8)',
              border: '1px solid rgba(59,130,246,0.3)',
              borderRadius: 10,
              padding: '9px 12px 9px 36px',
              color: '#F1F5F9',
              fontSize: 13,
              outline: 'none',
              fontFamily: 'inherit',
            }}
          />
          {keyword && (
            <button
              onClick={() => setKeyword('')}
              style={{
                position: 'absolute',
                right: 10,
                background: 'none',
                border: 'none',
                color: '#64748B',
                cursor: 'pointer',
                padding: 2,
              }}
            >
              <X size={13} />
            </button>
          )}
        </div>

        {/* Search Action Button */}
        <button
          onClick={() => executeSearch(1)}
          disabled={loading}
          style={{
            background: 'linear-gradient(135deg, #2563EB, #1D4ED8)',
            border: '1px solid #3B82F6',
            borderRadius: 10,
            padding: '9px 18px',
            color: '#FFFFFF',
            fontSize: 13,
            fontWeight: 600,
            cursor: 'pointer',
            display: 'flex',
            alignItems: 'center',
            gap: 6,
            transition: 'opacity 0.2s',
            opacity: loading ? 0.7 : 1,
          }}
        >
          <Search size={14} />
          {loading ? 'Searching…' : 'Search'}
        </button>

        {/* Toggle Advanced Filters Button */}
        <button
          onClick={() => setIsAdvancedOpen(v => !v)}
          style={{
            background: isAdvancedOpen || activeFilterCount > 0 ? 'rgba(59,130,246,0.15)' : 'rgba(30,41,59,0.7)',
            border: `1px solid ${isAdvancedOpen || activeFilterCount > 0 ? 'rgba(59,130,246,0.5)' : 'rgba(51,65,85,0.8)'}`,
            borderRadius: 10,
            padding: '9px 14px',
            color: isAdvancedOpen || activeFilterCount > 0 ? '#60A5FA' : '#94A3B8',
            fontSize: 13,
            fontWeight: 500,
            cursor: 'pointer',
            display: 'flex',
            alignItems: 'center',
            gap: 6,
          }}
        >
          <SlidersHorizontal size={14} />
          Filters
          {activeFilterCount > 0 && (
            <span style={{
              background: '#3B82F6',
              color: '#FFFFFF',
              borderRadius: 10,
              fontSize: 10,
              fontWeight: 700,
              padding: '1px 6px',
            }}>
              {activeFilterCount}
            </span>
          )}
          {isAdvancedOpen ? <ChevronUp size={13} /> : <ChevronDown size={13} />}
        </button>

        {/* Clear Filters Button */}
        {activeFilterCount > 0 && (
          <button
            onClick={handleResetFilters}
            style={{
              background: 'transparent',
              border: 'none',
              color: '#94A3B8',
              fontSize: 12,
              cursor: 'pointer',
              display: 'flex',
              alignItems: 'center',
              gap: 4,
              padding: '6px 8px',
            }}
          >
            <RotateCcw size={12} />
            Reset
          </button>
        )}
      </div>

      {/* Advanced Filters Expandable Drawer */}
      <AnimatePresence>
        {isAdvancedOpen && (
          <motion.div
            initial={{ opacity: 0, height: 0 }}
            animate={{ opacity: 1, height: 'auto' }}
            exit={{ opacity: 0, height: 0 }}
            transition={{ duration: 0.2 }}
            style={{ overflow: 'hidden', marginTop: 16, paddingTop: 16, borderTop: '1px solid rgba(30,41,59,0.7)' }}
          >
            <div style={{
              display: 'grid',
              gridTemplateColumns: 'repeat(auto-fit, minmax(170px, 1fr))',
              gap: 12,
              marginBottom: 14,
            }}>
              {/* Source IP */}
              <div>
                <label style={{ color: '#94A3B8', fontSize: 11, fontWeight: 600, display: 'block', marginBottom: 4 }}>
                  Origin / Source IP
                </label>
                <input
                  type="text"
                  placeholder="e.g. 198.51.100.42"
                  value={sourceIp}
                  onChange={e => setSourceIp(e.target.value)}
                  style={{
                    width: '100%',
                    background: 'rgba(15,23,42,0.9)',
                    border: '1px solid rgba(51,65,85,0.8)',
                    borderRadius: 8,
                    padding: '7px 10px',
                    color: '#F1F5F9',
                    fontSize: 12,
                    fontFamily: 'monospace',
                  }}
                />
              </div>

              {/* Destination IP */}
              <div>
                <label style={{ color: '#94A3B8', fontSize: 11, fontWeight: 600, display: 'block', marginBottom: 4 }}>
                  Target / Dest Host
                </label>
                <input
                  type="text"
                  placeholder="e.g. 10.0.0.5"
                  value={destIp}
                  onChange={e => setDestIp(e.target.value)}
                  style={{
                    width: '100%',
                    background: 'rgba(15,23,42,0.9)',
                    border: '1px solid rgba(51,65,85,0.8)',
                    borderRadius: 8,
                    padding: '7px 10px',
                    color: '#F1F5F9',
                    fontSize: 12,
                    fontFamily: 'monospace',
                  }}
                />
              </div>

              {/* Username */}
              <div>
                <label style={{ color: '#94A3B8', fontSize: 11, fontWeight: 600, display: 'block', marginBottom: 4 }}>
                  Affected Username
                </label>
                <input
                  type="text"
                  placeholder="e.g. admin, jdoe"
                  value={username}
                  onChange={e => setUsername(e.target.value)}
                  style={{
                    width: '100%',
                    background: 'rgba(15,23,42,0.9)',
                    border: '1px solid rgba(51,65,85,0.8)',
                    borderRadius: 8,
                    padding: '7px 10px',
                    color: '#F1F5F9',
                    fontSize: 12,
                  }}
                />
              </div>

              {/* Attack Stage Dropdown */}
              <div>
                <label style={{ color: '#94A3B8', fontSize: 11, fontWeight: 600, display: 'block', marginBottom: 4 }}>
                  MITRE Attack Stage
                </label>
                <select
                  value={selectedStage}
                  onChange={e => setSelectedStage(e.target.value)}
                  style={{
                    width: '100%',
                    background: 'rgba(15,23,42,0.9)',
                    border: '1px solid rgba(51,65,85,0.8)',
                    borderRadius: 8,
                    padding: '7px 10px',
                    color: '#F1F5F9',
                    fontSize: 12,
                  }}
                >
                  <option value="">Any Stage</option>
                  {STAGES.map(s => (
                    <option key={s} value={s}>{s}</option>
                  ))}
                </select>
              </div>

              {/* Severity Dropdown */}
              <div>
                <label style={{ color: '#94A3B8', fontSize: 11, fontWeight: 600, display: 'block', marginBottom: 4 }}>
                  Severity
                </label>
                <select
                  value={selectedSeverity}
                  onChange={e => setSelectedSeverity(e.target.value)}
                  style={{
                    width: '100%',
                    background: 'rgba(15,23,42,0.9)',
                    border: '1px solid rgba(51,65,85,0.8)',
                    borderRadius: 8,
                    padding: '7px 10px',
                    color: '#F1F5F9',
                    fontSize: 12,
                  }}
                >
                  <option value="">Any Severity</option>
                  {SEVERITIES.map(sev => (
                    <option key={sev} value={sev}>{sev}</option>
                  ))}
                </select>
              </div>

              {/* Status Dropdown */}
              <div>
                <label style={{ color: '#94A3B8', fontSize: 11, fontWeight: 600, display: 'block', marginBottom: 4 }}>
                  Investigation Status
                </label>
                <select
                  value={selectedStatus}
                  onChange={e => setSelectedStatus(e.target.value)}
                  style={{
                    width: '100%',
                    background: 'rgba(15,23,42,0.9)',
                    border: '1px solid rgba(51,65,85,0.8)',
                    borderRadius: 8,
                    padding: '7px 10px',
                    color: '#F1F5F9',
                    fontSize: 12,
                  }}
                >
                  <option value="">Any Status</option>
                  {STATUSES.map(st => (
                    <option key={st} value={st}>{st.replace('_', ' ')}</option>
                  ))}
                </select>
              </div>

              {/* Event ID */}
              <div>
                <label style={{ color: '#94A3B8', fontSize: 11, fontWeight: 600, display: 'block', marginBottom: 4 }}>
                  Event ID / Entry ID
                </label>
                <input
                  type="text"
                  placeholder="e.g. log-1, uuid"
                  value={eventId}
                  onChange={e => setEventId(e.target.value)}
                  style={{
                    width: '100%',
                    background: 'rgba(15,23,42,0.9)',
                    border: '1px solid rgba(51,65,85,0.8)',
                    borderRadius: 8,
                    padding: '7px 10px',
                    color: '#F1F5F9',
                    fontSize: 12,
                    fontFamily: 'monospace',
                  }}
                />
              </div>

              {/* Start Time */}
              <div>
                <label style={{ color: '#94A3B8', fontSize: 11, fontWeight: 600, display: 'block', marginBottom: 4 }}>
                  Earliest Activity
                </label>
                <input
                  type="datetime-local"
                  value={startTime}
                  onChange={e => setStartTime(e.target.value)}
                  style={{
                    width: '100%',
                    background: 'rgba(15,23,42,0.9)',
                    border: '1px solid rgba(51,65,85,0.8)',
                    borderRadius: 8,
                    padding: '6px 8px',
                    color: '#F1F5F9',
                    fontSize: 11,
                  }}
                />
              </div>

              {/* End Time */}
              <div>
                <label style={{ color: '#94A3B8', fontSize: 11, fontWeight: 600, display: 'block', marginBottom: 4 }}>
                  Latest Activity
                </label>
                <input
                  type="datetime-local"
                  value={endTime}
                  onChange={e => setEndTime(e.target.value)}
                  style={{
                    width: '100%',
                    background: 'rgba(15,23,42,0.9)',
                    border: '1px solid rgba(51,65,85,0.8)',
                    borderRadius: 8,
                    padding: '6px 8px',
                    color: '#F1F5F9',
                    fontSize: 11,
                  }}
                />
              </div>
            </div>

            <div style={{ display: 'flex', justifyContent: 'flex-end', gap: 10 }}>
              <button
                onClick={handleResetFilters}
                style={{
                  background: 'rgba(30,41,59,0.7)',
                  border: '1px solid rgba(51,65,85,0.8)',
                  borderRadius: 8,
                  padding: '7px 14px',
                  color: '#94A3B8',
                  fontSize: 12,
                  cursor: 'pointer',
                }}
              >
                Reset All
              </button>
              <button
                onClick={() => executeSearch(1)}
                style={{
                  background: '#2563EB',
                  border: '1px solid #3B82F6',
                  borderRadius: 8,
                  padding: '7px 16px',
                  color: '#FFFFFF',
                  fontSize: 12,
                  fontWeight: 600,
                  cursor: 'pointer',
                }}
              >
                Apply Filters
              </button>
            </div>
          </motion.div>
        )}
      </AnimatePresence>

      {/* Active Filter Badges */}
      {activeFilterCount > 0 && !isAdvancedOpen && (
        <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6, marginTop: 12 }}>
          {keyword && (
            <span style={{ background: 'rgba(59,130,246,0.15)', border: '1px solid rgba(59,130,246,0.3)', color: '#60A5FA', borderRadius: 6, fontSize: 11, padding: '2px 8px', display: 'flex', alignItems: 'center', gap: 4 }}>
              keyword: {keyword}
              <X size={10} style={{ cursor: 'pointer' }} onClick={() => setKeyword('')} />
            </span>
          )}
          {sourceIp && (
            <span style={{ background: 'rgba(59,130,246,0.15)', border: '1px solid rgba(59,130,246,0.3)', color: '#60A5FA', borderRadius: 6, fontSize: 11, padding: '2px 8px', display: 'flex', alignItems: 'center', gap: 4 }}>
              src: {sourceIp}
              <X size={10} style={{ cursor: 'pointer' }} onClick={() => setSourceIp('')} />
            </span>
          )}
          {destIp && (
            <span style={{ background: 'rgba(59,130,246,0.15)', border: '1px solid rgba(59,130,246,0.3)', color: '#60A5FA', borderRadius: 6, fontSize: 11, padding: '2px 8px', display: 'flex', alignItems: 'center', gap: 4 }}>
              dest: {destIp}
              <X size={10} style={{ cursor: 'pointer' }} onClick={() => setDestIp('')} />
            </span>
          )}
          {username && (
            <span style={{ background: 'rgba(59,130,246,0.15)', border: '1px solid rgba(59,130,246,0.3)', color: '#60A5FA', borderRadius: 6, fontSize: 11, padding: '2px 8px', display: 'flex', alignItems: 'center', gap: 4 }}>
              user: {username}
              <X size={10} style={{ cursor: 'pointer' }} onClick={() => setUsername('')} />
            </span>
          )}
          {selectedStage && (
            <span style={{ background: 'rgba(124,58,237,0.15)', border: '1px solid rgba(124,58,237,0.3)', color: '#A78BFA', borderRadius: 6, fontSize: 11, padding: '2px 8px', display: 'flex', alignItems: 'center', gap: 4 }}>
              stage: {selectedStage}
              <X size={10} style={{ cursor: 'pointer' }} onClick={() => setSelectedStage('')} />
            </span>
          )}
          {selectedSeverity && (
            <span style={{ background: `${SEV_COLORS[selectedSeverity]}20`, border: `1px solid ${SEV_COLORS[selectedSeverity]}50`, color: SEV_COLORS[selectedSeverity], borderRadius: 6, fontSize: 11, padding: '2px 8px', display: 'flex', alignItems: 'center', gap: 4 }}>
              sev: {selectedSeverity}
              <X size={10} style={{ cursor: 'pointer' }} onClick={() => setSelectedSeverity('')} />
            </span>
          )}
          {selectedStatus && (
            <span style={{ background: `${STATUS_COLORS[selectedStatus]}20`, border: `1px solid ${STATUS_COLORS[selectedStatus]}50`, color: STATUS_COLORS[selectedStatus], borderRadius: 6, fontSize: 11, padding: '2px 8px', display: 'flex', alignItems: 'center', gap: 4 }}>
              status: {selectedStatus.replace('_', ' ')}
              <X size={10} style={{ cursor: 'pointer' }} onClick={() => setSelectedStatus('')} />
            </span>
          )}
        </div>
      )}

      {/* Error state */}
      {error && (
        <div style={{
          marginTop: 12,
          background: 'rgba(239,68,68,0.1)',
          border: '1px solid rgba(239,68,68,0.3)',
          borderRadius: 8,
          padding: '8px 12px',
          color: '#FCA5A5',
          fontSize: 12,
          display: 'flex',
          alignItems: 'center',
          gap: 6,
        }}>
          <AlertTriangle size={12} />
          {error}
        </div>
      )}

      {/* Search Results Display Area */}
      {hasSearched && (
        <div style={{ marginTop: 16, borderTop: '1px solid rgba(30,41,59,0.7)', paddingTop: 14 }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 10 }}>
            <span style={{ color: '#94A3B8', fontSize: 12 }}>
              Found <strong style={{ color: '#F1F5F9' }}>{totalMatches ?? results.length}</strong> matching attack chain{totalMatches !== 1 ? 's' : ''}
            </span>
            {totalMatches !== null && totalMatches > 10 && (
              <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                <button
                  disabled={page <= 1}
                  onClick={() => executeSearch(page - 1)}
                  style={{
                    background: 'rgba(15,23,42,0.8)',
                    border: '1px solid rgba(51,65,85,0.8)',
                    borderRadius: 6,
                    padding: '3px 8px',
                    color: page <= 1 ? '#475569' : '#94A3B8',
                    cursor: page <= 1 ? 'default' : 'pointer',
                  }}
                >
                  <ArrowLeft size={11} />
                </button>
                <span style={{ color: '#64748B', fontSize: 11 }}>Page {page} of {Math.ceil((totalMatches || 1) / 10)}</span>
                <button
                  disabled={page * 10 >= (totalMatches || 0)}
                  onClick={() => executeSearch(page + 1)}
                  style={{
                    background: 'rgba(15,23,42,0.8)',
                    border: '1px solid rgba(51,65,85,0.8)',
                    borderRadius: 6,
                    padding: '3px 8px',
                    color: page * 10 >= (totalMatches || 0) ? '#475569' : '#94A3B8',
                    cursor: page * 10 >= (totalMatches || 0) ? 'default' : 'pointer',
                  }}
                >
                  <ArrowRight size={11} />
                </button>
              </div>
            )}
          </div>

          {/* Results List */}
          {results.length > 0 ? (
            <div style={{ display: 'flex', flexDirection: 'column', gap: 6, maxHeight: 220, overflowY: 'auto' }}>
              {results.map(c => {
                const isSelected = selectedChainId === c.id;
                const statusVal = c.status || 'NEW';
                const statusColor = STATUS_COLORS[statusVal] || '#60A5FA';
                return (
                  <div
                    key={c.id}
                    onClick={() => onSelectChain(c)}
                    style={{
                      display: 'flex',
                      justifyContent: 'space-between',
                      alignItems: 'center',
                      background: isSelected ? 'rgba(59,130,246,0.14)' : 'rgba(15,23,42,0.7)',
                      border: `1px solid ${isSelected ? 'rgba(59,130,246,0.6)' : 'rgba(30,41,59,0.8)'}`,
                      borderRadius: 8,
                      padding: '8px 12px',
                      cursor: 'pointer',
                      transition: 'background 0.15s',
                    }}
                  >
                    <div style={{ display: 'flex', alignItems: 'center', gap: 10, minWidth: 0 }}>
                      <span style={{
                        background: `${SEV_COLORS[c.severity]}18`,
                        border: `1px solid ${SEV_COLORS[c.severity]}50`,
                        color: SEV_COLORS[c.severity],
                        borderRadius: 4,
                        fontSize: 9,
                        fontWeight: 800,
                        padding: '1px 6px',
                      }}>
                        {c.severity}
                      </span>
                      <span style={{
                        background: `${statusColor}18`,
                        border: `1px solid ${statusColor}40`,
                        color: statusColor,
                        borderRadius: 4,
                        fontSize: 9,
                        fontWeight: 700,
                        padding: '1px 5px',
                        textTransform: 'uppercase',
                      }}>
                        {statusVal.replace('_', ' ')}
                      </span>
                      <span style={{ color: isSelected ? '#F1F5F9' : '#CBD5E1', fontSize: 12, fontWeight: 500, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                        {c.title}
                      </span>
                    </div>

                    <div style={{ display: 'flex', alignItems: 'center', gap: 12, flexShrink: 0 }}>
                      <span style={{ color: '#64748B', fontSize: 10, fontFamily: 'monospace' }}>
                        {c.source_ips[0] || 'Unknown IP'}
                      </span>
                      <span style={{ color: '#475569', fontSize: 10 }}>
                        {c.events.length} events
                      </span>
                    </div>
                  </div>
                );
              })}
            </div>
          ) : (
            <div style={{ textAlign: 'center', padding: '16px 0', color: '#64748B', fontSize: 12 }}>
              No attack chains matched the given filters. Try broadening your search criteria.
            </div>
          )}
        </div>
      )}
    </div>
  );
}

