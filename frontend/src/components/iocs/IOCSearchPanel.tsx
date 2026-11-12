'use client';

import { useState } from 'react';
import { Search, X, SlidersHorizontal } from 'lucide-react';
import { Button } from '@/components/ui/Button';
import type { IOCSearchParams } from '@/types';

const IOC_TYPES = ['', 'ipv4', 'ipv6', 'domain', 'url', 'md5', 'sha1', 'sha256', 'email', 'file_path'];
const IOC_STATUSES = ['', 'EXTRACTED', 'UNDER_REVIEW', 'CONFIRMED', 'FALSE_POSITIVE'];
const VALIDATION_STATUSES = ['', 'VALID', 'INVALID', 'SUSPICIOUS'];

interface Props {
  onSearch: (params: IOCSearchParams) => void;
  loading?: boolean;
}

export function IOCSearchPanel({ onSearch, loading }: Props) {
  const [value, setValue] = useState('');
  const [iocType, setIocType] = useState('');
  const [status, setStatus] = useState('');
  const [validationStatus, setValidationStatus] = useState('');
  const [sessionId, setSessionId] = useState('');
  const [attackChainId, setAttackChainId] = useState('');
  const [showAdvanced, setShowAdvanced] = useState(false);

  const handleSearch = () => {
    onSearch({
      normalized_value: value.trim() || undefined,
      ioc_type: iocType || undefined,
      status: status || undefined,
      validation_status: validationStatus || undefined,
      session_id: sessionId.trim() || undefined,
      attack_chain_id: attackChainId.trim() || undefined,
      page: 1,
      page_size: 50,
    });
  };

  const handleClear = () => {
    setValue('');
    setIocType('');
    setStatus('');
    setValidationStatus('');
    setSessionId('');
    setAttackChainId('');
    onSearch({ page: 1, page_size: 50 });
  };

  const selectStyle: React.CSSProperties = {
    background: '#0D1117',
    border: '1px solid rgba(255, 255, 255, 0.08)',
    borderRadius: 8,
    color: 'var(--text-secondary)',
    padding: '8px 12px',
    fontSize: 12,
    outline: 'none',
    cursor: 'pointer',
    minWidth: 130,
  };

  const inputStyle: React.CSSProperties = {
    background: '#0D1117',
    border: '1px solid rgba(255, 255, 255, 0.08)',
    borderRadius: 8,
    color: 'var(--text-primary)',
    padding: '8px 12px',
    fontSize: 13,
    outline: 'none',
    flex: 1,
    minWidth: 0,
  };

  return (
    <div style={{
      backgroundColor: '#11161E',
      border: '1px solid rgba(255, 255, 255, 0.08)',
      borderRadius: 16,
      padding: '20px 24px',
      boxShadow: '0 4px 20px rgba(0, 0, 0, 0.35)',
    }}>
      {/* Main search row */}
      <div style={{ display: 'flex', gap: 10, alignItems: 'center', flexWrap: 'wrap' }}>
        <div style={{ flex: 1, minWidth: 200, position: 'relative' }}>
          <Search size={14} style={{ position: 'absolute', left: 10, top: '50%', transform: 'translateY(-50%)', color: 'var(--text-muted)' }} />
          <input
            value={value}
            onChange={e => setValue(e.target.value)}
            onKeyDown={e => e.key === 'Enter' && handleSearch()}
            placeholder="Search IOC value (IP, domain, hash…)"
            style={{ ...inputStyle, paddingLeft: 32, width: '100%' }}
          />
        </div>
        <select value={iocType} onChange={e => setIocType(e.target.value)} style={selectStyle}>
          <option value="">All Types</option>
          {IOC_TYPES.filter(Boolean).map(t => <option key={t} value={t}>{t.toUpperCase()}</option>)}
        </select>
        <select value={status} onChange={e => setStatus(e.target.value)} style={selectStyle}>
          <option value="">All Statuses</option>
          {IOC_STATUSES.filter(Boolean).map(s => <option key={s} value={s}>{s.replace('_', ' ')}</option>)}
        </select>
        <Button size="sm" onClick={handleSearch} isLoading={loading} leftIcon={<Search size={13} />}>
          Search
        </Button>
        <Button size="sm" variant="ghost" onClick={() => setShowAdvanced(v => !v)} leftIcon={<SlidersHorizontal size={13} />}>
          {showAdvanced ? 'Fewer Filters' : 'More Filters'}
        </Button>
        <Button size="sm" variant="ghost" onClick={handleClear} leftIcon={<X size={13} />}>
          Clear
        </Button>
      </div>

      {/* Advanced filters */}
      {showAdvanced && (
        <div style={{ display: 'flex', gap: 10, flexWrap: 'wrap', marginTop: 12, paddingTop: 12, borderTop: '1px solid #1E2D4A' }}>
          <select value={validationStatus} onChange={e => setValidationStatus(e.target.value)} style={selectStyle}>
            <option value="">All Validation Status</option>
            {VALIDATION_STATUSES.filter(Boolean).map(s => <option key={s} value={s}>{s}</option>)}
          </select>
          <input
            value={sessionId}
            onChange={e => setSessionId(e.target.value)}
            placeholder="Filter by Session ID…"
            style={{ ...inputStyle, minWidth: 200, flex: 'none' }}
          />
          <input
            value={attackChainId}
            onChange={e => setAttackChainId(e.target.value)}
            placeholder="Filter by Attack Chain ID…"
            style={{ ...inputStyle, minWidth: 200, flex: 'none' }}
          />
        </div>
      )}
    </div>
  );
}

