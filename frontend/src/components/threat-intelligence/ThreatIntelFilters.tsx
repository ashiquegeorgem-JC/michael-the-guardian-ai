'use client';

import React from 'react';
import { Search, RotateCcw, Filter, CheckSquare, Square } from 'lucide-react';

export interface ThreatFilterState {
  search: string;
  ioc_type: string;
  threat_status: string;
  analyst_status: string;
  severity: string;
  confirmed_only: boolean;
}

interface ThreatIntelFiltersProps {
  filters: ThreatFilterState;
  onChange: (filters: ThreatFilterState) => void;
  onReset: () => void;
  loading?: boolean;
}

export function ThreatIntelFilters({
  filters,
  onChange,
  onReset,
  loading,
}: ThreatIntelFiltersProps) {
  const handleInput = (key: keyof ThreatFilterState, value: string | boolean) => {
    onChange({ ...filters, [key]: value });
  };

  return (
    <div
      style={{
        background: 'rgba(10, 14, 26, 0.9)',
        border: '1px solid #1E2D4A',
        borderRadius: 12,
        padding: '14px 18px',
        display: 'flex',
        flexDirection: 'column',
        gap: 12,
      }}
    >
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: 10 }}>
        {/* Search bar */}
        <div
          style={{
            display: 'flex',
            alignItems: 'center',
            gap: 8,
            background: '#0D1424',
            border: '1px solid #1E2D4A',
            borderRadius: 8,
            padding: '6px 12px',
            flexGrow: 1,
            minWidth: 240,
          }}
        >
          <Search size={14} color="var(--text-muted)" />
          <input
            type="text"
            placeholder="Search indicator value, domain, hash, or IP..."
            value={filters.search}
            onChange={(e) => handleInput('search', e.target.value)}
            style={{
              background: 'transparent',
              border: 'none',
              outline: 'none',
              color: '#F8FAFC',
              fontSize: 12,
              fontFamily: 'var(--font-mono)',
              width: '100%',
            }}
          />
        </div>

        {/* Confirmed Only Toggle */}
        <button
          type="button"
          onClick={() => handleInput('confirmed_only', !filters.confirmed_only)}
          style={{
            display: 'flex',
            alignItems: 'center',
            gap: 6,
            background: filters.confirmed_only ? '#10B98122' : '#0D1424',
            border: `1px solid ${filters.confirmed_only ? '#10B98166' : '#1E2D4A'}`,
            borderRadius: 8,
            padding: '6px 12px',
            color: filters.confirmed_only ? '#10B981' : 'var(--text-muted)',
            fontSize: 12,
            fontWeight: 600,
            cursor: 'pointer',
          }}
        >
          {filters.confirmed_only ? <CheckSquare size={13} /> : <Square size={13} />}
          Confirmed Links Only
        </button>

        {/* Reset */}
        <button
          type="button"
          onClick={onReset}
          style={{
            display: 'flex',
            alignItems: 'center',
            gap: 6,
            background: '#0D1424',
            border: '1px solid #1E2D4A',
            borderRadius: 8,
            padding: '6px 12px',
            color: 'var(--text-muted)',
            fontSize: 12,
            cursor: 'pointer',
          }}
        >
          <RotateCcw size={13} />
          Reset Filters
        </button>
      </div>

      {/* Dropdown Filters Row */}
      <div
        style={{
          display: 'grid',
          gridTemplateColumns: 'repeat(auto-fit, minmax(140px, 1fr))',
          gap: 10,
        }}
      >
        {/* IOC Type */}
        <select
          value={filters.ioc_type}
          onChange={(e) => handleInput('ioc_type', e.target.value)}
          style={{
            background: '#0D1424',
            border: '1px solid #1E2D4A',
            borderRadius: 6,
            padding: '6px 10px',
            color: '#CBD5E1',
            fontSize: 11,
            outline: 'none',
          }}
        >
          <option value="">All IOC Types</option>
          <option value="ipv4">IPv4</option>
          <option value="ipv6">IPv6</option>
          <option value="domain">Domain</option>
          <option value="url">URL</option>
          <option value="md5">MD5</option>
          <option value="sha1">SHA1</option>
          <option value="sha256">SHA256</option>
          <option value="email">Email</option>
          <option value="file_path">File Path</option>
        </select>

        {/* Threat Status (Feed verdict) */}
        <select
          value={filters.threat_status}
          onChange={(e) => handleInput('threat_status', e.target.value)}
          style={{
            background: '#0D1424',
            border: '1px solid #1E2D4A',
            borderRadius: 6,
            padding: '6px 10px',
            color: '#CBD5E1',
            fontSize: 11,
            outline: 'none',
          }}
        >
          <option value="">All Threat Verdicts</option>
          <option value="MALICIOUS">Malicious</option>
          <option value="SUSPICIOUS">Suspicious</option>
          <option value="CLEAN">Clean</option>
          <option value="UNKNOWN">Unknown</option>
          <option value="ERROR">Error</option>
        </select>

        {/* Analyst Status (Lifecycle) */}
        <select
          value={filters.analyst_status}
          onChange={(e) => handleInput('analyst_status', e.target.value)}
          style={{
            background: '#0D1424',
            border: '1px solid #1E2D4A',
            borderRadius: 6,
            padding: '6px 10px',
            color: '#CBD5E1',
            fontSize: 11,
            outline: 'none',
          }}
        >
          <option value="">All Analyst Triage States</option>
          <option value="EXTRACTED">Extracted</option>
          <option value="UNDER_REVIEW">Under Review</option>
          <option value="CONFIRMED">Confirmed Threat</option>
          <option value="FALSE_POSITIVE">False Positive</option>
        </select>

        {/* Severity */}
        <select
          value={filters.severity}
          onChange={(e) => handleInput('severity', e.target.value)}
          style={{
            background: '#0D1424',
            border: '1px solid #1E2D4A',
            borderRadius: 6,
            padding: '6px 10px',
            color: '#CBD5E1',
            fontSize: 11,
            outline: 'none',
          }}
        >
          <option value="">All Severities</option>
          <option value="CRITICAL">Critical</option>
          <option value="HIGH">High</option>
          <option value="MEDIUM">Medium</option>
          <option value="LOW">Low</option>
          <option value="UNKNOWN">Unknown</option>
        </select>
      </div>
    </div>
  );
}

