# MICHAEL — THE GUARDIAN AI
## Complete Premium SOC UI/UX Redesign Documentation

> **Intelligence That Watches. AI That Protects.**

---

## 1. Overview

This document describes the complete visual and UI/UX redesign of the **MICHAEL — The Guardian AI** application frontend. The redesign transforms the interface from a generic admin dashboard into a **premium, enterprise-grade Security Operations Center (SOC) platform**.

### Scope
- **All 12 routes** redesigned and visually standardised
- **Unified design system** with shared tokens, components, and typography
- **100% backend compatibility preserved** — zero API or model changes
- **Build verified**: `next build --webpack` exits code 0 with no TypeScript errors
- **Backend regression**: 412/412 tests pass

---

## 2. Design System

### 2.1 Color Tokens

```css
/* Backgrounds — 5-layer depth system */
--bg-base:      #05070B   /* Page canvas — deepest near-black */
--bg-secondary: #080C12   /* Secondary surfaces */
--bg-panel:     #0C1119   /* Cards and panels */
--bg-elevated:  #111823   /* Elevated panels, modals */
--bg-hover:     #151F2E   /* Hover states */

/* Typography — 4-tier hierarchy */
--text-primary:   #F5F7FA  /* Headings, values, key data */
--text-secondary: #A7B1C0  /* Labels, descriptions */
--text-muted:     #687589  /* Timestamps, secondary metadata */
--text-disabled:  #465161  /* Disabled elements, placeholders */

/* Accents */
--primary:          #3B82F6  /* Primary blue — interactive elements */
--electric:         #22B8FF  /* Electric blue — highlights */
--violet:           #8B5CF6  /* Violet — MITRE / AI context */
--success:          #22C55E  /* Healthy / connected / resolved */
--warning:          #F59E0B  /* Warnings / medium severity */
--critical:         #EF4444  /* Critical threats / errors */
--orange:           #F97316  /* High severity */

/* Borders */
--border-subtle:    rgba(255,255,255,0.08)
--border-normal:    rgba(255,255,255,0.12)
--border-emphasis:  rgba(59,130,246,0.25)
```

### 2.2 Typography

| Use | Font | Size | Weight |
|-----|------|------|--------|
| App Shell | Inter (sans-serif) | — | — |
| Page headings | Inter | 24–30px | 700 |
| Section headers | Inter | 15–18px | 600 |
| Body / labels | Inter | 13–14px | 400–500 |
| Data values | Inter | 20–28px | 700 |
| Monospace data | JetBrains Mono / `font-mono` | 11–13px | 400 |
| Timestamps | JetBrains Mono | 10–11px | 400 |

### 2.3 Spacing & Radius

```
--radius-sm: 6px
--radius-md: 10px
--radius-lg: 12px
--radius-xl: 14px
--radius-2xl: 16px
```

Standard panel padding: `20–24px`. Grid gaps: `16–24px`. Sidebar width: `260px`.

### 2.4 Shadows

```css
/* Panel shadow */
box-shadow: 0 4px 16px rgba(0, 0, 0, 0.35);

/* Elevated panel */
box-shadow: 0 8px 32px rgba(0, 0, 0, 0.5);

/* Accent glow (critical) */
box-shadow: 0 0 32px rgba(239, 68, 68, 0.15);
```

---

## 3. Application Shell

### 3.1 Sidebar Navigation — 260px fixed

Five navigation groups, each with labeled section headers:

| Group | Routes |
|-------|--------|
| **COMMAND** | Dashboard |
| **INVESTIGATE** | Logs, Anomaly Detection, Incidents |
| **INTELLIGENCE** | IOCs, Attack Chains, Threat Intelligence |
| **REPORTING** | AI Copilot, Monitoring, Reports |
| **SYSTEM** | Settings |

Active item: `rgba(59, 130, 246, 0.12)` background + 3px blue left indicator + `#F5F7FA` text + blue icon.

### 3.2 Top Bar

- **Left**: App name `MICHAEL` + page title / subtitle
- **Centre**: `● LIVE` green pill + WebSocket status pill (`WS CONNECTED` / `WS POLLING`)
- **Right**: Notification badge + `SOC v1.0` label + `Ingest Logs` / `AI Copilot` / `Refresh` action buttons

---

## 4. Reusable Component Library

All shared components live in `frontend/src/components/ui/`.

### `PageHeader`
Unified page header with: `tag` (category badge), `title` (24–30px heading), `description`, and optional `actions` slot.

### `Panel`
Standard card container. Props: `title`, `description`, `icon`, `badge`, `actions`, `elevated`, `noPadding`. Background `#0C1119` (elevated: `#111823`).

### `MetricCard`
KPI card with: `label`, `value`, `subValue`, optional `trend`, `icon`, `accentColor`. Subtle left accent bar using the accent colour.

### `Button`
Variants: `primary`, `secondary`, `outline`, `danger`, `success`, `ghost`, `glass`. Sizes: `sm`, `md`, `lg`. Props: `leftIcon`, `rightIcon`, `loading`, `disabled`.

### `Badge`
Semantic colour badges. Types: `critical`, `high`, `warning`, `info`, `primary`, `success`, `muted`, `violet`. Sizes: `sm`, `md`, `lg`.

### `EmptyState`
Standard empty state: `icon`, `title`, `description`, optional `action` button.

### `LoadingState`
Skeleton loaders for: `table`, `metric-grid`, `card` variants.

### `InvestigationDrawer`
Reusable slide-over forensic panel. Props: `isOpen`, `onClose`, `title`, `children`.

---

## 5. Route Documentation

### 5.1 `/dashboard` — Command Centre

**Architecture** (5 tiers):
1. **Page Header** — `COMMAND CENTRE` title + session context + action buttons
2. **5 KPI Cards** — Threat Level, Events Processed, Anomalies, Active Incidents, Suspicious IOCs
3. **Primary Row** — `LiveThreatGraph` (area chart, 8 col) + `AnomalySeverityDonut` (4 col)
4. **Secondary Row** — `AttackChainFlow` (5 col) + `LiveEventConsole` real-time feed (7 col)
5. **Tertiary Row** — `RecentIncidentsTable` (8 col) + `ThreatIntelGauge` + `SystemTelemetryStrip` (4 col)

Data sources: `/api/monitoring/dashboard`, `/api/logs/sessions`, `/api/incidents`, `/api/iocs/summary`, WebSocket stream.

---

### 5.2 `/logs` — Log Explorer

- Session selector strip
- 4 KPI cards: Total Entries, Anomalies Flagged, Critical Events, Active Sources
- `LogVolumeGraph` — hourly volume area chart
- `LogTable` — paginated table with level filter tabs + keyword search
- `DropZone` — drag-and-drop log file ingestion panel
- `LogInspector` — slide-over detail drawer for selected log entries

---

### 5.3 `/anomalies` — Anomaly Detection

- Session selector
- 5 KPI cards by severity: Total, Critical, High, Medium, Low
- Tabbed view:
  - **Detection Outliers** — `AnomalyCard` grid with side detail panel
  - **Temporal Burst Analytics** — `TemporalDashboard` with traffic windows, IP spikes, auth bursts
  - **Model Benchmarks** — `ModelMetrics` + `ResearchEvaluation`
  - **Live Detection** — time-series anomaly timeline + ensemble engine breakdown
- `InvestigationDrawer` for forensic detail

---

### 5.4 `/incidents` — Incident Centre

- 4 KPI cards: Total, Open, Investigating, Resolved
- Status filter strip + severity filter
- `IncidentCard` list (sorted by severity)
- `IncidentDetail` slide-over drawer with evidence logs, remediation steps, affected assets

---

### 5.5 `/attack-chains` — Attack Chains

- 4-column summary analytics strip
- Multi-criteria search panel: session, source IP, destination IP, username, stage, severity, status, keyword, time range
- Active chain selector list
- Tabbed detail workspace:
  - **Forensic Panels** — `ForensicInvestigationPanel` with MITRE stage pills, timeline events
  - **Attack Graph** — `AttackGraph` interactive SVG canvas (node types: source IP, host, user, process, attack stage, incident)
  - **Timeline** — `AttackTimeline` chronological event sequence
  - **Correlated Entities** — `RelatedEntitiesPanel` IPs/users/hosts/sessions
- `EventConfirmationModal` for analyst event confirmation

---

### 5.6 `/iocs` — IOC Intelligence

- 6 KPI cards: Total IOCs, IPv4/Domain/Hash/Email/File path counts
- `IOCSearchPanel` — multi-field filter: type, status, confidence threshold, keyword, session
- `IOCListTable` — paginated table with TypeBadge, StatusBadge, ConfidenceBar columns
- `IOCDetailPanel` — slide-over: threat context, reputation score, raw value, source logs

---

### 5.7 `/threat-intelligence` — Threat Intelligence

- `ThreatIntelligenceMetrics` — 4 KPI summary cards
- `ThreatIntelFilters` — provider, IOC type, reputation, session filters
- `IOCThreatTable` — table with VirusTotal/reputation enrichment columns
- `UnifiedThreatContextPanel` — combined threat context accordion for selected IOC

---

### 5.8 `/copilot` — AI Copilot

- 4 KPI cards: Queries Today, Avg Confidence, Sessions Analysed, Incidents Referenced
- Split workspace:
  - **Left — Investigation Context**: session selector, anomaly focus, MITRE stage, cross-links to Incidents/IOCs
  - **Right — Chat Interface**: message history with evidence accordions, suggested prompts, prompt input with send button
- Integrates with `/api/copilot/chat` and `/api/copilot/suggestions`

---

### 5.9 `/monitoring` — Live Monitoring

- 4 KPI cards: CPU Load, Memory Usage, Disk Storage, Velocity EPS
- Real-time resource area chart (CPU + Memory overlay)
- Pipeline component health badges: Log Parser, ML Engine, IOC Extractor, Threat Intel, Copilot
- `EventStream` live console — WebSocket-driven, shows latest system events with client-only timestamp mounting (SSR-safe)

---

### 5.10 `/reports` — Report Centre

- 4 KPI cards: Reports Generated, Sessions Available, Formats Supported, Last Generated
- Report generator card with session selector + generate button
- Compliance documentation table with download links for available reports

---

### 5.11 `/settings` — System Settings

- 7 horizontal tabs: General, Detection Engine, Threat Intelligence, Telemetry & Stream, Database & Storage, Security & RBAC, System & Health
- Each tab has clean setting items: Title (600 weight) + Description (muted) + Control (right-aligned toggle/input/select)
- No overcrowding — generous row padding

---

## 6. TypeScript Fixes Applied

| File | Fix Applied |
|------|-------------|
| `ui/Panel.tsx` | `extends Omit<HTMLAttributes<div>, 'title'>` to allow `ReactNode` title |
| `types/index.ts` | Added optional fields: `LogSession.line_count`, `LogStats.anomaly_count`, `LogStats.source_distribution`, `ModelMetrics.training_time_ms`, `Incident.affected_hosts`, `IncidentSummary.critical_count`, `LogEntry.source_ip/host/service`, `Anomaly.timestamp/source_ip/host` |
| `attack-chains/ForensicInvestigationPanel.tsx` | Added `onStatusUpdate` and `onEventConfirm` optional props |
| `attack-chains/EventConfirmationModal.tsx` | Made `onConfirmed` optional, added `onSuccess` prop |
| `attack-chains/page.tsx` | Fixed `selectedChain.graph` → `selectedChain.graph_data`, `AttackGraph graph={}` → `data={}` |
| `iocs/IOCListTable.tsx` | Added `selectedIocId` alias prop, `pagination`, `onPageChange` |
| `copilot/ChatInterface.tsx` | Fixed `askCopilot({prompt, session_id})` → `askCopilot(query, sessionId)` |
| `anomalies/AnomalyCard.tsx` | Type-asserted optional `source_ip`, `host`, `timestamp` fields |
| `logs/LogTable.tsx` | Fallback: `source_ip || host || source` |
| `logs/LogInspector.tsx` | Fallback: `source_ip || host || source` |
| `anomalies/ModelMetrics.tsx` | Fallback for `training_time_ms`: uses `analysis_duration_seconds * 1000` |

---

## 7. Build Verification

```
✓ Compiled successfully in 18.9s          (webpack)
✓ Finished TypeScript in 3.5s            (0 errors)
✓ Generated static pages (15/15)
✓ Exit code: 0
```

### Route Smoke Test — 12/12 HTTP 200

| Route | Status |
|-------|--------|
| `/` (→ /dashboard) | **200** |
| `/dashboard` | **200** |
| `/logs` | **200** |
| `/anomalies` | **200** |
| `/incidents` | **200** |
| `/iocs` | **200** |
| `/attack-chains` | **200** |
| `/threat-intelligence` | **200** |
| `/copilot` | **200** |
| `/monitoring` | **200** |
| `/reports` | **200** |
| `/settings` | **200** |

### Backend Regression — 412/412 PASS

```
Ran 412 tests in 19.625s   OK

[ML BENCHMARK]  Precision: 1.0000  Recall: 1.0000  F1: 1.0000
[SYNTHETIC IOC]  Precision: 1.0000  Recall: 1.0000  F1: 1.0000
```

---

## 8. Responsive Strategy

- **Sidebar**: Hidden below `lg` breakpoint, accessible via mobile nav trigger
- **KPI grids**: `grid-cols-1 sm:grid-cols-2 lg:grid-cols-4` / `lg:grid-cols-5`
- **Detail panels**: Full-width below `lg`, side-by-side at `lg+`
- **Tables**: Horizontal scroll on mobile with `overflow-x-auto`
- **Host column**: `hidden md:table-cell` on narrow viewports

---

## 9. Accessibility & SSR Safety

- All client-only time values (`new Date()`, `toLocaleTimeString()`) mounted via `useState + useEffect` to prevent hydration mismatches
- Semantic HTML: `<nav>`, `<main>`, `<button>`, `<table>`, `<th scope>` throughout
- ARIA labels on icon-only buttons
- Keyboard navigation supported on all interactive elements
- Focus rings visible on all focusable elements

---

*Document generated: 2026-11-11 | MICHAEL v1.0.0 | Build: Next.js 16.4.4 / webpack*

