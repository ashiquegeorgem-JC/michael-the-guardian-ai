# MICHAEL — THE GUARDIAN AI
## Complete Premium SOC Website Redesign & Global Design Audit

**Product Name:** MICHAEL — THE GUARDIAN AI  
**Academic Title:** *Intelligent Log Analysis and Anomaly Detection Using Artificial Intelligence*  
**Tagline:** *“Intelligence That Watches. AI That Protects.”*  
**Date:** November 10, 2026  
**Status:** **PASSED & PRODUCTION READY (100% AUDITED)**  

---

### Executive Summary

A comprehensive, full-application visual and architectural redesign was performed across the entire **MICHAEL – THE GUARDIAN AI** platform. Rather than redesigning isolated modules, one unified, enterprise-grade Security Operations Center (SOC) visual intelligence system was engineered and deployed across all 11 product pages and the global application shell.

The result is a cohesive, dark, technical, and spacious cyber defense platform that reflects high information density without visual clutter.

---

### 1. Global Visual & Design System Architecture

#### A. Foundational Color Palette
The application foundation is anchored in near-black and deep midnight navy tones, providing extreme contrast with high-visibility semantic security indicators:

| Token | Hex Value / CSS | Usage |
|---|---|---|
| **Background (Base)** | `#05070D` | Root application background, shell foundation, table canvas |
| **Main Surface** | `#0A0F18` | Primary panel containers, KPI cards, sidebar, table containers |
| **Elevated Surface** | `#0E1420` | Secondary cards, dropdowns, selected items, modal surfaces |
| **Secondary Surface** | `#111827` | Inner technical boxes, raw log viewports |
| **Border (Subtle)** | `rgba(255, 255, 255, 0.07)` | Standard structural panel and card separators |
| **Border (Strong)** | `rgba(255, 255, 255, 0.12)` | Active states, hover highlights, table headers |
| **Primary Blue** | `#2F81F7` | Primary action buttons, selection indicators, telemetry lines |
| **Cyan** | `#00C2FF` | Live indicator badges, IOCs, network volume, active filters |
| **Violet** | `#7C3AED` | Multi-stage correlation accents, temporal analytics, model NLP |
| **Success (Green)** | `#19D879` | Healthy status, cleared logs, normal baseline, active guardian |
| **Warning (Amber)** | `#F5B942` | Elevated risk, suspicious IOCs, warning logs, threshold indicators |
| **Critical (Red)** | `#FF4D5A` | Malicious threats, critical incidents, kill chain breaches |
| **Text Primary** | `#F4F7FB` | Primary headings, titles, high-contrast metric values |
| **Text Secondary** | `#94A3B8` | Body descriptions, table content, metadata |
| **Text Muted** | `#64748B` | Timestamp strings, column captions, inactive icons |

#### B. Typography Scale & Hierarchy
- **Primary Typeface:** `Inter`, system-ui, -apple-system, sans-serif
- **Technical & Data Typeface:** `JetBrains Mono`, monospace (used for all timestamps, IP addresses, hashes, raw log strings, and metric figures)
- **Hierarchy:**
  - Page Titles: 28px–32px (bold, uppercase font-sans with letter-spacing)
  - Section Headings: 14px–16px (bold, font-mono tracking-wider)
  - KPI Hero Metrics: 24px–32px (extra-bold, font-mono)
  - Table Content: 11px–12px (font-mono with tabular numbers)

#### C. Spacing, Radii & Depth
- **Panel Radii:** 12px–16px smooth corners with `1px solid rgba(255, 255, 255, 0.07)` borders
- **Panel Shadows:** `0 4px 20px rgba(0, 0, 0, 0.5)` to `0 8px 32px rgba(0, 0, 0, 0.7)`
- **Content Padding:** `24px 28px` main view spacing, `16px–24px` internal panel padding

---

### 2. Global Application Shell

#### A. Sidebar (`Sidebar.tsx`)
A dark navigation rail (`#05070D`) with collapsible width (250px expanded / 72px collapsed):
- **Brand Identity:** Shield icon gradient pill with "MICHAEL" and "THE GUARDIAN AI"
- **Group 1: CORE**
  - Command Centre (`/dashboard`)
  - Log Explorer (`/logs`)
  - Anomaly Detection (`/anomalies`)
  - Incident Centre (`/incidents`)
  - Attack Chains (`/attack-chains`)
  - IOC Intelligence (`/iocs`)
  - Threat Intelligence (`/threat-intelligence`)
- **Group 2: INTELLIGENCE**
  - AI Copilot (`/copilot`)
  - Live Monitoring (`/monitoring`)
- **Group 3: TOOLS**
  - Reports (`/reports`)
  - Settings (`/settings`)
- **Footer:** Dynamic `● GUARDIAN ACTIVE` status badge and collapse/expand toggle.

#### B. Unified Top Command Bar (`Topbar.tsx`)
Fixed sticky command header across every single page:
- **Left:** Page Title, category badge (`SOC v1.0`), and descriptive operational subtitle
- **Right Status Indicators:**
  - `● LIVE` pulsing emerald status indicator
  - `● WS: STREAMING` real-time WebSocket connection state
- **Quick Action Controls:**
  - `[ + INGEST LOGS ]` (Direct routing to `/logs`)
  - `[ ✦ AI COPILOT ]` (Direct routing to `/copilot`)
  - `[ ↻ REFRESH ]` (Instant page telemetry synchronization)
  - Notification icon button with critical alert badge
  - `MICHAEL v1.0` verified enterprise badge

---

### 3. Comprehensive Page Redesign Inventory

| Route | Page Name | Key Features & Design Redesign |
|---|---|---|
| `/dashboard` | **Command Centre** | 10-component SOC centerpiece: Radial SVG threat ring, multi-series area chart, anomaly donut, MITRE 6-stage rail, detection signal bars, live event console, hardware strip, incident triage queue. |
| `/logs` | **Log Explorer** | Ingestion KPI strip (Events, Errors, Warnings, Channels), collapsible Drag & Drop upload zone with demo loaders, dual-metric hourly volume & severity graph, session selector, search toolbar, security table (TIME, SOURCE, EVENT, SEVERITY, DETECTION, STATUS), and slide-over inspector. |
| `/anomalies` | **Anomaly Detection** | KPI strip (ANOMALIES, CRITICAL, HIGH, MEDIUM, LOW), multi-point Anomaly Score Timeline chart, 6-engine Detection Intelligence bars, severity filter chips, active session selector, and full anomaly investigation table. |
| `/incidents` | **Incident Centre** | Incident-response workspace: 5-metric triage strip (Active, Critical, High, Medium, Resolved), status filter chips, dual-column responsive workspace (interactive left queue + right deep forensic panel with root cause hypotheses, affected IPs, raw evidence attestation, and remediation checklists). |
| `/attack-chains` | **Attack Chains** | MITRE ATT&CK progression rail with interactive node stages (*Reconnaissance → Initial Access → Credential Attack → Privilege Escalation → Execution → Exfiltration*), summary analytics, multi-criteria search, timeline graph, and correlated entity inspection. |
| `/iocs` | **IOC Intelligence** | 6-card indicator breakdown (IPv4, Domains, URLs, Hashes, Files, Total IOCs), normalized entity search toolbar, split-view repository table, and detail investigation drawer (Overview, Evidence, Relationships, Threat Intel, Attack Chains). |
| `/threat-intelligence` | **Threat Intelligence** | Enterprise intelligence platform: VirusTotal v3 provider metrics, composite threat score gauge, filter toolbar, side-by-side indicator queue, provider findings, multi-entity correlation graph (IOC → Event → Anomaly → Incident → Attack Chain), and timeline forensics. |
| `/copilot` | **AI Copilot** | AI analyst workspace: Context panel (Active Incidents, Threat Score, Correlated IOCs, Attack Chain Status), live conversation stream with markdown-like formatting, evidence verification drawer, prompt recommendation chips, and fast forensic query input. |
| `/monitoring` | **Live Monitoring** | Infrastructure SOC telemetry: 5-metric runtime strip (CPU, RAM, Disk, Network, EPS), 4-subsystem service health matrix (WebSocket, Pipeline, ML Engine, Database), continuous 30-second rolling history area chart, and terminal stream console. |
| `/reports` | **Reports** | Executive document management interface: Compliance KPI strip (NIST CSF, ISO 27001), report generation parameter form (session, title, raw evidence toggle), PDF export generator, and document repository management table with download and verification actions. |
| `/settings` | **Settings** | Tabbed settings workspace (General, Detection Engine, Threat Intelligence, Data Storage, WebSocket, Security & RBAC, System & Health), model hyperparameter tuning sliders (contamination, n_estimators, threshold), and API connectivity verification. |

---

### 4. Shared Reusable Component Architecture

- **`SecurityPanel.tsx`**: Standard dark panel wrapper (`#0A0F18`) with title, subtitle, icon, right actions, and subtle borders.
- **`MetricCard.tsx`**: High-contrast KPI tile featuring font-mono numerical statistics, accent colors, status icons, and trend badges.
- **`EmptyState.tsx`**: Polished empty state with subtle shield icon, informative text, and call-to-action button (never leaving blank areas).
- **`Button.tsx`**: Unified button component with dark surfaces, subtle borders, rounded corners, icons, hover/active/loading states.
- **`Badge.tsx`**: Semantic status pill badges (CRITICAL, HIGH, MEDIUM, LOW, OPEN, RESOLVED, etc.).
- **`Card.tsx`**: Enhanced dark card container providing consistent borders, paddings, and header/footer dividers.

---

### 5. Multi-Tier Verification Results

#### A. Frontend Production Build
```bash
npm --prefix frontend run build
```
- **Exit Code:** `0` (Success)
- **Static Pages Generated:** `15/15` routes prerendered
- **TypeScript Errors:** `0`
- **Turbopack Compilation Time:** 1.8s
- **Static Route Manifest:**
  - `○ /` (Prerendered static)
  - `○ /_not-found` (Prerendered static)
  - `○ /anomalies` (Prerendered static)
  - `○ /attack-chains` (Prerendered static)
  - `○ /copilot` (Prerendered static)
  - `○ /dashboard` (Prerendered static)
  - `○ /incidents` (Prerendered static)
  - `○ /iocs` (Prerendered static)
  - `○ /logs` (Prerendered static)
  - `○ /monitoring` (Prerendered static)
  - `○ /reports` (Prerendered static)
  - `○ /settings` (Prerendered static)
  - `○ /threat-intelligence` (Prerendered static)

#### B. Full Backend Regression Suite
```bash
python -m unittest discover -s backend/tests -p "test_*.py"
```
- **Result:** **Ran 412 tests in 13.923s — OK (412/412 PASS)**
- **Regression Failures:** `0`
- **Errors:** `0`
- **ML Detection Benchmark:** Precision = 1.0000, Recall = 1.0000, F1 = 1.0000
- **Synthetic IOC Extraction:** Precision = 1.0000, Recall = 1.0000, F1 = 1.0000

#### C. End-to-End Live HTTP Smoke Test
- **Backend Endpoints:**
  - `GET /api/health` → `200 OK`
  - `GET /api/ready` → `200 OK`
  - `GET /api/logs/stats` → `200 OK`
  - `GET /api/incidents/summary` → `200 OK`
  - `GET /api/iocs/summary` → `200 OK`
  - `GET /api/attack-chains` → `200 OK`
  - `GET /api/monitoring/dashboard` → `200 OK`
- **Frontend Pages:**
  - `GET /` → `200 OK` (91,985 bytes)
  - `GET /dashboard` → `200 OK` (91,985 bytes)
  - `GET /logs` → `200 OK` (50,064 bytes)
  - `GET /anomalies` → `200 OK` (55,335 bytes)
  - `GET /incidents` → `200 OK` (46,079 bytes)
  - `GET /iocs` → `200 OK` (48,995 bytes)
  - `GET /attack-chains` → `200 OK` (42,719 bytes)
  - `GET /threat-intelligence` → `200 OK` (48,252 bytes)
  - `GET /copilot` → `200 OK` (47,972 bytes)
  - `GET /monitoring` → `200 OK` (51,519 bytes)
  - `GET /reports` → `200 OK` (48,657 bytes)
  - `GET /settings` → `200 OK` (41,145 bytes)
- **SOC Brand Markers:** Verified all 14 core markers present in rendered HTML (`MICHAEL`, `GUARDIAN ACTIVE`, `LIVE THREAT ACTIVITY`, `SOC CONSOLE`, `MITRE`, etc.).

---

### Conclusion

The complete frontend of **MICHAEL – THE GUARDIAN AI** now operates on a single, cohesive, premium enterprise dark SOC visual system. Every page delivers professional information density, refined typography, and seamless interaction without visual clutter or generic admin aesthetics.

