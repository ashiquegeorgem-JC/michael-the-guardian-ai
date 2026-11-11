# MICHAEL – THE GUARDIAN AI
## Command Centre Visual Intelligence Redesign Audit Report

**Academic Title:** Intelligent Log Analysis and Anomaly Detection Using Artificial Intelligence  
**Product Name:** MICHAEL – THE GUARDIAN AI  
**Tagline:** *"Intelligence That Watches. AI That Protects."*  
**Phase:** Command Centre Visual Intelligence Upgrade  
**Date:** November 2026  
**Status:** ✅ COMPLETE & VERIFIED

---

## 1. Executive Summary

The primary Command Centre (`/dashboard`) has been upgraded from a generic admin/analytics card view into a **Cyber Defense Security Operations Center (SOC) Command Centre**.

This upgrade is purely visual and architectural on the presentation layer. It preserves 100% of existing backend APIs, ML detection pipelines, WebSocket streaming, database persistence modes, IOC subsystems, attack-chain reconstruction, and forensic evidence traceability.

---

## 2. Files Modified & Created

### Modified File:
- [`frontend/src/app/dashboard/page.tsx`](file:///c:/Users/Ashique/OneDrive/Desktop/Michael%20-%20The%20Guardian%20AI/frontend/src/app/dashboard/page.tsx) — Completely restructured into the SOC Command Grid layout, binding all real-time feeds and specialized SOC widgets.

### New Specialized SOC Components Created:
1. [`frontend/src/components/dashboard/TopCommandStrip.tsx`](file:///c:/Users/Ashique/OneDrive/Desktop/Michael%20-%20The%20Guardian%20AI/frontend/src/components/dashboard/TopCommandStrip.tsx) — Compact top command strip with active defense indicators, live WebSocket telemetry, ML engine status, database health, threat level, and quick controls.
2. [`frontend/src/components/dashboard/ThreatStatusHero.tsx`](file:///c:/Users/Ashique/OneDrive/Desktop/Michael%20-%20The%20Guardian%20AI/frontend/src/components/dashboard/ThreatStatusHero.tsx) — Radial SVG threat ring indicator (72% ELEVATED/CRITICAL/GUARDED) + dense cyber KPI badges.
3. [`frontend/src/components/dashboard/LiveThreatGraph.tsx`](file:///c:/Users/Ashique/OneDrive/Desktop/Michael%20-%20The%20Guardian%20AI/frontend/src/components/dashboard/LiveThreatGraph.tsx) — Centerpiece multi-series Recharts chart visualizing ingestion volume (cyan), anomaly intensity (blue), and incident bursts (rose) with reference threshold.
4. [`frontend/src/components/dashboard/AnomalySeverityDonut.tsx`](file:///c:/Users/Ashique/OneDrive/Desktop/Michael%20-%20The%20Guardian%20AI/frontend/src/components/dashboard/AnomalySeverityDonut.tsx) — Recharts donut chart with centered total count and percentage breakdown across Critical, High, Medium, and Low tiers.
5. [`frontend/src/components/dashboard/AttackChainFlow.tsx`](file:///c:/Users/Ashique/OneDrive/Desktop/Michael%20-%20The%20Guardian%20AI/frontend/src/components/dashboard/AttackChainFlow.tsx) — MITRE ATT&CK 6-stage adversary progression flow diagram (Recon → Access → Credential → Privilege Escalation → C2 → Exfiltration) with active detection highlights.
6. [`frontend/src/components/dashboard/DetectionIntelligenceBars.tsx`](file:///c:/Users/Ashique/OneDrive/Desktop/Michael%20-%20The%20Guardian%20AI/frontend/src/components/dashboard/DetectionIntelligenceBars.tsx) — Horizontal gradient signal breakdown showing contributions of Isolation Forest, Temporal Behaviour, TF-IDF, Z-Score, Rule Engine, and Hybrid Correlation.
7. [`frontend/src/components/dashboard/LiveEventConsole.tsx`](file:///c:/Users/Ashique/OneDrive/Desktop/Michael%20-%20The%20Guardian%20AI/frontend/src/components/dashboard/LiveEventConsole.tsx) — Dark SOC terminal console with category filter chips (CRIT, WARN, ANOMALY, IOC, INCIDENT), real-time WebSocket event ingestion, and stream pause/resume controls.
8. [`frontend/src/components/dashboard/ThreatIntelGauge.tsx`](file:///c:/Users/Ashique/OneDrive/Desktop/Michael%20-%20The%20Guardian%20AI/frontend/src/components/dashboard/ThreatIntelGauge.tsx) — Enriched threat score gauge, VirusTotal v3 provider status, IOC type breakdown chips, and high-priority suspicious IOC list.
9. [`frontend/src/components/dashboard/SystemTelemetryStrip.tsx`](file:///c:/Users/Ashique/OneDrive/Desktop/Michael%20-%20The%20Guardian%20AI/frontend/src/components/dashboard/SystemTelemetryStrip.tsx) — Full-width infrastructure monitoring telemetry strip with real-time gauges for CPU, RAM, Disk, Network Throughput, Ingestion EPS, and pipeline vitality.
10. [`frontend/src/components/dashboard/RecentIncidentsTable.tsx`](file:///c:/Users/Ashique/OneDrive/Desktop/Michael%20-%20The%20Guardian%20AI/frontend/src/components/dashboard/RecentIncidentsTable.tsx) — Compact SOC incident triage queue with severity badges, source attribution, detection method, and one-click triage navigation.

---

## 3. Visual & UX Improvements

| Dimension | Before Redesign | After Redesign |
|---|---|---|
| **Aesthetic Paradigm** | Generic admin dashboard with large cards | Enterprise SOC / Cyber Defense Command Centre |
| **Color Theme** | Standard dark theme | Deep midnight navy (`#070B14`, `#0A0F1D`) with subtle electric blue, cyan, and violet accents |
| **Threat Status** | Static rectangular number card | Dynamic SVG radial progress ring with live color transitions |
| **Main Timeline** | Single-metric log volume line chart | Multi-series area chart combining Event Volume, Anomaly Score, and Incident Spikes with threshold line |
| **Anomaly Breakdown** | Basic horizontal bar chart | Circular donut chart with centered anomaly metric count and tier legend |
| **Attack Chains** | Absent on dashboard or plain table | 6-Stage MITRE ATT&CK node flow diagram with active stage detection indicators |
| **Detection Engines** | Not visualized | 6-Signal detection intelligence breakdown with progress bars |
| **Live Telemetry Stream** | Small text box | Full-featured SOC terminal console with live category filters |
| **IOC & Threat Intel** | Missing from main dashboard | Dedicated threat score gauge, provider status, and IOC type breakdown chips |
| **Hardware Telemetry** | Two small text indicators | 6-Tile infrastructure monitoring strip (CPU, RAM, Disk, Net, EPS, Pipeline) |
| **Information Density** | Sparse, requiring vertical scrolling | Compact, high-density SOC viewport communicating What → How Severe → Where → Why → Action |

---

## 4. Data Sources & API Integrations

All data displayed in the redesigned Command Centre originates from existing backend APIs and WebSocket feeds:

1. **`getDashboardStats()` (`/api/monitoring/dashboard`):** Total logs, total anomalies, total incidents, critical incidents, open incidents, and hardware metrics.
2. **`getLogStats()` (`/api/logs/stats`):** Ingestion hourly volume timeline points and log level distribution.
3. **`getIncidentSummary()` (`/api/incidents/summary`):** Severity distribution (CRITICAL, HIGH, MEDIUM, LOW) and category distribution.
4. **`getIncidents({ page_size: 5 })` (`/api/incidents`):** Active incident triage list with affected entities and root cause hypotheses.
5. **`getAttackChains()` (`/api/attack-chains`):** Reconstructed adversary progressions and observed MITRE attack stages.
6. **`getIOCSummary()` (`/api/iocs/summary`):** Total IOCs, type distribution, status breakdown, and confirmed/suspicious counts.
7. **`listIOCs({ page_size: 5 })` (`/api/iocs`):** High-priority indicator list with normalized values and threat reputations.
8. **`useWebSocket()` (`ws://.../ws/monitoring`):** Live streaming metrics (`cpu_percent`, `memory_percent`, `network_throughput`, `events_per_sec`) and incoming log events.

*Zero fake or hardcoded security metrics were introduced.*

---

## 5. Charts & Visualizations Added

1. **Radial Threat Ring:** Custom SVG circular gauge dynamically rendering threat score percentage (12% to 96%) with gradient stroke and threat level classification.
2. **Multi-Series Threat Activity Area Chart:** Recharts `AreaChart` with gradient fills, dual Y-axes (Event Volume on left, Anomaly Score % on right), and threshold reference line at 0.50.
3. **Anomaly Severity Donut Chart:** Recharts `PieChart` with `innerRadius={50}` and `outerRadius={72}`, centered text counter, and color-coded severity slices.
4. **MITRE ATT&CK Stage Progression Flow:** Directed pipeline flow with 6 stages (`Reconnaissance`, `Initial Access`, `Credential Access`, `Privilege Escalation`, `Execution & C2`, `Exfiltration`), active detection badges, and pulse animations.
5. **Detection Signal Progress Bars:** 6-engine breakdown with animated gradient tracks.
6. **Hardware Telemetry Gauge Bars:** Real-time mini progress bars for CPU, Memory, Disk, Network Throughput, and Ingestion Rate.

---

## 6. Verification & Build Results

### Production Build Validation
- **Command:** `npm --prefix frontend run build`
- **TypeScript:** `0 errors` (Finished in 3.3s)
- **Static Route Generation:** `15 / 15 static routes generated`
- **Exit Code:** `0` (Success)

### Browser / HTTP Live Probe Validation
- **Endpoint:** `GET http://localhost:3000/dashboard`
- **HTTP Status:** `200 OK` (Rendered in 951ms)
- **Payload Size:** `87,127 bytes`
- **Key Sections Verified:**
  - `GUARDIAN ACTIVE` status badge: ✅ FOUND
  - `MICHAEL` brand identity: ✅ FOUND
  - `LIVE THREAT ACTIVITY` chart container: ✅ FOUND
  - `ANOMALY SEVERITY` donut container: ✅ FOUND
  - `ATTACK CHAIN RECONSTRUCTION` flow: ✅ FOUND
  - `DETECTION INTELLIGENCE` signal bars: ✅ FOUND
  - `LIVE SECURITY EVENT STREAM` console: ✅ FOUND
  - `THREAT INTELLIGENCE & IOCS` gauge: ✅ FOUND
  - `INFRASTRUCTURE TELEMETRY` strip: ✅ FOUND
  - `ACTIVE INCIDENTS` triage queue: ✅ FOUND

---

## 7. Preserved Invariants & Unchanged Systems

1. **Backend Architecture:** Completely untouched; zero backend code changes.
2. **Machine Learning Pipeline:** Isolation Forest, TF-IDF, contamination rate, and scoring formulas remain identical.
3. **APIs & Schemas:** Zero API contract changes; all existing endpoints function normally.
4. **Subsystems:** Attack-chain engine, IOC subsystem, threat intelligence, Copilot, and PDF report generator remain intact.
5. **Other Routes:** `/logs`, `/anomalies`, `/incidents`, `/attack-chains`, `/iocs`, `/threat-intelligence`, `/copilot`, `/monitoring`, `/reports`, `/settings` all compile and function as before.

---

## 8. Remaining Limitations

1. **Synthetic Telemetry in Dev Mode:** When psutil is absent, hardware metrics fall back to realistic simulated variations as designed in `monitor.py`.
2. **Tailwind v4 Non-blocking Warning:** 1 standard Turbopack warning on `@theme` in `globals.css` noted and preserved without modification.

---

*"Intelligence That Watches. AI That Protects."*  
**MICHAEL – THE GUARDIAN AI**  
Command Centre Visual Intelligence Redesign Complete

