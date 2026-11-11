# ACADEMIC ABSTRACT

**Title:** Intelligent Log Analysis and Anomaly Detection Using Artificial Intelligence  
**System:** MICHAEL – THE GUARDIAN AI  
**Tagline:** *“Intelligence That Watches. AI That Protects.”*  
**Keywords:** Log Analysis, Anomaly Detection, Isolation Forest, TF-IDF, Threat Intelligence, Indicators of Compromise (IOC), Threat Correlation, SOC Automation.

---

Automated detection and investigation of cyber threats across heterogeneous computing infrastructure is impeded by immense data velocity, severe class imbalance, high false-positive alarms, and fragmented triage workflows. Traditional Security Information and Event Management (SIEM) systems frequently overwhelm Security Operations Center (SOC) analysts with isolated, context-deficient alerts. This work presents **MICHAEL – THE GUARDIAN AI**, an end-to-end intelligent log analysis, anomaly detection, and threat correlation platform engineered to synthesize multi-tier machine learning with deterministic threat intelligence.

The core architecture ingests multi-format system telemetry (Syslog, Auth, Web/Nginx, Firewall, Application) and executes a hybrid detection pipeline combining unsupervised Isolation Forest spatial isolation, TF-IDF semantic dispersion analysis, statistical Z-score/IQR bounds, deterministic heuristic rules, and multi-scale sliding-window temporal frequency modeling. Detected anomalies are clustered into structured security incidents and correlated into chronological MITRE ATT&CK attack chains. An Indicator of Compromise (IOC) engine extracts, normalizes (RFC-compliant), and validates indicators across nine forensic categories (IPv4, IPv6, Domain, URL, MD5, SHA1, SHA256, Email, File Path) while preserving strict provenance via append-only evidence references.

External intelligence telemetry—ingested via an offline mock provider and a resilient VirusTotal integration—is evaluated by a deterministic Threat Reputation Engine that separates threat severity ($0–100$) from confidence ($0–1$), enforcing strict telemetry deficit safeguards ($\text{UNKNOWN} \ne \text{CLEAN}$). Directional correlations across IOCs, events, anomalies, incidents, and attack chains form a consolidated `UnifiedThreatContext` presented via a 15-route Next.js SOC dashboard. Evaluated under controlled synthetic validation benchmarks, the platform demonstrated zero data loss across process restarts via a 12-table relational persistence tier, sustained over 8,000 log events/sec bulk insertion, passed a 12-vector security audit, and maintained deterministic reproducibility across dual-run verification.

