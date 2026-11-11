# CHAPTER 7: EXISTING SYSTEM & LIMITATIONS

## 5.1 Analysis of Traditional Security Monitoring Architectures
Traditional enterprise security architectures rely predominantly on three classes of monitoring tools:
1. **Centralized Syslog Collectors (e.g., rsyslog, syslog-ng):** Primarily function as transport and aggregation utilities. They store raw text files on central disk arrays without semantic parsing, correlation, or behavioral analysis.
2. **Legacy Rule-Based SIEMs (e.g., Splunk Core, Elastic Stack / ELK, ArcSight):** Parse logs using regular expressions and execute boolean query alerts against static thresholds (e.g., alert if failed logins exceed 10 in 5 minutes).
3. **Point Anomaly Detection Engines:** Evaluate single features (e.g., packet counts or response times) using basic statistical bounds or black-box density estimators.

## 5.2 Systemic Deficiencies in Existing Systems

### 1. Alert Fatigue & High False-Alarm Ratios
Because static threshold rules cannot distinguish between benign operational spikes (e.g., a scheduled administrative backup or marketing campaign) and genuine attacks, they produce immense volumes of false alarms. Security analysts experience cognitive fatigue, causing them to deprioritize alerts.

### 2. High False-Negative Vulnerability to Zero-Day Attacks
Static rules only detect attacks with known, pre-programmed signatures. Novel zero-day injection attacks, polymorphic script commands, and low-and-slow reconnaissance that deliberately operate beneath threshold levels remain completely invisible to traditional SIEMs.

### 3. Fragmented Triage Workflows
In existing platforms, an alert indicating an SSH login failure is stored in one dashboard, a web server 500 error in another, and a firewall outbound connection in a third. The burden of mentally connecting these disjoint events into a coherent attack progression falls entirely upon human analysts.

### 4. Telemetry Deficit Misinterpretation
When traditional tools integrate external threat intelligence feeds, they frequently coerce an external provider's $404\text{ Not Found}$ response into a "Clean" classification. This critical error allows newly established attacker command-and-control servers—which have zero historical records in threat databases—to bypass perimeter monitoring undetected.

### 5. Destructive State Overwrites
Many automated orchestration tools execute state mutations directly on primary tickets. When an automated engine correlates an indicator, it often changes the incident's severity or marks an unverified IP as compromised without human oversight, undermining analyst trust in the system.

