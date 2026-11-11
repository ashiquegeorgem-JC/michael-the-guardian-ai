# PRESENTER SCRIPT: CAPSTONE DEFENSE PRESENTATION

**Product Name:** MICHAEL – THE GUARDIAN AI  
**Academic Title:** *Intelligent Log Analysis and Anomaly Detection Using Artificial Intelligence*  
**Tagline:** *“Intelligence That Watches. AI That Protects.”*  
**Target Duration:** 12–15 Minutes  

---

## [00:00 – 02:00] 1. Opening & Problem Context

"Good morning, respected members of the evaluation committee, project supervisors, and faculty members.

Today, I am proud to present our capstone engineering defense project: **MICHAEL – THE GUARDIAN AI**, an intelligent log analysis, anomaly detection, and threat correlation platform engineered for modern Security Operations Centers.

To understand why MICHAEL was built, consider the operational reality of enterprise cybersecurity today. A standard datacenter emits tens of millions of raw log entries every 24 hours. Hidden within these millions of lines are subtle traces of intrusion: credential harvesting, lateral movement, database probes, and data exfiltration.

However, traditional monitoring tools—such as legacy SIEMs and syslog collectors—suffer from three severe failures:
1. **The Velocity Gap:** Human analysts cannot review 50,000 logs a minute.
2. **Alert Fatigue:** Because existing tools rely on brittle, static threshold rules, they drown analysts in thousands of false-positive alarms every day. Analysts burn out, and real attacks get missed.
3. **Context Fragmentation:** An authentication failure, a database error, and an outbound socket are alerted on three separate screens. The analyst has to manually piece together what happened.

MICHAEL was designed to solve this. Operating under our core tagline, *“Intelligence That Watches. AI That Protects.”*, MICHAEL autonomous transforms unstructured log streams into unified, explainable threat contexts."

---

## [02:00 – 06:00] 2. Technical Architecture & Hybrid Machine Learning

"Now, let us examine how the system works technically.

When a log stream is ingested, MICHAEL parses and normalizes it into structured `LogEntry` entities, standardizing timestamps into explicit UTC objects while preserving the exact raw line and physical line number.

Rather than relying on a single black-box algorithm, our detection tier implements an **explainable Hybrid Multi-Model Ensemble**:
1. **Unsupervised Isolation Forest:** We extract numeric feature vectors representing message character length, numerical digit density, and Shannon character entropy. Because anomalies are structurally 'few and different,' Isolation Forest isolates them near the root of random decision trees.
2. **TF-IDF Semantic Dispersion:** We tokenize log vocabulary to identify rare exploit syntax—such as `UNION SELECT` or `/etc/shadow`—that might have normal length but abnormal semantic weights.
3. **Statistical Z-Score Bounds:** We flag extreme volumetric deviations across quantitative metrics.
4. **Deterministic Heuristic Rules:** We guarantee $100\%$ precision on verified critical exploit signatures like SQL injection and path traversal.

Complementing this point detection is our **Temporal Behaviour Intelligence Engine**. A single login failure is normal; 50 failures in 10 seconds is an attack. Our temporal engine runs four sliding-window horizons—10 seconds, 30 seconds, 60 seconds, and 300 seconds—computing rolling standard deviations, Exponential Moving Averages, and first-order rates of change to catch burst attacks and periodic C2 beaconing.

When anomalies occur on shared entities, our **Incident Triage Service** clusters them into structured `Incident` records with root-cause hypotheses and remediation steps. Furthermore, our **Attack Chain Engine** reconstructs chronological progression graphs mapped directly to the **MITRE ATT&CK** matrix, showing the intrusion narrative from Initial Access to Exfiltration."

---

## [06:00 – 09:30] 3. Threat Intelligence, Forensic Invariants & Security

"Next, let us look at the forensic and threat intelligence tier.

MICHAEL extracts indicators of compromise across 9 standard classes—including IPv4, IPv6, Domains, URLs, and SHA-256 hashes. We enforce strict RFC normalization, such as stripping IPv4 leading zeros, case-folding domains, and compressing IPv6 per RFC 5952. Crucially, every indicator maintains an append-only `IOCEvidence` record linking directly to the exact source event ID and line number.

When querying threat intelligence feeds—via our offline air-gapped mock provider or our live VirusTotal API integration—we enforce two critical academic and security invariants:

First, **The Telemetry Deficit Defense**: In standard SIEMs, if an external API returns a 404 Not Found response, the system naively assumes the IP is 'Clean.' This is a dangerous flaw because newly created attacker C2 servers have zero historical records in public feeds. In MICHAEL, we strictly enforce:
$$\text{HTTP } 404 \implies \text{ThreatIntelStatus.UNKNOWN}$$
We never coerce a lack of data into a false declaration of innocence.

Second, **Decoupled Scoring**: We calculate Threat Score ($0–100$) independently from Threat Confidence ($0–1$). If a single engine flags an IP, the threat score is high ($75.0$), but the confidence is penalized ($0.25$). Conversely, if 70 engines declare an IP safe, the threat score is $0.0$ and confidence is $0.95$. Analysts see both numbers and their explainable contributing signal breakdown.

Third, our cardinal correlation rule: **Correlation is NOT Classification**. Automated correlation adds directional evidence relationships, but it **never** mutates human analyst triage statuses (`IOCStatus`). Furthermore, cross-session correlations receive a $0.40$ confidence penalty and are marked unconfirmed, preventing cross-tenant data contamination."

---

## [09:30 – 12:00] 4. Empirical Results & Performance Benchmarks

"Let us review our empirical results.

In strictly partitioned, held-out synthetic validation benchmarks across 190 labeled log entries under anti-leakage spatial and temporal separation:
- Standalone heuristic rules achieved $100\%$ precision but only $28.57\%$ recall on zero-day attacks.
- Standalone statistical Z-scores achieved only $4.29\%$ recall on semantic attacks.
- Our **MICHAEL Hybrid Multi-Model Ensemble** achieved **$94.21\%$ Accuracy**, **$92.75\%$ Precision**, **$91.43\%$ Recall**, and an **ROC-AUC of $0.9927$**, successfully isolating $100\%$ of novel zero-day patterns.

In persistence benchmarks on SQLite file storage:
- Ingestion sustained bulk insertion throughput of **$8,290$ to $10,559$ log events per second**.
- Point-read query latency averaged **$0.49\text{ms}$ to $0.81\text{ms}$**.
- Process restart recovery tests verified **$100\%$ zero data loss**.

Our quality gates are rigorously validated:
- **Backend Regression Suite:** **412 / 412 tests PASS (100%)** in $13.43\text{ seconds}$.
- **Frontend Production Build:** **15 / 15 routes statically prerendered cleanly** with 0 errors.
- **Security Audit:** **12 / 12 defensive vectors PASSED** including secret scrubbing, SSRF defense, and XSS immunity."

---

## [12:00 – 14:00] 5. Operational Limitations, Future Work & Conclusion

"In keeping with scientific integrity, we explicitly acknowledge our operational boundaries:
1. Our benchmarks reflect controlled synthetic validation fixtures. Live enterprise deployment requires continuous calibration against site-specific background noise.
2. Free-tier public VirusTotal lookups are bounded by provider quotas (4 requests/minute); production deployments require commercial multi-provider licenses.
3. Our sliding windows currently span up to 5 minutes; multi-week low-and-slow drip campaigns evade short-horizon Z-scores.
4. We intentionally omit autonomous destructive blocking (such as automatically killing processes or altering firewall rules) to prevent false-positive denial-of-service on critical enterprise assets. Human analysts remain in the loop by design.

Our future roadmap includes scaling to distributed Apache Kafka log streaming, multi-provider threat intelligence consensus, native Neo4j graph database backends, and analyst-confirmed one-click SOAR remediation webhooks.

In conclusion, **MICHAEL – THE GUARDIAN AI** proves that autonomous anomaly detection, temporal frequency modeling, and threat intelligence can be unified into an explainable, durable, and production-ready platform that empowers SOC analysts to defend modern infrastructure.

Thank you very much. I am now open to your questions."

