# CHAPTER 15: LIMITATIONS

## 13.1 Academic and Operational Boundaries
In accordance with academic standards of scientific transparency, this chapter documents the operational boundaries and technical constraints of **MICHAEL – THE GUARDIAN AI**:

### 1. Synthetic Validation Constraints
Empirical detection metrics ($94.21\%$ Accuracy, $0.9209$ F1-Score) and IOC extraction benchmarks ($1.0$ F1-Score) were established using rigorously partitioned, held-out synthetic datasets ($N=190$ and $23$ ground-truth scenarios). While these datasets enforce spatial and temporal disjointness to simulate zero-day attacks, they cannot fully reflect the unbounded semantic entropy, malformed characters, and vendor-specific dialect quirks present in large live enterprise datacenters.

### 2. External Provider Rate Limits
Integration with external threat feeds (specifically public VirusTotal API v3) is bounded by provider quotas (e.g., 4 requests per minute for public free tiers). While the architecture implements thread-safe TTL caching and graceful 429 error mapping, enterprise environments ingesting tens of thousands of unique indicators require commercial multi-provider aggregation licenses or local offline threat database mirrors.

### 3. Horizon Constraints on "Low-and-Slow" Campaigns
The Temporal Behaviour Intelligence Engine currently evaluates sliding windows spanning durations up to 300 seconds ($5\text{ minutes}$). An adversary executing a stealthy "drip" attack (e.g., a single brute-force attempt every 45 minutes across 30 days) will evade detection within 5-minute sliding windows. Detecting multi-week low-frequency campaigns requires multi-day persistent state aggregation.

### 4. Deliberate Absence of Autonomous Destructive Remediation
MICHAEL deliberately omits autonomous destructive response actions (e.g., automatically killing processes, reconfiguring live edge firewall rules, or locking user directories). This is an intentional design boundary: autonomous intervention in automated systems introduces severe operational risks of unintended denial-of-service against legitimate business assets due to false positives. The platform provides explainable prescriptive guidance, reserving containment authority for human SOC operators.

### 5. Threat Intelligence Coverage Asymmetry
External intelligence databases rely upon previously observed telemetry. Novel command-and-control infrastructure and private attacker IP ranges have zero historical presence in threat feeds. MICHAEL mitigates this via its `UNKNOWN != CLEAN` invariant, but absence of intelligence remains an inherent limitation of external threat feeds.

