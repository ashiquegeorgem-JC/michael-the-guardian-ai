"""
Attack Chain Reconstruction Engine (Phase 4.1).

Correlates individual suspicious log events and anomalies into chronological,
multi-stage attack sequences (e.g., Recon -> Initial Access -> Credential Attack
-> Privilege Escalation -> Lateral Movement -> Exfiltration).

Strictly adheres to:
- Explainable correlation rules (timestamps, IP pairs, session tokens, MITRE stages).
- Anti-false-correlation: avoids clustering disjoint events solely due to shared IP.
- Evidence traceability: every stage and link preserves exact line numbers and raw logs.
- Robust handling of missing timestamps, duplicates, and out-of-order logs.
"""

import re
import hashlib
from datetime import datetime, timedelta
from typing import List, Dict, Any, Optional, Tuple
from collections import defaultdict

from app.models.log_entry import LogEntry, LogLevel
from app.models.anomaly import Anomaly
from app.models.incident import Incident
from app.models.attack_chain import (
    AttackChain,
    AttackStage,
    ChainLinkEvent,
    AttackGraphData,
    AttackGraphNode,
    AttackGraphEdge,
    GraphNodeType,
)

# Regex patterns for entity extraction
IP_REGEX = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
# Capture actual username after keywords: 'user admin', 'for user admin', 'account root'
# Uses non-capturing group for keyword, capturing group for the name that follows
USER_REGEX = re.compile(
    r'\b(?:user|for\s+user|account|login(?:\s+as)?|invalid\s+user)\s+([a-zA-Z0-9_\-\.]{2,32})',
    re.IGNORECASE
)
PROCESS_REGEX = re.compile(r'\b(?:process|exec|cmd|binary)\s+([a-zA-Z0-9_\-\./]+)', re.IGNORECASE)

# MITRE ATT&CK Stage signature patterns
STAGE_SIGNATURES: Dict[AttackStage, List[re.Pattern]] = {
    AttackStage.RECONNAISSANCE: [
        re.compile(r'(?:port\s*scan|nmap|nikto|dirb|gobuster|masscan|banner\s*grab)', re.IGNORECASE),
        re.compile(r'(?:404\s*flood|probing\s*paths|directory\s*enumeration|scanning\s*network)', re.IGNORECASE),
    ],
    AttackStage.INITIAL_ACCESS: [
        re.compile(r'(?:sql\s*injection|sqli|union\s*select|\'--|1=1)', re.IGNORECASE),
        re.compile(r'(?:path\s*traversal|\.\./\.\./|etc/passwd|windows/win\.ini)', re.IGNORECASE),
        re.compile(r'(?:cve-\d{4}-\d+|remote\s*code\s*execution|rce\s*payload|log4j|jndi:)', re.IGNORECASE),
        re.compile(r'(?:webshell|cmd\.jsp|eval\(|base64_decode)', re.IGNORECASE),
    ],
    AttackStage.CREDENTIAL_ATTACK: [
        re.compile(r'(?:failed\s*(?:password|login|auth)|invalid\s*user|pam_authenticate)', re.IGNORECASE),
        re.compile(r'(?:brute\s*force|password\s*spraying|hydra|medusa|credential\s*stuffing)', re.IGNORECASE),
        re.compile(r'(?:shadow\s*file|hashcat|john\s*the\s*ripper|kerberoast)', re.IGNORECASE),
    ],
    AttackStage.PRIVILEGE_ESCALATION: [
        re.compile(r'(?:sudo:\s*root|sudo\s+su|setuid|suid|pkexec|sudoers)', re.IGNORECASE),
        re.compile(r'(?:privilege\s*escalat|root\s*session\s*opened|uac\s*bypass|dirtycow)', re.IGNORECASE),
        re.compile(r'(?:chmod\s*\+s|chown\s*root|elevat(?:ed|ing)\s*privilege)', re.IGNORECASE),
    ],
    AttackStage.EXECUTION: [
        re.compile(r'(?:/bin/(?:ba)?sh\s+-i|cmd\.exe|powershell\s+-enc|reverse\s*shell)', re.IGNORECASE),
        re.compile(r'(?:curl\s+[^\s]+\s*\|\s*sh|wget\s+[^\s]+\s*\|\s*bash|spawn\s*process)', re.IGNORECASE),
        re.compile(r'(?:malicious\s*script|payload\s*executed|system\([^\)]+\))', re.IGNORECASE),
    ],
    AttackStage.PERSISTENCE: [
        re.compile(r'(?:authorized_keys|crontab\s+-e|/etc/cron|systemd/system)', re.IGNORECASE),
        re.compile(r'(?:backdoor\s*account|new\s*user\s*created|scheduled\s*task|persistence)', re.IGNORECASE),
    ],
    AttackStage.COMMAND_AND_CONTROL: [
        re.compile(r'(?:c2|beaconing|reverse\s*shell\s*connected|outbound\s*connection\s*to\s*c2)', re.IGNORECASE),
        re.compile(r'(?:dynamic\s*dns|tor\s*proxy|meterpreter|cobalt\s*strike)', re.IGNORECASE),
    ],
    AttackStage.LATERAL_MOVEMENT: [
        re.compile(r'(?:lateral\s*movement|psexec|wmic|internal\s*ssh|smb\s*login)', re.IGNORECASE),
        re.compile(r'(?:pivot(?:ing)?|port\s*forwarding|ssh\s+-R|internal\s*scan)', re.IGNORECASE),
    ],
    AttackStage.DATA_ACCESS: [
        re.compile(r'(?:dump\s*database|pg_dump|mysqldump|select\s+\*\s+from\s+users)', re.IGNORECASE),
        re.compile(r'(?:accessing\s*customer|sensitive\s*data\s*query|reading\s*credit)', re.IGNORECASE),
    ],
    AttackStage.EXFILTRATION: [
        re.compile(r'(?:exfiltrat|massive\s*outbound|large\s*file\s*transfer|megaupload)', re.IGNORECASE),
        re.compile(r'(?:tar\s+-czf\s+.*|zip\s+-r\s+.*dump|dns\s*tunneling|curl\s+-X\s*POST\s+-F)', re.IGNORECASE),
    ],
}


class AttackChainEngine:
    """
    Forensic correlation engine that groups suspicious log events,
    anomalies, and incidents into multi-stage attack chains.
    """

    def __init__(self, correlation_window_minutes: int = 30):
        self.correlation_window = timedelta(minutes=correlation_window_minutes)

    def classify_stage(self, text: str, anomaly_reason: str = "") -> Tuple[AttackStage, float]:
        """
        Map log text and anomaly rationale to a MITRE attack stage.
        Returns (stage, confidence).
        """
        combined = f"{text} {anomaly_reason}".lower()

        # Score matching patterns
        scores: Dict[AttackStage, int] = defaultdict(int)
        for stage, patterns in STAGE_SIGNATURES.items():
            for pat in patterns:
                if pat.search(combined):
                    scores[stage] += 1

        if not scores:
            # Check for generic anomaly hints
            if "brute" in combined or "auth" in combined:
                return AttackStage.CREDENTIAL_ATTACK, 0.65
            if "injection" in combined or "exploit" in combined:
                return AttackStage.INITIAL_ACCESS, 0.70
            if "root" in combined or "privilege" in combined:
                return AttackStage.PRIVILEGE_ESCALATION, 0.70
            if "exfiltrat" in combined or "outbound spike" in combined:
                return AttackStage.EXFILTRATION, 0.65
            if "recon" in combined or "scan" in combined:
                return AttackStage.RECONNAISSANCE, 0.65
            return AttackStage.UNKNOWN, 0.30

        # Return highest scoring stage
        best_stage = max(scores.items(), key=lambda x: x[1])[0]
        match_count = scores[best_stage]
        confidence = min(0.95, 0.55 + (match_count * 0.20))
        return best_stage, confidence

    def extract_entities(self, text: str, raw_line: str) -> Dict[str, Any]:
        """Extract IP addresses, usernames, and processes from text."""
        full_text = f"{text} {raw_line}"
        ips = IP_REGEX.findall(full_text)
        src_ip = ips[0] if len(ips) > 0 else None
        dst_ip = ips[1] if len(ips) > 1 else None

        user_match = USER_REGEX.search(full_text)
        user = user_match.group(1) if user_match else None

        proc_match = PROCESS_REGEX.search(full_text)
        process = proc_match.group(1) if proc_match else None

        return {
            "source_ip": src_ip,
            "destination_ip": dst_ip,
            "user": user,
            "process": process,
        }

    def correlate(
        self,
        entries: List[LogEntry],
        anomalies: List[Anomaly],
        incidents: List[Incident],
        session_id: str,
    ) -> List[AttackChain]:
        """
        Execute full attack chain reconstruction.
        """
        if not entries:
            return []

        # 1. Deduplicate entries by ID/raw_line to prevent double counting
        seen_entry_ids = set()
        unique_entries: List[LogEntry] = []
        for e in entries:
            key = (e.id or "") + (e.raw_line or "")
            if key not in seen_entry_ids:
                seen_entry_ids.add(key)
                unique_entries.append(e)

        # 2. Build index of anomalies and incidents for cross-referencing
        entry_to_anomaly: Dict[str, Anomaly] = {}
        for a in anomalies:
            for eid in a.log_entry_ids:
                entry_to_anomaly[eid] = a

        anomaly_to_incident: Dict[str, Incident] = {}
        for inc in incidents:
            if inc.anomaly_id:
                anomaly_to_incident[inc.anomaly_id] = inc

        # 3. Filter for suspicious or anomalous entries
        suspicious_candidates: List[Tuple[LogEntry, Optional[Anomaly], Optional[Incident]]] = []
        for e in unique_entries:
            anom = entry_to_anomaly.get(e.id)
            is_suspicious = (
                anom is not None
                or getattr(e, 'is_anomaly', False)
                or e.level in (LogLevel.ERROR, LogLevel.CRITICAL)
                or any(pat.search(e.raw_line + (e.message or '')) for pats in STAGE_SIGNATURES.values() for pat in pats)
            )
            if is_suspicious:
                inc = anomaly_to_incident.get(anom.id) if anom else None
                suspicious_candidates.append((e, anom, inc))

        if not suspicious_candidates:
            return []

        # 4. Sort chronologically (handle missing timestamps cleanly using line_number)
        def sort_key(item: Tuple[LogEntry, Optional[Anomaly], Optional[Incident]]):
            entry = item[0]
            # If timestamp is available and valid
            if entry.timestamp:
                return (0, entry.timestamp, entry.line_number or 0)
            return (1, datetime.min, entry.line_number or 0)

        sorted_candidates = sorted(suspicious_candidates, key=sort_key)

        # 5. Form clusters based on Entity linkage + Temporal Proximity
        # Clusters contain lists of candidate tuples
        # Each cluster tracks a frozen set of all IPs observed across its events
        clusters: List[List[Tuple[LogEntry, Optional[Anomaly], Optional[Incident]]]] = []
        cluster_ip_sets: List[set] = []   # all IPs (src+dst) seen in each cluster
        cluster_user_sets: List[set] = [] # all users seen in each cluster

        for item in sorted_candidates:
            entry, anom, inc = item
            ent = self.extract_entities(entry.message or "", entry.raw_line)
            src_ip = ent["source_ip"]
            dst_ip = ent["destination_ip"]
            user = ent["user"]
            t_curr = entry.timestamp

            # Collect all IPs appearing in this entry (both src and dst)
            entry_ips = {ip for ip in [src_ip, dst_ip] if ip}

            matched_cluster_idx = -1

            for idx, cluster in enumerate(clusters):
                c_ips = cluster_ip_sets[idx]
                c_users = cluster_user_sets[idx]

                # Entity link: any overlap between this entry's IPs and the cluster's known IPs
                ip_match = bool(entry_ips & c_ips)
                user_match = (user and user in c_users)

                if ip_match or user_match:
                    # Check temporal proximity with the most recent event in the cluster
                    cluster_entries = [c[0] for c in cluster]
                    latest_entry = max(
                        cluster_entries,
                        key=lambda e: e.timestamp if e.timestamp else datetime.min
                    )
                    if t_curr and latest_entry.timestamp:
                        time_delta = abs(t_curr - latest_entry.timestamp)
                        if time_delta <= self.correlation_window:
                            matched_cluster_idx = idx
                            break
                    elif not t_curr and not latest_entry.timestamp:
                        # Fallback for logs without timestamp: proximity by line numbers (< 50 lines apart)
                        line_delta = abs((entry.line_number or 0) - (latest_entry.line_number or 0))
                        if line_delta <= 50:
                            matched_cluster_idx = idx
                            break

            if matched_cluster_idx >= 0:
                clusters[matched_cluster_idx].append(item)
                cluster_ip_sets[matched_cluster_idx].update(entry_ips)
                if user:
                    cluster_user_sets[matched_cluster_idx].add(user)
            else:
                clusters.append([item])
                cluster_ip_sets.append(set(entry_ips))
                cluster_user_sets.append({user} if user else set())

        # 6. Build AttackChain objects from clusters
        # Filter clusters: a single isolated unknown log with no anomaly is not an attack chain
        chains: List[AttackChain] = []

        for c_idx, cluster in enumerate(clusters):
            # Form ChainLinkEvents
            chain_links: List[ChainLinkEvent] = []
            chain_stages: List[AttackStage] = []
            unconfirmed_stages: List[AttackStage] = []
            source_ips = set()
            dest_ips = set()
            users = set()
            processes = set()
            anomaly_ids = set()
            incident_ids = set()
            evidence_lines = []
            unconfirmed_hypotheses = []

            for entry, anom, inc in cluster:
                ent = self.extract_entities(entry.message or "", entry.raw_line)
                anom_reason = anom.reason if anom else ""
                stage, stage_conf = self.classify_stage(entry.raw_line, anom_reason)

                is_confirmed = (stage != AttackStage.UNKNOWN and stage_conf >= 0.60)
                if is_confirmed:
                    if stage not in chain_stages:
                        chain_stages.append(stage)
                else:
                    if stage != AttackStage.UNKNOWN and stage not in unconfirmed_stages:
                        unconfirmed_stages.append(stage)

                if ent["source_ip"]:
                    source_ips.add(ent["source_ip"])
                if ent["destination_ip"]:
                    dest_ips.add(ent["destination_ip"])
                if ent["user"]:
                    users.add(ent["user"])
                if ent["process"]:
                    processes.add(ent["process"])
                if anom:
                    anomaly_ids.add(anom.id)
                if inc:
                    incident_ids.add(inc.id)

                evidence_lines.append(f"[Line {entry.line_number or '?'}] {entry.raw_line.strip()}")

                link = ChainLinkEvent(
                    log_entry_id=entry.id,
                    line_number=entry.line_number,
                    timestamp=entry.timestamp,
                    stage=stage,
                    stage_confidence=stage_conf,
                    source_ip=ent["source_ip"],
                    destination_ip=ent["destination_ip"],
                    user=ent["user"],
                    process=ent["process"],
                    raw_log=entry.raw_line,
                    message=entry.message or entry.raw_line,
                    correlation_reason=f"Correlated via entity proximity and {stage.value} behavioral signature",
                    anomaly_id=anom.id if anom else None,
                    incident_id=inc.id if inc else None,
                    is_confirmed=is_confirmed,
                )
                chain_links.append(link)

            # Ignore 1-event trivial clusters that have 0 confirmed attack stages and no anomaly
            if len(chain_links) == 1 and not chain_stages and not anomaly_ids:
                continue

            # Deterministic ID based on session and first event
            first_entry = cluster[0][0]
            chain_seed = f"{session_id}_{c_idx}_{first_entry.raw_line}_{len(cluster)}"
            chain_id = f"chain-{hashlib.sha256(chain_seed.encode('utf-8')).hexdigest()[:12]}"

            # Timestamps
            valid_timestamps = [l.timestamp for l in chain_links if l.timestamp]
            first_seen = min(valid_timestamps) if valid_timestamps else None
            last_seen = max(valid_timestamps) if valid_timestamps else None
            duration_sec = (last_seen - first_seen).total_seconds() if (first_seen and last_seen) else 0.0

            # Severity computation
            critical_stages = {AttackStage.PRIVILEGE_ESCALATION, AttackStage.DATA_ACCESS, AttackStage.EXFILTRATION}
            high_stages = {AttackStage.INITIAL_ACCESS, AttackStage.EXECUTION, AttackStage.COMMAND_AND_CONTROL, AttackStage.LATERAL_MOVEMENT}
            if any(s in critical_stages for s in chain_stages) or len(chain_stages) >= 3:
                severity = "CRITICAL"
            elif any(s in high_stages for s in chain_stages) or len(chain_stages) >= 2:
                severity = "HIGH"
            elif AttackStage.CREDENTIAL_ATTACK in chain_stages or AttackStage.RECONNAISSANCE in chain_stages:
                severity = "MEDIUM"
            else:
                severity = "LOW"

            # Confidence
            avg_stage_conf = sum(l.stage_confidence for l in chain_links) / max(1, len(chain_links))
            confidence_score = round(min(0.98, avg_stage_conf + (0.05 * len(chain_stages))), 2)

            # Hypothesis and unconfirmed deductions
            if unconfirmed_stages:
                for us in unconfirmed_stages:
                    unconfirmed_hypotheses.append(
                        f"Suspected {us.value} activity observed without conclusive payload proof."
                    )
            if not chain_stages and unconfirmed_stages:
                unconfirmed_hypotheses.append(
                    "Attacker intent remains unconfirmed; events correlate by temporal clustering."
                )

            # Titles and summaries
            src_str = ", ".join(list(source_ips)[:2]) if source_ips else "Unknown Origin"
            target_str = ", ".join(list(dest_ips)[:2]) or ", ".join(list(users)[:2]) or "Internal Infrastructure"
            stages_str = " -> ".join([s.value for s in chain_stages]) if chain_stages else "Anomalous Activity"
            title = f"Multi-Stage Sequence: {stages_str} from {src_str}"
            summary = (
                f"Reconstructed {len(chain_links)}-event chronological attack sequence originating from {src_str} "
                f"targeting {target_str}. Observed progression across {len(chain_stages)} verified MITRE attack stages."
            )

            potential_impact = (
                f"Compromise of {target_str} with potential {', '.join([s.value for s in chain_stages])}. "
                f"Risk of unauthorized privilege escalation or data extraction."
            )

            correlation_explanation = (
                f"Events correlated within a {int(self.correlation_window.total_seconds() / 60)}-minute temporal window. "
                f"Tied together through shared source IP ({src_str}), destination targets ({target_str}), and "
                f"causal attack progression."
            )

            recommended_actions = [
                f"Isolate network communication from source IP(s): {', '.join(source_ips) or 'suspicious endpoint'}.",
                f"Revoke active credentials and review audit logs for user(s): {', '.join(users) or 'affected accounts'}.",
                "Inspect system binaries, scheduled tasks, and crontab for persistence artifacts.",
                "Review outbound firewall logs to verify if C2 beaconing or data exfiltration occurred.",
            ]

            # Generate Graph Data
            graph_data = self._generate_graph_data(chain_id, chain_links, source_ips, dest_ips, users, processes, chain_stages, incident_ids)

            chain = AttackChain(
                id=chain_id,
                session_id=session_id,
                title=title,
                summary=summary,
                severity=severity,
                confidence_score=confidence_score,
                first_seen=first_seen,
                last_seen=last_seen,
                duration_seconds=duration_sec,
                stages_observed=chain_stages,
                stages_unconfirmed=unconfirmed_stages,
                source_ips=sorted(list(source_ips)),
                target_systems=sorted(list(dest_ips)),
                affected_users=sorted(list(users)),
                affected_processes=sorted(list(processes)),
                associated_anomaly_ids=sorted(list(anomaly_ids)),
                associated_incident_ids=sorted(list(incident_ids)),
                event_ids=[l.log_entry_id for l in chain_links if l.log_entry_id],
                events=chain_links,
                supporting_evidence=evidence_lines[:20],
                hypotheses_unconfirmed=unconfirmed_hypotheses,
                potential_impact=potential_impact,
                correlation_explanation=correlation_explanation,
                recommended_actions=recommended_actions,
                graph_data=graph_data,
            )
            chains.append(chain)

        return chains

    def _generate_graph_data(
        self,
        chain_id: str,
        events: List[ChainLinkEvent],
        source_ips: set,
        dest_ips: set,
        users: set,
        processes: set,
        stages: List[AttackStage],
        incident_ids: set,
    ) -> AttackGraphData:
        """Construct nodes and directed edges representing the forensic attack graph."""
        nodes: List[AttackGraphNode] = []
        edges: List[AttackGraphEdge] = []
        node_ids = set()

        def add_node(nid: str, label: str, ntype: GraphNodeType, details: dict, sev: Optional[str] = None):
            if nid not in node_ids:
                node_ids.add(nid)
                nodes.append(AttackGraphNode(id=nid, label=label, type=ntype, details=details, severity=sev))

        # 1. Source IP Nodes (Red / Attacker glow)
        for ip in source_ips:
            add_node(f"ip_{ip}", f"IP: {ip}", GraphNodeType.SOURCE_IP, {"ip": ip}, sev="CRITICAL")

        # 2. Target Host / Systems
        for tip in dest_ips:
            add_node(f"target_{tip}", f"Host: {tip}", GraphNodeType.TARGET_HOST, {"host": tip}, sev="HIGH")

        # 3. User accounts
        for u in users:
            add_node(f"user_{u}", f"User: {u}", GraphNodeType.USER_ACCOUNT, {"username": u}, sev="MEDIUM")

        # 4. Processes
        for p in processes:
            add_node(f"proc_{p}", f"Proc: {p}", GraphNodeType.PROCESS, {"binary": p}, sev="HIGH")

        # 5. Attack Stages
        for s in stages:
            add_node(f"stage_{s.value}", s.value, GraphNodeType.ATTACK_STAGE, {"stage": s.value}, sev="HIGH")

        # 6. Incidents
        for inc_id in incident_ids:
            add_node(f"inc_{inc_id}", f"Incident {inc_id[:8]}", GraphNodeType.INCIDENT, {"incident_id": inc_id}, sev="CRITICAL")

        # Build Directed Edges linking entities and attack progression
        edge_id = 0
        for i, ev in enumerate(events):
            src_node = f"ip_{ev.source_ip}" if ev.source_ip and f"ip_{ev.source_ip}" in node_ids else None
            stage_node = f"stage_{ev.stage.value}" if ev.stage != AttackStage.UNKNOWN and f"stage_{ev.stage.value}" in node_ids else None
            user_node = f"user_{ev.user}" if ev.user and f"user_{ev.user}" in node_ids else None
            target_node = f"target_{ev.destination_ip}" if ev.destination_ip and f"target_{ev.destination_ip}" in node_ids else None

            # Edge: Attacker IP -> Stage
            if src_node and stage_node:
                edges.append(AttackGraphEdge(
                    id=f"e_{edge_id}",
                    source=src_node,
                    target=stage_node,
                    label="executed",
                    timestamp=ev.timestamp.isoformat() if ev.timestamp else None,
                    confidence=ev.stage_confidence,
                    stage=ev.stage.value,
                    evidence=ev.message[:80],
                ))
                edge_id += 1

            # Edge: Stage -> User Account (e.g. credential attack or privilege escalation on user)
            if stage_node and user_node:
                edges.append(AttackGraphEdge(
                    id=f"e_{edge_id}",
                    source=stage_node,
                    target=user_node,
                    label="targeted",
                    confidence=0.85,
                    stage=ev.stage.value,
                ))
                edge_id += 1

            # Edge: Stage -> Target Server
            if stage_node and target_node:
                edges.append(AttackGraphEdge(
                    id=f"e_{edge_id}",
                    source=stage_node,
                    target=target_node,
                    label="compromised",
                    confidence=0.90,
                    stage=ev.stage.value,
                ))
                edge_id += 1

        # Chain stage progression edges: Stage(t) -> Stage(t+1)
        for i in range(len(stages) - 1):
            s1 = f"stage_{stages[i].value}"
            s2 = f"stage_{stages[i+1].value}"
            if s1 in node_ids and s2 in node_ids:
                edges.append(AttackGraphEdge(
                    id=f"e_{edge_id}",
                    source=s1,
                    target=s2,
                    label="progressed_to",
                    confidence=0.95,
                ))
                edge_id += 1

        return AttackGraphData(nodes=nodes, edges=edges)

    def correlate_cross_session(
        self,
        chains: List[AttackChain],
        candidate_chains: Optional[List[AttackChain]] = None,
    ) -> List[AttackChain]:
        """
        Evaluate cross-session evidence relationships for a list of chains.
        Populates related_chain_ids and cross_session_evidence on each chain.
        Strictly applies the 7 false-correlation prevention rules via CrossSessionCorrelator.
        """
        from app.services.cross_session_correlator import CrossSessionCorrelator

        updated_chains = []
        for chain in chains:
            links = CrossSessionCorrelator.find_related_chains(chain, candidate_chains)
            related_ids = [l.chain_id for l in links]
            evidence = [f"{l.chain_id}: {l.correlation_explanation}" for l in links]

            updated = chain.model_copy(update={
                "related_chain_ids": related_ids,
                "cross_session_evidence": evidence,
            })
            updated_chains.append(updated)
        return updated_chains


# Module-level convenience function
def reconstruct_attack_chains(
    entries: List[LogEntry],
    anomalies: List[Anomaly],
    incidents: List[Incident],
    session_id: str,
    window_minutes: int = 30,
    enable_cross_session: bool = True,
) -> List[AttackChain]:
    engine = AttackChainEngine(correlation_window_minutes=window_minutes)
    chains = engine.correlate(entries, anomalies, incidents, session_id)
    if enable_cross_session and chains:
        chains = engine.correlate_cross_session(chains)
    return chains
