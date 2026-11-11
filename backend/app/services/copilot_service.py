"""
AI Copilot Service - Answers questions about analysed log data.
Answers are grounded in actual log data stored in the session state.
"""

import re
import logging
from datetime import datetime
from typing import List, Dict, Any, Optional
from collections import Counter, defaultdict

from app.models.log_entry import LogEntry, LogLevel
from app.models.anomaly import Anomaly
from app.models.incident import Incident
from app.models.attack_chain import AttackChain, AttackStage

logger = logging.getLogger("michael.copilot")


class CopilotService:
    """
    Context-aware Q&A engine over analysed log data and reconstructed attack chains.
    All answers are grounded in actual parsed/analysed data.
    """

    def __init__(
        self,
        entries: List[LogEntry],
        anomalies: List[Anomaly],
        incidents: List[Incident],
        attack_chains: Optional[List[AttackChain]] = None,
    ):
        self.entries = entries
        self.anomalies = anomalies
        self.incidents = incidents
        self.attack_chains = attack_chains or []

        # Pre-compute indices for fast lookups
        self._level_index: Dict[LogLevel, List[LogEntry]] = defaultdict(list)
        self._ip_counter: Counter = Counter()
        self._error_messages: List[str] = []
        self._sources: Counter = Counter()
        self._build_indices()

    def _build_indices(self):
        """Pre-compute lookup structures from log entries."""
        ip_pattern = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
        for e in self.entries:
            self._level_index[e.level].append(e)
            if e.source:
                self._sources[e.source] += 1
            text = (e.message or '') + e.raw_line
            for ip in ip_pattern.findall(text):
                self._ip_counter[ip] += 1
            if e.level in (LogLevel.ERROR, LogLevel.CRITICAL):
                self._error_messages.append(e.message or e.raw_line)

    def answer(self, question: str) -> Dict[str, Any]:
        """
        Route the user's question to the appropriate handler.
        Returns a structured response with answer text and supporting evidence.
        """
        q = question.lower().strip()

        # Attack chain specific forensic routing
        if any(k in q for k in ["first event", "occurred first", "how did the attack start", "start event"]):
            return self._first_event_analysis(q)
        elif any(k in q for k in ["systems were affected", "affected system", "which host", "affected target", "affected server"]):
            return self._affected_systems_analysis(q)
        elif any(k in q for k in ["privilege escalation", "priv esc", "root access", "sudo abuse"]):
            return self._privilege_escalation_analysis(q)
        elif any(k in q for k in ["unconfirmed", "unverified stage", "hypothes"]):
            return self._unconfirmed_stages_analysis(q)
        elif any(k in q for k in ["investigate next", "next step", "analyst investigate"]):
            return self._next_investigation_steps(q)
        elif any(k in q for k in ["attack chain", "attack sequence", "kill chain", "what happened"]):
            return self._attack_chain_analysis(q)
        elif any(k in q for k in ["evidence supports", "supporting evidence", "forensic proof"]):
            return self._evidence_analysis(q)

        # General log analysis routing
        if any(k in q for k in ["crash", "down", "outage", "fail", "restart"]):
            return self._explain_crashes(q)
        elif any(k in q for k in ["critical", "severe", "worst", "most error"]):
            return self._critical_errors(q)
        elif any(k in q for k in ["ip", "address", "source", "login attempt", "failed login"]):
            return self._ip_analysis(q)
        elif any(k in q for k in ["database", "db", "sql", "query", "mysql", "postgres"]):
            return self._database_activity(q)
        elif any(k in q for k in ["anomaly", "anomalie", "unusual", "strange", "weird"]):
            return self._explain_anomalies(q)
        elif any(k in q for k in ["recommend", "fix", "mitigate", "remediat", "should i", "what to do"]):
            return self._recommendations(q)
        elif any(k in q for k in ["summary", "overview", "total", "how many", "count", "stat"]):
            return self._summary(q)
        elif any(k in q for k in ["error", "warning", "warn"]):
            return self._error_analysis(q)
        elif any(k in q for k in ["time", "when", "peak", "spike", "hour"]):
            return self._temporal_analysis(q)
        else:
            return self._general_search(question)

    def _explain_crashes(self, q: str) -> Dict[str, Any]:
        crash_incidents = [
            i for i in self.incidents
            if "crash" in i.category.value.lower() or "crash" in i.title.lower()
        ]
        crash_logs = [
            e for e in self.entries
            if re.search(r"crash|panic|segfault|core\s+dump|killed", e.raw_line, re.I)
        ]

        if not crash_logs and not crash_incidents:
            return {
                "answer": "No crash events were found in the analysed logs. The system appears to have been stable during the monitored period.",
                "evidence": [],
                "confidence": "high",
            }

        evidence = [e.raw_line for e in crash_logs[:5]]
        hypothesis = crash_incidents[0].root_cause_hypothesis if crash_incidents else (
            "[AI HYPOTHESIS] Crash events were detected in the logs. "
            "Common causes include memory exhaustion, unhandled exceptions, hardware faults, "
            "or kernel panics. Review the evidence lines below for specific indicators."
        )

        return {
            "answer": (
                f"Found **{len(crash_logs)} crash-related log entries** and "
                f"**{len(crash_incidents)} crash incidents**.\n\n"
                f"{hypothesis}"
            ),
            "evidence": evidence,
            "confidence": "high",
            "related_incidents": [i.id for i in crash_incidents[:3]],
        }

    def _critical_errors(self, q: str) -> Dict[str, Any]:
        critical = self._level_index.get(LogLevel.CRITICAL, [])
        errors = self._level_index.get(LogLevel.ERROR, [])

        top_errors = Counter(e.message or e.raw_line for e in critical + errors)
        top_5 = top_errors.most_common(5)

        if not top_5:
            return {
                "answer": "No critical or error-level log entries were found in the current session.",
                "evidence": [],
                "confidence": "high",
            }

        answer_lines = [f"Found **{len(critical)} CRITICAL** and **{len(errors)} ERROR** level entries.\n"]
        answer_lines.append("**Top 5 most frequent critical/error messages:**")
        for i, (msg, count) in enumerate(top_5, 1):
            answer_lines.append(f"{i}. ({count}×) `{msg[:120]}`")

        return {
            "answer": "\n".join(answer_lines),
            "evidence": [e.raw_line for e in (critical + errors)[:5]],
            "confidence": "high",
        }

    def _ip_analysis(self, q: str) -> Dict[str, Any]:
        if not self._ip_counter:
            return {
                "answer": "No IP addresses were found in the analysed log entries.",
                "evidence": [],
                "confidence": "high",
            }

        top_ips = self._ip_counter.most_common(10)
        
        # Check for failed login context
        failed_ips: Counter = Counter()
        for e in self.entries:
            if re.search(r"failed|invalid|denied|refuse", e.raw_line, re.I):
                text = (e.message or '') + e.raw_line
                for ip in re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', text):
                    failed_ips[ip] += 1

        answer_parts = [f"**{len(self._ip_counter)} unique IP addresses** detected across all logs.\n"]
        answer_parts.append("**Top 5 IPs by occurrence:**")
        for ip, count in top_ips[:5]:
            failed = failed_ips.get(ip, 0)
            suffix = f" (⚠ {failed} failed attempts)" if failed > 0 else ""
            answer_parts.append(f"- `{ip}`: {count} events{suffix}")

        if failed_ips:
            most_failed = failed_ips.most_common(1)[0]
            answer_parts.append(f"\n**Highest failed attempt count:** `{most_failed[0]}` with {most_failed[1]} failures")

        return {
            "answer": "\n".join(answer_parts),
            "evidence": [f"IP {ip}: {count} occurrences" for ip, count in top_ips[:5]],
            "confidence": "high",
        }

    def _database_activity(self, q: str) -> Dict[str, Any]:
        db_logs = [
            e for e in self.entries
            if re.search(r"mysql|postgres|mongo|redis|sqlite|query|database|db\b|sql", e.raw_line, re.I)
        ]
        db_errors = [e for e in db_logs if e.level in (LogLevel.ERROR, LogLevel.CRITICAL)]
        db_anomalies = [
            a for a in self.anomalies
            if re.search(r"database|sql|query", a.reason, re.I)
        ]

        if not db_logs:
            return {
                "answer": "No database-related log entries were found in the current session.",
                "evidence": [],
                "confidence": "high",
            }

        return {
            "answer": (
                f"Found **{len(db_logs)} database-related log entries**, "
                f"including **{len(db_errors)} errors** and **{len(db_anomalies)} detected anomalies**.\n\n"
                + ("[AI HYPOTHESIS] Elevated database error rates may indicate slow queries, "
                   "connection pool exhaustion, or unauthorized access attempts." if db_errors else
                   "Database activity appears within normal operational parameters.")
            ),
            "evidence": [e.raw_line for e in db_logs[:5]],
            "confidence": "high",
        }

    def _explain_anomalies(self, q: str) -> Dict[str, Any]:
        if not self.anomalies:
            return {
                "answer": "No anomalies have been detected yet. Run the anomaly detection analysis first.",
                "evidence": [],
                "confidence": "high",
            }

        by_severity = Counter(a.severity.value for a in self.anomalies)
        methods = Counter(a.method.value for a in self.anomalies)
        critical = [a for a in self.anomalies if a.severity.value == "CRITICAL"]

        answer = (
            f"**{len(self.anomalies)} total anomalies** detected.\n\n"
            f"**By severity:** " + ", ".join(f"{k}: {v}" for k, v in by_severity.most_common()) + "\n\n"
            f"**Detection methods:** " + ", ".join(f"{k}: {v}" for k, v in methods.most_common()) + "\n\n"
        )

        if critical:
            answer += f"**⚠ {len(critical)} CRITICAL anomalies require immediate attention:**\n"
            for a in critical[:3]:
                answer += f"- {a.reason}\n"

        return {
            "answer": answer,
            "evidence": [a.supporting_logs[0] for a in self.anomalies[:5] if a.supporting_logs],
            "confidence": "high",
        }

    def _recommendations(self, q: str) -> Dict[str, Any]:
        if not self.incidents:
            return {
                "answer": "No incidents detected yet. Run anomaly detection to generate recommendations.",
                "evidence": [],
                "confidence": "medium",
            }

        # Aggregate unique remediation steps from critical/high incidents
        priority_incidents = [i for i in self.incidents if i.severity in ("CRITICAL", "HIGH")]
        if not priority_incidents:
            priority_incidents = self.incidents

        all_steps = []
        seen = set()
        for incident in priority_incidents[:5]:
            for step in incident.remediation_steps:
                if step not in seen:
                    all_steps.append(f"- {step}")
                    seen.add(step)

        answer = (
            f"Based on **{len(self.incidents)} detected incidents**, here are the top recommendations:\n\n"
            + "\n".join(all_steps[:10])
            + "\n\n*Note: These recommendations are AI-generated based on detected patterns. "
            "Verify all actions with your security team before implementation.*"
        )

        return {
            "answer": answer,
            "evidence": [],
            "confidence": "medium",
        }

    def _summary(self, q: str) -> Dict[str, Any]:
        total = len(self.entries)
        level_counts = {lvl.value: len(entries) for lvl, entries in self._level_index.items()}
        
        answer = (
            f"**Log Analysis Summary**\n\n"
            f"- Total log entries: **{total}**\n"
            f"- Critical: **{level_counts.get('CRITICAL', 0)}**\n"
            f"- Errors: **{level_counts.get('ERROR', 0)}**\n"
            f"- Warnings: **{level_counts.get('WARNING', 0)}**\n"
            f"- Anomalies detected: **{len(self.anomalies)}**\n"
            f"- Active incidents: **{len(self.incidents)}**\n"
            f"- Unique IP addresses: **{len(self._ip_counter)}**\n"
            f"- Log sources: **{len(self._sources)}**\n"
        )
        return {"answer": answer, "evidence": [], "confidence": "high"}

    def _error_analysis(self, q: str) -> Dict[str, Any]:
        target_level = LogLevel.WARNING if "warn" in q else LogLevel.ERROR
        entries = self._level_index.get(target_level, [])
        counter = Counter(e.message or e.raw_line for e in entries)
        top = counter.most_common(5)

        if not top:
            return {
                "answer": f"No {target_level.value} level entries found in the current session.",
                "evidence": [],
                "confidence": "high",
            }

        lines = [f"**{len(entries)} {target_level.value} entries found:**\n"]
        for msg, count in top:
            lines.append(f"- ({count}×) `{msg[:120]}`")

        return {
            "answer": "\n".join(lines),
            "evidence": [e.raw_line for e in entries[:5]],
            "confidence": "high",
        }

    def _temporal_analysis(self, q: str) -> Dict[str, Any]:
        timed = [e for e in self.entries if e.timestamp]
        if not timed:
            return {
                "answer": "No timestamped entries found. Cannot perform temporal analysis.",
                "evidence": [],
                "confidence": "low",
            }

        hour_counts = Counter(e.timestamp.hour for e in timed)
        peak_hour, peak_count = hour_counts.most_common(1)[0]

        return {
            "answer": (
                f"**Temporal Analysis:**\n"
                f"- Timestamped entries: {len(timed)}\n"
                f"- Peak activity hour: **{peak_hour:02d}:00** with {peak_count} events\n"
                f"- Time range: {min(e.timestamp for e in timed)} → {max(e.timestamp for e in timed)}\n"
            ),
            "evidence": [],
            "confidence": "high",
        }

    def _general_search(self, question: str) -> Dict[str, Any]:
        """Fallback: search log messages for keywords from the question."""
        words = [w for w in re.sub(r'[^a-z0-9\s]', '', question.lower()).split() if len(w) > 3]
        if not words:
            return {
                "answer": "Could not understand the question. Try asking about errors, crashes, anomalies, IPs, or recommendations.",
                "evidence": [],
                "confidence": "low",
            }

        pattern = re.compile('|'.join(re.escape(w) for w in words), re.IGNORECASE)
        matches = [e for e in self.entries if pattern.search(e.raw_line)][:10]

        if not matches:
            return {
                "answer": f"No log entries found matching keywords: {', '.join(words)}",
                "evidence": [],
                "confidence": "medium",
            }

        return {
            "answer": f"Found **{len(matches)} log entries** matching your query keywords ({', '.join(words)}):",
            "evidence": [e.raw_line for e in matches],
            "confidence": "medium",
        }

    def _get_target_chain(self, q: str) -> Optional[AttackChain]:
        """Find matching chain by ID in query, or default to highest severity chain."""
        if not self.attack_chains:
            return None
        for c in self.attack_chains:
            if c.id.lower() in q.lower():
                return c
        # Default to highest severity or most complex chain
        return max(self.attack_chains, key=lambda c: (c.severity == "CRITICAL", len(c.stages_observed), len(c.events)))

    def _attack_chain_analysis(self, q: str) -> Dict[str, Any]:
        if not self.attack_chains:
            return {
                "answer": "No multi-stage attack chains have been correlated in this session. Anomalies may be isolated or require broader correlation.",
                "evidence": [],
                "confidence": "medium",
            }

        chain = self._get_target_chain(q)
        stages_str = " → ".join(s.value for s in chain.stages_observed) if chain.stages_observed else "Unclassified sequence"
        ev_lines = [e.raw_log for e in chain.events[:5]]

        answer = (
            f"### Attack Chain Overview: `{chain.id}`\n\n"
            f"- **Title**: {chain.title}\n"
            f"- **Severity**: **{chain.severity}** (Confidence: {int(chain.confidence_score * 100)}%)\n"
            f"- **Observed Progression**: {stages_str}\n"
            f"- **Timeline**: {chain.first_seen or 'Unknown'} to {chain.last_seen or 'Unknown'} ({int(chain.duration_seconds)}s duration)\n"
            f"- **Origin**: {', '.join(chain.source_ips) or 'Unknown IP'}\n"
            f"- **Target Systems / Users**: {', '.join(chain.target_systems + chain.affected_users) or 'Internal Assets'}\n\n"
            f"**Forensic Summary**: {chain.summary}\n\n"
            f"**Impact**: {chain.potential_impact}"
        )
        return {
            "answer": answer,
            "evidence": ev_lines,
            "confidence": "high",
        }

    def _first_event_analysis(self, q: str) -> Dict[str, Any]:
        if not self.attack_chains:
            return {
                "answer": "No attack chain is active. Examining earliest parsed log entry.",
                "evidence": [self.entries[0].raw_line] if self.entries else [],
                "confidence": "medium",
            }
        chain = self._get_target_chain(q)
        if not chain.events:
            return {"answer": "No chronological events recorded for this chain.", "evidence": [], "confidence": "low"}

        first_ev = chain.events[0]
        ts_str = first_ev.timestamp.isoformat() if first_ev.timestamp else "Timestamp not parsed"
        ans = (
            f"The **initial event** in attack chain `{chain.id}` occurred at **{ts_str}**:\n\n"
            f"- **Stage**: {first_ev.stage.value}\n"
            f"- **Source IP**: {first_ev.source_ip or 'N/A'}\n"
            f"- **Log Line**: {first_ev.line_number or '?'}\n"
            f"- **Correlation Rationale**: {first_ev.correlation_reason}\n\n"
            f"Raw log entry:\n```\n{first_ev.raw_log.strip()}\n```"
        )
        return {
            "answer": ans,
            "evidence": [first_ev.raw_log],
            "confidence": "high",
        }

    def _affected_systems_analysis(self, q: str) -> Dict[str, Any]:
        if not self.attack_chains:
            return {
                "answer": "No systems have been confirmed compromised by multi-stage attack chains.",
                "evidence": [],
                "confidence": "medium",
            }
        chain = self._get_target_chain(q)
        targets = chain.target_systems or ["Internal Network Assets"]
        users = chain.affected_users or ["None identified"]
        procs = chain.affected_processes or ["None observed"]

        ans = (
            f"### Affected Systems & Entities for `{chain.id}`:\n\n"
            f"- **Target Hosts / IPs**: {', '.join(targets)}\n"
            f"- **Compromised User Accounts**: {', '.join(users)}\n"
            f"- **Spawned / Target Processes**: {', '.join(procs)}\n"
            f"- **Source Attack Origin**: {', '.join(chain.source_ips) or 'Unknown'}"
        )
        return {
            "answer": ans,
            "evidence": chain.supporting_evidence[:5],
            "confidence": "high",
        }

    def _evidence_analysis(self, q: str) -> Dict[str, Any]:
        if not self.attack_chains:
            return {"answer": "No forensic evidence for attack chains available.", "evidence": [], "confidence": "low"}
        chain = self._get_target_chain(q)
        ans = (
            f"### Forensic Evidence for `{chain.id}`:\n"
            f"This attack sequence is supported by **{len(chain.events)} correlated log events** "
            f"and **{len(chain.associated_anomaly_ids)} ML anomalies**.\n\n"
            f"Key evidence excerpts:\n"
            + "\n".join(f"- `{line}`" for line in chain.supporting_evidence[:6])
        )
        return {
            "answer": ans,
            "evidence": [e.raw_log for e in chain.events[:6]],
            "confidence": "high",
        }

    def _privilege_escalation_analysis(self, q: str) -> Dict[str, Any]:
        if not self.attack_chains:
            return {"answer": "No attack chain data available to verify privilege escalation.", "evidence": [], "confidence": "medium"}
        chain = self._get_target_chain(q)

        priv_events = [e for e in chain.events if e.stage == AttackStage.PRIVILEGE_ESCALATION]
        if priv_events:
            ev = priv_events[0]
            ans = (
                f"**YES. Privilege escalation was OBSERVED** in attack chain `{chain.id}`.\n\n"
                f"- **Stage**: {ev.stage.value} (Confidence: {int(ev.stage_confidence * 100)}%)\n"
                f"- **User**: {ev.user or 'root/privileged account'}\n"
                f"- **Timestamp**: {ev.timestamp or 'N/A'}\n"
                f"- **Log Line**: {ev.line_number or '?'}\n\n"
                f"Evidence:\n```\n{ev.raw_log.strip()}\n```"
            )
            return {"answer": ans, "evidence": [ev.raw_log], "confidence": "high"}
        else:
            return {
                "answer": (
                    f"**NO. Privilege escalation was NOT observed** in attack chain `{chain.id}`. "
                    f"Observed stages were: {', '.join(s.value for s in chain.stages_observed) or 'None'}. "
                    f"No sudo abuse, setuid manipulation, or unauthorized root elevation signatures were detected."
                ),
                "evidence": [],
                "confidence": "high",
            }

    def _unconfirmed_stages_analysis(self, q: str) -> Dict[str, Any]:
        if not self.attack_chains:
            return {"answer": "No attack chains currently active.", "evidence": [], "confidence": "low"}
        chain = self._get_target_chain(q)
        if not chain.hypotheses_unconfirmed and not chain.stages_unconfirmed:
            return {
                "answer": f"All observed stages in `{chain.id}` have verified ground-truth evidence. There are no unconfirmed hypotheses.",
                "evidence": [],
                "confidence": "high",
            }

        unconfirmed_str = ", ".join(s.value for s in chain.stages_unconfirmed) if chain.stages_unconfirmed else "None"
        hypotheses_str = "\n".join(f"- {h}" for h in chain.hypotheses_unconfirmed)

        ans = (
            f"### Unconfirmed Stages & Hypotheses for `{chain.id}`:\n\n"
            f"- **Unconfirmed Stages**: {unconfirmed_str}\n\n"
            f"**Hypotheses Requiring Further Forensic Verification**:\n"
            f"{hypotheses_str}\n\n"
            f"These stages are marked unconfirmed because while temporal or behavioral proximity exists, "
            f"conclusive cryptographic or process execution payloads were not captured in the ingested logs."
        )
        return {
            "answer": ans,
            "evidence": chain.supporting_evidence[-3:],
            "confidence": "high",
        }

    def _next_investigation_steps(self, q: str) -> Dict[str, Any]:
        if not self.attack_chains:
            return {
                "answer": "Upload system logs and run analysis to receive prioritized forensic investigation steps.",
                "evidence": [],
                "confidence": "low",
            }
        chain = self._get_target_chain(q)
        steps = chain.recommended_actions or [
            "Isolate affected endpoints from network egress.",
            "Rotate credentials for compromised service and user accounts.",
            "Audit scheduled tasks and cron jobs for persistence.",
        ]

        ans = (
            f"### Recommended Forensic Investigation Steps for `{chain.id}`:\n\n"
            + "\n".join(f"{i+1}. **{step}**" for i, step in enumerate(steps))
            + f"\n\n**Analyst Directive**: Prioritize containment of origin IP `{', '.join(chain.source_ips) or 'unknown'}` "
            f"before remediation of secondary internal targets."
        )
        return {
            "answer": ans,
            "evidence": chain.supporting_evidence[:3],
            "confidence": "high",
        }
