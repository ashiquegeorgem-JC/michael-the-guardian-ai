"""
ChainValidator — Phase 4.1A.

Validates the structural integrity and logical consistency of a reconstructed
AttackChain before it is stored or returned to the API.

Validation checks (in order):
  1. Minimum event count (structural viability).
  2. Minimum anomaly evidence (prevents pure-noise clusters).
  3. Duplicate ChainLinkEvent detection (by event ID and raw log hash).
  4. Chronological consistency (timestamps must be non-decreasing when present).
  5. Stage-regression guard (MITRE stage confirmed *before* its prerequisite).
  6. Missing-timestamp chain assessment (flags chains with no timestamps at all).
  7. Single-actor, single-stage, low-confidence guard (auto-suspect weak chains).
  8. Evidence reference integrity (every event_id must appear in events list).
  9. Stage-attribution support check (confirmed stages must have pattern matches).
 10. Contradictory entity check (same user as both attacker and victim is suspicious).

STORAGE NOTE: All validation is stateless and in-memory.  No data is written.
ChainValidator never modifies the AttackChain it receives.

Usage:
    from app.services.chain_validator import ChainValidator
    result = ChainValidator.validate(chain)
    if not result.is_valid:
        for err in result.errors:
            logger.error(err.message)
"""

import hashlib
import logging
from datetime import timedelta
from typing import List, Set

from app.models.attack_chain import (
    AttackChain,
    AttackStage,
    ChainValidationResult,
    ValidationFinding,
    ValidationSeverity,
)

logger = logging.getLogger("michael.chain_validator")

# ── Configurable thresholds ──────────────────────────────────────────────────
MIN_EVENTS_FOR_VIABLE_CHAIN: int = 2          # < this → trivial, reject
MIN_ANOMALY_REFS_FOR_EVIDENCE: int = 1        # 0 anomaly refs → warn
MAX_TEMPORAL_GAP_HOURS: float = 4.0           # events > this apart → warn
LOW_CONFIDENCE_THRESHOLD: float = 0.40        # chain-level confidence
STAGE_REGRESSION_TOLERANCE_SECONDS: float = 0  # negative time allowed (0 = strict)

# MITRE-aligned expected stage ordering (partial; used for regression detection only)
STAGE_ORDER = [
    AttackStage.RECONNAISSANCE,
    AttackStage.INITIAL_ACCESS,
    AttackStage.CREDENTIAL_ATTACK,
    AttackStage.PRIVILEGE_ESCALATION,
    AttackStage.EXECUTION,
    AttackStage.PERSISTENCE,
    AttackStage.COMMAND_AND_CONTROL,
    AttackStage.LATERAL_MOVEMENT,
    AttackStage.DATA_ACCESS,
    AttackStage.EXFILTRATION,
    AttackStage.UNKNOWN,
]
STAGE_INDEX = {s: i for i, s in enumerate(STAGE_ORDER)}


class ChainValidator:
    """
    Stateless validator for AttackChain objects.
    Call ChainValidator.validate(chain) — no instantiation needed.
    """

    @staticmethod
    def validate(chain: AttackChain) -> ChainValidationResult:
        """
        Run all structural and logical validation checks.

        Returns a ChainValidationResult with is_valid=True only when
        no ERROR-level findings exist.
        """
        findings: List[ValidationFinding] = []

        ChainValidator._check_minimum_events(chain, findings)
        ChainValidator._check_anomaly_evidence(chain, findings)
        ChainValidator._check_duplicate_events(chain, findings)
        ChainValidator._check_chronological_consistency(chain, findings)
        ChainValidator._check_stage_regression(chain, findings)
        ChainValidator._check_missing_timestamps(chain, findings)
        ChainValidator._check_low_confidence_single_actor(chain, findings)
        ChainValidator._check_event_id_integrity(chain, findings)
        ChainValidator._check_stage_attribution_support(chain, findings)
        ChainValidator._check_contradictory_entities(chain, findings)

        has_errors = any(f.severity == ValidationSeverity.ERROR for f in findings)

        result = ChainValidationResult(
            chain_id=chain.id,
            is_valid=not has_errors,
            findings=findings,
        )

        if findings:
            logger.info(
                "ChainValidator [%s]: %d finding(s) — %d error(s), %d warning(s)",
                chain.id,
                len(findings),
                len(result.errors),
                len(result.warnings),
            )
        return result

    # ── Individual checks ────────────────────────────────────────────────────

    @staticmethod
    def _check_minimum_events(chain: AttackChain, findings: List[ValidationFinding]) -> None:
        """Rule 1 — Minimum viable event count."""
        if len(chain.events) < MIN_EVENTS_FOR_VIABLE_CHAIN:
            # A single confirmed-stage event is acceptable; otherwise error.
            if not chain.stages_observed:
                findings.append(ValidationFinding(
                    severity=ValidationSeverity.ERROR,
                    code="TRIVIAL_CHAIN",
                    message=(
                        f"Chain has only {len(chain.events)} event(s) and no confirmed "
                        f"attack stage. Minimum {MIN_EVENTS_FOR_VIABLE_CHAIN} events "
                        "required for a viable attack chain."
                    ),
                    affected_event_ids=[e.id for e in chain.events],
                ))

    @staticmethod
    def _check_anomaly_evidence(chain: AttackChain, findings: List[ValidationFinding]) -> None:
        """Rule 2 — At least one anomaly reference required for evidential grounding."""
        if len(chain.associated_anomaly_ids) < MIN_ANOMALY_REFS_FOR_EVIDENCE:
            findings.append(ValidationFinding(
                severity=ValidationSeverity.WARNING,
                code="NO_ANOMALY_EVIDENCE",
                message=(
                    "Chain contains no associated anomaly IDs. "
                    "All events are based on pattern matching alone without ML-backed "
                    "anomaly support. Treat findings as suspected rather than confirmed."
                ),
            ))

    @staticmethod
    def _check_duplicate_events(chain: AttackChain, findings: List[ValidationFinding]) -> None:
        """Rule 3 — Duplicate events inflate confidence and distort stage counts."""
        seen_ids: Set[str] = set()
        seen_hashes: Set[str] = set()
        duplicate_ids: List[str] = []

        for ev in chain.events:
            # Deduplicate by event ID
            if ev.id in seen_ids:
                duplicate_ids.append(ev.id)
                continue
            seen_ids.add(ev.id)

            # Deduplicate by raw log content hash (catches same log with different ID)
            raw_hash = hashlib.sha256(ev.raw_log.encode("utf-8")).hexdigest()
            if raw_hash in seen_hashes:
                duplicate_ids.append(ev.id)
            else:
                seen_hashes.add(raw_hash)

        if duplicate_ids:
            findings.append(ValidationFinding(
                severity=ValidationSeverity.ERROR,
                code="DUPLICATE_EVENTS",
                message=(
                    f"{len(duplicate_ids)} duplicate event(s) detected. "
                    "Duplicate events inflate chain confidence scores and must be removed "
                    "before the chain is used for investigation."
                ),
                affected_event_ids=duplicate_ids,
            ))

    @staticmethod
    def _check_chronological_consistency(chain: AttackChain, findings: List[ValidationFinding]) -> None:
        """Rule 4 — Events with timestamps must be non-decreasing (within tolerance)."""
        timestamped = [ev for ev in chain.events if ev.timestamp is not None]
        if len(timestamped) < 2:
            return  # Not enough data to check ordering

        tolerance = timedelta(seconds=STAGE_REGRESSION_TOLERANCE_SECONDS)
        violations: List[str] = []
        for i in range(1, len(timestamped)):
            prev = timestamped[i - 1]
            curr = timestamped[i]
            if curr.timestamp < prev.timestamp - tolerance:
                violations.append(curr.id)

        if violations:
            findings.append(ValidationFinding(
                severity=ValidationSeverity.WARNING,
                code="CHRONOLOGICAL_INCONSISTENCY",
                message=(
                    f"{len(violations)} event(s) appear out of chronological order. "
                    "The engine sorts events by timestamp; if this persists, the source "
                    "logs may contain clock skew or incorrect timestamps."
                ),
                affected_event_ids=violations,
            ))

        # Also flag chains where the temporal gap between first and last event exceeds the cap
        if chain.first_seen and chain.last_seen:
            gap_hours = (chain.last_seen - chain.first_seen).total_seconds() / 3600
            if gap_hours > MAX_TEMPORAL_GAP_HOURS:
                findings.append(ValidationFinding(
                    severity=ValidationSeverity.WARNING,
                    code="EXCESSIVE_TEMPORAL_SPAN",
                    message=(
                        f"Chain spans {gap_hours:.1f} hours — exceeds the "
                        f"{MAX_TEMPORAL_GAP_HOURS}h recommended maximum. "
                        "Consider whether these events represent a single attack "
                        "or multiple distinct incidents."
                    ),
                ))

    @staticmethod
    def _check_stage_regression(chain: AttackChain, findings: List[ValidationFinding]) -> None:
        """
        Rule 5 — A confirmed MITRE stage must not appear *after* a later-phase stage
        unless that event is already marked is_confirmed=False.
        """
        # Build list of (stage_index, event) for confirmed events with timestamps
        ordered_confirmed = [
            (STAGE_INDEX.get(ev.stage, 999), ev)
            for ev in chain.events
            if ev.is_confirmed and ev.timestamp is not None and ev.stage != AttackStage.UNKNOWN
        ]
        ordered_confirmed.sort(key=lambda x: x[1].timestamp)

        regressions: List[str] = []
        max_stage_idx = -1
        for stage_idx, ev in ordered_confirmed:
            if stage_idx < max_stage_idx:
                # Stage is "earlier" in kill chain but appears later in time
                regressions.append(ev.id)
            else:
                max_stage_idx = max(max_stage_idx, stage_idx)

        if regressions:
            findings.append(ValidationFinding(
                severity=ValidationSeverity.WARNING,
                code="STAGE_REGRESSION",
                message=(
                    f"{len(regressions)} event(s) show a MITRE stage that regresses "
                    "backward in the kill-chain sequence relative to earlier events. "
                    "These events have been pre-marked is_confirmed=False by the engine "
                    "but should be manually reviewed."
                ),
                affected_event_ids=regressions,
            ))

    @staticmethod
    def _check_missing_timestamps(chain: AttackChain, findings: List[ValidationFinding]) -> None:
        """Rule 6 — Missing timestamps must not fabricate sequence."""
        missing_count = sum(1 for ev in chain.events if ev.timestamp is None)
        if missing_count == len(chain.events) and len(chain.events) > 0:
            findings.append(ValidationFinding(
                severity=ValidationSeverity.WARNING,
                code="ALL_TIMESTAMPS_MISSING",
                message=(
                    "No events in this chain have parseable timestamps. "
                    "Chronological ordering is based on log line numbers only. "
                    "The reconstructed sequence is an approximation and should not "
                    "be treated as a confirmed timeline."
                ),
            ))
        elif missing_count > 0:
            findings.append(ValidationFinding(
                severity=ValidationSeverity.INFO,
                code="PARTIAL_TIMESTAMPS_MISSING",
                message=(
                    f"{missing_count} of {len(chain.events)} event(s) have no parseable "
                    "timestamp. Line-number fallback ordering is used for those events."
                ),
            ))

    @staticmethod
    def _check_low_confidence_single_actor(chain: AttackChain, findings: List[ValidationFinding]) -> None:
        """
        Rule 7 — A chain with a single source IP, a single confirmed stage,
        and confidence below the threshold is likely noise.
        """
        if (
            len(chain.source_ips) <= 1
            and len(chain.stages_observed) <= 1
            and chain.confidence_score < LOW_CONFIDENCE_THRESHOLD
        ):
            findings.append(ValidationFinding(
                severity=ValidationSeverity.WARNING,
                code="LOW_CONFIDENCE_SINGLE_ACTOR",
                message=(
                    f"Chain has confidence {chain.confidence_score:.2f} with only "
                    f"{len(chain.stages_observed)} confirmed stage(s) from a single source. "
                    "This chain may represent benign anomalous activity rather than an attack. "
                    "Review before escalating."
                ),
            ))

    @staticmethod
    def _check_event_id_integrity(chain: AttackChain, findings: List[ValidationFinding]) -> None:
        """Rule 8 — Every ID listed in event_ids must correspond to an actual event."""
        event_id_set = {ev.id for ev in chain.events}
        log_entry_id_set = {ev.log_entry_id for ev in chain.events if ev.log_entry_id}

        orphan_event_ids = [
            eid for eid in chain.event_ids
            if eid not in event_id_set and eid not in log_entry_id_set
        ]
        if orphan_event_ids:
            findings.append(ValidationFinding(
                severity=ValidationSeverity.ERROR,
                code="ORPHAN_EVENT_REFERENCES",
                message=(
                    f"{len(orphan_event_ids)} ID(s) in event_ids do not match any "
                    "ChainLinkEvent. The chain's event_ids list is inconsistent with "
                    "its events list."
                ),
                affected_event_ids=orphan_event_ids,
            ))

    @staticmethod
    def _check_stage_attribution_support(chain: AttackChain, findings: List[ValidationFinding]) -> None:
        """
        Rule 9 — A stage marked confirmed (is_confirmed=True) must have
        stage_confidence >= 0.55.  Lower confidence must be is_confirmed=False.
        """
        unsupported: List[str] = []
        for ev in chain.events:
            if ev.is_confirmed and ev.stage != AttackStage.UNKNOWN:
                if ev.stage_confidence < 0.55:
                    unsupported.append(ev.id)

        if unsupported:
            findings.append(ValidationFinding(
                severity=ValidationSeverity.WARNING,
                code="UNSUPPORTED_STAGE_ATTRIBUTION",
                message=(
                    f"{len(unsupported)} event(s) are marked is_confirmed=True but have "
                    "stage_confidence < 0.55. These attributions lack sufficient pattern "
                    "evidence and should be treated as suspected."
                ),
                affected_event_ids=unsupported,
            ))

    @staticmethod
    def _check_contradictory_entities(chain: AttackChain, findings: List[ValidationFinding]) -> None:
        """
        Rule 10 — Flag when an entity appears as both an attacker-source IP and
        a victim-target system, which can indicate IP spoofing or logging errors.
        """
        src_set = set(chain.source_ips)
        tgt_set = set(chain.target_systems)
        overlap = src_set & tgt_set

        if overlap:
            findings.append(ValidationFinding(
                severity=ValidationSeverity.WARNING,
                code="CONTRADICTORY_ENTITY_ROLES",
                message=(
                    f"Entity/entities {sorted(overlap)} appear as both source IP(s) and "
                    "target system(s). This may indicate IP spoofing, NAT ambiguity, or a "
                    "logging error. Manual verification recommended."
                ),
            ))

