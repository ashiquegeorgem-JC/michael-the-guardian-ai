"""
CrossSessionCorrelator — Phase 4.1A.

Identifies potential evidence-based relationships between AttackChains that
belong to different upload sessions.

IMPORTANT DESIGN CONSTRAINT:
  Cross-session associations are NEVER confirmed merges.
  They are represented as potential links (RelatedChainLink) with:
    - A list of shared signals (IPs, users, stages, techniques).
    - A confidence score derived from the number and quality of shared signals.
    - is_confirmed=False until an analyst explicitly promotes them.

Seven false-correlation prevention rules (all applied before emitting a link):

  Rule 1 — IP alone is insufficient.
           A shared source IP must be accompanied by at least one additional
           independent signal (shared user, shared stage, shared technique,
           overlapping anomaly reason, or corroborating time window).

  Rule 2 — Unrelated users must not be merged.
           User identity is only considered a shared signal when the username
           appears in both chains AND is not a generic account name (root, admin,
           user, guest, anonymous, system).

  Rule 3 — Temporal proximity requirement.
           Cross-session events must occur within CROSS_SESSION_WINDOW_HOURS.
           Events outside this window are not considered temporally correlated.

  Rule 4 — Duplicates are excluded.
           A chain is never linked to itself.  Links between the same pair of
           chains are deduplicated.

  Rule 5 — Missing timestamps do not fabricate correlations.
           If neither chain has any valid timestamps, temporal proximity is
           skipped entirely.  The link may still be emitted if enough other
           signals are present, but ALL_TIMESTAMPS_MISSING is noted in the
           explanation.

  Rule 6 — Different attack chains remain separate.
           A link is only emitted when the combined confidence score meets
           MINIMUM_CROSS_SESSION_CONFIDENCE.  Below this threshold the chains
           are considered unrelated.

  Rule 7 — Every link retains its full supporting evidence and explanation.
           RelatedChainLink.shared_signals lists every specific signal used.
           RelatedChainLink.correlation_explanation provides a human-readable
           narrative.

STORAGE NOTE: Cross-session correlation reads in-memory SessionStore state.
              No data is written.  Results are returned to the caller.
"""

import logging
from datetime import timedelta
from typing import Dict, List, Optional, Set, Tuple

from app.models.attack_chain import (
    AttackChain,
    AttackStage,
    RelatedChainLink,
    RelatedEntitiesResponse,
    RelatedEntity,
)
from app.services.store import store

logger = logging.getLogger("michael.cross_session_correlator")

# ── Configurable thresholds ───────────────────────────────────────────────────
CROSS_SESSION_WINDOW_HOURS: float = 24.0   # Events outside this window are not temporally linked
MINIMUM_CROSS_SESSION_CONFIDENCE: float = 0.30  # Minimum score to emit a link
GENERIC_USERNAMES: Set[str] = {
    "root", "admin", "administrator", "user", "guest", "anonymous",
    "system", "service", "daemon", "nobody", "www-data",
}

# Signal weights for confidence scoring
WEIGHT_SHARED_IP        = 0.15   # IP alone is weak (Rule 1)
WEIGHT_SHARED_USER      = 0.25   # Specific user match
WEIGHT_SHARED_STAGE     = 0.20   # Same MITRE stage observed
WEIGHT_SHARED_TECHNIQUE = 0.20   # Stage + source_ip combination
WEIGHT_TEMPORAL_OVERLAP = 0.20   # Overlapping time windows


class CrossSessionCorrelator:
    """
    Stateless cross-session correlation service.
    All methods are static.
    """

    @staticmethod
    def build_related_entities(chain: AttackChain) -> RelatedEntitiesResponse:
        """
        Build a RelatedEntitiesResponse for a given chain.

        Includes:
          - Intra-chain forensic entities (IPs, users, hosts, sessions).
          - Cross-chain / cross-session potential links.
        """
        response = RelatedEntitiesResponse(chain_id=chain.id)

        # ── Intra-chain entities ──────────────────────────────────────────────
        for ip in chain.source_ips:
            response.related_ips.append(RelatedEntity(
                entity_type="ip",
                entity_value=ip,
                relationship_type="attacker_source_ip",
                evidence=[f"Observed as originating IP in {len(chain.events)} chain event(s)"],
                confidence=1.0,
            ))

        for host in chain.target_systems:
            response.related_hosts.append(RelatedEntity(
                entity_type="host",
                entity_value=host,
                relationship_type="targeted_system",
                evidence=[f"Recorded as destination/target in chain events"],
                confidence=1.0,
            ))

        for user in chain.affected_users:
            response.related_users.append(RelatedEntity(
                entity_type="user",
                entity_value=user,
                relationship_type="targeted_user_account",
                evidence=[f"User identity extracted from correlated log evidence"],
                confidence=1.0,
            ))

        response.related_sessions.append(RelatedEntity(
            entity_type="session",
            entity_value=chain.session_id,
            relationship_type="origin_upload_session",
            evidence=["Primary session from which this chain was reconstructed"],
            confidence=1.0,
        ))

        # ── Cross-chain / cross-session links ─────────────────────────────────
        response.related_chains = CrossSessionCorrelator.find_related_chains(chain)

        response.total_relationships = (
            len(response.related_ips)
            + len(response.related_users)
            + len(response.related_hosts)
            + len(response.related_sessions)
            + len(response.related_chains)
        )

        return response

    @staticmethod
    def find_related_chains(
        target: AttackChain,
        candidate_chains: Optional[List[AttackChain]] = None,
    ) -> List[RelatedChainLink]:
        """
        Search candidate chains (or all chains in store across all sessions)
        for potential evidence-based correlations with the target chain.
        """
        links: List[RelatedChainLink] = []
        seen_pairs: Set[Tuple[str, str]] = set()

        if candidate_chains is not None:
            all_chains = candidate_chains
        else:
            all_chains = [
                c
                for chains_list in store.attack_chains.values()
                for c in chains_list
            ]

        for candidate in all_chains:
            # Rule 4 — never link a chain to itself
            if candidate.id == target.id:
                continue

            # Deduplication — do not emit the same pair twice
            pair = tuple(sorted([target.id, candidate.id]))
            if pair in seen_pairs:
                continue
            seen_pairs.add(pair)

            link = CrossSessionCorrelator._evaluate_link(target, candidate)
            if link is not None:
                links.append(link)

        # Sort by descending confidence
        links.sort(key=lambda l: l.confidence, reverse=True)
        return links

    @staticmethod
    def _evaluate_link(
        a: AttackChain,
        b: AttackChain,
    ) -> Optional[RelatedChainLink]:
        """
        Evaluate whether chains a and b have sufficient shared evidence
        to emit a potential cross-session association.

        Returns a RelatedChainLink when the combined confidence meets the
        minimum threshold, otherwise returns None (Rule 6).
        """
        shared_signals: List[str] = []
        confidence: float = 0.0

        # ── Signal 1: Shared source IPs ───────────────────────────────────────
        shared_ips = set(a.source_ips) & set(b.source_ips)
        if shared_ips:
            # IP alone is a weak signal (Rule 1) — add weight but mark as partial
            confidence += WEIGHT_SHARED_IP * len(shared_ips)
            for ip in sorted(shared_ips):
                shared_signals.append(f"Shared source IP: {ip}")

        # ── Signal 2: Shared users (non-generic only, Rule 2) ─────────────────
        users_a = {u.lower() for u in a.affected_users} - GENERIC_USERNAMES
        users_b = {u.lower() for u in b.affected_users} - GENERIC_USERNAMES
        shared_users = users_a & users_b
        if shared_users:
            confidence += WEIGHT_SHARED_USER * len(shared_users)
            for u in sorted(shared_users):
                shared_signals.append(f"Shared specific username: {u}")

        # ── Signal 3: Shared MITRE attack stages ──────────────────────────────
        stages_a = {s for s in a.stages_observed if s != AttackStage.UNKNOWN}
        stages_b = {s for s in b.stages_observed if s != AttackStage.UNKNOWN}
        shared_stages = stages_a & stages_b
        if shared_stages:
            confidence += WEIGHT_SHARED_STAGE * min(1.0, len(shared_stages) / 2)
            for s in sorted(shared_stages, key=lambda x: x.value):
                shared_signals.append(f"Shared MITRE stage: {s.value}")

        # ── Signal 4: Stage + IP technique combination ────────────────────────
        if shared_ips and shared_stages:
            confidence += WEIGHT_SHARED_TECHNIQUE
            shared_signals.append(
                f"Technique overlap: same IP(s) used across same stage(s) "
                f"({', '.join(s.value for s in shared_stages)})"
            )

        # ── Signal 5: Temporal proximity (Rule 3 & 5) ─────────────────────────
        temporal_note = CrossSessionCorrelator._check_temporal_proximity(a, b)
        if temporal_note == "overlap":
            confidence += WEIGHT_TEMPORAL_OVERLAP
            shared_signals.append(
                f"Temporal proximity: chains occurred within "
                f"{CROSS_SESSION_WINDOW_HOURS}h of each other"
            )
        elif temporal_note == "no_timestamps":
            shared_signals.append(
                "[NOTE] Neither chain has parseable timestamps — "
                "temporal proximity could not be assessed (Rule 5)"
            )
        # If temporal_note == "disjoint", no signal added (Rule 3)

        # ── Rule 1 guard — IP alone is not sufficient ─────────────────────────
        # If the only shared signal is an IP (no user, no stage, no temporal),
        # do not emit a link regardless of confidence score.
        non_ip_signals = [s for s in shared_signals if "Shared source IP" not in s
                          and "[NOTE]" not in s]
        if shared_ips and not non_ip_signals:
            logger.debug(
                "Cross-session: chains %s↔%s share only IP — suppressed (Rule 1)",
                a.id, b.id,
            )
            return None

        # ── Rule 6 — minimum confidence threshold ─────────────────────────────
        confidence = min(1.0, confidence)
        if confidence < MINIMUM_CROSS_SESSION_CONFIDENCE:
            return None

        # ── Build explanation ─────────────────────────────────────────────────
        explanation = (
            f"Potential cross-session association detected between chain {a.id[:12]} "
            f"(session {a.session_id[:8]}…) and chain {b.id[:12]} "
            f"(session {b.session_id[:8]}…). "
            f"Supporting signals ({len(shared_signals)}): "
            + "; ".join(shared_signals)
            + f". Confidence: {confidence:.0%}. "
            "This is a SUSPECTED link — not a confirmed merge. "
            "Manual analyst review is required before escalating."
        )

        return RelatedChainLink(
            chain_id=b.id,
            session_id=b.session_id,
            title=b.title,
            severity=b.severity,
            shared_signals=shared_signals,
            correlation_explanation=explanation,
            confidence=round(confidence, 3),
            is_confirmed=False,
        )

    @staticmethod
    def _check_temporal_proximity(a: AttackChain, b: AttackChain) -> str:
        """
        Returns:
          "overlap"       — chains are within CROSS_SESSION_WINDOW_HOURS of each other
          "disjoint"      — chains are temporally separate (Rule 3 applies)
          "no_timestamps" — neither chain has timestamps (Rule 5 applies)
        """
        a_start = a.first_seen
        a_end   = a.last_seen or a.first_seen
        b_start = b.first_seen
        b_end   = b.last_seen or b.first_seen

        if a_start is None and b_start is None:
            return "no_timestamps"
        if a_start is None or b_start is None:
            # One chain has timestamps, the other does not — can't assess proximity
            return "disjoint"

        window = timedelta(hours=CROSS_SESSION_WINDOW_HOURS)

        # Check if the chains' time ranges overlap or are close to each other
        gap_a_before_b = b_start - a_end
        gap_b_before_a = a_start - b_end

        if gap_a_before_b <= window and gap_b_before_a <= window:
            return "overlap"
        return "disjoint"

