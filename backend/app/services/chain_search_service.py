"""
ChainSearchService — Phase 4.1A.

Provides advanced, multi-criteria search across all AttackChains held in the
in-memory SessionStore.  Multiple filters are applied together (AND logic).

Supported filter dimensions:
  - chain_id       — exact match
  - session_id     — exact match
  - source_ip      — substring match across chain.source_ips
  - destination_ip — substring match across chain.target_systems
  - username       — substring match across chain.affected_users
  - stage          — case-insensitive match in stages_observed + stages_unconfirmed
  - severity       — exact case-insensitive match (LOW/MEDIUM/HIGH/CRITICAL)
  - status         — ChainStatus enum match
  - keyword        — substring search in title, summary, supporting_evidence, correlation_explanation
  - start_time     — chain.first_seen >= start_time
  - end_time       — chain.last_seen <= end_time
  - event_id       — match against event.id or event.log_entry_id within chain.events

Pagination: page / page_size.
Sorting: sort_by field name, sort_desc flag.

STORAGE NOTE: Operates exclusively on in-memory SessionStore state.
              No database queries are issued.  All data is lost on restart.
"""

import logging
from typing import Any, List, Optional

from app.models.attack_chain import (
    AttackChain,
    ChainSearchParams,
    ChainSearchResult,
    ChainStatus,
)
from app.services.store import store

logger = logging.getLogger("michael.chain_search")


class ChainSearchService:
    """
    Stateless search service — all methods are static.
    Query the SessionStore and apply multi-dimensional filters.
    """

    @staticmethod
    def search(params: ChainSearchParams) -> ChainSearchResult:
        """
        Execute a multi-filter search and return a paginated result.

        Guarantees:
          - All active filters work together (AND logic).
          - Events from unrelated chains are never included.
          - An empty params object returns all chains (paginated).
          - Invalid / non-existent session_id returns an empty result set.
        """
        # --- Collect candidate chains -----------------------------------
        all_chains: List[AttackChain] = ChainSearchService._collect_candidates(
            params.session_id
        )

        # --- Apply filters (each filter prunes the candidate list) ------
        filtered = [
            c for c in all_chains
            if ChainSearchService._matches(c, params)
        ]

        # --- Sort -------------------------------------------------------
        filtered = ChainSearchService._sort(filtered, params.sort_by, params.sort_desc)

        # --- Paginate ---------------------------------------------------
        total = len(filtered)
        start = (params.page - 1) * params.page_size
        end   = start + params.page_size
        page_chains = filtered[start:end]

        logger.debug(
            "ChainSearch: %d total match(es) → page %d/%d (size %d)",
            total,
            params.page,
            max(1, -(-total // params.page_size)),
            params.page_size,
        )

        return ChainSearchResult(
            total=total,
            page=params.page,
            page_size=params.page_size,
            chains=page_chains,
        )

    # ── Candidate collection ─────────────────────────────────────────────────

    @staticmethod
    def _collect_candidates(session_id: Optional[str]) -> List[AttackChain]:
        """
        Return all chains for a given session, or all chains in the store
        when session_id is None.
        """
        if session_id:
            return list(store.get_attack_chains(session_id))

        # No session filter — search across ALL sessions
        all_chains: List[AttackChain] = []
        for chains in store.attack_chains.values():
            all_chains.extend(chains)
        return all_chains

    # ── Master filter ────────────────────────────────────────────────────────

    @staticmethod
    def _matches(chain: AttackChain, p: ChainSearchParams) -> bool:
        """Return True if *all* active filter criteria match the chain."""

        # 1. Exact chain_id match
        if p.chain_id and chain.id != p.chain_id:
            return False

        # 2. Source IP substring match (any IP in chain.source_ips)
        if p.source_ip:
            needle = p.source_ip.lower()
            if not any(needle in ip.lower() for ip in chain.source_ips):
                return False

        # 3. Destination IP / target system substring match
        if p.destination_ip:
            needle = p.destination_ip.lower()
            if not any(needle in h.lower() for h in chain.target_systems):
                return False

        # 4. Username substring match
        if p.username:
            needle = p.username.lower()
            if not any(needle in u.lower() for u in chain.affected_users):
                return False

        # 5. Stage match (stages_observed + stages_unconfirmed)
        if p.stage:
            needle = p.stage.lower()
            all_stages = [s.value.lower() for s in chain.stages_observed] + \
                         [s.value.lower() for s in chain.stages_unconfirmed]
            if not any(needle in s for s in all_stages):
                return False

        # 6. Severity — exact case-insensitive
        if p.severity:
            if chain.severity.upper() != p.severity.upper():
                return False

        # 7. Status match (ChainStatus enum)
        if p.status:
            chain_status = getattr(chain, "status", ChainStatus.NEW)
            if chain_status != p.status:
                return False

        # 8. Free-text keyword search — title, summary, evidence, explanation
        if p.keyword:
            needle = p.keyword.lower()
            searchable = " ".join([
                chain.title,
                chain.summary,
                chain.correlation_explanation,
                chain.potential_impact,
                " ".join(chain.supporting_evidence),
                " ".join(chain.hypotheses_unconfirmed),
                " ".join(chain.recommended_actions),
            ]).lower()
            if needle not in searchable:
                return False

        # 9. Time range — start_time
        if p.start_time and chain.first_seen:
            if chain.first_seen < p.start_time:
                return False

        # 10. Time range — end_time
        if p.end_time and chain.last_seen:
            if chain.last_seen > p.end_time:
                return False

        # 11. Event ID match — search within chain.events
        if p.event_id:
            event_ids = {ev.id for ev in chain.events}
            log_entry_ids = {ev.log_entry_id for ev in chain.events if ev.log_entry_id}
            if p.event_id not in event_ids and p.event_id not in log_entry_ids:
                return False

        return True

    # ── Sorting ──────────────────────────────────────────────────────────────

    @staticmethod
    def _sort(chains: List[AttackChain], sort_by: str, descending: bool) -> List[AttackChain]:
        """
        Sort chains by a chain attribute.  Falls back to first_seen on unknown fields.
        None values sort last regardless of direction.
        """
        SORTABLE_FIELDS = {
            "first_seen", "last_seen", "confidence_score",
            "duration_seconds", "severity", "title",
        }

        field = sort_by if sort_by in SORTABLE_FIELDS else "first_seen"

        def sort_key(c: AttackChain) -> Any:
            val = getattr(c, field, None)
            if val is None:
                # Put None last in both directions
                return (1, "")
            return (0, val)

        return sorted(chains, key=sort_key, reverse=descending)

