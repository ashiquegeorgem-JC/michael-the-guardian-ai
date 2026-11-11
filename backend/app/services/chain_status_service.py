"""
ChainStatusService — Phase 4.1A.

Manages the investigation lifecycle of AttackChains.

Lifecycle states:
    NEW  →  INVESTIGATING  →  CONFIRMED  →  RESOLVED
                         ↘  FALSE_POSITIVE ↗ (re-open to INVESTIGATING)

Rules:
  - Every transition must supply a non-empty reason (min 5 chars).
  - Only transitions listed in VALID_STATUS_TRANSITIONS are accepted.
  - Each transition is appended to chain.status_history (full audit trail).
  - No existing chain evidence is ever deleted or modified on a status change.
  - Chain IDs are located across all sessions in the SessionStore.

Per-event confirmation:
  - Individual ChainLinkEvents within a chain can be independently marked
    is_confirmed=True/False with a supplied reason.
  - The event's correlation_reason is updated to reflect the analyst decision.

STORAGE NOTE: Mutations operate on the live in-memory SessionStore objects.
              All state is lost on server restart.
              No database is written.
"""

import logging
from datetime import datetime
from typing import Optional, Tuple

from app.models.attack_chain import (
    AttackChain,
    ChainStatus,
    ChainStatusHistory,
    ChainStatusUpdate,
    VALID_STATUS_TRANSITIONS,
    ChainLinkEvent,
)
from app.services.store import store

logger = logging.getLogger("michael.chain_status")


class ChainStatusService:
    """
    Stateless service for chain and event lifecycle management.
    All methods are static; no instance state is maintained.
    """

    # ── Chain-level status management ────────────────────────────────────────

    @staticmethod
    def update_status(
        chain_id: str,
        update: ChainStatusUpdate,
    ) -> Tuple[Optional[AttackChain], Optional[str]]:
        """
        Transition a chain to a new investigation status.

        Returns:
            (updated_chain, None)           — on success
            (None, error_message_string)    — on failure (chain not found, invalid transition)

        Guarantees:
          - Only valid transitions are applied.
          - The previous status and timestamp are preserved in status_history.
          - Chain evidence is never modified.
          - A clear error string is returned instead of raising exceptions, so
            callers can map to appropriate HTTP status codes.
        """
        chain = store.get_attack_chain(chain_id)
        if chain is None:
            return None, f"Attack chain '{chain_id}' not found."

        current_status: ChainStatus = getattr(chain, "status", ChainStatus.NEW)
        target_status: ChainStatus = update.status

        # Validate transition
        allowed = VALID_STATUS_TRANSITIONS.get(current_status, set())
        if target_status not in allowed:
            allowed_names = ", ".join(s.value for s in allowed) if allowed else "none"
            return None, (
                f"Invalid status transition: {current_status.value} → {target_status.value}. "
                f"Allowed transitions from {current_status.value}: {allowed_names}."
            )

        # Record history entry
        history_entry = ChainStatusHistory(
            previous_status=current_status,
            new_status=target_status,
            changed_at=datetime.utcnow(),
            changed_by=update.changed_by,
            reason=update.reason,
        )

        # Append to history (preserving all previous entries)
        history = list(getattr(chain, "status_history", []))
        history.append(history_entry)

        # Build the updated chain using model_copy (Pydantic v2 API).
        # We never delete fields — only the status, analyst_note, and
        # status_history fields are changed.
        updated_chain = chain.model_copy(update={
            "status": target_status,
            "analyst_note": update.reason,
            "status_history": history,
        })

        # Persist back to the store
        ChainStatusService._replace_chain_in_store(chain_id, updated_chain)

        logger.info(
            "Chain [%s] status: %s → %s (by %s): %s",
            chain_id,
            current_status.value,
            target_status.value,
            update.changed_by or "system",
            update.reason,
        )

        return updated_chain, None

    # ── Per-event confirmation management ────────────────────────────────────

    @staticmethod
    def confirm_event(
        chain_id: str,
        event_id: str,
        is_confirmed: bool,
        reason: str,
        changed_by: Optional[str] = None,
    ) -> Tuple[Optional[ChainLinkEvent], Optional[str]]:
        """
        Mark a specific ChainLinkEvent as confirmed or suspected.

        Matching is attempted first by event.id, then by event.log_entry_id.

        Returns:
            (updated_event, None)           — on success
            (None, error_message_string)    — on failure

        Guarantees:
          - Only is_confirmed and correlation_reason are changed on the event.
          - All other event fields (raw_log, timestamp, stage, etc.) are preserved.
          - The parent chain is updated in-store to reflect the change.
        """
        chain = store.get_attack_chain(chain_id)
        if chain is None:
            return None, f"Attack chain '{chain_id}' not found."

        # Locate the target event
        target_event: Optional[ChainLinkEvent] = None
        event_index: int = -1
        for i, ev in enumerate(chain.events):
            if ev.id == event_id or ev.log_entry_id == event_id:
                target_event = ev
                event_index = i
                break

        if target_event is None:
            return None, (
                f"Event '{event_id}' not found in chain '{chain_id}'. "
                "Check that the event_id matches either the ChainLinkEvent.id "
                "or the ChainLinkEvent.log_entry_id."
            )

        if not reason or len(reason.strip()) < 3:
            return None, "A reason of at least 3 characters is required to confirm/reject an event."

        # Build updated event — only is_confirmed and correlation_reason change
        decision_label = "CONFIRMED" if is_confirmed else "REJECTED"
        analyst_prefix = f"[ANALYST {decision_label}]"
        if changed_by:
            analyst_prefix = f"[ANALYST {decision_label} by {changed_by}]"

        updated_correlation_reason = (
            f"{analyst_prefix} {reason}  |  "
            f"[ORIGINAL] {target_event.correlation_reason}"
        )

        updated_event = target_event.model_copy(update={
            "is_confirmed": is_confirmed,
            "correlation_reason": updated_correlation_reason,
        })

        # Rebuild the events list with the updated event in-place
        new_events = list(chain.events)
        new_events[event_index] = updated_event

        updated_chain = chain.model_copy(update={"events": new_events})
        ChainStatusService._replace_chain_in_store(chain_id, updated_chain)

        logger.info(
            "Event [%s] in chain [%s] marked is_confirmed=%s by %s: %s",
            event_id,
            chain_id,
            is_confirmed,
            changed_by or "system",
            reason,
        )

        return updated_event, None

    # ── Store helpers ─────────────────────────────────────────────────────────

    @staticmethod
    def _replace_chain_in_store(chain_id: str, updated_chain: AttackChain) -> bool:
        """
        Locate and replace the chain object in the SessionStore by ID.

        Iterates all session buckets because a chain_id lookup may not know
        which session_id bucket it belongs to (cross-session use case).

        Returns True if the chain was found and replaced, False otherwise.
        """
        for session_id, chains in store.attack_chains.items():
            for i, c in enumerate(chains):
                if c.id == chain_id:
                    store.attack_chains[session_id][i] = updated_chain
                    return True
        return False

