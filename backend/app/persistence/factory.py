"""
Persistence Layer Factory for MICHAEL – THE GUARDIAN AI.

Phase 5.0 — Production Hardening & Persistence Integration.

Instantiates either in-memory or database-backed repositories based on
the PERSISTENCE_BACKEND configuration ('memory', 'postgres', 'sqlite').
"""

import logging
from typing import Optional

from app.config import settings
from app.persistence.database import db_manager, sanitize_db_url
from app.persistence.sql_store import SQLIOCRepository, SQLStoreRepository

logger = logging.getLogger("michael.persistence.factory")


def init_persistence() -> bool:
    """
    Initialize persistent storage if configured.
    Creates schema tables when backend is 'postgres' or 'sqlite'.
    """
    backend = getattr(settings, "PERSISTENCE_BACKEND", "memory").lower()
    if backend in ("postgres", "sqlite"):
        try:
            logger.info("Initializing persistence layer with backend '%s'", backend)
            success = db_manager.init_db()
            if success:
                logger.info("Persistence layer ready (backend: %s)", backend)
            else:
                logger.warning("Persistence layer initialization returned False for backend '%s'", backend)
            return success
        except Exception as exc:
            safe_msg = sanitize_db_url(str(exc))
            logger.error("Failed to initialize persistence backend '%s': %s", backend, safe_msg)
            return False
    return True


def get_persistence_backend_name() -> str:
    """Return the active persistence backend name."""
    return getattr(settings, "PERSISTENCE_BACKEND", "memory").lower()

