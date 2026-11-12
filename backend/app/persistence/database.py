"""
Database Connection & Engine Factory for MICHAEL – THE GUARDIAN AI.

Phase 5.0 — Production Hardening & Persistence Integration.

Provides:
- Thread-safe SQLAlchemy Engine & Session Factory.
- Secret scrubbing from database URLs, logs, and exception messages.
- Connection pooling with pre-ping health checks.
- Robust, defensive database health probe (`check_db_health`).
- Schema initialization (`init_db`).
"""

from contextlib import contextmanager
import logging
import os
import re
from typing import Any, Dict, Generator, Optional
from urllib.parse import urlparse

from sqlalchemy import create_engine, text
from sqlalchemy.engine import Engine
from sqlalchemy.orm import declarative_base, sessionmaker, Session
from sqlalchemy.pool import QueuePool, StaticPool

from app.config import settings
from app.persistence.models import Base, DBSession

logger = logging.getLogger("michael.persistence.database")

# Pattern to scrub credentials from connection strings
_CREDENTIAL_PATTERN = re.compile(r"://([^:]+):([^@]+)@", re.IGNORECASE)


def sanitize_db_url(url: str) -> str:
    """Scrub passwords from database connection URLs for safe logging."""
    if not url:
        return ""
    return _CREDENTIAL_PATTERN.sub(r"://\1:******@", url)


class DatabaseManager:
    """
    Manages SQLAlchemy engine lifecycle, session factory, and connection health.
    """

    def __init__(self, database_url: Optional[str] = None, db_url: Optional[str] = None):
        self._custom_url = database_url or db_url
        self._engine: Optional[Engine] = None
        self._session_factory: Optional[sessionmaker] = None

    def get_database_url(self) -> str:
        """Resolve database URL from config or environment."""
        if self._custom_url:
            return self._custom_url
        if settings.DATABASE_URL:
            return settings.DATABASE_URL
        if settings.SUPABASE_URL and settings.SUPABASE_SERVICE_ROLE_KEY:
            # If Supabase URL is provided without direct DB URL, derive connection if applicable
            pass
        # Default SQLite path if sqlite or postgres without URL
        backend = getattr(settings, "PERSISTENCE_BACKEND", "memory").lower()
        if backend == "sqlite":
            sqlite_path = getattr(settings, "SQLITE_DB_PATH", "./data/michael.db")
            os.makedirs(os.path.dirname(os.path.abspath(sqlite_path)), exist_ok=True)
            return f"sqlite:///{os.path.abspath(sqlite_path)}"
        return ""

    def get_engine(self) -> Optional[Engine]:
        """Lazy-initialize and return the SQLAlchemy engine."""
        if self._engine is not None:
            return self._engine

        url = self.get_database_url()
        if not url:
            return None

        clean_url = sanitize_db_url(url)
        logger.info("Initializing database connection with: %s", clean_url)

        try:
            if url.startswith("sqlite"):
                # SQLite configuration
                if ":memory:" in url:
                    engine = create_engine(
                        url,
                        connect_args={"check_same_thread": False},
                        poolclass=StaticPool,
                    )
                else:
                    engine = create_engine(
                        url,
                        connect_args={"check_same_thread": False},
                        pool_pre_ping=True,
                    )
            else:
                # PostgreSQL / Supabase configuration
                engine = create_engine(
                    url,
                    poolclass=QueuePool,
                    pool_size=getattr(settings, "DB_POOL_SIZE", 10),
                    max_overflow=getattr(settings, "DB_MAX_OVERFLOW", 20),
                    pool_timeout=getattr(settings, "DB_POOL_TIMEOUT", 30),
                    pool_pre_ping=True,
                )

            self._engine = engine
            self._session_factory = sessionmaker(
                bind=self._engine,
                autocommit=False,
                autoflush=False,
                expire_on_commit=False,
            )
            return self._engine
        except Exception as exc:
            safe_msg = sanitize_db_url(str(exc))
            logger.error("Failed to initialize database engine: %s", safe_msg)
            return None

    def get_session_factory(self) -> Optional[sessionmaker]:
        """Ensure engine is initialized and return session factory."""
        if self._session_factory is None:
            self.get_engine()
        return self._session_factory

    @contextmanager
    def session(self) -> Generator[Session, None, None]:
        """Provide a transactional session scope with automatic rollback and close."""
        factory = self.get_session_factory()
        if factory is None:
            raise RuntimeError("Database engine is not configured or available.")

        session: Session = factory()
        try:
            yield session
            session.commit()
        except Exception as exc:
            session.rollback()
            safe_msg = sanitize_db_url(str(exc))
            logger.error("Database transaction rolled back due to error: %s", safe_msg)
            raise
        finally:
            session.close()

    def init_db(self) -> bool:
        """Create all tables if they do not exist."""
        backend = getattr(settings, "PERSISTENCE_BACKEND", "memory").lower()
        if backend == "memory" and not self.get_database_url():
            logger.info("In-memory persistence active; skipping relational schema creation.")
            return True

        engine = self.get_engine()
        if engine is None:
            return False
        try:
            Base.metadata.create_all(bind=engine)
            logger.info("Database schema initialized successfully.")
            return True
        except Exception as exc:
            safe_msg = sanitize_db_url(str(exc))
            logger.error("Failed to initialize database schema: %s", safe_msg)
            return False

    def check_db_health(self) -> Dict[str, Any]:
        """
        Health probe for database connection.
        Returns clean status without leaking connection strings or credentials.
        """
        backend = getattr(settings, "PERSISTENCE_BACKEND", "memory").lower()
        if backend == "memory":
            return {
                "status": "ready",
                "backend": "memory",
                "message": "In-memory persistence active",
            }

        engine = self.get_engine()
        if engine is None:
            return {
                "status": "unhealthy",
                "backend": backend,
                "error": "Engine initialization failed or DATABASE_URL not configured",
            }

        try:
            with engine.connect() as conn:
                conn.execute(text("SELECT 1"))
            return {
                "status": "healthy",
                "backend": backend,
                "pool_size": getattr(engine.pool, "size", lambda: None)(),
            }
        except Exception as exc:
            safe_err = sanitize_db_url(str(exc))
            logger.warning("Database health check failed: %s", safe_err)
            return {
                "status": "unhealthy",
                "backend": backend,
                "error": "Database connectivity check failed",
            }

    def close(self):
        """Dispose of engine connections."""
        if self._engine is not None:
            try:
                self._engine.dispose()
            except Exception:
                pass
            self._engine = None
            self._session_factory = None


# Global DatabaseManager instance
db_manager = DatabaseManager()
