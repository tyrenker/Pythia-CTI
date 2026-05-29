"""SQLAlchemy engine, session, and declarative base."""

from __future__ import annotations

from collections.abc import Iterator

from sqlalchemy import create_engine, event
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker

from pythia.core.config import get_settings


class Base(DeclarativeBase):
    """Shared declarative base for all ORM models."""


_settings = get_settings()
engine = create_engine(
    _settings.database_url,
    echo=False,
    future=True,
    connect_args={"check_same_thread": False} if _settings.database_url.startswith("sqlite") else {},
)

# Enable WAL mode for SQLite — allows concurrent reads while writing.
if _settings.database_url.startswith("sqlite"):
    @event.listens_for(engine, "connect")
    def set_sqlite_pragma(dbapi_conn, _connection_record):  # type: ignore[misc]
        cursor = dbapi_conn.cursor()
        cursor.execute("PRAGMA journal_mode=WAL")
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.close()

SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False, future=True)


def init_db() -> None:
    """Create all tables and apply idempotent column migrations."""
    import pythia.models  # noqa: F401 — registers all ORM classes with metadata
    Base.metadata.create_all(bind=engine)
    _migrate_columns()


def _migrate_columns() -> None:
    """Add any columns introduced after initial table creation (idempotent)."""
    from sqlalchemy import text

    migrations = [
        "ALTER TABLE malware_families ADD COLUMN mitre_id VARCHAR",
        "ALTER TABLE detection_rules ADD COLUMN source VARCHAR",
    ]
    with engine.begin() as conn:
        for stmt in migrations:
            try:
                conn.execute(text(stmt))
            except Exception:
                pass  # column already exists


def get_session() -> Iterator[Session]:
    """FastAPI dependency that yields a transactional DB session."""
    session = SessionLocal()
    try:
        yield session
    finally:
        session.close()
