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
    """Create all tables. Safe to call on every startup (no-op if tables exist)."""
    import pythia.models  # noqa: F401 — registers all ORM classes with metadata
    Base.metadata.create_all(bind=engine)


def get_session() -> Iterator[Session]:
    """FastAPI dependency that yields a transactional DB session."""
    session = SessionLocal()
    try:
        yield session
    finally:
        session.close()
