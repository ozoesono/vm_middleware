"""Database connection and session management."""

from __future__ import annotations

from contextlib import contextmanager
from typing import Generator

from sqlalchemy import create_engine
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker

from src.common.config import AppSettings


class Base(DeclarativeBase):
    """SQLAlchemy declarative base for all models."""

    pass


_engine = None
_SessionLocal = None


def init_db(database_url: str | None = None) -> None:
    """Initialise the database engine and session factory."""
    global _engine, _SessionLocal
    url = database_url or AppSettings().database_url
    _engine = create_engine(url, pool_pre_ping=True, pool_size=5, max_overflow=10)
    _SessionLocal = sessionmaker(bind=_engine, expire_on_commit=False)


def get_engine():
    """Return the current engine, initialising if needed."""
    if _engine is None:
        init_db()
    return _engine


def get_session_factory():
    """Return the session factory, initialising if needed."""
    if _SessionLocal is None:
        init_db()
    return _SessionLocal


@contextmanager
def get_session() -> Generator[Session, None, None]:
    """Provide a transactional database session scope."""
    factory = get_session_factory()
    session = factory()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()
