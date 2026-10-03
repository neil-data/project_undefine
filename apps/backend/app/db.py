"""
backend/app/db.py — Postgres connection layer (SQLAlchemy Core + asyncpg, plus ORM session support).

Executes plain SQL against the tables already defined in
storage/postgres/schema.sql, which stays the single source of truth for the
schema — there are no duplicate ORM model declarations here. The schema is
applied automatically on startup if the tables don't exist yet, so
`docker-compose up -d postgres` plus a backend restart is enough to get a
working database with no separate migration step to remember.

If Postgres isn't reachable, `init_db()` raises and startup aborts. This is a
deliberate departure from the graceful-degradation pattern used for Redis
(ingestion/gateway.py), Groq (agents/narrative_agent/narrative.py), and upx
(static-analysis packing/unpacker.py): those degrade to a *worse* result, while
a missing database degrades to a *wrong* one. The in-memory fallback in
store.py accepts writes, returns success, and discards everything on restart —
so a typo in DATABASE_URL produced a server that looked completely healthy
while quietly losing evidence, which is indefensible for a forensics tool.

Set ALLOW_DB_FALLBACK=1 to opt back into the in-memory store for local work
without Postgres. It is an explicit choice, never a silent default.

Also provides sync SQLAlchemy ORM session factory for routers that use the
traditional `Depends(get_db)` pattern with `Session`.
"""

from __future__ import annotations

import asyncio
import logging
import os
from pathlib import Path
from typing import Optional, Generator

from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from sqlalchemy import create_engine, text
from sqlalchemy.ext.asyncio import AsyncEngine, create_async_engine
from sqlalchemy.orm import Session, sessionmaker

_LOGGER = logging.getLogger(__name__)

# Only used when DATABASE_URL is unset. Port 5434 matches the "5434:5432"
# mapping for the postgres service in docker-compose.yml.
_DEFAULT_URL = "postgresql://ps4:ps4pass@localhost:5434/ps4_malware"

# libpq accepts these in the query string; asyncpg's connect() does not and
# raises TypeError on the unexpected keyword. Managed providers (Neon, Supabase,
# Render) all hand out URLs containing sslmode, so translate rather than drop:
# losing sslmode entirely would silently downgrade the connection to plaintext.
_LIBPQ_TO_ASYNCPG_SSL = {
    "disable": "disable",
    "allow": "prefer",
    "prefer": "prefer",
    "require": "require",
    "verify-ca": "verify-ca",
    "verify-full": "verify-full",
}

# Understood by libpq, meaningless to asyncpg — safe to drop for that driver.
_ASYNCPG_UNSUPPORTED_PARAMS = {"channel_binding", "target_session_attrs", "connect_timeout"}

_SCHEMA_PATH = Path(__file__).resolve().parents[3] / "data" / "schemas" / "postgres" / "schema.sql"
if not _SCHEMA_PATH.exists():
    _SCHEMA_PATH = Path(__file__).resolve().parents[2] / "storage" / "postgres" / "schema.sql"

_engine: Optional[AsyncEngine] = None
_db_available = False

# Sync engine/session for ORM routers
_sync_engine = None
_SessionLocal = None


def _raw_database_url() -> str:
    """The DATABASE_URL exactly as configured, with the scheme normalised."""
    url = os.environ.get("DATABASE_URL", _DEFAULT_URL).strip().strip('"').strip("'")
    # Some providers still hand out the legacy "postgres://" scheme.
    if url.startswith("postgres://"):
        url = "postgresql://" + url[len("postgres://"):]
    return url


def _with_driver(url: str, driver: str) -> str:
    """
    Rewrites DATABASE_URL for a specific DBAPI driver.

    A plain string replace of the scheme is not enough: the query string that
    managed Postgres providers append is written for libpq, and asyncpg rejects
    several of those parameters outright. This normalises the query string to
    match whichever driver is being targeted, so one DATABASE_URL can feed both
    the async engine and the sync ORM engine.
    """
    parts = urlsplit(url)
    scheme = parts.scheme.split("+", 1)[0]  # drop any driver already pinned
    params = dict(parse_qsl(parts.query, keep_blank_values=True))

    if driver == "asyncpg":
        sslmode = params.pop("sslmode", None)
        for key in _ASYNCPG_UNSUPPORTED_PARAMS:
            params.pop(key, None)
        if sslmode and "ssl" not in params:
            translated = _LIBPQ_TO_ASYNCPG_SSL.get(sslmode.lower())
            if translated:
                # asyncpg has no notion of "disable"; omitting ssl is the
                # equivalent, and passing it through would be rejected.
                if translated != "disable":
                    params["ssl"] = translated
            else:
                _LOGGER.warning("Unrecognised sslmode=%r in DATABASE_URL — ignoring", sslmode)
    else:
        # libpq understands sslmode natively; undo an asyncpg-style ssl= param
        # if someone configured the URL the other way round.
        ssl = params.pop("ssl", None)
        if ssl and "sslmode" not in params:
            params["sslmode"] = "require" if ssl in ("true", "1") else ssl

    return urlunsplit((
        f"{scheme}+{driver}",
        parts.netloc,
        parts.path,
        urlencode(params),
        parts.fragment,
    ))


def _safe_url(url: str) -> str:
    """Same URL with the password masked, for logging."""
    parts = urlsplit(url)
    if parts.password:
        netloc = parts.netloc.replace(f":{parts.password}@", ":***@")
        parts = parts._replace(netloc=netloc)
    return urlunsplit(parts)


def _database_url() -> str:
    """Async (asyncpg) form of DATABASE_URL."""
    return _with_driver(_raw_database_url(), "asyncpg")


async def init_db() -> bool:
    """
    Attempt to connect to Postgres and apply storage/postgres/schema.sql.
    Returns True if the database is reachable and ready, False otherwise.
    Safe to call multiple times (schema.sql uses `IF NOT EXISTS` throughout).
    """
    global _engine, _db_available

    try:
        engine = create_async_engine(_database_url(), pool_pre_ping=True)

        # Test connection first
        async with engine.connect() as conn:
            result = await conn.execute(text("SELECT 1"))
            result.fetchone()

        # Check if tables already exist (schema already applied)
        async with engine.connect() as conn:
            result = await conn.execute(text("""
                SELECT EXISTS (
                    SELECT FROM information_schema.tables 
                    WHERE table_schema = 'public' AND table_name = 'cases'
                )
            """))
            tables_exist = result.scalar()

        # schema.sql is idempotent throughout (CREATE TABLE/INDEX IF NOT EXISTS,
        # CREATE OR REPLACE FUNCTION, DROP TRIGGER IF EXISTS, ADD COLUMN IF NOT
        # EXISTS), so it is re-applied on every startup rather than only on a
        # fresh database. That is what makes the trailing ALTER TABLE block at
        # the bottom of the file work as the no-migration upgrade path it
        # documents itself to be — gating it on "tables don't exist yet" meant
        # an existing database never picked up newly added columns.
        await _apply_schema(engine)
        await _create_orm_tables()
        _LOGGER.info(
            "Postgres ready at %s (schema %s from %s)",
            _safe_url(_database_url()),
            "verified" if tables_exist else "created",
            _SCHEMA_PATH.name,
        )

        _engine = engine
        _db_available = True
    except Exception as error:
        _db_available = False

        if not _fallback_allowed():
            _LOGGER.error(
                "Postgres is unreachable at %s (%s: %s)",
                _safe_url(_database_url()), type(error).__name__, error,
                exc_info=True,
            )
            raise RuntimeError(
                f"Cannot connect to the database at {_safe_url(_database_url())} "
                f"({type(error).__name__}: {error}). Refusing to start on the in-memory "
                "store, because it accepts writes and then discards them on restart — "
                "the API would look healthy while losing data. Fix DATABASE_URL, or set "
                "ALLOW_DB_FALLBACK=1 to run without persistence on purpose."
            ) from error

        _LOGGER.warning(
            "Postgres unavailable (%s: %s) — running on the in-memory case store because "
            "ALLOW_DB_FALLBACK is set. DATA WILL NOT PERSIST ACROSS RESTARTS.",
            type(error).__name__, error,
            exc_info=True,
        )

    return _db_available


def _fallback_allowed() -> bool:
    """
    Whether the in-memory store may stand in for a missing database.

    Off by default: silent degradation is only safe when the caller has said
    they expect it. Honours the older DB_REQUIRED=0 spelling so existing local
    setups keep working.
    """
    if os.environ.get("ALLOW_DB_FALLBACK", "").lower() in ("1", "true", "yes"):
        return True
    return os.environ.get("DB_REQUIRED", "").lower() in ("0", "false", "no")


async def _apply_schema(engine: AsyncEngine) -> None:
    """
    Applies storage/postgres/schema.sql in full.

    The file is executed as a single script rather than being split on ";".
    Naive splitting breaks this schema in two separate ways: the
    `set_updated_at()` trigger function contains semicolons inside its
    dollar-quoted ($$ ... $$) body, which splitting tears into syntactically
    invalid fragments; and because nearly every statement is preceded by a
    banner comment, the resulting chunks begin with "--" and were being
    discarded by the comment filter — including the one that creates `cases`.

    asyncpg's Connection.execute() uses the simple query protocol when called
    without arguments, which accepts a multi-statement script. Reaching for the
    raw driver connection is what makes that possible; SQLAlchemy's normal
    execute path prepares statements, and Postgres refuses to prepare more than
    one statement at a time.
    """
    schema_sql = _SCHEMA_PATH.read_text(encoding="utf-8")
    async with engine.begin() as conn:
        raw_connection = await conn.get_raw_connection()
        await raw_connection.driver_connection.execute(schema_sql)


async def _create_orm_tables() -> None:
    """
    Creates the live-monitoring tables declared in models/db_models.py.

    schema.sql covers the case/IOC side only. The eleven ORM tables
    (analysis_events, risk_scores, alerts, live_monitoring_sessions, ...) were
    declared but never created by anything: there is no Alembic setup in this
    repo and no create_all() call, so those tables only ever existed on
    databases where someone had made them by hand. Against a brand-new database
    the live_monitoring and network_intelligence routers would fail on their
    first query. create_all() issues CREATE TABLE IF NOT EXISTS, so this is
    idempotent and leaves existing tables untouched.

    Raises unless ALLOW_DB_FALLBACK is set: this runs on the sync psycopg2
    engine, so it is also the first thing to fail if psycopg2 is missing — and
    that same engine backs every Depends(get_db) route. Swallowing the error
    here would just move the failure to the first request that hits one.
    """
    from .models.db_models import Base

    def _create() -> None:
        Base.metadata.create_all(bind=_get_sync_engine())

    try:
        await asyncio.to_thread(_create)
        _LOGGER.info("ORM tables ensured (%d declared)", len(Base.metadata.tables))
    except Exception as error:
        if not _fallback_allowed():
            raise
        _LOGGER.warning(
            "Could not create ORM tables (%s: %s) — live monitoring endpoints "
            "will fail. Is psycopg2-binary installed?",
            type(error).__name__, error,
            exc_info=True,
        )


def is_available() -> bool:
    return _db_available


def get_engine() -> AsyncEngine:
    if _engine is None:
        raise RuntimeError("Database engine not initialized — call init_db() first")
    return _engine


async def close_db() -> None:
    global _engine, _db_available
    if _engine is not None:
        await _engine.dispose()
    _engine = None
    _db_available = False


def _sync_database_url() -> str:
    """Sync (psycopg2) form of DATABASE_URL."""
    return _with_driver(_raw_database_url(), "psycopg2")


def _get_sync_engine():
    """Get or create sync engine for ORM."""
    global _sync_engine
    if _sync_engine is None:
        _sync_engine = create_engine(_sync_database_url(), pool_pre_ping=True)
    return _sync_engine


def _get_session_factory():
    """Get or create session factory."""
    global _SessionLocal
    if _SessionLocal is None:
        _SessionLocal = sessionmaker(bind=_get_sync_engine(), autoflush=False, autocommit=False)
    return _SessionLocal


def get_db() -> Generator[Session, None, None]:
    """
    FastAPI dependency that yields a sync SQLAlchemy ORM Session.
    Used by routers with `db: Session = Depends(get_db)`.
    """
    session_factory = _get_session_factory()
    db = session_factory()
    try:
        yield db
    finally:
        db.close()


def close_sync_db() -> None:
    """Close sync engine (call on app shutdown)."""
    global _sync_engine, _SessionLocal
    if _sync_engine is not None:
        _sync_engine.dispose()
    _sync_engine = None
    _SessionLocal = None
