"""
scripts/verify_neon.py — end-to-end check that the backend is really talking to Neon.

Run from the project root:

    python scripts/verify_neon.py

Why this exists: a connected database is not the same as a working one. The
schema has to be applied, the ORM tables have to exist, and both the async and
sync drivers have to be able to talk to it. This script checks all of that, then
proves persistence by writing a row, reading it back through a second
connection, and deleting it.

Exit code 0 means the database is genuinely wired up. Non-zero means it is not.
"""

from __future__ import annotations

import asyncio
import os
import sys
import uuid
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(_ROOT))

from dotenv import load_dotenv

load_dotenv(_ROOT / ".env")

# init_db() now fails hard by default; make sure a stray opt-out in the
# environment cannot turn this verification into a false pass.
os.environ.pop("ALLOW_DB_FALLBACK", None)
os.environ.pop("DB_REQUIRED", None)

from backend.app import db  # noqa: E402
from backend.app.models.db_models import Base  # noqa: E402
from backend.app.models.live_monitoring import AlertSeverity, EventType, IOCType  # noqa: E402
from sqlalchemy import text  # noqa: E402

# Tables from storage/postgres/schema.sql
_SCHEMA_TABLES = {
    "cases",
    "mitre_techniques",
    "capability_tags",
    "iocs",
    "chain_of_custody",
    "users",
    "user_activity",
}

_PASS = "  [PASS]"
_FAIL = "  [FAIL]"

_failures: list[str] = []


def _check(ok: bool, label: str, detail: str = "") -> bool:
    print(f"{_PASS if ok else _FAIL} {label}{f' — {detail}' if detail else ''}")
    if not ok:
        _failures.append(label)
    return ok


def _section(title: str) -> None:
    print(f"\n{title}\n{'-' * len(title)}")


async def main() -> int:
    _section("1. Configuration")

    raw = os.environ.get("DATABASE_URL", "")
    if not raw:
        _check(False, "DATABASE_URL is set", "not found in .env")
        return 1

    # A URL wrapped across two lines in .env truncates at the newline; the
    # resulting host looks plausible but never resolves.
    _check("\n" not in raw and " " not in raw.strip(), "DATABASE_URL is on a single line")
    _check("username:password" not in raw, "DATABASE_URL is not the placeholder from the setup guide")

    is_neon = "neon.tech" in raw
    print(f"  async URL : {db._safe_url(db._database_url())}")
    print(f"  sync URL  : {db._safe_url(db._sync_database_url())}")
    _check("sslmode" not in db._database_url(), "asyncpg URL has no sslmode (asyncpg rejects it)")
    _check("sslmode" in db._sync_database_url() or not is_neon, "psycopg2 URL keeps sslmode")

    _section("2. Drivers installed")
    for module, why in (("asyncpg", "async engine"), ("psycopg2", "sync ORM engine / Depends(get_db)")):
        try:
            __import__(module)
            _check(True, f"{module} importable", why)
        except ImportError:
            _check(False, f"{module} importable", "pip install -r backend/requirements.txt")

    _section("3. Connect and apply schema")
    try:
        available = await db.init_db()
    except Exception as error:  # init_db() raises rather than degrading
        _check(False, "init_db() connected", f"{type(error).__name__}: {error}")
        _summary()
        return 1

    if not _check(available, "init_db() reports the database as available"):
        _summary()
        return 1

    engine = db.get_engine()

    async with engine.connect() as conn:
        version = (await conn.execute(text("SELECT version()"))).scalar_one()
        print(f"  server: {version.split(',')[0]}")
        _check(is_neon, "connected to a Neon host", "host in DATABASE_URL is not neon.tech" if not is_neon else "")

        rows = await conn.execute(text(
            "SELECT table_name FROM information_schema.tables WHERE table_schema = 'public'"
        ))
        present = {r[0] for r in rows}

    _section("4. Tables created")
    missing_schema = sorted(_SCHEMA_TABLES - present)
    _check(not missing_schema, f"schema.sql tables present ({len(_SCHEMA_TABLES)})",
           f"missing: {', '.join(missing_schema)}" if missing_schema else "")

    orm_tables = set(Base.metadata.tables)
    missing_orm = sorted(orm_tables - present)
    _check(not missing_orm, f"ORM tables present ({len(orm_tables)})",
           f"missing: {', '.join(missing_orm)}" if missing_orm else "")

    # Index names are unique per schema in Postgres, not per table. Seven models
    # once shared the name 'idx_analysis_timestamp', which made create_all()
    # abort partway through and leave most of these tables uncreated. Checked
    # here so the same mistake cannot quietly come back.
    index_owners: dict[str, list[str]] = {}
    for table in Base.metadata.tables.values():
        for index in table.indexes:
            index_owners.setdefault(index.name, []).append(table.name)
    collisions = {n: t for n, t in index_owners.items() if len(t) > 1}
    _check(not collisions, f"ORM index names are unique ({len(index_owners)})",
           "; ".join(f"{n} on {', '.join(t)}" for n, t in collisions.items()) if collisions else "")

    # The trigger function is the part a naive split-on-";" corrupts, because
    # its body is dollar-quoted and contains semicolons of its own.
    async with engine.connect() as conn:
        has_fn = (await conn.execute(text(
            "SELECT EXISTS (SELECT 1 FROM pg_proc WHERE proname = 'set_updated_at')"
        ))).scalar_one()
        has_trigger = (await conn.execute(text(
            "SELECT EXISTS (SELECT 1 FROM pg_trigger WHERE tgname = 'trg_cases_updated_at')"
        ))).scalar_one()
    _check(bool(has_fn), "set_updated_at() function created")
    _check(bool(has_trigger), "trg_cases_updated_at trigger created")

    # The ENUM labels must be the lowercase values the API speaks ("file"), not
    # the uppercase member names SQLAlchemy stores by default ("FILE"). If these
    # come back uppercase, every insert from event_processor will fail.
    async with engine.connect() as conn:
        rows = await conn.execute(text(
            "SELECT t.typname, e.enumlabel FROM pg_type t "
            "JOIN pg_enum e ON e.enumtypid = t.oid "
            "WHERE t.typname IN ('event_type', 'alert_severity', 'ioc_type')"
        ))
        labels: dict[str, set[str]] = {}
        for typname, label in rows:
            labels.setdefault(typname, set()).add(label)

    for typname, enum_cls in (
        ("event_type", EventType), ("alert_severity", AlertSeverity), ("ioc_type", IOCType)
    ):
        expected = {m.value for m in enum_cls}
        found = labels.get(typname, set())
        _check(found == expected, f"{typname} enum labels match {enum_cls.__name__} values",
               f"db has {sorted(found) or 'nothing'}, expected {sorted(expected)}"
               if found != expected else "")

    _section("5. Data actually persists")
    sample_id = f"verify{uuid.uuid4().hex}"[:64]
    try:
        async with engine.begin() as conn:
            await conn.execute(
                text(
                    "INSERT INTO cases (sample_id, platform, file_type, risk_score, status) "
                    "VALUES (:sid, 'android', 'apk', 42, 'suspicious')"
                ),
                {"sid": sample_id},
            )

        # A separate connection: proves the row reached the server, not a
        # session-local buffer.
        async with engine.connect() as conn:
            score = (await conn.execute(
                text("SELECT risk_score FROM cases WHERE sample_id = :sid"), {"sid": sample_id}
            )).scalar_one_or_none()
        _check(score == 42, "row written and read back over a new connection", f"got {score!r}")

        async with engine.begin() as conn:
            await conn.execute(
                text("UPDATE cases SET risk_score = 43 WHERE sample_id = :sid"), {"sid": sample_id}
            )
            touched = (await conn.execute(
                text("SELECT updated_at > created_at FROM cases WHERE sample_id = :sid"),
                {"sid": sample_id},
            )).scalar_one()
        _check(bool(touched), "updated_at trigger fires on UPDATE")
    finally:
        async with engine.begin() as conn:
            await conn.execute(text("DELETE FROM cases WHERE sample_id = :sid"), {"sid": sample_id})

    _section("6. Sync ORM session (Depends(get_db))")
    try:
        session_gen = db.get_db()
        session = next(session_gen)
        try:
            _check(session.execute(text("SELECT 1")).scalar_one() == 1,
                   "sync psycopg2 session queries Neon")
        finally:
            session_gen.close()
    except Exception as error:
        _check(False, "sync psycopg2 session queries Neon", f"{type(error).__name__}: {error}")

    await db.close_db()
    db.close_sync_db()
    return _summary()


def _summary() -> int:
    _section("Result")
    if _failures:
        print(f"  {len(_failures)} check(s) failed:")
        for item in _failures:
            print(f"    - {item}")
        print("\n  Neon is NOT correctly wired up.")
        return 1
    print("  All checks passed — the backend is persisting to Neon.")
    return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
