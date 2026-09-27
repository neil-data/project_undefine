"""
backend/app/pipeline_status.py — Real analysis-pipeline status tracking.

The upload endpoint accepts a sample, persists a job row immediately, and then
runs static/dynamic analysis in the background. This module owns that job row:
the status (UPLOADED -> VALIDATING -> HASHING -> STATIC_ANALYSIS ->
DYNAMIC_ANALYSIS -> COMPLETED / FAILED) is written as each stage starts and
finishes so a polling client sees the real pipeline, never a fabricated timer.

Persistence mirrors store.py: the in-memory dict is always kept warm, and
Postgres (analysis_jobs) is used whenever reachable so a page refresh — or a
full server restart — does not lose the in-flight status.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from threading import Lock
from typing import Optional

from sqlalchemy import text

from . import db

_LOGGER = logging.getLogger(__name__)

# Canonical pipeline states (surface these verbatim to the frontend).
UPLOADED = "UPLOADED"
VALIDATING = "VALIDATING"
HASHING = "HASHING"
STATIC_ANALYSIS = "STATIC_ANALYSIS"
DYNAMIC_ANALYSIS = "DYNAMIC_ANALYSIS"
COMPLETED = "COMPLETED"
FAILED = "FAILED"

_STAGES = (UPLOADED, VALIDATING, HASHING, STATIC_ANALYSIS, DYNAMIC_ANALYSIS, COMPLETED, FAILED)

_jobs: dict[str, dict] = {}
_lock = Lock()


def _now() -> str:
    return datetime.utcnow().isoformat() + "Z"


def _sanitize(changes: dict) -> dict:
    """Only allow known fields — never let a caller set arbitrary keys."""
    allowed = {
        "user_email", "original_filename", "file_size_bytes", "mime_type",
        "file_type", "status", "stage", "dynamic_status", "error",
    }
    out = {k: v for k, v in changes.items() if k in allowed and v is not None}
    return out


async def create_job(analysis_id: str, **fields) -> dict:
    job = {
        "analysis_id": analysis_id,
        "user_email": fields.get("user_email"),
        "original_filename": fields.get("original_filename"),
        "file_size_bytes": fields.get("file_size_bytes"),
        "mime_type": fields.get("mime_type"),
        "file_type": fields.get("file_type"),
        "status": fields.get("status", UPLOADED),
        "stage": fields.get("stage"),
        "dynamic_status": fields.get("dynamic_status"),
        "error": fields.get("error"),
        "created_at": _now(),
        "updated_at": _now(),
    }
    with _lock:
        _jobs[analysis_id] = job

    await _persist_upsert(job)
    return dict(job)


async def update_job(analysis_id: str, **changes) -> Optional[dict]:
    changes = _sanitize(changes)
    changes["updated_at"] = _now()
    with _lock:
        job = _jobs.get(analysis_id)
        if job is None:
            job = {"analysis_id": analysis_id, "created_at": _now()}
            _jobs[analysis_id] = job
        job.update(changes)

    await _persist_upsert(job)
    return dict(job)


async def get_job(analysis_id: str) -> Optional[dict]:
    # Prefer Postgres so a restart cannot hide persisted progress; fall back
    # to the warm in-memory row when the DB is unreachable or has nothing.
    if db.is_available():
        try:
            engine = db.get_engine()
            async with engine.connect() as conn:
                row = (
                    await conn.execute(
                        text("SELECT * FROM analysis_jobs WHERE analysis_id = :aid"),
                        {"aid": analysis_id},
                    )
                ).mappings().first()
            if row is not None:
                out = dict(row)
                for key in ("created_at", "updated_at"):
                    if out.get(key) is not None and hasattr(out[key], "isoformat"):
                        out[key] = out[key].isoformat()
                with _lock:
                    _jobs[analysis_id] = out
                return out
        except Exception:
            _LOGGER.exception("analysis job read failed for %s — using in-memory row", analysis_id)

    with _lock:
        return _jobs.get(analysis_id)


async def list_jobs() -> list[dict]:
    if db.is_available():
        try:
            engine = db.get_engine()
            async with engine.connect() as conn:
                rows = (
                    await conn.execute(
                        text("SELECT analysis_id, status, stage, file_type, created_at, updated_at "
                             "FROM analysis_jobs ORDER BY updated_at DESC")
                    )
                ).mappings().all()
                return [dict(r) for r in rows]
        except Exception:
            _LOGGER.exception("analysis_jobs DB list failed — falling back to in-memory rows")
    with _lock:
        return [dict(j) for j in _jobs.values()]


def _parse_dt(val) -> datetime:
    if isinstance(val, str) and val.strip():
        try:
            return datetime.fromisoformat(val.replace("Z", "+00:00"))
        except Exception:
            return datetime.now(timezone.utc)
    elif isinstance(val, datetime):
        return val
    return datetime.now(timezone.utc)


async def _persist_upsert(job: dict) -> None:
    if not db.is_available():
        return
    try:
        engine = db.get_engine()
        async with engine.begin() as conn:
            await conn.execute(
                text(
                    "INSERT INTO analysis_jobs "
                    "(analysis_id, user_email, original_filename, file_size_bytes, mime_type, file_type, "
                    "status, stage, dynamic_status, error, created_at, updated_at) "
                    "VALUES (:analysis_id, :user_email, :original_filename, :file_size_bytes, :mime_type, "
                    ":file_type, :status, :stage, :dynamic_status, :error, :created_at, :updated_at) "
                    "ON CONFLICT (analysis_id) DO UPDATE SET "
                    "user_email = EXCLUDED.user_email, original_filename = EXCLUDED.original_filename, "
                    "file_size_bytes = EXCLUDED.file_size_bytes, mime_type = EXCLUDED.mime_type, "
                    "file_type = EXCLUDED.file_type, status = EXCLUDED.status, stage = EXCLUDED.stage, "
                    "dynamic_status = EXCLUDED.dynamic_status, error = EXCLUDED.error, "
                    "updated_at = EXCLUDED.updated_at"
                ),
                {
                    "analysis_id": str(job.get("analysis_id")),
                    "user_email": job.get("user_email"),
                    "original_filename": job.get("original_filename"),
                    "file_size_bytes": job.get("file_size_bytes"),
                    "mime_type": job.get("mime_type"),
                    "file_type": job.get("file_type"),
                    "status": job.get("status"),
                    "stage": job.get("stage"),
                    "dynamic_status": job.get("dynamic_status"),
                    "error": job.get("error"),
                    "created_at": _parse_dt(job.get("created_at")),
                    "updated_at": _parse_dt(job.get("updated_at")),
                },
            )
    except Exception:
        _LOGGER.exception("analysis_jobs DB write failed for %s — falling back to memory", job.get("analysis_id"))