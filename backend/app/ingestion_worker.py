"""
backend/app/ingestion_worker.py — Background consumer for the ingestion
gateway's Redis queue.

ingestion/gateway.py hashes an upload, saves its bytes, and pushes a job
onto the "isolation_queue" Redis list — but nothing ever consumed that
queue before this module existed, so a sample submitted through the
gateway just sat there forever. This starts an asyncio background task on
FastAPI startup that BLPOPs jobs and runs them through the same
analyze_and_save() pipeline POST /api/cases/upload uses, so the ingestion
path and the direct-upload path produce identical results.

Gracefully does nothing if REDIS_URL/the redis package aren't available —
the direct /api/cases/upload path keeps working regardless, same
degrade-don't-crash pattern used throughout this codebase.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
from pathlib import Path
from typing import Optional

from .analysis import analyze_and_save, UnsupportedFormatError

try:
    import redis.asyncio as redis_asyncio
    from redis.exceptions import TimeoutError as RedisTimeoutError
except ImportError:
    redis_asyncio = None
    RedisTimeoutError = None

_LOGGER = logging.getLogger(__name__)

QUEUE_KEY = "isolation_queue"
_POLL_TIMEOUT_SECONDS = 5  # BLPOP timeout — lets the loop notice cancellation between jobs

_task: Optional[asyncio.Task] = None
_redis_client = None


async def start_ingestion_worker() -> None:
    global _task, _redis_client

    if redis_asyncio is None:
        _LOGGER.warning("redis package not installed — ingestion queue consumer disabled")
        return

    redis_url = os.environ.get("REDIS_URL")
    if not redis_url:
        _LOGGER.info("REDIS_URL not set — ingestion queue consumer disabled (direct /api/cases/upload still works)")
        return

    try:
        # socket_timeout set higher than _POLL_TIMEOUT_SECONDS so BLPOP's server-side
        # timeout returns None before socket read timeout fires.
        client = redis_asyncio.from_url(
            redis_url,
            decode_responses=True,
            socket_timeout=_POLL_TIMEOUT_SECONDS + 5,
            socket_connect_timeout=5,
        )
        await client.ping()
    except Exception as error:
        _LOGGER.warning(
            "Redis unavailable (%s: %s) — ingestion queue consumer disabled. "
            "Run `docker-compose up -d redis` to enable it.",
            type(error).__name__, error,
        )
        return

    _redis_client = client
    _task = asyncio.create_task(_consume_loop(client), name="ingestion-worker")
    _LOGGER.info("Ingestion queue consumer started, polling '%s'", QUEUE_KEY)


async def stop_ingestion_worker() -> None:
    global _task, _redis_client

    if _task is not None:
        _task.cancel()
        try:
            await _task
        except asyncio.CancelledError:
            pass
        _task = None

    if _redis_client is not None:
        closer = getattr(_redis_client, "aclose", None) or _redis_client.close
        await closer()
        _redis_client = None


async def _consume_loop(client) -> None:
    while True:
        try:
            popped = await client.blpop(QUEUE_KEY, timeout=_POLL_TIMEOUT_SECONDS)
        except asyncio.CancelledError:
            raise
        except (asyncio.TimeoutError, TimeoutError) if RedisTimeoutError is None else (asyncio.TimeoutError, TimeoutError, RedisTimeoutError):
            popped = None
        except Exception:
            _LOGGER.exception("Ingestion queue poll failed — retrying in %ss", _POLL_TIMEOUT_SECONDS)
            await asyncio.sleep(_POLL_TIMEOUT_SECONDS)
            continue

        if popped is None:
            continue  # BLPOP timed out with nothing queued — loop back and poll again

        _, raw_job = popped
        await _process_job(raw_job)


async def _process_job(raw_job: str) -> None:
    try:
        job = json.loads(raw_job)
    except (TypeError, ValueError):
        _LOGGER.error("Ingestion queue job was not valid JSON, dropping: %r", raw_job[:200])
        return

    sample_id = job.get("sample_id", "unknown")
    sample_path = job.get("sample_path")
    if not sample_path or not Path(sample_path).exists():
        _LOGGER.error(
            "Ingestion job %s has no retrievable sample file (path=%r) — dropping. "
            "This means the file was queued before ingestion/gateway.py started saving sample bytes.",
            sample_id, sample_path,
        )
        return

    try:
        original_filename = job.get("filename") or (Path(sample_path).name if sample_path else None)
        validation_data = job.get("validation") or {}
        mime_type = validation_data.get("mime_type")

        case_data = await analyze_and_save(
            sample_path,
            event_type="ingested_via_queue",
            extra_meta={
                "original_filename": original_filename,
                "mime_type": mime_type,
            },
        )
        
        # Check if dynamic analysis is already present (e.g., from loaded JSON/BSON).
        # Otherwise run dynamic analysis.
        if "dynamic_analysis" not in case_data:
            from . import sandbox
            from .store import save_case
            dynamic = await sandbox.run_dynamic_analysis(
                sample_path,
                platform=case_data.get("platform"),
                file_type=case_data.get("file_type"),
            )
            case_data["dynamic_analysis"] = dynamic.model_dump() if hasattr(dynamic, "model_dump") else dynamic
            case_data["analysis_status"] = "COMPLETED"
            await save_case(case_data["sample_id"], case_data, event_type="dynamic_analysis_checked")

        _LOGGER.info(
            "Ingestion queue processed sample %s -> case %s (risk_score=%s)",
            sample_id, case_data["sample_id"], case_data["risk_score"],
        )
    except UnsupportedFormatError as error:
        _LOGGER.warning("Ingestion job %s: unsupported format — %s", sample_id, error)
    except Exception:
        _LOGGER.exception("Ingestion job %s failed during analysis", sample_id)
