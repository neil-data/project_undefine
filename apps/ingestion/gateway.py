"""
ingestion/gateway.py — Ingestion Gateway (Layer 1 of the architecture).

Responsibilities, per the architecture diagram:
  1. Accept an uploaded sample
  2. Hash it on intake (SHA-256) — this becomes the sample_id used
     throughout the entire pipeline
  3. Dedup check — if this hash was already submitted, don't
     re-queue it, return the existing case reference instead
  4. Run India-scam pre-triage (fast heuristic, see
     india_scam_triage.py) to help order the isolation queue
  5. Push the job onto the isolation queue (Redis) for the
     Isolation Controller to pick up

This is intentionally a separate, small FastAPI app from
backend/app/main.py — matches the architecture diagram's "Ingestion
Gateway" being its own box, decoupled from the case-serving API.
In a real deployment these could be separate containers; for the
hackathon demo they can run on different ports on the same box.

Run with:
    uvicorn ingestion.gateway:app --port 8001
"""

import hashlib
import json
import logging
import os
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from fastapi import FastAPI, UploadFile, File, Form, HTTPException
from pydantic import BaseModel

from ingestion.india_scam_triage import triage_sample
from ingestion.validation import (
    FileTooLargeError,
    ValidationError,
    ValidationResult,
    max_sample_bytes,
    validate_sample,
)

_LOGGER = logging.getLogger(__name__)

try:
    import redis
except ImportError:
    redis = None


app = FastAPI(title="SentinelScan Ingestion Gateway")

QUEUE_KEY = "isolation_queue"
SEEN_HASHES_KEY = "seen_sample_hashes"

# Where uploaded sample bytes are persisted, keyed by sha256 — the backend's
# ingestion_worker.py consumer reads from here. Previously this gateway only
# hashed the upload and discarded the bytes, so nothing downstream could ever
# actually analyze a queued sample; SAMPLES_DIR is the fix for that gap.
# Mirrors README's existing gitignore rule for real malware samples.
SAMPLES_DIR = Path(os.environ.get("INGESTION_SAMPLES_DIR", "ingestion_samples"))

_redis_client = None


class _InMemoryQueueFallback:
    """Minimal Redis-like fallback (list + set operations only) for dev without Redis."""
    _singleton = None

    def __init__(self):
        self._queue: list[str] = []
        self._seen: set[str] = set()

    @classmethod
    def instance(cls):
        if cls._singleton is None:
            cls._singleton = cls()
        return cls._singleton

    def sismember(self, key, value):
        return value in self._seen

    def sadd(self, key, value):
        self._seen.add(value)

    def rpush(self, key, value):
        self._queue.append(value)

    def lpush(self, key, value):
        self._queue.insert(0, value)

    def llen(self, key):
        return len(self._queue)


def get_redis():
    """
    Lazy Redis connection. If REDIS_URL isn't set or redis isn't
    installed, falls back to an in-memory store so this is still
    runnable/demoable without Redis up — but a restart loses queue
    state in that fallback mode (fine for dev, not for the real
    isolation controller integration).
    """
    global _redis_client
    if _redis_client is not None:
        return _redis_client

    redis_url = os.environ.get("REDIS_URL")
    if redis and redis_url:
        _redis_client = redis.from_url(redis_url, decode_responses=True)
        try:
            _redis_client.ping()
            return _redis_client
        except Exception:
            _redis_client = None  # fall through to in-memory fallback

    return _InMemoryQueueFallback.instance()


class IngestResponse(BaseModel):
    sample_id: str
    is_duplicate: bool
    triage_flagged: bool
    triage_category: Optional[str] = None
    triage_confidence: float = 0.0
    queue_priority: str = "normal"
    submitted_at: str
    sample_path: Optional[str] = None

    # Populated by ingestion/validation.py. file_format/platform come from the
    # sample's magic header, not its filename or declared Content-Type, so the
    # rest of the pipeline can trust them. extension_mismatch is investigative
    # signal (a PE named "invoice.pdf"), not a rejection — see validate_sample().
    file_format: str
    platform: str
    mime_type: str
    file_size_bytes: int
    extension_mismatch: bool = False


# 1 MiB — large enough that per-chunk overhead is negligible on a 256 MiB
# sample, small enough that an oversized upload is aborted almost immediately
# instead of after buffering the whole body.
_UPLOAD_CHUNK_BYTES = 1024 * 1024


async def _buffer_upload(file: UploadFile, limit: int) -> Path:
    """
    Stream the upload to a temporary file, aborting as soon as it exceeds `limit`.

    Replaces a bare `await file.read()`, which read the entire body into memory
    before anything could reject it — an unauthenticated caller could force the
    gateway to allocate an arbitrary amount of RAM. Streaming with a running
    total means an oversized upload is refused after one chunk over the line,
    never fully buffered.

    The temp file is created inside SAMPLES_DIR's parent so that promoting a
    validated sample to its final path is a same-filesystem rename rather than
    a second full copy.
    """
    SAMPLES_DIR.mkdir(parents=True, exist_ok=True)
    handle, temp_name = tempfile.mkstemp(dir=SAMPLES_DIR, prefix=".upload-", suffix=".part")
    temp_path = Path(temp_name)

    total = 0
    try:
        with os.fdopen(handle, "wb") as buffered:
            while True:
                chunk = await file.read(_UPLOAD_CHUNK_BYTES)
                if not chunk:
                    break
                total += len(chunk)
                if total > limit:
                    raise FileTooLargeError(
                        f"Upload exceeds the {limit}-byte limit. Raise "
                        "INGESTION_MAX_SAMPLE_BYTES if a larger sample must be accepted."
                    )
                buffered.write(chunk)
    except BaseException:
        temp_path.unlink(missing_ok=True)
        raise

    return temp_path


@app.post("/ingest", response_model=IngestResponse)
async def ingest_sample(
    file: UploadFile = File(...),
    package_name: Optional[str] = Form(None),
    app_label: Optional[str] = Form(None),
    permissions: Optional[str] = Form(None),  # comma-separated, cheap to pass at intake
):
    """
    Accepts a file upload plus optional cheap metadata (package name,
    app label, permissions) if the caller already has it — e.g. an
    APK's manifest can often be read without full unpacking. If not
    provided, triage is skipped (not every file type has this
    metadata available at intake time — Windows PE samples, for
    instance, won't).

    The upload is streamed to a temporary file and validated (size bounds +
    magic-header format detection, see ingestion/validation.py) *before* it is
    hashed, persisted to SAMPLES_DIR, or queued. A rejected sample therefore
    consumes no permanent disk and no queue slot, and never reaches the
    analysis pipeline. Rejections surface as 400 (empty/truncated), 413
    (too large), or 415 (unsupported format).
    """
    # _buffer_upload aborts mid-stream with FileTooLargeError, so this except
    # covers both the size cap and every validate_sample() rejection.
    try:
        temp_path = await _buffer_upload(file, max_sample_bytes())
    except ValidationError as error:
        _LOGGER.info("Rejected upload %r at intake: %s (%s)", file.filename, error.code, error.message)
        raise HTTPException(status_code=error.status_code, detail=error.as_detail())

    try:
        validation = validate_sample(
            temp_path,
            declared_filename=file.filename,
            declared_content_type=file.content_type,
        )
    except ValidationError as error:
        temp_path.unlink(missing_ok=True)
        _LOGGER.info(
            "Rejected upload %r at intake: %s (%s)",
            file.filename, error.code, error.message,
        )
        raise HTTPException(status_code=error.status_code, detail=error.as_detail())

    try:
        return await _accept_validated_sample(
            temp_path, validation, file.filename, package_name, app_label, permissions
        )
    finally:
        # No-op once the sample has been promoted via rename; matters when the
        # upload was a duplicate (nothing promoted) or an error interrupted us.
        temp_path.unlink(missing_ok=True)


def _sha256_of_file(path: Path) -> str:
    """SHA-256 of a file on disk, read in bounded chunks."""
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(_UPLOAD_CHUNK_BYTES), b""):
            digest.update(chunk)
    return digest.hexdigest()


async def _accept_validated_sample(
    temp_path: Path,
    validation: ValidationResult,
    filename: Optional[str],
    package_name: Optional[str],
    app_label: Optional[str],
    permissions: Optional[str],
) -> IngestResponse:
    """Hash, dedup, persist, and queue a sample that has already passed validation."""
    sha256 = _sha256_of_file(temp_path)

    r = get_redis()
    is_duplicate = bool(r.sismember(SEEN_HASHES_KEY, sha256))

    triage_result = None
    if package_name:
        perm_list = [p.strip() for p in permissions.split(",")] if permissions else []
        triage_result = triage_sample(package_name=package_name, app_label=app_label, permissions=perm_list)

    sample_path: Optional[str] = None
    if not is_duplicate:
        r.sadd(SEEN_HASHES_KEY, sha256)

        # Persist the validated bytes, keyed by sha256 — without this, the
        # queued job carries only metadata and nothing downstream can ever
        # analyze the sample it describes. The extension comes from the
        # *detected* format, not the client-supplied filename, so a mislabelled
        # sample lands on disk under a name that reflects what it actually is.
        sample_file = SAMPLES_DIR / f"{sha256}.{validation.file_format}"
        temp_path.replace(sample_file)
        sample_path = str(sample_file)

        job = {
            "sample_id": sha256,
            "filename": filename,
            "sample_path": sample_path,
            "submitted_at": datetime.now(timezone.utc).isoformat(),
            "validation": {
                "file_format": validation.file_format,
                "platform": validation.platform,
                "mime_type": validation.mime_type,
                "file_size_bytes": validation.size_bytes,
                "extension_mismatch": validation.extension_mismatch,
            },
            "triage": {
                "flagged": triage_result.is_flagged if triage_result else False,
                "category": triage_result.category if triage_result else None,
                "confidence": triage_result.confidence if triage_result else 0.0,
            } if triage_result else None,
        }

        # High-priority (confirmed India-scam pattern) jobs jump the
        # queue instead of going to the back — this is the actual
        # payoff of doing triage at ingestion time.
        if triage_result and triage_result.priority == "high":
            r.lpush(QUEUE_KEY, json.dumps(job))
        else:
            r.rpush(QUEUE_KEY, json.dumps(job))

    return IngestResponse(
        sample_id=sha256,
        is_duplicate=is_duplicate,
        triage_flagged=triage_result.is_flagged if triage_result else False,
        triage_category=triage_result.category if triage_result else None,
        triage_confidence=triage_result.confidence if triage_result else 0.0,
        queue_priority=triage_result.priority if triage_result else "normal",
        submitted_at=datetime.now(timezone.utc).isoformat(),
        sample_path=sample_path,
        file_format=validation.file_format,
        platform=validation.platform,
        mime_type=validation.mime_type,
        file_size_bytes=validation.size_bytes,
        extension_mismatch=validation.extension_mismatch,
    )


@app.get("/queue/length")
def queue_length():
    """Debug endpoint — lets you check the isolation queue depth during dev."""
    r = get_redis()
    if isinstance(r, _InMemoryQueueFallback):
        return {"queue_length": len(r._queue), "backend": "in-memory-fallback"}
    return {"queue_length": r.llen(QUEUE_KEY), "backend": "redis"}