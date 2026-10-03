"""
ingestion/test_pipeline_e2e.py — End-to-end tests for the upload pipeline.

Covers the full path the architecture diagram's Layer 1 describes:

    POST /ingest  ->  validate  ->  hash  ->  store sample  ->  push to queue
                                                                     |
                                          backend ingestion_worker <-+
                                                (consumer pick-up)

Nothing is mocked between the HTTP request and the consumer picking the job
back up: the gateway really parses the multipart body, really validates and
hashes the bytes, really writes the sample to SAMPLES_DIR, and really pushes a
JSON job onto the isolation queue, which the real _process_job() then decodes
and resolves back to that file on disk.

The one substitution is at the far boundary: backend.app.analysis is stubbed so
the pipeline test does not drag in the static-analysis engine and the LangGraph
agent graph. That is the correct seam — the scope here is *hand-off to the
consumer*, and it lets the test assert exactly which path the consumer resolved.
The analysis engine has its own suite under static-analysis/tests/.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import sys
import types

import pytest
from fastapi.testclient import TestClient

from ingestion import gateway
from ingestion.conftest import build_apk, build_elf, build_pe


# ---------------------------------------------------------------------------
# Test doubles
# ---------------------------------------------------------------------------

class _AnalysisRecorder:
    """Stands in for analyze_and_save(), recording how the consumer called it."""

    def __init__(self):
        self.calls: list[dict] = []
        self.raise_unsupported = False

    async def __call__(self, sample_path, event_type="static_analysis_complete", extra_meta=None, **kwargs):
        self.calls.append({"sample_path": str(sample_path), "event_type": event_type, "extra_meta": extra_meta})
        if self.raise_unsupported:
            raise _StubUnsupportedFormatError("stubbed unsupported format")
        return {
            "sample_id": hashlib.sha256(str(sample_path).encode()).hexdigest(),
            "risk_score": 42,
        }

    @property
    def paths(self) -> list[str]:
        return [call["sample_path"] for call in self.calls]


class _StubUnsupportedFormatError(ValueError):
    """Mirrors backend.app.analysis.UnsupportedFormatError for the stub module."""


class FakeAsyncRedis:
    """
    Minimal async stand-in for redis.asyncio, implementing only BLPOP.

    The consumer's contract with Redis is exactly one call, so faking it keeps
    the end-to-end test runnable without `docker-compose up -d redis` while
    still driving the real _consume_loop().
    """

    def __init__(self, items: list[str] | None = None):
        self.items = list(items or [])
        self.blpop_calls = 0

    async def blpop(self, key, timeout=None):
        self.blpop_calls += 1
        if not self.items:
            await asyncio.sleep(0)  # yield so cancellation can land
            return None
        return (key, self.items.pop(0))


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def worker(monkeypatch):
    """
    Import backend.app.ingestion_worker against a stubbed analysis module.

    ingestion_worker imports analyze_and_save at module scope, which transitively
    imports the static-analysis engine and compiles the LangGraph graph. Stubbing
    that import keeps this test hermetic and fast, and gives us a recorder to
    assert against.
    """
    recorder = _AnalysisRecorder()

    stub = types.ModuleType("backend.app.analysis")
    stub.analyze_and_save = recorder
    stub.UnsupportedFormatError = _StubUnsupportedFormatError
    monkeypatch.setitem(sys.modules, "backend.app.analysis", stub)

    # Drop any previously imported copy so the stub is picked up on this import.
    monkeypatch.delitem(sys.modules, "backend.app.ingestion_worker", raising=False)

    import backend.app.ingestion_worker as ingestion_worker

    return ingestion_worker, recorder


@pytest.fixture
def client(tmp_path, monkeypatch):
    """Gateway with per-test SAMPLES_DIR, Redis client, and queue-singleton state."""
    monkeypatch.delenv("REDIS_URL", raising=False)
    monkeypatch.delenv("INGESTION_MAX_SAMPLE_BYTES", raising=False)
    monkeypatch.setattr(gateway, "SAMPLES_DIR", tmp_path / "samples")
    monkeypatch.setattr(gateway, "_redis_client", None)
    monkeypatch.setattr(gateway._InMemoryQueueFallback, "_singleton", None)

    with TestClient(gateway.app) as test_client:
        yield test_client


def raw_queue() -> list[str]:
    """The JSON job strings sitting on the isolation queue, front first."""
    return list(gateway.get_redis()._queue)


def upload(client, data: bytes, filename: str, **form):
    return client.post(
        "/ingest",
        files={"file": (filename, data, "application/octet-stream")},
        data=form,
    )


# ---------------------------------------------------------------------------
# End-to-end
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
class TestUploadToConsumerPickup:
    async def test_sample_uploaded_via_api_is_resolved_by_the_consumer(self, client, worker):
        """The complete happy path: bytes in at the API, same bytes out at the consumer."""
        ingestion_worker, recorder = worker
        payload = build_pe()

        response = upload(client, payload, "tool.exe")
        assert response.status_code == 200

        jobs = raw_queue()
        assert len(jobs) == 1

        await ingestion_worker._process_job(jobs[0])

        assert len(recorder.calls) == 1
        resolved = recorder.paths[0]
        assert resolved == response.json()["sample_path"]

        # The consumer resolved a path that really holds the uploaded bytes —
        # this is the link that was broken before the gateway persisted samples.
        from pathlib import Path
        assert Path(resolved).read_bytes() == payload

    async def test_sample_id_is_the_same_sha256_at_every_stage(self, client, worker):
        """
        sample_id is the case identifier for the whole platform, so the API
        response, the queued job, and the bytes on disk must all agree.
        """
        ingestion_worker, _ = worker
        payload = build_apk()
        expected = hashlib.sha256(payload).hexdigest()

        body = upload(client, payload, "app.apk").json()
        job = json.loads(raw_queue()[0])

        from pathlib import Path
        stored = Path(body["sample_path"])

        assert body["sample_id"] == expected
        assert job["sample_id"] == expected
        assert hashlib.sha256(stored.read_bytes()).hexdigest() == expected

    async def test_consumer_tags_queue_sourced_work_distinctly(self, client, worker):
        """
        Queue-sourced analyses are recorded with their own event type so the
        chain-of-custody log distinguishes them from direct API uploads.
        """
        ingestion_worker, recorder = worker
        upload(client, build_elf(), "binary.elf")

        await ingestion_worker._process_job(raw_queue()[0])

        assert recorder.calls[0]["event_type"] == "ingested_via_queue"

    async def test_validation_metadata_survives_the_queue_hop(self, client, worker):
        """The consumer receives the format the gateway detected, not a re-guess."""
        upload(client, build_pe(), "invoice.pdf")

        job = json.loads(raw_queue()[0])
        assert job["validation"]["file_format"] == "exe"
        assert job["validation"]["platform"] == "windows"
        assert job["validation"]["extension_mismatch"] is True


@pytest.mark.asyncio
class TestConsumerLoop:
    async def test_consume_loop_drains_jobs_produced_by_the_gateway(self, client, worker):
        """Drives the real BLPOP loop against real gateway output."""
        ingestion_worker, recorder = worker
        upload(client, build_pe(), "tool.exe")
        upload(client, build_elf(), "binary.elf")

        fake_redis = FakeAsyncRedis(raw_queue())
        task = asyncio.create_task(ingestion_worker._consume_loop(fake_redis))

        for _ in range(200):
            if len(recorder.calls) == 2:
                break
            await asyncio.sleep(0.01)

        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task

        assert len(recorder.calls) == 2

    async def test_high_priority_sample_is_consumed_first(self, client, worker):
        """
        A triage-flagged loan-app scam was LPUSHed to the front, so the consumer
        must reach it before the sample uploaded ahead of it.
        """
        ingestion_worker, recorder = worker

        upload(client, build_pe(), "ordinary.exe")
        scam = upload(
            client,
            build_apk(),
            "loan.apk",
            package_name="com.quickloan.easyapp",
            permissions="android.permission.READ_SMS,android.permission.SYSTEM_ALERT_WINDOW",
        ).json()

        for job in raw_queue():
            await ingestion_worker._process_job(job)

        assert recorder.paths[0] == scam["sample_path"]


@pytest.mark.asyncio
class TestPipelineResilience:
    async def test_rejected_upload_never_reaches_the_consumer(self, client, worker):
        """
        Validation is the gate: an unsupported file must produce no queue entry,
        so the consumer is never handed work it cannot do.
        """
        ingestion_worker, recorder = worker

        assert upload(client, b"plain notes\n" * 64, "notes.txt").status_code == 415
        assert raw_queue() == []

        fake_redis = FakeAsyncRedis([])
        task = asyncio.create_task(ingestion_worker._consume_loop(fake_redis))
        await asyncio.sleep(0.05)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task

        assert recorder.calls == []

    async def test_job_whose_sample_file_vanished_is_dropped_not_crashed(self, client, worker):
        """
        Samples are gitignored and the volume can be cleared independently of
        Redis, so a job can outlive its file. That must not kill the consumer.
        """
        ingestion_worker, recorder = worker
        body = upload(client, build_pe(), "tool.exe").json()

        from pathlib import Path
        Path(body["sample_path"]).unlink()

        await ingestion_worker._process_job(raw_queue()[0])

        assert recorder.calls == []

    async def test_malformed_job_json_is_dropped_not_crashed(self, worker):
        ingestion_worker, recorder = worker

        await ingestion_worker._process_job("{not valid json")

        assert recorder.calls == []

    async def test_unsupported_format_from_analysis_does_not_kill_the_consumer(self, client, worker):
        """
        The gateway and the engine disagree on edge cases (the gateway reads
        headers, the engine fully parses). When the engine refuses a sample the
        gateway let through, the consumer must log and move on.
        """
        ingestion_worker, recorder = worker
        recorder.raise_unsupported = True

        upload(client, build_pe(), "first.exe")
        upload(client, build_elf(), "second.elf")

        for job in raw_queue():
            await ingestion_worker._process_job(job)

        assert len(recorder.calls) == 2  # second job still processed after the first raised
