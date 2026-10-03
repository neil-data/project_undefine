"""
ingestion/test_gateway.py — Integration tests for the Ingestion Gateway API.

Exercises POST /ingest and GET /queue/length through a real ASGI stack
(FastAPI TestClient), so multipart parsing, the streaming upload buffer,
validation, hashing, sample persistence, and the Redis push are all covered
end to end within the gateway process. The downstream hand-off to the
backend consumer is covered separately in test_pipeline_e2e.py.

Redis is not required: the gateway already ships an in-memory queue fallback
for dev, and these tests drive that same path, so the suite runs in CI without
`docker-compose up redis`.
"""

from __future__ import annotations

import json

import pytest
from fastapi.testclient import TestClient

from ingestion import gateway
from ingestion.conftest import build_apk, build_elf, build_pe, build_zip_without_manifest


@pytest.fixture
def client(tmp_path, monkeypatch):
    """
    A gateway with isolated per-test state.

    Three globals survive across requests and would otherwise leak between
    tests: the SAMPLES_DIR path, the memoized Redis client, and the
    _InMemoryQueueFallback singleton (which holds both the queue and the
    seen-hashes set that drives dedup).
    """
    monkeypatch.delenv("REDIS_URL", raising=False)
    monkeypatch.delenv("INGESTION_MAX_SAMPLE_BYTES", raising=False)
    monkeypatch.setattr(gateway, "SAMPLES_DIR", tmp_path / "samples")
    monkeypatch.setattr(gateway, "_redis_client", None)
    monkeypatch.setattr(gateway._InMemoryQueueFallback, "_singleton", None)

    with TestClient(gateway.app) as test_client:
        yield test_client


def queued_jobs() -> list[dict]:
    """Decode the in-memory isolation queue into job dicts, front of queue first."""
    return [json.loads(raw) for raw in gateway.get_redis()._queue]


def upload(client, data: bytes, filename: str = "sample.exe", content_type: str = "application/octet-stream", **form):
    return client.post(
        "/ingest",
        files={"file": (filename, data, content_type)},
        data=form,
    )


class TestSuccessfulIngestion:
    def test_accepts_pe_and_returns_sha256_as_sample_id(self, client):
        import hashlib

        payload = build_pe()
        response = upload(client, payload, "tool.exe")

        assert response.status_code == 200
        body = response.json()
        assert body["sample_id"] == hashlib.sha256(payload).hexdigest()
        assert body["is_duplicate"] is False

    def test_response_carries_validation_metadata(self, client):
        body = upload(client, build_apk(), "app.apk").json()

        assert body["file_format"] == "apk"
        assert body["platform"] == "android"
        assert body["mime_type"] == "application/vnd.android.package-archive"
        assert body["file_size_bytes"] > 0
        assert body["extension_mismatch"] is False

    def test_sample_bytes_are_persisted_to_disk(self, client):
        payload = build_elf()
        body = upload(client, payload, "binary.elf").json()

        stored = gateway.SAMPLES_DIR / f"{body['sample_id']}.elf"
        assert stored.exists()
        assert stored.read_bytes() == payload
        assert body["sample_path"] == str(stored)

    def test_stored_filename_uses_detected_format_not_client_extension(self, client):
        """A PE claiming to be a PDF is stored as .exe — disk reflects reality."""
        body = upload(client, build_pe(), "invoice.pdf").json()

        assert body["file_format"] == "exe"
        assert body["sample_path"].endswith(".exe")
        assert (gateway.SAMPLES_DIR / f"{body['sample_id']}.exe").exists()

    def test_extension_mismatch_is_reported_not_rejected(self, client):
        response = upload(client, build_pe(), "invoice.pdf")

        assert response.status_code == 200
        assert response.json()["extension_mismatch"] is True

    def test_no_temporary_upload_files_are_left_behind(self, client):
        upload(client, build_pe(), "tool.exe")
        assert list(gateway.SAMPLES_DIR.glob("*.part")) == []
        assert list(gateway.SAMPLES_DIR.glob(".upload-*")) == []


class TestQueueBehaviour:
    def test_accepted_sample_is_pushed_onto_the_isolation_queue(self, client):
        body = upload(client, build_pe(), "tool.exe").json()

        jobs = queued_jobs()
        assert len(jobs) == 1
        assert jobs[0]["sample_id"] == body["sample_id"]

    def test_job_payload_carries_everything_the_consumer_needs(self, client):
        body = upload(client, build_apk(), "app.apk").json()
        job = queued_jobs()[0]

        assert job["sample_id"] == body["sample_id"]
        assert job["filename"] == "app.apk"
        assert job["sample_path"] == body["sample_path"]
        assert job["submitted_at"]
        assert job["validation"]["file_format"] == "apk"
        assert job["validation"]["platform"] == "android"
        assert job["validation"]["extension_mismatch"] is False

    def test_high_priority_triage_jumps_the_queue(self, client):
        """
        The payoff of triaging at intake: a confirmed India-scam pattern is
        LPUSHed to the front instead of queuing behind unrelated samples.
        """
        upload(client, build_pe(), "ordinary.exe")
        scam = upload(
            client,
            build_apk(),
            "loan.apk",
            package_name="com.quickloan.easyapp",
            permissions="android.permission.READ_SMS,android.permission.SYSTEM_ALERT_WINDOW",
        ).json()

        assert scam["queue_priority"] == "high"
        assert scam["triage_flagged"] is True
        assert scam["triage_category"] == "loan_app_scam"
        assert queued_jobs()[0]["sample_id"] == scam["sample_id"]

    def test_untriaged_sample_goes_to_the_back(self, client):
        first = upload(client, build_pe(), "first.exe").json()
        second = upload(client, build_elf(), "second.elf").json()

        assert [job["sample_id"] for job in queued_jobs()] == [
            first["sample_id"],
            second["sample_id"],
        ]

    def test_queue_length_endpoint_reports_depth_and_backend(self, client):
        upload(client, build_pe(), "tool.exe")
        upload(client, build_elf(), "binary.elf")

        body = client.get("/queue/length").json()
        assert body["queue_length"] == 2
        assert body["backend"] == "in-memory-fallback"


class TestDeduplication:
    def test_resubmitting_the_same_bytes_is_flagged_as_duplicate(self, client):
        payload = build_pe()
        first = upload(client, payload, "tool.exe").json()
        second = upload(client, payload, "tool-copy.exe").json()

        assert first["is_duplicate"] is False
        assert second["is_duplicate"] is True
        assert second["sample_id"] == first["sample_id"]

    def test_duplicate_is_not_queued_a_second_time(self, client):
        payload = build_pe()
        upload(client, payload, "tool.exe")
        upload(client, payload, "tool-copy.exe")

        assert len(queued_jobs()) == 1

    def test_duplicate_still_reports_validation_metadata(self, client):
        """The caller needs the format even when the sample was seen before."""
        payload = build_apk()
        upload(client, payload, "app.apk")
        second = upload(client, payload, "app.apk").json()

        assert second["is_duplicate"] is True
        assert second["file_format"] == "apk"
        assert second["sample_path"] is None

    def test_duplicate_upload_leaves_no_temp_file(self, client):
        payload = build_pe()
        upload(client, payload, "tool.exe")
        upload(client, payload, "tool.exe")

        assert list(gateway.SAMPLES_DIR.glob(".upload-*")) == []


class TestRejection:
    def test_unsupported_format_returns_415(self, client):
        response = upload(client, b"just notes\n" * 64, "notes.txt", "text/plain")

        assert response.status_code == 415
        assert response.json()["detail"]["error"] == "unsupported_format"

    def test_zip_without_manifest_returns_415(self, client):
        response = upload(client, build_zip_without_manifest(), "archive.zip")
        assert response.status_code == 415

    def test_empty_file_returns_400(self, client):
        response = upload(client, b"", "empty.exe")

        assert response.status_code == 400
        assert response.json()["detail"]["error"] == "empty_file"

    def test_truncated_file_returns_400(self, client):
        response = upload(client, b"MZ", "truncated.exe")

        assert response.status_code == 400
        assert response.json()["detail"]["error"] == "file_too_small"

    def test_oversized_upload_returns_413(self, client, monkeypatch):
        monkeypatch.setenv("INGESTION_MAX_SAMPLE_BYTES", "1024")
        response = upload(client, build_pe() + b"\x00" * 4096, "big.exe")

        assert response.status_code == 413
        assert response.json()["detail"]["error"] == "file_too_large"

    def test_missing_file_field_returns_422(self, client):
        """FastAPI's own validation — the endpoint requires a file part."""
        assert client.post("/ingest", data={"package_name": "com.x.y"}).status_code == 422

    @pytest.mark.parametrize(
        "payload, filename",
        [
            (b"just notes\n" * 64, "notes.txt"),
            (b"", "empty.exe"),
            (b"MZ", "truncated.exe"),
        ],
    )
    def test_rejected_sample_is_never_persisted_or_queued(self, client, payload, filename):
        """
        The whole point of validating at the door: a refused upload must cost
        no permanent disk and no queue slot.
        """
        upload(client, payload, filename)

        assert queued_jobs() == []
        stored = list(gateway.SAMPLES_DIR.glob("*")) if gateway.SAMPLES_DIR.exists() else []
        assert stored == []

    def test_rejected_sample_does_not_poison_dedup_state(self, client):
        """
        A rejected upload must not mark its hash as seen — otherwise a later
        valid submission of a repaired file would be silently swallowed as a
        duplicate and never analyzed.
        """
        upload(client, b"MZ", "truncated.exe")
        response = upload(client, build_pe(), "tool.exe")

        assert response.status_code == 200
        assert response.json()["is_duplicate"] is False


class TestPathSafety:
    @pytest.mark.parametrize(
        "hostile_name",
        [
            "../../../../etc/passwd",
            "..\\..\\..\\Windows\\System32\\evil.dll",
            "sample.exe\x00.txt",
            "....//....//escape.exe",
        ],
    )
    def test_hostile_filenames_cannot_escape_the_samples_directory(self, client, hostile_name):
        """
        The stored name is derived entirely from the content hash and the
        detected format, so a traversal sequence in the client-supplied
        filename has nowhere to go.
        """
        response = upload(client, build_pe(), hostile_name)

        assert response.status_code == 200
        written = response.json()["sample_path"]
        assert gateway.SAMPLES_DIR.resolve() == type(gateway.SAMPLES_DIR)(written).resolve().parent

    def test_filename_is_still_recorded_for_the_investigator(self, client):
        """Sanitizing the *storage* path must not discard the original name as evidence."""
        upload(client, build_pe(), "Aadhaar_Update.apk.exe")
        assert queued_jobs()[0]["filename"] == "Aadhaar_Update.apk.exe"
