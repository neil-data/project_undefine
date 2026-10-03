"""
test_phase6_regression.py — Mandatory regression tests for Phase 6 (Category C findings).
Written BEFORE fixing production code to establish baseline failures.
"""

import asyncio
import json
import sys
from pathlib import Path
import pytest
from unittest.mock import patch, AsyncMock, MagicMock
from fastapi.testclient import TestClient

sandbox_host_dir = Path(__file__).resolve().parent.parent.parent / "sandbox-host"
if str(sandbox_host_dir) not in sys.path:
    sys.path.insert(0, str(sandbox_host_dir))

from app.main import app
from app import config as sandbox_config
from app.runner import SandboxRunner
try:
    from app.runner import WorkerPool, WorkerState
except ImportError:
    WorkerPool = None
    WorkerState = None


# ─────────────────────────────────────────────────────────────────────────────
# C1: Worker Pool, Concurrency & Lifecycle
# ─────────────────────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_c1_worker_pool_concurrency_and_lifecycle():
    """Verify WorkerPool manages concurrent workers, tracking states (idle -> busy -> recovering -> idle)."""
    assert WorkerPool is not None, "WorkerPool must be implemented in sandbox-host/app/runner.py"
    pool = WorkerPool(max_workers=2)
    assert pool.total_workers == 2
    assert pool.available_workers == 2

    # Acquire worker for job 1
    w1 = await pool.acquire_worker("11111111-1111-1111-1111-111111111111")
    assert w1 is not None
    assert w1.state == WorkerState.BUSY
    assert pool.available_workers == 1

    # Acquire worker for job 2
    w2 = await pool.acquire_worker("22222222-2222-2222-2222-222222222222")
    assert w2 is not None
    assert w2.state == WorkerState.BUSY
    assert pool.available_workers == 0

    # Acquire when pool exhausted should return None (caller emits 429/409)
    w3 = await pool.acquire_worker("33333333-3333-3333-3333-333333333333")
    assert w3 is None

    # Release worker 1 -> transitions through recovering to idle
    await pool.release_worker(w1.worker_id)
    assert w1.state == WorkerState.IDLE
    assert pool.available_workers == 1


def test_c1_sandbox_host_health_reports_worker_pool_metrics():
    """Verify sandbox host /health endpoint reports worker pool capacity, active jobs, and available workers."""
    client = TestClient(app)
    resp = client.get("/health")
    assert resp.status_code == 200
    data = resp.json()
    assert "total_workers" in data, f"/health missing total_workers: {data}"
    assert "available_workers" in data, f"/health missing available_workers: {data}"
    assert "active_jobs" in data, f"/health missing active_jobs: {data}"


# ─────────────────────────────────────────────────────────────────────────────
# C2: Incomplete Execution Semantics & Artifact Validation
# ─────────────────────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_c2_incomplete_status_when_critical_artifacts_missing_in_runner(tmp_path):
    """Verify SandboxRunner marks job status as 'incomplete' when strace.log is missing or empty."""
    runner = SandboxRunner(artifacts_dir=tmp_path)
    sample_file = tmp_path / "sample.bin"
    sample_file.write_bytes(b"\x7fELFfake")

    # Patch create_subprocess_exec to exit 0 but produce no strace file
    async def mock_exec(*args, **kwargs):
        mock_proc = AsyncMock()
        mock_proc.communicate = AsyncMock(return_value=(b"", b""))
        mock_proc.returncode = 0
        return mock_proc

    with patch("sys.platform", "linux"), \
         patch("shutil.which", return_value="/usr/bin/strace"), \
         patch("asyncio.create_subprocess_exec", side_effect=mock_exec), \
         patch("app.runner.check_canary_isolation", return_value=(True, "isolated")):
        res = await runner.run(
            job_id="aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
            sample_path=sample_file,
            raw_arch="x86_64",
            timeout_seconds=5,
        )
        assert res["status"] == "incomplete", f"Expected status 'incomplete' when strace.log is missing, got {res['status']}"


@pytest.mark.asyncio
async def test_c2_backend_propagates_incomplete_on_artifact_download_failure(tmp_path):
    """Verify backend client sets status='incomplete' when strace.log fails to download (non-200)."""
    from backend.app.sandbox import run_dynamic_analysis
    from app.runner import sign_manifest

    sample = tmp_path / "test.elf"
    sample.write_bytes(b"\x7fELFdummy")

    import hashlib
    job_id = "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"
    meta_json = json.dumps({"sample_sha256": "3cb40ff8d1e34e56eb600beff68e9be5b9bc56934c9c1b446c1e30ee8e6141c2", "status": "completed"})
    manifest_core = {
        "strace.log": "dummyhash",
        "capture.pcap": "dummyhash2",
        "fs_diff.json": "dummyhash3",
        "meta.json": hashlib.sha256(meta_json.encode("utf-8")).hexdigest(),
    }
    manifest = dict(manifest_core)
    manifest["_hmac"] = sign_manifest(manifest_core, secret="testtoken")

    # Async mock responses
    async def mock_post(url, *args, **kwargs):
        m = MagicMock()
        m.status_code = 201
        m.json.return_value = {"job_id": job_id, "status": "completed"}
        return m

    async def mock_get(url, *args, **kwargs):
        m = MagicMock()
        if url.rstrip("/").endswith(f"/jobs/{job_id}"):
            m.status_code = 200
            m.json.return_value = {"job_id": job_id, "status": "completed"}
        elif "manifest.json" in url:
            m.status_code = 200
            m.json.return_value = manifest
        elif "meta.json" in url:
            m.status_code = 200
            m.content = meta_json.encode("utf-8")
            m.json.return_value = {"sample_sha256": "3cb40ff8d1e34e56eb600beff68e9be5b9bc56934c9c1b446c1e30ee8e6141c2", "status": "completed"}
        elif "strace.log" in url:
            m.status_code = 404  # Failed download!
            m.content = b""
        else:
            m.status_code = 200
            m.content = b""
        return m

    with patch.dict("os.environ", {"SANDBOX_API_URL": "http://mock-sandbox:8000", "SANDBOX_API_TOKEN": "testtoken"}), \
         patch("httpx.AsyncClient.post", side_effect=mock_post), \
         patch("httpx.AsyncClient.get", side_effect=mock_get), \
         patch("backend.app.sandbox.compute_file_sha256", return_value="3cb40ff8d1e34e56eb600beff68e9be5b9bc56934c9c1b446c1e30ee8e6141c2"):
        res = await run_dynamic_analysis(sample)
        assert res.dynamic_status == "incomplete", f"Expected dynamic_status 'incomplete', got {res.dynamic_status}"
        assert "incomplete" in res.failure_reason.lower() or "missing" in res.failure_reason.lower()


# ─────────────────────────────────────────────────────────────────────────────
# C3: Automatic Cleanup & Resource Leak Prevention
# ─────────────────────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_c3_backend_cleans_up_job_on_sandbox_host(tmp_path):
    """Verify backend issues DELETE /jobs/{job_id} after downloading artifacts or on terminal status."""
    from backend.app.sandbox import run_dynamic_analysis
    from app.runner import sign_manifest

    sample = tmp_path / "test.elf"
    sample.write_bytes(b"\x7fELFdummy")
    import hashlib
    job_id = "cccccccc-cccc-cccc-cccc-cccccccccccc"
    meta_json = json.dumps({"sample_sha256": "dummy_sha", "status": "completed"})
    strace_bytes = b"1000 00:00:00.000000 exit_group(0) = ?\n"
    pcap_bytes = b""
    fs_diff_bytes = b"{}"
    manifest_core = {
        "meta.json": hashlib.sha256(meta_json.encode("utf-8")).hexdigest(),
        "strace.log": hashlib.sha256(strace_bytes).hexdigest(),
        "capture.pcap": hashlib.sha256(pcap_bytes).hexdigest(),
        "fs_diff.json": hashlib.sha256(fs_diff_bytes).hexdigest(),
    }
    manifest = dict(manifest_core)
    manifest["_hmac"] = sign_manifest(manifest_core, secret="testtoken")

    delete_called = False

    async def mock_post(url, *args, **kwargs):
        m = MagicMock()
        m.status_code = 201
        m.json.return_value = {"job_id": job_id, "status": "completed"}
        return m

    async def mock_get(url, *args, **kwargs):
        m = MagicMock()
        if url.rstrip("/").endswith(f"/jobs/{job_id}"):
            m.status_code = 200
            m.json.return_value = {"job_id": job_id, "status": "completed"}
        elif "manifest.json" in url:
            m.status_code = 200
            m.json.return_value = manifest
        elif "meta.json" in url:
            m.status_code = 200
            m.content = meta_json.encode("utf-8")
            m.json.return_value = {"sample_sha256": "dummy_sha", "status": "completed"}
        elif "strace.log" in url:
            m.status_code = 200
            m.content = strace_bytes
        elif "capture.pcap" in url:
            m.status_code = 200
            m.content = pcap_bytes
        elif "fs_diff.json" in url:
            m.status_code = 200
            m.content = fs_diff_bytes
        else:
            m.status_code = 200
            m.content = b""
        return m

    async def mock_delete(url, *args, **kwargs):
        nonlocal delete_called
        if f"/jobs/{job_id}" in url:
            delete_called = True
        m = MagicMock()
        m.status_code = 200
        m.json.return_value = {"job_id": job_id, "deleted": True}
        return m

    with patch.dict("os.environ", {"SANDBOX_API_URL": "http://mock-sandbox:8000", "SANDBOX_API_TOKEN": "testtoken"}), \
         patch("httpx.AsyncClient.post", side_effect=mock_post), \
         patch("httpx.AsyncClient.get", side_effect=mock_get), \
         patch("httpx.AsyncClient.delete", side_effect=mock_delete), \
         patch("backend.app.sandbox.compute_file_sha256", return_value="dummy_sha"):
        await run_dynamic_analysis(sample)
        assert delete_called, "Backend should issue DELETE /jobs/{job_id} to clean up sandbox host artifacts after analysis"


# ─────────────────────────────────────────────────────────────────────────────
# C4: Artifact Size Ceiling & DoS Protection
# ─────────────────────────────────────────────────────────────────────────────

def test_c4_artifact_size_limit_and_truncation(tmp_path):
    """Verify runner defines and enforces MAX_ARTIFACT_SIZE_BYTES to prevent disk exhaustion."""
    try:
        from app.runner import MAX_ARTIFACT_SIZE_BYTES, truncate_artifact_if_oversized
    except ImportError:
        MAX_ARTIFACT_SIZE_BYTES = None
        truncate_artifact_if_oversized = None

    assert MAX_ARTIFACT_SIZE_BYTES is not None, "MAX_ARTIFACT_SIZE_BYTES must be defined in runner"
    assert truncate_artifact_if_oversized is not None, "truncate_artifact_if_oversized helper must be defined"

    test_file = tmp_path / "oversized.log"
    # Write slightly more than max (mocking smaller max for test)
    test_file.write_bytes(b"A" * 1024)
    was_truncated = truncate_artifact_if_oversized(test_file, max_bytes=512)
    assert was_truncated is True
    assert test_file.stat().st_size <= 600  # Truncated plus small warning header
    assert b"[TRUNCATED]" in test_file.read_bytes()


# ─────────────────────────────────────────────────────────────────────────────
# C5: Production Docker Deployment Configuration
# ─────────────────────────────────────────────────────────────────────────────

def test_c5_production_docker_and_compose_configuration():
    """Verify sandbox-host/Dockerfile exists and docker-compose.yml declares sandbox-host service."""
    base_dir = Path(__file__).resolve().parent.parent.parent
    dockerfile = base_dir / "sandbox-host" / "Dockerfile"
    compose_file = base_dir / "docker-compose.yml"

    assert dockerfile.is_file(), "sandbox-host/Dockerfile must exist for production container deployment"
    content = dockerfile.read_text(encoding="utf-8")
    assert "FROM" in content
    assert "sandbox-runner" in content or "useradd" in content or "USER" in content, "Dockerfile must configure non-root runner user"

    assert compose_file.is_file(), "docker-compose.yml must exist"
    compose_text = compose_file.read_text(encoding="utf-8")
    assert "sandbox-host:" in compose_text, "docker-compose.yml must define sandbox-host service"
    assert "SANDBOX_API_TOKEN" in compose_text, "docker-compose.yml must configure SANDBOX_API_TOKEN"
