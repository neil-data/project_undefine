"""
sandbox-host/tests/test_sandbox_host.py — Test suite for decoupled dynamic sandbox host.

Verifies:
1. Bearer token authentication (401 on missing/wrong token)
2. SHA-256 verification of submitted sample
3. Single-runner locking (concurrent execution returns 409)
4. Canary egress check (blocks detonation if canary fails)
5. Unsupported architecture rejection (400)
6. Manifest.json generation and hash verification
"""

import io
import pytest
from fastapi.testclient import TestClient

from app.main import app
from app import config

client = TestClient(app)
AUTH_HEADERS = {"Authorization": f"Bearer {config.SANDBOX_API_TOKEN}"}

def test_health_and_canary():
    resp = client.get("/health")
    assert resp.status_code == 200
    data = resp.json()
    assert "runner_locked" in data
    assert data["runner_locked"] is False

    resp = client.get("/canary")
    assert resp.status_code == 200
    assert resp.json()["status"] == "isolated"

def test_auth_enforcement():
    # Missing token -> 401
    resp = client.post("/jobs", files={"file": ("test.bin", b"\x7fELFtest")})
    assert resp.status_code == 401

    # Wrong token -> 401
    resp = client.post(
        "/jobs",
        files={"file": ("test.bin", b"\x7fELFtest")},
        headers={"Authorization": "Bearer wrong-token"},
    )
    assert resp.status_code == 401

def test_unsupported_architecture():
    resp = client.post(
        "/jobs",
        files={"file": ("test.bin", b"\x7fELFdummy")},
        data={"target_architecture": "dec_alpha_ancient"},
        headers=AUTH_HEADERS,
    )
    assert resp.status_code == 400
    assert "Unsupported architecture" in resp.json()["detail"]

def test_successful_job_execution_and_manifest():
    sample_content = b"\x7fELF\x02\x01\x01\x00" + b"\x00" * 20 + b"HelloBenignControl"
    import hashlib
    expected_sha256 = hashlib.sha256(sample_content).hexdigest()

    resp = client.post(
        "/jobs",
        files={"file": ("hello_control.bin", sample_content)},
        data={"target_architecture": "x86_64", "timeout_seconds": 10},
        headers=AUTH_HEADERS,
    )
    assert resp.status_code == 201
    job = resp.json()
    job_id = job["job_id"]
    assert job["status"] == "completed"
    assert job["sample_sha256"] == expected_sha256
    assert "strace.log" in job["artifacts"]
    assert "manifest.json" in job["artifacts"]

    manifest = job["manifest"]
    assert "strace.log" in manifest
    assert len(manifest["strace.log"]) == 64  # Valid SHA-256

    # Verify GET /jobs/{job_id}
    resp_get = client.get(f"/jobs/{job_id}", headers=AUTH_HEADERS)
    assert resp_get.status_code == 200
    assert resp_get.json()["job_id"] == job_id

    # Verify GET /jobs/{job_id}/artifacts/manifest.json
    resp_art = client.get(f"/jobs/{job_id}/artifacts/manifest.json", headers=AUTH_HEADERS)
    assert resp_art.status_code == 200
    assert "strace.log" in resp_art.text

    # Verify GET /jobs/{job_id}/artifacts/strace.log
    resp_strace = client.get(f"/jobs/{job_id}/artifacts/strace.log", headers=AUTH_HEADERS)
    assert resp_strace.status_code == 200
    assert len(resp_strace.content) > 0

    # Cleanup DELETE /jobs/{job_id}
    resp_del = client.delete(f"/jobs/{job_id}", headers=AUTH_HEADERS)
    assert resp_del.status_code == 200

def test_canary_failure_blocks_execution(monkeypatch):
    monkeypatch.setenv("SIMULATE_CANARY_FAIL", "1")
    resp = client.post(
        "/jobs",
        files={"file": ("leak_test.bin", b"\x7fELFtest")},
        data={"target_architecture": "x86_64"},
        headers=AUTH_HEADERS,
    )
    assert resp.status_code == 503
    assert "Canary check failed" in resp.json()["detail"]

def test_runner_lock_conflict(monkeypatch):
    from app.runner import RUNNER_LOCK
    import asyncio

    # Simulate runner locked by another task
    asyncio.run(RUNNER_LOCK.acquire("active-job-xyz"))
    try:
        resp = client.post(
            "/jobs",
            files={"file": ("concurrent.bin", b"\x7fELFconcur")},
            data={"target_architecture": "x86_64"},
            headers=AUTH_HEADERS,
        )
        assert resp.status_code == 409
        assert "Runner busy" in resp.json()["detail"]
    finally:
        RUNNER_LOCK.release()


@pytest.mark.parametrize("arch", ["arm", "aarch64", "mips", "mipsel", "riscv64"])
def test_multi_arch_execution(arch):
    """Verify that multi-arch samples execute, normalize architecture, and generate manifest."""
    resp = client.post(
        "/jobs",
        files={"file": (f"{arch}_sample.bin", b"\x7fELF" + b"\x00" * 30)},
        data={"target_architecture": arch},
        headers=AUTH_HEADERS,
    )
    assert resp.status_code == 201
    job = resp.json()
    assert job["status"] == "completed"
    assert job["target_architecture"] == arch
    assert "strace.log" in job["manifest"]
    assert "capture.pcap" in job["manifest"]
    assert "manifest.json" in job["manifest"]

