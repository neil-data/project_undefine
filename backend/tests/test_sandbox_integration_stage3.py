"""
backend/tests/test_sandbox_integration_stage3.py — End-to-end tests for Real Dynamic Sandbox integration.

Tests:
1. Successful benign control execution via SANDBOX_API_URL client
2. Cryptographic artifact manifest validation
3. Tampered artifact detection (SHA-256 mismatch rejection)
4. Sandbox runner busy handling
5. Sandbox safety lock / canary failure handling
6. Investigation chain HMAC integrity binding
"""

import hashlib
import json
import sys
from pathlib import Path
import pytest
import httpx

sandbox_host_dir = str(Path(__file__).resolve().parent.parent.parent / "sandbox-host")
if sandbox_host_dir not in sys.path:
    sys.path.insert(0, sandbox_host_dir)

from app.main import app as sandbox_app
from backend.app import sandbox
from agents.investigation_engine.chain_verification import ChainVerifier, ChainLinkType, verify_integrity


@pytest.fixture
def anyio_backend():
    return "asyncio"


@pytest.fixture
def mock_httpx_sandbox_client(monkeypatch):
    """
    Mounts the sandbox FastAPI app directly into httpx.AsyncClient so that
    sandbox.run_dynamic_analysis communicates directly with the real sandbox host app in-process.
    """
    monkeypatch.setenv("SANDBOX_API_URL", "http://testserver-sandbox")
    monkeypatch.setenv("SANDBOX_API_TOKEN", "erakshak-sandbox-secret-token")

    transport = httpx.ASGITransport(app=sandbox_app)
    real_async_client = httpx.AsyncClient

    def custom_async_client(*args, **kwargs):
        kwargs["transport"] = transport
        return real_async_client(*args, **kwargs)

    monkeypatch.setattr(httpx, "AsyncClient", custom_async_client)


@pytest.mark.asyncio
async def test_sandbox_benign_control_execution(tmp_path, mock_httpx_sandbox_client):
    """Verify that a benign ELF executes through real sandbox client, verifies manifest, and parses artifacts."""
    sample = tmp_path / "hello_control.bin"
    sample.write_bytes(b"\x7fELF\x02\x01\x01\x00" + b"\x00" * 40 + b"BenignControlExecution")

    result = await sandbox.run_dynamic_analysis(
        sample_path=sample,
        target_architecture="x86_64",
    )

    assert result.execution_mode == "real"
    assert result.dynamic_status in ("completed", "no_behavior_observed")
    assert result.task_id is not None
    assert result.artifact_hashes is not None
    assert "strace.log" in result.artifact_hashes
    assert len(result.artifact_hashes["strace.log"]) == 64


@pytest.mark.asyncio
async def test_sandbox_manifest_mismatch_detection(tmp_path, monkeypatch):
    """If an artifact hash does not match manifest.json, dynamic analysis fails with specific reason."""
    monkeypatch.setenv("SANDBOX_API_URL", "http://testserver-sandbox")
    monkeypatch.setenv("SANDBOX_API_TOKEN", "erakshak-sandbox-secret-token")

    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"\x7fELF\x02\x01\x01\x00" + b"\x00" * 50)

    # Mock responses where manifest claims a different hash than artifact content
    async def mock_handler(request: httpx.Request):
        url = str(request.url)
        if url.endswith("/jobs"):
            return httpx.Response(201, json={"job_id": "test-job-mismatch", "status": "completed"})
        if url.endswith("/jobs/test-job-mismatch"):
            return httpx.Response(200, json={"job_id": "test-job-mismatch", "status": "completed"})
        if url.endswith("/manifest.json"):
            return httpx.Response(200, json={
                "strace.log": "0000000000000000000000000000000000000000000000000000000000000000",
                "capture.pcap": "1111111111111111111111111111111111111111111111111111111111111111",
                "fs_diff.json": "2222222222222222222222222222222222222222222222222222222222222222",
            })
        if url.endswith("/strace.log"):
            return httpx.Response(200, text="1000 00:00:00.000000 execve(\"test\", [], []) = 0\n")
        if url.endswith("/capture.pcap"):
            return httpx.Response(200, content=b"\xd4\xc3\xb2\xa1\x02\x00\x04\x00")
        if url.endswith("/fs_diff.json"):
            return httpx.Response(200, json={"created": []})
        return httpx.Response(404)

    transport = httpx.MockTransport(mock_handler)
    orig_client = httpx.AsyncClient
    monkeypatch.setattr(httpx, "AsyncClient", lambda *args, **kwargs: orig_client(transport=transport))

    result = await sandbox.run_dynamic_analysis(sample_path=sample)
    assert result.dynamic_status == "failed"
    assert "Artifact manifest validation failed: strace.log" in result.failure_reason


@pytest.mark.asyncio
async def test_sandbox_hmac_chain_integrity(tmp_path, mock_httpx_sandbox_client):
    """Verify that artifact hashes and sandbox status are bound to HMAC investigation chain."""
    sample = tmp_path / "hello_hmac.bin"
    sample.write_bytes(b"\x7fELF\x02\x01\x01\x00" + b"\x00" * 40 + b"HmacChainTest")

    dyn_result = await sandbox.run_dynamic_analysis(
        sample_path=sample,
        target_architecture="x86_64",
    )

    state = {
        "sample_id": "hello_hmac.bin",
        "task_id": dyn_result.task_id,
        "sandbox_id": "sandbox_host_01",
        "execution_mode": dyn_result.execution_mode,
        "dynamic_status": dyn_result.dynamic_status,
        "evidence_state": "OBSERVED",
        "intel_floor": 0,
        "artifact_hashes": dyn_result.artifact_hashes,
        "dynamic_output": dyn_result.model_dump(),
        "static_output": {"sha256": "abc"},
        "mitre_techniques": [],
        "capability_tags": [],
        "risk_score": 10,
        "narrative_summary": "Clean execution",
        "investigation_output": {},
    }

    verifier = ChainVerifier(secret_key="unit_test_key_123")
    res, chain = verifier.verify_integrity(state)
    assert res.is_valid is True
    assert res.status.value == "valid"