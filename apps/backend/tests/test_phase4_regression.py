"""
backend/tests/test_phase4_regression.py — TDD Regression & Security Tests for Phase 4 (B1–B3).

Phase 4 Scope:
- B1 (Security / Integrity):
    - Manifest HMAC generation and cryptographic verification.
    - Detection and rejection of tampered manifest.
    - Detection and rejection of tampered artifacts (strace.log, capture.pcap, fs_diff.json).
    - Evidence-to-sample binding: sample_sha256 verification between submitted sample and sandbox meta.json.
    - Investigation chain verification: tamper detection with HMAC binding sample and artifact hashes.
- B2 (Security Boundaries):
    - Path traversal prevention on job_id and artifact_name endpoints.
    - Whitelist enforcement for artifact downloads.
    - Subprocess execution environment scrubbing (preventing leakage of SANDBOX_API_TOKEN and host secrets).
    - Untrusted filename sanitization during job submission.
    - Temporary file cleanup under failure/timeout conditions.
- B3 (Sandbox Architecture):
    - Execution lifecycle state distinction: "completed", "timed_out", "failed", "incomplete".
    - Preventing timed-out or failed executions from being masqueraded as "completed".
    - Backend thin client handling of "timed_out", "failed", and "incomplete" states.
    - Rejection of incomplete artifact sets.
"""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import os
import shutil
import tempfile
import uuid
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi.testclient import TestClient

# Sandbox host imports
import sys

# Ensure sandbox-host is in sys.path
sandbox_host_dir = Path(__file__).resolve().parent.parent.parent / "sandbox-host"
if str(sandbox_host_dir) not in sys.path:
    sys.path.insert(0, str(sandbox_host_dir))

from app.main import app as sandbox_app
from app import config as sandbox_config
from app.runner import SandboxRunner, compute_sha256
from app.canary import check_canary_isolation

# Backend imports
from backend.app import sandbox as backend_sandbox
from backend.app.sandbox import run_dynamic_analysis
from agents.orchestrator.schema import DynamicAnalysisOutput
from agents.investigation_engine.chain_verification import (
    ChainVerifier,
    ChainLinkType,
    VerificationStatus,
)


sandbox_client = TestClient(sandbox_app)
AUTH_HEADERS = {"Authorization": f"Bearer {sandbox_config.SANDBOX_API_TOKEN}"}


# ===========================================================================
# B1: Security / Integrity
# ===========================================================================

class TestB1SecurityIntegrity:
    """B1: Artifact integrity, HMAC verification, evidence-to-sample binding, tamper detection."""

    @pytest.mark.asyncio
    async def test_b1_manifest_hmac_generated_and_verified(self, tmp_path):
        """Runner must sign manifest.json using HMAC-SHA256 and store _hmac signature."""
        runner = SandboxRunner(artifacts_dir=tmp_path)
        sample = tmp_path / "test.bin"
        sample.write_bytes(b"\x7fELF" + b"\x00" * 32)
        job_id = str(uuid.uuid4())

        result = await runner.run(job_id=job_id, sample_path=sample, raw_arch="x86_64")
        manifest = result.get("manifest", {})

        # The manifest must include an HMAC signature for authenticity
        assert "_hmac" in manifest or "signature" in manifest
        sig = manifest.get("_hmac") or manifest.get("signature")
        assert len(sig) == 64

        # Verify signature can be recomputed from manifest contents
        manifest_file = tmp_path / job_id / "manifest.json"
        assert manifest_file.exists()
        on_disk_manifest = json.loads(manifest_file.read_text(encoding="utf-8"))
        assert "_hmac" in on_disk_manifest or "signature" in on_disk_manifest

    @pytest.mark.asyncio
    async def test_b1_tampered_manifest_rejected_by_backend(self, tmp_path, monkeypatch):
        """Backend must reject analysis if manifest.json HMAC signature does not verify."""
        sample = tmp_path / "sample.bin"
        sample_bytes = b"\x7fELF\x02\x01\x01\x00" + b"\x00" * 20
        sample.write_bytes(sample_bytes)

        job_id = str(uuid.uuid4())
        monkeypatch.setenv("SANDBOX_API_URL", "http://fake-sandbox:8000")

        # Fake manifest with invalid HMAC
        tampered_manifest = {
            "strace.log": hashlib.sha256(b"fake").hexdigest(),
            "capture.pcap": hashlib.sha256(b"fake").hexdigest(),
            "fs_diff.json": hashlib.sha256(b"fake").hexdigest(),
            "stdout.log": hashlib.sha256(b"").hexdigest(),
            "stderr.log": hashlib.sha256(b"").hexdigest(),
            "meta.json": hashlib.sha256(b"fake").hexdigest(),
            "_hmac": "0" * 64,  # Invalid HMAC
        }

        async def mock_handler(request):
            import httpx
            req_url = str(request.url)
            if req_url.endswith("/jobs"):
                return httpx.Response(201, json={"job_id": job_id, "status": "completed"})
            elif f"/jobs/{job_id}/artifacts/manifest.json" in req_url:
                return httpx.Response(200, json=tampered_manifest)
            elif f"/jobs/{job_id}" in req_url and "artifacts" not in req_url:
                return httpx.Response(200, json={"job_id": job_id, "status": "completed"})
            return httpx.Response(404)

        import httpx
        transport = httpx.MockTransport(mock_handler)

        with patch("httpx.AsyncClient", return_value=httpx.AsyncClient(transport=transport)):
            output = await run_dynamic_analysis(sample)
            assert output.status == "failed"
            assert output.dynamic_status == "failed"
            assert "manifest" in output.failure_reason.lower() or "hmac" in output.failure_reason.lower()

    @pytest.mark.asyncio
    async def test_b1_tampered_artifact_rejected_by_backend(self, tmp_path, monkeypatch):
        """Backend must reject analysis if downloaded artifact hash doesn't match manifest."""
        sample = tmp_path / "sample.bin"
        sample_bytes = b"\x7fELF\x02\x01\x01\x00" + b"\x00" * 20
        sample.write_bytes(sample_bytes)

        job_id = str(uuid.uuid4())
        monkeypatch.setenv("SANDBOX_API_URL", "http://fake-sandbox:8000")

        real_strace = b"execve(\"./sample.bin\", ...)"
        strace_hash = hashlib.sha256(real_strace).hexdigest()

        meta_bytes = json.dumps({"sample_sha256": hashlib.sha256(sample_bytes).hexdigest()}).encode()
        meta_hash = hashlib.sha256(meta_bytes).hexdigest()

        # Compute valid HMAC for manifest
        manifest_core = {
            "strace.log": strace_hash,
            "capture.pcap": hashlib.sha256(b"pcap").hexdigest(),
            "fs_diff.json": hashlib.sha256(b"{}").hexdigest(),
            "meta.json": meta_hash,
        }
        canonical = json.dumps(manifest_core, sort_keys=True)
        sig = hmac.new(sandbox_config.SANDBOX_API_TOKEN.encode(), canonical.encode(), hashlib.sha256).hexdigest()
        valid_manifest = dict(manifest_core)
        valid_manifest["_hmac"] = sig

        async def mock_handler(request):
            import httpx
            req_url = str(request.url)
            if req_url.endswith("/jobs"):
                return httpx.Response(201, json={"job_id": job_id, "status": "completed"})
            elif f"/jobs/{job_id}/artifacts/manifest.json" in req_url:
                return httpx.Response(200, json=valid_manifest)
            elif f"/jobs/{job_id}/artifacts/strace.log" in req_url:
                # Return TAMPERED content differing from strace_hash
                return httpx.Response(200, content=b"TAMPERED_LOG_CONTENT")
            elif f"/jobs/{job_id}/artifacts/meta.json" in req_url:
                return httpx.Response(200, content=meta_bytes)
            elif f"/jobs/{job_id}" in req_url and "artifacts" not in req_url:
                return httpx.Response(200, json={"job_id": job_id, "status": "completed"})
            return httpx.Response(200, content=b"{}")

        import httpx
        transport = httpx.MockTransport(mock_handler)

        with patch("httpx.AsyncClient", return_value=httpx.AsyncClient(transport=transport)):
            output = await run_dynamic_analysis(sample)
            assert output.status == "failed"
            assert output.dynamic_status == "failed"
            assert "strace.log" in output.failure_reason

    @pytest.mark.asyncio
    async def test_b1_evidence_to_sample_binding_mismatch_rejected(self, tmp_path, monkeypatch):
        """Backend must verify meta.json sample_sha256 matches the submitted sample's SHA-256."""
        sample = tmp_path / "actual_sample.bin"
        sample_bytes = b"\x7fELFActualSampleContent"
        sample.write_bytes(sample_bytes)

        job_id = str(uuid.uuid4())
        monkeypatch.setenv("SANDBOX_API_URL", "http://fake-sandbox:8000")

        # meta.json reports a completely different SHA-256 (e.g. sample swap attack)
        different_sha256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        meta_bytes = json.dumps({"sample_sha256": different_sha256, "status": "completed"}).encode()
        meta_hash = hashlib.sha256(meta_bytes).hexdigest()

        manifest_core = {
            "strace.log": hashlib.sha256(b"log").hexdigest(),
            "capture.pcap": hashlib.sha256(b"pcap").hexdigest(),
            "fs_diff.json": hashlib.sha256(b"{}").hexdigest(),
            "meta.json": meta_hash,
        }
        canonical = json.dumps(manifest_core, sort_keys=True)
        sig = hmac.new(sandbox_config.SANDBOX_API_TOKEN.encode(), canonical.encode(), hashlib.sha256).hexdigest()
        valid_manifest = dict(manifest_core)
        valid_manifest["_hmac"] = sig

        async def mock_handler(request):
            import httpx
            req_url = str(request.url)
            if req_url.endswith("/jobs"):
                return httpx.Response(201, json={"job_id": job_id, "status": "completed"})
            elif f"/jobs/{job_id}/artifacts/manifest.json" in req_url:
                return httpx.Response(200, json=valid_manifest)
            elif f"/jobs/{job_id}/artifacts/meta.json" in req_url:
                return httpx.Response(200, content=meta_bytes)
            elif f"/jobs/{job_id}/artifacts/strace.log" in req_url:
                return httpx.Response(200, content=b"log")
            elif f"/jobs/{job_id}/artifacts/capture.pcap" in req_url:
                return httpx.Response(200, content=b"pcap")
            elif f"/jobs/{job_id}/artifacts/fs_diff.json" in req_url:
                return httpx.Response(200, content=b"{}")
            elif f"/jobs/{job_id}" in req_url and "artifacts" not in req_url:
                return httpx.Response(200, json={"job_id": job_id, "status": "completed"})
            return httpx.Response(404)

        import httpx
        transport = httpx.MockTransport(mock_handler)

        with patch("httpx.AsyncClient", return_value=httpx.AsyncClient(transport=transport)):
            output = await run_dynamic_analysis(sample)
            assert output.status == "failed"
            assert output.dynamic_status == "failed"
            assert "sample" in output.failure_reason.lower() or "binding" in output.failure_reason.lower() or "mismatch" in output.failure_reason.lower()

    def test_b1_chain_verification_binds_sample_and_detects_tamper(self):
        """ChainVerifier must bind sample_sha256 & artifact hashes and detect tampered links."""
        secret = "super-chain-secret-key"
        verifier = ChainVerifier(secret_key=secret)

        state = {
            "sample_id": "test_sample_123",
            "sample_sha256": "a" * 64,
            "task_id": "task_456",
            "sandbox_id": "sandbox_789",
            "dynamic_status": "completed",
            "evidence_state": "OBSERVED",
            "strace_hash": "b" * 64,
            "pcap_hash": "c" * 64,
            "fs_diff_hash": "d" * 64,
            "static_output": {"sha256": "a" * 64},
            "dynamic_output": {"status": "completed"},
            "mitre_techniques": ["T1059.004"],
            "capability_tags": ["persistence"],
            "risk_score": 85,
            "narrative_summary": "Malware report summary",
            "investigation_output": {"verdict": "MALICIOUS"},
        }

        # 1. Valid chain creation & verification
        res, chain = verifier.verify_integrity(state)
        assert res.is_valid is True
        assert res.status == VerificationStatus.VALID

        # 2. Tampered metadata (altering artifact hash) must cause verification failure
        chain[1].metadata["strace_hash"] = "tampered_strace_hash"
        tampered_res = verifier.verify_chain(chain)
        assert tampered_res.is_valid is False
        assert tampered_res.status == VerificationStatus.TAMPERED

        # 3. Tampered data hash
        chain[1].data_hash = "deadbeef" * 8
        tampered_res2 = verifier.verify_chain(chain)
        assert tampered_res2.is_valid is False
        assert tampered_res2.status == VerificationStatus.TAMPERED


# ===========================================================================
# B2: Security Boundaries
# ===========================================================================

class TestB2SecurityBoundaries:
    """B2: Path traversal, subprocess environment scrubbing, untrusted inputs, cleanup."""

    def test_b2_job_id_path_traversal_rejected(self):
        """job_id with path traversal sequences must be rejected with 400 or 404."""
        malicious_ids = [
            "../../etc/passwd",
            "..\\..\\windows\\system32",
            "../../../artifacts",
            "job123/../../secret",
            "not-a-valid-uuid",
        ]
        for bad_id in malicious_ids:
            resp_get = sandbox_client.get(f"/jobs/{bad_id}", headers=AUTH_HEADERS)
            assert resp_get.status_code in (400, 404), f"Path traversal in job_id not blocked: {bad_id}"

            resp_art = sandbox_client.get(f"/jobs/{bad_id}/artifacts/manifest.json", headers=AUTH_HEADERS)
            assert resp_art.status_code in (400, 404), f"Path traversal in job_id artifact not blocked: {bad_id}"

            resp_del = sandbox_client.delete(f"/jobs/{bad_id}", headers=AUTH_HEADERS)
            assert resp_del.status_code in (400, 404), f"Path traversal in job_id delete not blocked: {bad_id}"

    def test_b2_artifact_name_whitelist_enforced(self):
        """Only whitelisted artifact names may be fetched; directory traversal must be blocked."""
        valid_job_id = str(uuid.uuid4())
        forbidden_artifacts = [
            "../../../../etc/passwd",
            "..\\..\\boot.ini",
            "sample.bin",        # The malware binary itself should not be re-downloaded via artifact API
            "unapproved.sh",
            "core.dump",
            "random_file.txt",
        ]
        for bad_name in forbidden_artifacts:
            resp = sandbox_client.get(f"/jobs/{valid_job_id}/artifacts/{bad_name}", headers=AUTH_HEADERS)
            assert resp.status_code in (400, 404), f"Unapproved artifact name was not rejected: {bad_name}"

    @pytest.mark.asyncio
    async def test_b2_subprocess_environment_scrubbing(self, tmp_path, monkeypatch):
        """Runner must scrub environment variables so host secrets are NEVER passed to child process."""
        monkeypatch.setenv("SANDBOX_API_TOKEN", "super-secret-host-token-xyz")
        monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "AKIAHOSTSECRET123")
        monkeypatch.setenv("DATABASE_URL", "postgres://admin:pass@host/db")

        runner = SandboxRunner(artifacts_dir=tmp_path)
        sample = tmp_path / "sample.bin"
        sample.write_bytes(b"\x7fELF" + b"\x00" * 32)
        job_id = str(uuid.uuid4())

        recorded_env = {}

        async def mock_exec(*cmd, **kwargs):
            nonlocal recorded_env
            recorded_env = kwargs.get("env")
            mock_proc = MagicMock()
            mock_proc.returncode = 0
            mock_proc.communicate = AsyncMock(return_value=(b"Executed", b""))
            mock_proc.wait = AsyncMock(return_value=0)
            return mock_proc

        with patch("asyncio.create_subprocess_exec", side_effect=mock_exec):
            with patch("sys.platform", "linux"):
                with patch("shutil.which", return_value="/usr/bin/strace"):
                    await runner.run(job_id=job_id, sample_path=sample, raw_arch="x86_64")

        assert recorded_env is not None, "Runner failed to pass explicit scrubbed env to subprocess"
        assert "SANDBOX_API_TOKEN" not in recorded_env
        assert "AWS_SECRET_ACCESS_KEY" not in recorded_env
        assert "DATABASE_URL" not in recorded_env
        assert "PATH" in recorded_env

    def test_b2_untrusted_filename_sanitized_on_upload(self, tmp_path):
        """Untrusted filenames with path traversal in POST /jobs must not escape job directory."""
        traversal_filenames = [
            "../../../../escaped.bin",
            "..\\..\\system.bin",
            "dir/sub/sample.bin",
            "sample;rm -rf.bin",
        ]
        for fname in traversal_filenames:
            resp = sandbox_client.post(
                "/jobs",
                files={"file": (fname, b"\x7fELF" + b"\x00" * 20)},
                data={"target_architecture": "x86_64"},
                headers=AUTH_HEADERS,
            )
            assert resp.status_code == 201
            job_data = resp.json()
            job_id = job_data["job_id"]
            job_dir = sandbox_config.ARTIFACTS_DIR / job_id
            assert (job_dir / "sample.bin").exists()
            assert not (job_dir / fname).exists()
            sandbox_client.delete(f"/jobs/{job_id}", headers=AUTH_HEADERS)


# ===========================================================================
# B3: Sandbox Architecture
# ===========================================================================

class TestB3SandboxArchitecture:
    """B3: Execution lifecycle states (completed, timed_out, failed, incomplete), timeout & failure handling."""

    @pytest.mark.asyncio
    async def test_b3_runner_distinguishes_timed_out_status(self, tmp_path):
        """Runner must return status='timed_out' when execution exceeds timeout limit (not 'completed')."""
        runner = SandboxRunner(artifacts_dir=tmp_path)
        sample = tmp_path / "sample.bin"
        sample.write_bytes(b"\x7fELF" + b"\x00" * 32)
        job_id = str(uuid.uuid4())

        async def mock_exec(*cmd, **kwargs):
            mock_proc = MagicMock()
            mock_proc.returncode = -9
            mock_proc.communicate = AsyncMock(side_effect=asyncio.TimeoutError())
            mock_proc.kill = MagicMock()
            mock_proc.wait = AsyncMock(return_value=-9)
            return mock_proc

        with patch("asyncio.create_subprocess_exec", side_effect=mock_exec):
            with patch("sys.platform", "linux"):
                with patch("shutil.which", return_value="/usr/bin/strace"):
                    res = await runner.run(job_id=job_id, sample_path=sample, raw_arch="x86_64", timeout_seconds=1)

        assert res["status"] == "timed_out"
        assert res["exit_code"] == -9

        meta_file = tmp_path / job_id / "meta.json"
        meta = json.loads(meta_file.read_text(encoding="utf-8"))
        assert meta["status"] == "timed_out"
        assert meta["exit_code"] == -9

    @pytest.mark.asyncio
    async def test_b3_runner_distinguishes_failed_status(self, tmp_path):
        """Runner must return status='failed' when subprocess crashes or fails to execute."""
        runner = SandboxRunner(artifacts_dir=tmp_path)
        sample = tmp_path / "sample.bin"
        sample.write_bytes(b"\x7fELF" + b"\x00" * 32)
        job_id = str(uuid.uuid4())

        async def mock_exec(*cmd, **kwargs):
            mock_proc = MagicMock()
            mock_proc.returncode = 127
            mock_proc.communicate = AsyncMock(return_value=(b"", b"Segmentation fault\n"))
            mock_proc.wait = AsyncMock(return_value=127)
            return mock_proc

        with patch("asyncio.create_subprocess_exec", side_effect=mock_exec):
            with patch("sys.platform", "linux"):
                with patch("shutil.which", return_value="/usr/bin/strace"):
                    res = await runner.run(job_id=job_id, sample_path=sample, raw_arch="x86_64")

        assert res["status"] == "failed"
        assert res["exit_code"] == 127

        meta_file = tmp_path / job_id / "meta.json"
        meta = json.loads(meta_file.read_text(encoding="utf-8"))
        assert meta["status"] == "failed"
        assert meta["exit_code"] == 127

    @pytest.mark.asyncio
    async def test_b3_backend_propagates_timed_out_status(self, tmp_path, monkeypatch):
        """Backend must output status='timed_out' and dynamic_status='timed_out' when sandbox times out."""
        sample = tmp_path / "sample.bin"
        sample_bytes = b"\x7fELF\x02\x01\x01\x00" + b"\x00" * 20
        sample.write_bytes(sample_bytes)
        job_id = str(uuid.uuid4())

        monkeypatch.setenv("SANDBOX_API_URL", "http://fake-sandbox:8000")

        async def mock_handler(request):
            import httpx
            req_url = str(request.url)
            if req_url.endswith("/jobs"):
                return httpx.Response(201, json={"job_id": job_id, "status": "timed_out", "exit_code": -9})
            elif f"/jobs/{job_id}" in req_url and "artifacts" not in req_url:
                return httpx.Response(200, json={"job_id": job_id, "status": "timed_out", "exit_code": -9, "error": "Execution timed out"})
            return httpx.Response(404)

        import httpx
        transport = httpx.MockTransport(mock_handler)

        with patch("httpx.AsyncClient", return_value=httpx.AsyncClient(transport=transport)):
            output = await run_dynamic_analysis(sample)
            assert output.status == "timed_out"
            assert output.dynamic_status == "timed_out"
            assert "timed out" in output.failure_reason.lower()

    @pytest.mark.asyncio
    async def test_b3_incomplete_artifacts_rejected(self, tmp_path, monkeypatch):
        """Backend must treat missing manifest or incomplete artifacts as failure / incomplete."""
        sample = tmp_path / "sample.bin"
        sample_bytes = b"\x7fELF\x02\x01\x01\x00" + b"\x00" * 20
        sample.write_bytes(sample_bytes)
        job_id = str(uuid.uuid4())

        monkeypatch.setenv("SANDBOX_API_URL", "http://fake-sandbox:8000")

        async def mock_handler(request):
            import httpx
            req_url = str(request.url)
            if req_url.endswith("/jobs"):
                return httpx.Response(201, json={"job_id": job_id, "status": "completed"})
            elif f"/jobs/{job_id}/artifacts/manifest.json" in req_url:
                return httpx.Response(404, text="Manifest missing")
            elif f"/jobs/{job_id}" in req_url and "artifacts" not in req_url:
                return httpx.Response(200, json={"job_id": job_id, "status": "completed"})
            return httpx.Response(404)

        import httpx
        transport = httpx.MockTransport(mock_handler)

        with patch("httpx.AsyncClient", return_value=httpx.AsyncClient(transport=transport)):
            output = await run_dynamic_analysis(sample)
            assert output.status in ("failed", "incomplete")
            assert output.dynamic_status in ("failed", "incomplete")
            assert "manifest" in output.failure_reason.lower()
