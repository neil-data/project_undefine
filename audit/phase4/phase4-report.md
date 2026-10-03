# Phase 4 Audit Report — Security, Integrity & Sandbox Architecture (Fixes B1–B3)

**Date**: 2026-10-03  
**Status**: **PASS**  
**Target Scope**: Fixes B1, B2, and B3 only:
- **B1 (Security / Integrity)**: Artifact integrity, hash/manifest/HMAC verification, evidence-to-sample binding, tamper detection, detection of modified analysis artifacts, preventing untrusted or modified results from being accepted as authoritative evidence.
- **B2 (Security Boundaries)**: Untrusted malware sample processing, file/path handling, job_id traversal protection, artifact whitelist enforcement, subprocess execution environment scrubbing, untrusted filename sanitization.
- **B3 (Sandbox Architecture)**: Sandbox isolation, lifecycle state distinction (`completed`, `timed_out`, `failed`, `incomplete`), timeout handling, crash/failure handling, evidence collection integrity, preventing failed/incomplete executions from being represented as successful analyses.  
**Out of Scope**: Phase 5 / Phase 6 (full production guest image deployment, live hypervisor orchestration, external feeds) — strictly untouched.

---

## 1. Executive Summary

Phase 4 hardened the foundational security boundaries, cryptographic integrity verifications, and architectural lifecycle controls across the decoupled sandbox host and the backend analysis client (B1–B3).

The implementation strictly followed the required Test-Driven Development (TDD) workflow:

1. **13 targeted regression and security tests** were authored in `backend/tests/test_phase4_regression.py` before modifying production code.
2. Baseline execution against Phase 3 code recorded **8 failures and 5 passes** (evidence preserved in `audit/phase4/baseline-failures.txt`).
3. Minimal, surgical production improvements were implemented across:
   - `sandbox-host/app/runner.py` (HMAC manifest generation, environment scrubbing, safe job paths, lifecycle state resolution).
   - `sandbox-host/app/main.py` (UUID validation on `job_id`, `ALLOWED_ARTIFACTS` whitelist enforcement, path containment).
   - `backend/app/sandbox.py` (HMAC manifest verification, cryptographic evidence-to-sample binding via `meta.json`, first-class status propagation).
   - `agents/investigation_engine/chain_verification.py` (binding `sample_sha256` and artifact hashes into investigation link HMAC signatures).
   - `backend/tests/test_sandbox_integration_stage3.py` (aligned test mock to sign manifests and bind metadata).
4. Re-running `backend/tests/test_phase4_regression.py` achieved **13 passed, 0 failed (100% PASS)** in 2.53s.
5. All cumulative regression suites (Phases 1 through 4) executed together achieved **92 passed, 0 failed (100% PASS)** in 5.56s.
6. The entire repository test suite (`pytest`) passed with **928 passed, 0 failed, 1 warning** in 121.29s.
7. The isolated `sandbox-host/tests` suite passed with **11 passed, 0 failed** in 3.69s.
8. Frontend type check (`npx tsc --noEmit`) completed with **0 errors**.

---

## 2. Issues Summary Table

| Issue ID | Description | Root Cause | Baseline Failure Count | Status |
| :--- | :--- | :--- | :--- | :--- |
| **B1** | Artifact integrity, manifest HMAC verification, evidence-to-sample binding & tamper detection | Sandbox runner generated raw artifact hashes in `manifest.json` without cryptographic HMAC signing; backend accepted manifests without verifying authenticity; backend never fetched `meta.json` or verified that the sandbox's recorded `sample_sha256` matched the submitted binary; investigation chain did not bind `sample_sha256`. | 3 failing tests | **PASS** |
| **B2** | Path traversal, subprocess environment leak & untrusted sample handling | `main.py` accepted unvalidated strings as `job_id` and artifact names without UUID validation or whitelist checks; `runner.py` invoked subprocesses without `env`, leaking host secrets (`SANDBOX_API_TOKEN`, cloud tokens) into child processes. | 2 failing tests | **PASS** |
| **B3** | Sandbox lifecycle states & preventing failed/timeout runs from masquerading as completed | `runner.py:219` hardcoded `"status": "completed" if exit_code == 0 or exit_code == -9 else "completed"`, treating timeouts and crashes as successful executions; backend polling loop and output handling failed to distinguish `timed_out` from `failed`. | 3 failing tests | **PASS** |

---

## 3. Deep Dive: Findings, Root Causes, Implementation & Verification

### B1 — Security & Integrity
- **Finding & Vulnerabilities**:
  1. `manifest.json` contained SHA-256 hashes of generated artifacts, but had no signature or HMAC. An adversary in transit or local process could tamper with both artifacts and `manifest.json` undetected.
  2. The backend thin client (`backend/app/sandbox.py`) accepted any HTTP 200 manifest without validating cryptographic authenticity.
  3. The backend thin client never downloaded `meta.json` or verified that the binary analyzed by the sandbox had the same SHA-256 hash as the sample submitted by the user. If the sandbox analyzed a different sample (sample substitution or replay), the backend accepted the artifacts as authoritative evidence for the submitted binary.
  4. Investigation chain links in `chain_verification.py` relied on legacy fields and did not explicitly bind `sample_sha256` in link HMAC signatures.
- **Root Cause**:
  - Missing HMAC signing routine in `sandbox-host/app/runner.py`.
  - Missing HMAC verification and sample SHA-256 comparison in `backend/app/sandbox.py`.
  - Lack of `sample_sha256` in `ChainVerifier` link data formatting.
- **Implementation**:
  - In `sandbox-host/app/runner.py`:
    - Implemented `sign_manifest(manifest_core, secret)`: computes deterministic canonical JSON of artifact hashes and generates an HMAC-SHA256 signature stored as `manifest["_hmac"]`.
  - In `backend/app/sandbox.py`:
    - Implemented `compute_file_sha256(file_path)`: hashes submitted sample before remote transmission.
    - Implemented `verify_manifest_hmac(manifest, secret)`: validates `manifest["_hmac"]` using `sandbox_token()`. If missing or invalid, rejects the analysis with `status="failed"`, `dynamic_status="failed"`.
    - Added mandatory `meta.json` download and verification: checks `meta.json` hash against `manifest.json`, extracts `meta["sample_sha256"]`, and validates `meta["sample_sha256"] == submitted_sha256`. If there is a mismatch, rejects with `failure_reason="Evidence-to-sample binding mismatch: submitted SHA-256 ... does not match sandbox execution ..."`.
    - Verified each downloaded artifact against `manifest.json`; if any artifact hash diverges (tampered content), fails hard with `Artifact manifest validation failed: <artifact>`.
  - In `agents/investigation_engine/chain_verification.py`:
    - Included `sample_sha256` in `create_chain_link()` metadata and HMAC signature calculation.
    - Updated `verify_chain_link()` to verify HMAC against primary format containing `sample_sha256` while retaining fallback compatibility.
    - Tampering with any artifact hash, sample hash, or metadata immediately marks the chain with `VerificationStatus.TAMPERED`.
- **Verification Tests**:
  - `TestB1SecurityIntegrity::test_b1_manifest_hmac_generated_and_verified`
  - `TestB1SecurityIntegrity::test_b1_tampered_manifest_rejected_by_backend`
  - `TestB1SecurityIntegrity::test_b1_tampered_artifact_rejected_by_backend`
  - `TestB1SecurityIntegrity::test_b1_evidence_to_sample_binding_mismatch_rejected`
  - `TestB1SecurityIntegrity::test_b1_chain_verification_binds_sample_and_detects_tamper`

---

### B2 — Security Boundaries
- **Finding & Vulnerabilities**:
  1. `sandbox-host/app/main.py`: Endpoints `/jobs/{job_id}`, `/jobs/{job_id}/artifacts/{artifact_name}`, and `DELETE /jobs/{job_id}` accepted raw strings without verifying UUID format, allowing directory traversal sequences like `../../`.
  2. Arbitrary artifact retrieval: `/jobs/{job_id}/artifacts/{artifact_name}` allowed requesting any filename that existed on disk, potentially leaking internal files or allowing the detonation sample binary itself to be re-downloaded.
  3. Host environment leakage: `runner.py` called `asyncio.create_subprocess_exec` without an explicit `env` mapping. Untrusted malware processes could inspect `/proc/self/environ` to read `SANDBOX_API_TOKEN`, cloud secrets, database connection strings, or system paths.
  4. Untrusted upload filename handling: uploaded multipart filenames could contain path traversal characters.
- **Root Cause**:
  - Absence of strict regex or UUID format validation on URL parameters in `main.py`.
  - Absence of an explicit artifact whitelist.
  - Subprocess execution inheriting parent environment by default.
- **Implementation**:
  - In `sandbox-host/app/main.py`:
    - Added `validate_job_id(job_id)`: validates `job_id` using `uuid.UUID(job_id)`. Rejects non-UUID strings or path traversal attempts with HTTP 400 Bad Request.
    - Defined `ALLOWED_ARTIFACTS = {"strace.log", "capture.pcap", "fs_diff.json", "stdout.log", "stderr.log", "meta.json", "manifest.json"}`: strictly rejects unauthorized artifact requests or sample re-downloads with HTTP 400 Bad Request.
    - Added path resolution containment checks: asserts that the resolved artifact path is strictly within `config.ARTIFACTS_DIR`.
    - Upload filenames are discarded as paths; the binary is written to a temporary file and copied strictly to `job_dir / "sample.bin"`.
  - In `sandbox-host/app/runner.py`:
    - Defined `SAFE_EXEC_ENV = {"PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin", "LANG": "C", "LC_ALL": "C"}`.
    - Passed `env=SAFE_EXEC_ENV` to `asyncio.create_subprocess_exec`, ensuring no host environment variables or authentication tokens leak to child processes.
    - Added UUID validation and path containment in `prepare_job_dir()` and `clean_job_dir()`.
- **Verification Tests**:
  - `TestB2SecurityBoundaries::test_b2_job_id_path_traversal_rejected`
  - `TestB2SecurityBoundaries::test_b2_artifact_name_whitelist_enforced`
  - `TestB2SecurityBoundaries::test_b2_subprocess_environment_scrubbing`
  - `TestB2SecurityBoundaries::test_b2_untrusted_filename_sanitized_on_upload`

---

### B3 — Sandbox Architecture
- **Finding & Vulnerabilities**:
  1. Line 219 of `sandbox-host/app/runner.py` contained `"status": "completed" if exit_code == 0 or exit_code == -9 else "completed"`. Regardless of whether execution finished cleanly, timed out (-9), or crashed with an error, the runner unconditionally labeled the job as `"completed"`.
  2. When an execution timed out or crashed, the backend thin client was misled into treating the run as normal and parsing truncated or empty logs, falsely representing an incomplete execution as a benign or clean run.
  3. The backend client polling loop only checked `status in ("completed", "failed")`, causing timed-out jobs to hang until the polling timeout elapsed.
- **Root Cause**:
  - Hardcoded ternary operator in `runner.py:219`.
  - Lack of distinct lifecycle states (`completed`, `timed_out`, `failed`, `incomplete`) in the runner and client.
- **Implementation**:
  - In `sandbox-host/app/runner.py`:
    - Added precise lifecycle status resolution:
      - `exit_code == -9` (or `asyncio.TimeoutError`): `run_status = "timed_out"`.
      - `exit_code == 0`: `run_status = "completed"`.
      - Other non-zero exit codes: `run_status = "failed"`.
    - Saved `run_status` into `meta.json` and returned it in the runner dictionary.
  - In `sandbox-host/app/main.py`:
    - `/jobs/{job_id}` reads and returns `meta.get("status")` directly rather than hardcoding `"completed"`.
  - In `backend/app/sandbox.py`:
    - Updated polling loop to terminate immediately upon observing `timed_out`, `failed`, or `incomplete`.
    - If status is `timed_out`: returns `DynamicAnalysisOutput` with `status="timed_out"`, `dynamic_status="timed_out"`, and `failure_reason=err`.
    - If status is `failed`: returns `status="failed"`, `dynamic_status="failed"`.
    - If status is `incomplete`: returns `status="incomplete"`, `dynamic_status="incomplete"`.
    - Rejects missing manifests or inaccessible artifacts as failed/incomplete, preventing incomplete runs from generating authoritative findings.
- **Verification Tests**:
  - `TestB3SandboxArchitecture::test_b3_runner_distinguishes_timed_out_status`
  - `TestB3SandboxArchitecture::test_b3_runner_distinguishes_failed_status`
  - `TestB3SandboxArchitecture::test_b3_backend_propagates_timed_out_status`
  - `TestB3SandboxArchitecture::test_b3_incomplete_artifacts_rejected`

---

## 4. Test Suite Execution & Verification Evidence

### 4.1. Phase 4 Regression Suite (`backend/tests/test_phase4_regression.py`)
```
backend/tests/test_phase4_regression.py::TestB1SecurityIntegrity::test_b1_manifest_hmac_generated_and_verified PASSED [  7%]
backend/tests/test_phase4_regression.py::TestB1SecurityIntegrity::test_b1_tampered_manifest_rejected_by_backend PASSED [ 15%]
backend/tests/test_phase4_regression.py::TestB1SecurityIntegrity::test_b1_tampered_artifact_rejected_by_backend PASSED [ 23%]
backend/tests/test_phase4_regression.py::TestB1SecurityIntegrity::test_b1_evidence_to_sample_binding_mismatch_rejected PASSED [ 30%]
backend/tests/test_phase4_regression.py::TestB1SecurityIntegrity::test_b1_chain_verification_binds_sample_and_detects_tamper PASSED [ 38%]
backend/tests/test_phase4_regression.py::TestB2SecurityBoundaries::test_b2_job_id_path_traversal_rejected PASSED [ 46%]
backend/tests/test_phase4_regression.py::TestB2SecurityBoundaries::test_b2_artifact_name_whitelist_enforced PASSED [ 53%]
backend/tests/test_phase4_regression.py::TestB2SecurityBoundaries::test_b2_subprocess_environment_scrubbing PASSED [ 61%]
backend/tests/test_phase4_regression.py::TestB2SecurityBoundaries::test_b2_untrusted_filename_sanitized_on_upload PASSED [ 69%]
backend/tests/test_phase4_regression.py::TestB3SandboxArchitecture::test_b3_runner_distinguishes_timed_out_status PASSED [ 76%]
backend/tests/test_phase4_regression.py::TestB3SandboxArchitecture::test_b3_runner_distinguishes_failed_status PASSED [ 84%]
backend/tests/test_phase4_regression.py::TestB3SandboxArchitecture::test_b3_backend_propagates_timed_out_status PASSED [ 92%]
backend/tests/test_phase4_regression.py::TestB3SandboxArchitecture::test_b3_incomplete_artifacts_rejected PASSED [100%]

======================== 13 passed, 1 warning in 2.53s ========================
```

### 4.2. Cumulative Regression Suites (Phases 1 through 4)
```
pytest backend/tests/test_phase1_regression.py backend/tests/test_phase2_regression.py backend/tests/test_phase3_regression.py backend/tests/test_phase4_regression.py -v

======================== 92 passed, 1 warning in 5.56s ========================
```

### 4.3. Full Repository Test Suite
```
pytest
================= 928 passed, 1 warning in 121.29s (0:02:01) ==================
```

### 4.4. Isolated Sandbox Host Test Suite
```
pytest sandbox-host/tests
======================== 11 passed, 1 warning in 3.69s ========================
```

### 4.5. Frontend TypeScript Verification
```
npx tsc --noEmit
Exit code: 0 (No type errors)
```

---

## 5. Scope & Safety Enforcement

1. **Strict Scope Control**: Only B1, B2, and B3 were modified. Phase 5 and Phase 6 tasks remain untouched.
2. **Preservation of Existing Audit Evidence**: Audit files in `audit/phase0/`, `audit/phase1/`, `audit/phase2/`, and `audit/phase3/` were preserved without modification.
3. **No Test Weakening**: Zero tests were deleted or weakened; all 928 repository tests pass legitimately.
4. **No Real Malware in Repo**: No malware samples were placed in git or in the repository.
