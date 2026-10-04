# Changelog — E-Rakshak Dynamic Sandbox Overhaul & ELF Pipeline Defense

All notable changes to the E-Rakshak malware analysis and triage pipeline are documented in this file.

## [v4.1.0] — 2026-10-03

### Summary of Major Architectural Changes
- **Decoupled Real Dynamic Sandbox (`sandbox-host/`)**:
  - Implemented standalone microservice with FastAPI, Bearer token authentication (`SANDBOX_API_TOKEN`).
  - Native x86_64 user-mode detonation under `strace -f -tt -s 512 -yy`.
  - Multi-architecture QEMU emulation for ARM, AArch64, MIPS, MIPSEL, and RISC-V (`qemu-<arch> -strace`) with `-L /opt/sandbox/rootfs/<arch>`.
  - Single-job runner lock (`RUNNER_LOCK`) returning HTTP 409 Conflict for concurrent detonation requests.
  - Canary external network egress verification probe (`canary.py`) returning HTTP 503 Service Unavailable if public internet is accessible.
  - Cryptographic artifact manifest (`manifest.json`) containing SHA-256 hashes of all generated artifacts (`strace.log`, `capture.pcap`, `fs_diff.json`, `stdout.log`, `stderr.log`, `meta.json`).
  - Sandbox host returns **only raw artifacts and metadata**; it performs zero telemetry parsing.

- **Backend Thin Client (`backend/app/sandbox.py`)**:
  - Transformed into a lightweight HTTP client for `SANDBOX_API_URL`.
  - If `SANDBOX_API_URL` is unconfigured: returns `dynamic_status="unavailable"` with `"Dynamic analysis not performed: SANDBOX_API_URL is not configured"`. Zero synthetic events emitted.
  - If sandbox execution fails or times out: returns `dynamic_status="failed"` with the specific failure reason.
  - Downloads `manifest.json` and cryptographically verifies the SHA-256 of all artifacts before passing to `strace_parser.py`. If any hash fails verification, rejects with `"Artifact manifest validation failed: <filename>"`.

- **Comprehensive Strace & PCAP Parser (`backend/app/strace_parser.py`)**:
  - Native `strace -f -tt -s 512 -yy` and `qemu-<arch> -strace` log parser.
  - Reassembles interleaved syscall lines (`<unfinished ...>` and `<... resumed>`).
  - Converts wall-clock timestamps to relative seconds from execution onset (`+0.000000s`).
  - Reconstructs full process tree from `clone`, `fork`, `vfork`, and `execve` syscalls.
  - Tracks file writes and persistence paths (`/etc/cron*`, `/etc/rc.local`, `/etc/init.d/`, `/etc/systemd/system/`).
  - Detects anti-debugging via `ptrace(PTRACE_TRACEME)`.
  - Parses PCAP DNS responses via `dpkt` to map internal bridge IP connections back to actual queried domains.
  - Standard limitation notice: `"Network is emulated by a fake-service host; remote servers did not respond"`.

- **Cryptographic Evidence Chain Verification (`agents/investigation_engine/chain_verification.py`)**:
  - Extended HMAC-SHA256 signature payload to bind `sample_id`, `task_id`, `sandbox_id`, `execution_mode`, `dynamic_status`, `evidence_state`, `intel_floor`, and artifact manifest hashes (`strace_hash`, `pcap_hash`, `fs_diff_hash`).
  - Tampering with any generated artifact file or status breaks verification.

- **Zero-Simulation Mandate**:
  - Permanently removed all simulation modes, heuristic simulation branches, `SimulatedSandbox`, and `+15` simulated score caps.
  - Removed `SIMULATED` and `PREDICTED` states; strictly standardizing on canonical `OBSERVED`, `STATIC`, `INTEL`.
  - Removed simulation notice banner and tags from UI (`DynamicSandboxTab.tsx`) and PDF report generator (`reportPdf.tsx`).
  - Passed Test 12 no-simulation guard: 0 occurrences of the word `simulated` in production Python code across `backend/app/`, `agents/`, `static-analysis/`, and frontend.

- **Deterministic Risk Scoring & Grounded AI Pipeline**:
  - Configured ELF risk scoring constants with modular caps (`SCORE_OBSERVED_CAP=50`, `SCORE_STATIC_CAP=20`, `YARA_CAP=40`, `INTEL_FLOOR_SCORE=85`).
  - Enforced exact mathematical sum consistency in `_build_risk_explanation` with cap adjustment contributions.
  - Single 4-tier threat classification scale: `LOW | MEDIUM | HIGH | CRITICAL` (eliminated `SEVERE`).
  - Strict regex token-level grounding validator in `agents/narrative_agent/narrative.py`.
  - Deduplicated, actionable forensic remediation generator in `investigation_engine`.

## [v4.1.6] — Phase 6: Category C Real Sandbox / Deployment / Operations (2026-10-03)

### C1 — Real Multi-Worker Pool Architecture & Concurrency Lifecycle
- **WorkerPool & Concurrency State Tracking (`sandbox-host/app/runner.py`)**:
  - Implemented `WorkerState` enum (`IDLE`, `BUSY`, `RECOVERING`, `OFFLINE`) and `WorkerPool` managing worker lifecycles.
  - Workers transition strictly through `idle` -> `busy` -> `recovering` -> `idle`.
  - Maintained backward-compatible `RUNNER_LOCK` backed by `WorkerPool`.
- **Operational Metrics in Health Check (`sandbox-host/app/main.py`)**:
  - Exposing `total_workers`, `available_workers`, `active_jobs`, and worker state details via `/health`.
  - Enforced 409 Conflict with `Retry-After: 5` header when all workers in the pool are busy.

### C2 — Incomplete Execution Semantics
- **Runner Incomplete State Detection (`sandbox-host/app/runner.py`)**:
  - Detects missing or empty `strace.log` and marks job `status="incomplete"` with descriptive forensic error instead of collapsing into `completed` or `failed`.
- **Backend Incomplete Trace Propagation (`backend/app/sandbox.py`)**:
  - Returns `dynamic_status="incomplete"` when critical forensic trace download fails (`HTTP 404/500`).

### C3 — Remote Job Lifecycle & Automatic Cleanup
- **Automatic Sandbox Host Cleanup (`backend/app/sandbox.py`)**:
  - Issues `DELETE /jobs/{job_id}` after fetching artifacts and in failed download paths, preventing host storage exhaustion and orphaned workspaces.

### C4 — Artifact Size Limit & Truncation
- **Safe Artifact Truncation (`sandbox-host/app/runner.py`, `config.py`)**:
  - Added `MAX_ARTIFACT_SIZE_BYTES` cap (default 50MB, configurable via `SANDBOX_MAX_ARTIFACT_SIZE`).
  - Safely truncates oversized artifacts and appends `\n[TRUNCATED: artifact exceeded max size of ... bytes]\n`.

### C5 — Production Containerization & Orchestration
- **Production Dockerization (`sandbox-host/Dockerfile`)**:
  - Created standalone container image with non-root user `sandbox-runner`, `strace`, `tcpdump`, and `qemu-user-static`.
- **Compose Orchestration (`docker-compose.yml`)**:
  - Added `sandbox-host` service definition mapped to port 8004.
  - Configured `backend` service with `SANDBOX_API_URL: http://sandbox-host:8000` and authentication token.

## [v4.1.5] — Phase 5: B4/B5 Threat Intelligence, Narrative & IoC Coverage (2026-10-03)

### B4 — Threat Intelligence
- **Transparent Negative & Offline Result Caching**:
  - `backend/app/malware_bazaar.py`: Updated cache lookup in memory and Redis to return cached negative/offline payloads directly instead of swallowing them with `if cached.get("found")`.
- **Multi-Vendor Verdict Parsing**:
  - `backend/app/malware_bazaar.py`: Expanded vendor verdicts extraction to parse `malware_family` and `status` in addition to `verdict`, `detection`, and `threat_name`.
- **Explicit Threat Assessment Feed Status**:
  - `backend/app/analysis.py`: Added explicit branch in `_build_threat_assessment` surfacing when threat feeds are offline/unreachable, novel/unreported, or returned no matching records.
- **Elimination of Hardcoded TI Mock Data**:
  - `backend/app/ioc_extractor.py`: Removed hardcoded `Emotet`, `Google LLC`, `AS15169`, and `reputation_score=95` fabrication; retained honest `known_c2=True` indicator classification.
- **Structured Threat Intelligence Section**:
  - `backend/app/analysis.py`: Implemented `_build_threat_intelligence_summary` and attached `"threat_intelligence"` across case details and analysis pipeline returns.

### B5 — Narrative, IoC & Detection-Rule Coverage
- **Guaranteed Primary Hash IoC Presence**:
  - `backend/app/analysis.py`: Refactored `_build_ioc_intelligence` to unconditionally record `HASH_SHA256` (and `HASH_MD5`, `HASH_SHA1` if present), classifying with `STATIC` evidence state when TI is absent or negative, and `INTEL` when confirmed by MalwareBazaar.
- **Persistence Artifacts & Process Tree in IoC Intelligence**:
  - `backend/app/analysis.py`: Surface persistence paths as `PERSISTENCE_PATH` IoCs with appropriate `OBSERVED`/`STATIC` states, and process executions from dynamic sandbox as `PROCESS` IoCs with PID context.
- **Quiet Run Narrative Accuracy**:
  - `agents/narrative_agent/narrative.py`: Updated quiet run handling to eliminate fabricated `threat-intelligence matches (unclassified)` statements when TI is unclassified or absent.

## [v4.1.4] — Phase 4: B1–B3 Security, Integrity & Sandbox Architecture (2026-10-03)

### B1 — Security & Integrity
- **Artifact Manifest HMAC Verification**:
  - `sandbox-host/app/runner.py`: Manifests are cryptographically signed with HMAC-SHA256 (`_hmac`) using the shared secret (`SANDBOX_API_TOKEN`).
  - `backend/app/sandbox.py`: Added `verify_manifest_hmac()`. Verifies HMAC signature on downloaded `manifest.json` before accepting artifacts; tampered manifests reject dynamic analysis with `status="failed"`.
- **Evidence-to-Sample Cryptographic Binding**:
  - `backend/app/sandbox.py`: Added `compute_file_sha256()`. Fetches `meta.json`, verifies its hash against `manifest.json`, and strictly validates `meta["sample_sha256"] == submitted_sha256`. Mismatched sample hashes reject dynamic evidence.
- **Evidence Chain Verification Hardening**:
  - `agents/investigation_engine/chain_verification.py`: Bound `sample_sha256` explicitly into link metadata and cryptographic signature data. Tampered metadata or artifacts produce `VerificationStatus.TAMPERED`.
- **Test Suite Updates**:
  - `backend/tests/test_sandbox_integration_stage3.py`: Updated `test_sandbox_manifest_mismatch_detection` to test artifact hash mismatch against signed manifests with metadata binding.

### B2 — Security Boundaries
- **Path Traversal & UUID Validation**:
  - `sandbox-host/app/main.py`: Added `validate_job_id()` requiring strict UUID format for `/jobs/{job_id}`, `/jobs/{job_id}/artifacts/{artifact_name}`, and `DELETE /jobs/{job_id}` endpoints.
  - `sandbox-host/app/runner.py`: Enforced path containment checks in `prepare_job_dir()` and `clean_job_dir()`.
- **Artifact Whitelist Enforcement**:
  - `sandbox-host/app/main.py`: Added strict `ALLOWED_ARTIFACTS` whitelist (`strace.log`, `capture.pcap`, `fs_diff.json`, `stdout.log`, `stderr.log`, `meta.json`, `manifest.json`). Disallows directory traversal and re-downloading of the sample binary.
- **Subprocess Environment Scrubbing**:
  - `sandbox-host/app/runner.py`: Subprocess execution passes explicit minimal `SAFE_EXEC_ENV` (`PATH`, `LANG`, `LC_ALL`), preventing host secrets and `SANDBOX_API_TOKEN` from leaking into child processes.
- **Untrusted Filename Handling**:
  - `sandbox-host/app/main.py` & `runner.py`: Sample uploads are saved strictly as `sample.bin` within isolated job directories, never using client-provided filenames as filesystem paths.

### B3 — Sandbox Architecture
- **Execution Lifecycle State Distinction**:
  - `sandbox-host/app/runner.py`: Fixed state resolution bug that unconditionally returned `"completed"`. Runner now returns distinct states: `"completed"`, `"timed_out"` (exit code -9), `"failed"` (crashes / non-zero exits), and `"incomplete"`.
  - `sandbox-host/app/main.py`: `/jobs/{job_id}` returns the actual recorded lifecycle status from `meta.json`.
- **Status Propagation in Backend**:
  - `backend/app/sandbox.py`: Polling loop and handlers propagate `"timed_out"`, `"failed"`, and `"incomplete"` states, preventing timed-out or crashed executions from being falsely reported as successful completed analyses.
## E2E fixture integrity
- Restored bug fixtures from 677d17c for detector and pipeline regression coverage; retained the synthetic provenance marker on synthetic_mirai_droppee.json. Updated tests/e2e/fixtures/MANIFEST.sha256 to pin the restored fixture bytes.

- Restored fixture `base64_and_system_libs_as_paths.json` from 677d17c to preserve the original detector regression case; its SHA-256 is recorded in the fixture manifest.
- Restored fixture `benign_hosts_suspicious.json` from 677d17c to preserve the original detector regression case; its SHA-256 is recorded in the fixture manifest.
- Restored fixture `fabricated_narrative.json` from 677d17c to preserve the original detector regression case; its SHA-256 is recorded in the fixture manifest.
- Restored fixture `go_symbols_as_domains.json` from 677d17c to preserve the original detector regression case; its SHA-256 is recorded in the fixture manifest.
- Restored fixture `llm_refusal.json` from 677d17c to preserve the original detector regression case; its SHA-256 is recorded in the fixture manifest.
- Restored fixture `random_fragment_domains.json` from 677d17c to preserve the original detector regression case; its SHA-256 is recorded in the fixture manifest.
- Restored fixture `static_rule_labeled_intel.json` from 677d17c to preserve the original detector regression case; its SHA-256 is recorded in the fixture manifest.
- Restored fixture `synthetic_mirai_droppee.json` from 677d17c to preserve the original detector regression case; its SHA-256 is recorded in the fixture manifest.
- Restored fixture `clean_control.json` from 677d17c to preserve the original clean control sample; it remains the clean reference.

- Restored fixture `credential_advice_no_evidence.json` from 677d17c to preserve the original regression sample; the SHA-256 is recorded in the fixture manifest.
- Restored fixture `critical_all_vendors_clean.json` from 677d17c to preserve the original regression sample; the SHA-256 is recorded in the fixture manifest.
- Restored fixture `duplicate_timestamps_synthetic_offset.json` from 677d17c to preserve the original regression sample; the SHA-256 is recorded in the fixture manifest.
- Restored fixture `static_cap_exceeded.json` from 677d17c to preserve the original regression sample; the SHA-256 is recorded in the fixture manifest.

## Day 2b — detector and pipeline regression coverage
- Added layer-1 expected-violation coverage for all 12 frozen bug fixtures and clean-control zero-violation coverage.
- Added raw pipeline inputs, report-builder IOC validation, mocked narrative entrypoint checks, and static-YARA C2 provenance coverage.
- Static YARA/network hits now report STATIC network communication; static evidence cannot create c2_communication.
- Contextually accept valid short-SLD domain names from URLs and observed DNS queries while retaining the three-character rule for bare domains.

## Day 3 — score, timeline, recommendation, and MITRE safeguards
- Capped reported static MITRE and capability contributions, gated unsupported CRITICAL scores, and assigned zero score to generic/compiler/hash-constant YARA rules.
- Removed synthetic approximate timeline timestamps while preserving event sequence labels.
- Suppressed credential remediation advice without a credential capability and limited T1071 techniques to observed network traffic.
