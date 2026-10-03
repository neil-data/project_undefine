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