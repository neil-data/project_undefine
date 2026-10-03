# Sandbox Host & Infrastructure Baseline (Phase 0)

Assessment of sandbox infrastructure, host controls, and multi-architecture emulation components.

| Component / Control | Current Implementation State | Source Location | Details |
|---|---|---|---|
| **Sandbox API Server** | **Real** | `sandbox-host/app/main.py` | FastAPI server exposing `/health`, `/canary`, `/jobs`, `/artifacts/{job_id}/{filename}`. |
| **Authentication / Bearer Token** | **Partial** | `sandbox-host/app/main.py:28` | Bearer token verified on `/jobs` and `/artifacts`, but `/health` is currently unauthenticated. |
| **Pre-detonation Egress Canary** | **Real** | `sandbox-host/app/canary.py` | UDP connection probe to `1.1.1.1:53` with 2.0s timeout; fails if socket connects (leak). Currently runs in host namespace, not isolated runner netns. |
| **Runner Lock / Concurrency** | **Real (HTTP 409)** | `sandbox-host/app/runner.py:RUNNER_LOCK` | In-memory asyncio lock. Rejects concurrent jobs with 409 Conflict (no job queue or 429+retry yet). |
| **Multi-Arch QEMU Runner** | **Real** | `sandbox-host/app/runner.py:ARCH_CONFIG` | Supports `x86_64`, `i386`, `arm`, `aarch64`, `mips`, `mipsel`, `riscv64`, `ppc` via `qemu-<arch>-static`. |
| **Rootfs Per-Architecture** | **Stubbed** | `sandbox-host/provision.sh:36` | `provision.sh` only runs `mkdir -p /opt/sandbox/rootfs/{...}`. No static busybox or `resolv.conf` built yet. |
| **Snapshot / Revert Enforcement** | **Unimplemented** | N/A | No automatic VM snapshot revert hook (503 "reverting" state until confirmed). |
| **Sample-only Seccomp Filter** | **Unimplemented** | N/A | No seccomp BPF filter applied to detonate sample without restricting runner/strace. |
| **TLS Enforcement** | **Unimplemented** | `sandbox-host/app/config.py` | Runs plain HTTP on port 8000; no cert pinning or TLS enforcement configuration. |
| **Artifact Size Caps** | **Unimplemented** | `sandbox-host/app/runner.py` | Raw `strace.log` and `capture.pcap` are captured without explicit file size truncation ceilings. |
| **Raw Artifact Storage & Retention** | **Real** | `sandbox-host/artifacts/` | Stores `strace.log`, `capture.pcap`, `fs_diff.json`, `stdout.log`, `stderr.log`, `meta.json`, `manifest.json`. Excluded from Git. |
| **Thin Client & SHA-256 Manifest** | **Real** | `backend/app/sandbox.py` | Downloads artifacts and verifies SHA-256 against `manifest.json`. Returns `dynamic_status="unavailable"` when unconfigured. |
| **HMAC Chain-of-Custody Binding** | **Partial** | `agents/investigation_engine/chain_verification.py` | Binds sample SHA-256, task_id, sandbox_id, artifact hashes, but still references `execution_mode` in link generation. |
| **UPX Unpack Worker** | **Unimplemented** | N/A | UPX unpacking is not decoupled into a sandboxed host job. |
