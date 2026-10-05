# Day 6 — Honest Engineering & Operational Limitations

This document records the verified, honest limitations of the E-Rakshak triage and analysis platform as of Day 6 acceptance and code freeze.

---

## 1. Android Dynamic Analysis (MobSF)
- **Status**: GATED / UNVERIFIED LIVE
- **Root Cause**: While MobSF static analysis is fully operational (normalizing package, permissions, SDK, exported components, and signing certificates), the host Android emulator is ADB `offline`.
- **Defensive Behavior**: In strict accordance with the zero-simulation mandate, the platform never invents or simulates dynamic Android behavior. The pipeline emits:
  `Dynamic analysis not performed: analyzer/emulator not ready`
- **Audit Verification**: Verified in `tests/e2e/test_day5_integration_lanes.py` and `tests/e2e/test_day6_acceptance_pipeline.py`.

---

## 2. External Provider Automated Submissions (Hybrid Analysis)
- **Status**: POLICY-GATED / RESTRICTED KEY
- **Root Cause**: The current Hybrid Analysis API key operates at `auth_level: 1` (restricted). While public hash lookup, environment enumeration, and quota checks are verified live against official endpoints (HTTP 200), automated submission of new unknown binaries to external cloud sandbox is disabled by policy (`ALLOW_EXTERNAL_SUBMISSION=false`).
- **Defensive Behavior**: The platform protects sample confidentiality and strictly uses hash lookups and recorded environments. When a hash is unknown, it emits `Dynamic analysis not performed: no result` rather than inventing telemetry.

---

## 3. Mach-O macOS Platform
- **Status**: STRICTLY STATIC-ONLY
- **Root Cause**: The platform host runs Windows/Linux container environments. Native Darwin execution of Mach-O binaries is not supported.
- **Defensive Behavior**: Mach-O binaries are routed exclusively to the static parsing pipeline, rendering load commands, architecture slices, and static indicators. The dynamic pipeline emits the exact contract line:
  `Dynamic analysis: not performed (static-only)`
- **Audit Verification**: Verified in `tests/e2e/test_day5_macho_static_only.py` and `tests/e2e/test_day6_acceptance_pipeline.py`.

---

## 4. Unsupported ELF Architectures
- **Status**: STATIC-ONLY
- **Root Cause**: Cloud provider dynamic execution environments for ELF are restricted to Linux x86_64 (Environment ID 330).
- **Defensive Behavior**: Non-x86_64 ELF architectures (e.g. ARM, MIPS, PPC, RISC-V) are cleanly intercepted and emit:
  `Dynamic analysis not performed: unsupported platform (<architecture>)`
