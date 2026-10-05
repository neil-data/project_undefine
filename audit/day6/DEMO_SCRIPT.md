# Day 6 — Final Demo Walkthrough & Rehearsal Guide

This guide details the step-by-step presentation script for the live competition demo, backup rehearsal, and video demonstration.

---

## 1. Quick Verification Pre-Flight (1 Minute)

Run the automated self-check and live provider check:
```bash
# 1. Verify provider connectivity & gating
python scripts/provider_selfcheck.py

# 2. Verify all analysis lanes
python scripts/live_check.py

# 3. Verify zero secrets
python scripts/secret_scan.py
```
Expected output: All lanes report PASS or clean defensive SKIP with honest reasons.

---

## 2. Multi-Modal Demo Flow (4 Platforms)

Run the full end-to-end acceptance demo generator:
```bash
python scripts/generate_day6_demo_evidence.py
```

### Scenario 1: Linux ELF x86_64
- **Sample**: `12c9f2477161b4fa...` (`mirai_dropper.elf`)
- **Key Talking Points**:
  - Full static disassembly and ELF section analysis.
  - Attributed dynamic execution under Hybrid Analysis Linux environment 330 (Task ID `ha-task-elf-12c9`).
  - Corroborated network observables: C2 endpoint matched between static strings and observed dynamic network connections.
  - Composite risk score: **70/100 (MALICIOUS)**.
  - Generated PDF report: `reports/elf_x86_64_12c9f2477161_report.pdf`.

### Scenario 2: Windows PE / EXE (Verdict-Only)
- **Sample**: `4faccd95d2372446...` (`banking_trojan.exe`)
- **Key Talking Points**:
  - Demonstrates the **verdict vs behavior policy**: provider verdict reports malicious score, but without observed execution, zero dynamic findings are fabricated.
  - Threat intelligence matches RedLineStealer signature from MalwareBazaar, establishing an honest intel floor.
  - Composite risk score: **85/100 (MALICIOUS)**.
  - Generated PDF report: `reports/pe__exe_4faccd95d237_report.pdf`.

### Scenario 3: Android APK (Static & Dynamic Gating)
- **Sample**: `02c4ef6bccf06e3a...` (`E-Rakshak_Harmless_Test.apk`)
- **Key Talking Points**:
  - Full MobSF static inspection: package extraction, dangerous permissions (`SEND_SMS`), exported activities, and certificates.
  - **Honest failure degradation**: local Android emulator is offline, so the platform cleanly displays `Dynamic analysis not performed: analyzer/emulator not ready` rather than inventing synthetic runtime traces.
  - Composite risk score: **24/100 (SUSPICIOUS)**.
  - Generated PDF report: `reports/apk_android_02c4ef6bccf0_report.pdf`.

### Scenario 4: macOS Mach-O (Static-Only Guarantee)
- **Sample**: `daf1bd1155108413...` (`security_agent.macho`)
- **Key Talking Points**:
  - Parsing thin and fat universal binaries and load commands.
  - Enforces the strict invariant: `Dynamic analysis: not performed (static-only)`.
  - Static-only MITRE confidence cap (<= 0.5).
  - Composite risk score: **15/100 (CLEAN)**.
  - Generated PDF report: `reports/mach-o_macos_daf1bd115510_report.pdf`.

---

## 3. Deliberate Failure Demonstration
Demonstrate the system's resilience by showcasing the failure test suite:
```bash
pytest tests/e2e/test_day6_failure_modes.py tests/unit/test_day6_failure_modes.py -v
```
Demonstrates that provider unavailability, timeouts, rate limits, and AI safety refusals degrade safely to deterministic fallbacks without crashing or hallucinating evidence.

---

## 4. Pre-Generated Artifact Backups
In case of presentation network failure, pre-generated forensic PDF reports and JSON cases are preserved in:
- `reports/`
- `audit/day6/reports/`
