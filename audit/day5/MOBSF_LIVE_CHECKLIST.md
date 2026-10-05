# MobSF Live Integration & Dynamic Analyzer Checklist

## 1. Static Analysis (Operational)
- [x] **Host Reachability**: MobSF server reachable at configured `MOBSF_URL` (`http://localhost:8003`).
- [x] **API Key Authentication**: Authenticated via `Authorization` and `X-Mobsf-Api-Key` headers (probe POST `/api/v1/upload` returns HTTP 400).
- [x] **Static Routes Verified**:
  - `POST /api/v1/upload`: uploads APK, returns `hash`.
  - `POST /api/v1/scan`: triggers static analysis for `hash`.
  - `POST /api/v1/report_json`: retrieves complete static JSON report.
  - `POST /api/v1/delete_scan`: purges scan data from MobSF.
- [x] **Static Findings Normalized**:
  - Package name, version, SDKs (min/target).
  - Permissions with dangerous flagged.
  - Exported components (activities, services, receivers, providers).
  - Signing certificate (subject, issuer, SHA-256, debug/self-signed flag).
  - Native libraries (.so files).
  - MobSF static code/manifest findings attributed to `provider:mobsf`.
- [x] **Mandatory Cleanup**: `delete_scan` is called in `finally` block; deletion errors are logged without failing analysis.

## 2. Dynamic Analysis (Gated)
Dynamic analysis runs ONLY if all 4 conditions hold:
1. `MOBSF_DYNAMIC=true`
2. `MOBSF_DYNAMIC_ISOLATION_CONFIRMED=true`
3. `MOBSF_DYNAMIC_TIMEOUT` set (e.g. `30`)
4. Dynamic analyzer / Android emulator confirmed ready via `/api/v1/dynamic/is_ready`.

### Current Dynamic Status: Gated / Offline
- **Emulator Status**: Host Android x86_64 emulator is currently ADB `offline`.
- **Readiness Probe**: Returns unready/offline.
- **Defensible Behavior**: Dynamic analysis is NOT faked or forced. The pipeline emits:
  `Dynamic analysis not performed: analyzer/emulator not ready`
- **Integrity Guarantee**: Static analysis continues to function normally and report all static findings.
