# Day 5 Provider Notes — Full Integration & Verification

## 1. Provider Implementations
- **Hybrid Analysis Adapter** (`providers/dynamic/hybrid_analysis.py`):
  - Supported platforms: ELF x86_64, EXE, PE, DLL. Unsupported ELF architectures emit `NOT_SUPPORTED_PLATFORM`.
  - Routes verified from official docs & recordings: GET `/api/v2/search/hash`, GET `/api/v2/system/environments`, GET `/api/v2/key/current`, GET `/api/v2/overview/{sha256}/summary`.
  - Environments selected dynamically from recorded environment list (Linux ID 330, Windows ID 160).
  - Request/submission budgets enforced locally against `PROVIDER_DAILY_REQUEST_LIMIT` and `PROVIDER_DAILY_SUBMISSION_LIMIT`.
  - Verdict-only responses produce INTEL findings only and never modify `risk_score`. Zero dynamic evidence generated without reported behavior.
- **MobSF Adapter** (`sandbox/adapters/mobsf/adapter.py`):
  - Static APK analysis: uploads, triggers scan, retrieves `report_json`, normalizes package, SDK, permissions (flagging dangerous), exported components, signing certificate, and native libraries.
  - Mandatory cleanup: calls `delete_scan` in `finally` block (logs failures without masking results).
  - Dynamic APK analysis: strictly gated on `MOBSF_DYNAMIC=true`, `MOBSF_DYNAMIC_ISOLATION_CONFIRMED=true`, `MOBSF_DYNAMIC_TIMEOUT`, and emulator readiness. Because host Android emulator is ADB `offline`, dynamic analysis cleanly emits: `Dynamic analysis not performed: analyzer/emulator not ready`.
- **Parsers** (`analysis/static/static_analysis/unified_parser.py`):
  - Best-effort LIEF / androguard support with robust fallback to native ELF/PE/Mach-O parsers.
  - Enriched with verified MobSF static data for APKs.
  - All parser findings are `STATIC`, `evidence_state="STATIC"`, confidence `<= 0.5`. Zip entry names are never treated as domains/paths.

## 2. States & Attributions
| State | Behavior & Evidence | Report Line |
| --- | --- | --- |
| COMPLETED (Behavior) | Capped DYNAMIC / OBSERVED findings | `Provider <p> task <t> reported behavior: ...` |
| COMPLETED (Verdict-only) | INTEL finding only; zero dynamic findings; risk_score unchanged | `A provider verdict was reported, but no behavior was observed.` |
| NO_RESULT | Zero dynamic findings | `Dynamic analysis not performed: no result` |
| NOT_SUPPORTED_PLATFORM | Mach-O: static-only; Unsupported ELF: unsupported arch | `Dynamic analysis: not performed (static-only)` |
| KEY_MISSING | Zero dynamic findings | `Dynamic analysis not performed: key missing` |
| KEY_RESTRICTED | Zero dynamic findings | `Dynamic analysis not performed: key restricted` |
| SUBMISSION_DISABLED | Zero dynamic findings | `Dynamic analysis not performed: submission disabled` |
| RATE_LIMITED | Zero dynamic findings | `Dynamic analysis not performed: rate limited` |
| TIMEOUT | Zero dynamic findings | `Dynamic analysis not performed: timeout` |
| PROVIDER_UNAVAILABLE | Zero dynamic findings | `Dynamic analysis not performed: provider unavailable` |
| INVALID_RESPONSE | Atomic rejection, zero dynamic findings | `Dynamic analysis not performed: invalid response` |

## 3. End-to-End Connected Pipeline
`File -> Platform -> Static -> Provider -> Trust Boundary -> Evidence -> Correlation -> Score -> MITRE -> Grounded AI -> Report`
Proven across all lanes in `tests/e2e/test_day5_integration_lanes.py`:
- Task ID / provenance survives end-to-end.
- Observed network endpoints correlate with static indicators.
- Cache prevents redundant provider lookups.
- Provider verdict never alters `risk_score`.
- Provider attribution is explicit (`provider:hybrid_analysis`, `provider:mobsf`).
