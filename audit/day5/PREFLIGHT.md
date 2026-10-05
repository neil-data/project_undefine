# Day 5 Preflight & Self-Check Status

Captured 2026-10-05. `scripts/provider_selfcheck.py` and `scripts/live_check.py` executed cleanly.
Zero secrets, credentials, or real sample bytes were printed, stored, or exposed.

| Provider / Check | Status | Reason |
| --- | --- | --- |
| Hybrid Analysis runtime key | PASS | `HYBRID_ANALYSIS_API_KEY` present and loaded via centralized config loader (value redacted). |
| Hybrid Analysis hash lookup | PASS | Documented GET `https://www.hybrid-analysis.com/api/v2/search/hash` verified (HTTP 200). |
| Hybrid Analysis environments | PASS | Parsed dynamically from verified environments recording (`environments.json`), selecting Linux ID 330 and Windows ID 160. |
| Hybrid Analysis key-info / quota | PASS | Recorded in `key_current.json` (auth_level 1, restricted). |
| Hybrid Analysis submission | GATED / SKIP | External sample submission disabled (`ALLOW_EXTERNAL_SUBMISSION=false`); restricted key cannot submit. |
| MobSF URL reachability | PASS | MobSF server verified reachable at `http://localhost:8003`. |
| MobSF API key acceptance | PASS | Probed `/api/v1/upload` without file; returned HTTP 400 (auth accepted). |
| MobSF static pipeline | PASS | Upload -> scan -> report_json -> normalize -> delete_scan workflow verified. |
| MobSF dynamic analyzer | GATED / SKIP | Android emulator is ADB `offline`; dynamic analysis safely skipped (`Dynamic analysis not performed: analyzer/emulator not ready`). |
| Mach-O platform | PASS | Verified static-only routing without dynamic execution (`Dynamic analysis: not performed (static-only)`). |
| Unsupported architectures | PASS | ELF non-x86_64 cleanly mapped to `NOT_SUPPORTED_PLATFORM`. |
