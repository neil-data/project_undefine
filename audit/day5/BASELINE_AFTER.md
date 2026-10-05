# Day 5 Baseline After (Final)

- Full suite: **1,221 passed, 1 skipped** across all testpaths (`analysis`, `apps/backend/tests`, `apps/ingestion`, `sandbox/host/tests`, `tests`).
- E2E: **60 passed, 1 skipped**; includes frozen fixture integrity, baseline, Mach-O static-only, and Day 5 integration lanes.
- Day 5 new tests: **19 passed** across all Day 5 unit and integration test files:
  - `tests/unit/test_hybrid_analysis_adapter.py`: 7 passed
  - `tests/unit/test_mobsf_adapter.py`: 4 passed
  - `tests/unit/test_parsers_mobsf.py`: 2 passed
  - `tests/e2e/test_day5_integration_lanes.py`: 6 passed
  - `tests/test_provider_scripts.py`: 7 passed (from preflight)
- Frozen fixtures unchanged; `test_fixture_integrity` green.
- Provider recordings committed in `tests/fixtures/providers/hybrid_analysis/` with SHA-256 manifest and `RECORDING_SUMMARY.md`.
- End-to-end connected pipeline verified across all 6 lanes:
  - Lane 1: Hybrid Analysis with observed behavior (DYNAMIC finding, capped confidence, correlation)
  - Lane 2: Hybrid Analysis verdict-only (INTEL finding only, zero dynamic findings, risk score unchanged)
  - Lane 3: Hybrid Analysis hash not found (clean NO_RESULT fallback)
  - Lane 4: MobSF static APK analysis (package, permissions, components, certs normalized)
  - Lane 5: MobSF dynamic gating (emulator offline -> cleanly skipped without faking)
  - Lane 6: Mach-O static-only (zero dynamic execution)
- Live check script `scripts/live_check.py` returns 0 with defensible gating and explicit reasons.
