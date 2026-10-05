# Day 5 Baseline After (Phase 1)

- Full suite: **1,202 passed, 1 skipped** across all testpaths (`analysis`, `apps/backend/tests`, `apps/ingestion`, `sandbox/host/tests`, `tests`).
- E2E: **54 passed, 1 skipped**; includes frozen fixture integrity and Mach-O static-only end-to-end test.
- Day 5 new unit tests: **7 passed** (`tests/test_provider_scripts.py`).
- Frozen fixtures unchanged; `test_fixture_integrity` green.
- Preflight self-check: Attempted once through the centralized config loader.
  - Hybrid Analysis key loaded and validated via documented GET `/search/hash` (HTTP 200).
  - MobSF compose tag warned (floating `latest`); connection refused on port 8001.
- Gate: Phase 2 is blocked on human execution of `audit/day5/HUMAN_STEPS.md` to produce and commit `tests/fixtures/providers/RECORDING_SUMMARY.md`.
