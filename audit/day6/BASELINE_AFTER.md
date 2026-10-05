# Day 6 Baseline After (Final Freeze)

- Full test suite: **1,237 passed, 1 skipped** across all monorepo testpaths (\nalysis\, \pps/backend/tests\, \pps/ingestion\, \sandbox/host/tests\, \	ests\).
- E2E test suite: **69 passed, 1 skipped**; includes frozen fixture integrity, baseline tests, Day 5 provider lanes, Day 6 failure modes, and Day 6 acceptance pipeline.
- Unit test suite: **1,168 passed**; includes Day 6 unit failure modes (\	est_day6_failure_modes.py\).
- Day 6 new tests: **16 passed**:
  - \	ests/unit/test_day6_failure_modes.py\: 7 passed
  - \	ests/e2e/test_day6_failure_modes.py\: 5 passed
  - \	ests/e2e/test_day6_acceptance_pipeline.py\: 4 passed
- Frozen fixture integrity: 100% verified (\	ests/e2e/test_fixture_integrity.py\ green, \MANIFEST.sha256\ unchanged).
- Provider self-check & Live check: \scripts/provider_selfcheck.py\ and \scripts/live_check.py\ pass cleanly.
- Secret scan: \scripts/secret_scan.py\ scanned 511 tracked files with **0 active secrets detected**.
- Frontend typecheck & build: pm run lint\ (\	sc --noEmit\) and pm run build\ pass cleanly with 0 errors.
- Demo evidence generated: 4 sample cases (ELF, PE, APK, Mach-O) in \udit/day6/DEMO_EVIDENCE.md\ and cached multi-page PDF reports in \udit/day6/reports/\ and eports/\.
- Section 9 Audit Checklist: **25 / 25 criteria marked PASS** in \udit/day6/FINAL_AUDIT_CHECKLIST.md\.
