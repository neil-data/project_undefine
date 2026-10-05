# Day 4 baseline after

- Base: Day 3 commit `c8276e2`.
- Day 4 commits: `70ed9ba`, `8be8f22`, `f13c3f4`, `efc3a2c`, `2147b8e`, plus
  the parser commit created with this baseline.
- Last full-suite run: **1,158 passed, 1 skipped** (before Parts 1 and 5).
- Part 0 focused tests: **3 passed**.
- Part 1/4 focused trust-boundary tests: **28 passed**.
- Part 5 focused parser tests: **8 passed**.
- Frozen fixtures were not modified. The full-suite run included the fixture
  integrity test. No `.env` content was read.
- No real provider requests, uploads, malware execution, or live checks ran.
- Hybrid Analysis submission/poll/report/environment/quota contracts and the
  installed MobSF API contracts remain UNVERIFIED as recorded in `NOTES.md`.
- LIEF/androguard-specific coverage and MobSF APK extraction remain partial;
  built-in native binary parsers passed the focused generated-input suite.
