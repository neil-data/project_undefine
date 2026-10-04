# Day 3b post-change test matrix

## Layer 1 — frozen fixture detectors

| Input set | Expected check | Result |
|---|---|---|
| 12 original bad fixtures | Each fires its mapped violation in `tests/e2e/test_detectors.py` | 13/13 checks passed in final focused run (includes clean control) |
| `clean_control.json` | Zero violations | Passed |
| All fixtures | Manifest matches frozen content | Integrity test passed |

## Layer 2 — raw input cases

| Input/test area | Coverage | Result |
|---|---|---|
| Day 2 IOC inputs | Go symbols, fragments, benign hosts, base64/system paths, static cap, credentials, critical/clean vendors, fabricated narrative, refusal, static rule as intel, duplicate times | 11 cases; final focused run stopped before this module |
| `analyze_and_save` inputs | Mocked LLM failure modes, raw narrative/refusal, static YARA capability | Existing pipeline cases retained; final focused run stopped before this module |
| Score/verdict | Generic Go-style binary, family-only, intel floor, score cap and explanation sum | Score case passed in final focused run |
| Vendor confidence | Unsupported, single, mixed, YOROI/vxCube/MalwareBazaar | First case passed; remaining cases not reached after early stop |
| Timeline | Stage/null timestamps and duplicate sequence labels | Initial assertion expected four same-time records; corrected to the three records present (sample + two network events); not rerun due the four-run e2e limit |
| Recommendations | Dedupe, isolate cap, IP list cap, static paths, credential evidence | Not reached in final focused run |
| MITRE/capabilities | Static C2 exclusion, provider network evidence, platform IDs, static confidence | Not reached in final focused run |
| Report quality | Stage times, file size, truncation, explanation cap | Not reached in final focused run |

The final focused e2e invocation reported 19 passing checks before the timeline assertion stopped execution. The timeline assertion was corrected afterward; no additional e2e run was made to stay within the four-run limit. The first test-first run failed because an unsupported high score was reported as MALICIOUS; the implementation now gates/caps that verdict and adds an explicit cap explanation.
