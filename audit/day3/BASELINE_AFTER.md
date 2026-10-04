# Day 3 regression baseline after fixes

## Final test runs

- Full suite: **1066 passed**, 1 warning, 255.57s.
- E2E suite: **53 passed, 1 manual layout skip**, 7.68s.
- Layer 1: **15 passed**: 12 frozen bug fixtures, 2 additional expected violations for `synthetic_mirai_droppee`, and `clean_control` (zero violations). Fixture-integrity guard passed.
- Layer 2: **29 passed**: 11 Day 2 raw IOC cases, 8 `analyze_and_save` mocked/raw cases, and 10 Day 3b score/vendor/timeline/recommendation/MITRE/report-quality cases.
- Remaining e2e product-output assertions run against `clean_control`; the 12 original bad fixtures run through the detector map.

## Raw test matrix

| Layer 2 input group | Test inputs | Result |
|---|---|---|
| Day 2 IOC pipeline | Go symbols, random fragments, benign hosts, fabricated narrative, refusal, static rule as intel, static cap exceeded, critical with clean vendors, duplicate timestamps, credential advice without evidence, base64/system libraries | 11/11 passed |
| Pipeline mocked LLM/YARA | Five LLM failure modes, fabricated/refusal narrative raw inputs, static YARA capability | 8/8 passed |
| Score and verdict | Compiler/generic Go-style binary, family-specific rules, MalwareBazaar intel floor, explicit cap explanation and exact score sum | Passed |
| Vendor confidence | Unrated, one vendor, mixed clean/malicious, YOROI/vxCube/MalwareBazaar | 4/4 passed |
| Timeline | Completion stages, null display, duplicate times with distinct sequence IDs, no synthetic offsets | Passed |
| Recommendations | Case-insensitive dedupe, isolate/IP limits, persistence wording, evidence-gated credential advice, no invalid sinkhole | Passed |
| MITRE/capabilities | Static C2 rejection, provider-attributed DYNAMIC C2, platform IDs, static confidence/persistence caps | Passed |
| Report quality | Runtime timestamps, human-sized file sizes, truncation, explanation-string cap | Passed |

## Prior full-suite failure disposition

The 25 failures and collection error recorded before this run are resolved. Triage: `REGRESSION_TRIAGE.md`. Test edits, with no removed assertion lines: `TEST_DIFFS.patch`. Baseline command outputs: `e2e-before-3b.txt` and the final suite totals above. The only final skip is the pre-existing manual PDF layout check.
