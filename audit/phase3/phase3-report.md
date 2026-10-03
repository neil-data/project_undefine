# Phase 3 Audit Report — Report, PDF & GeoIP Fixes (Fixes A11–A16)

**Date**: 2026-10-03  
**Status**: **PASS**  
**Target Scope**: Fixes A11 through A16 only (Report correctness, PDF generation, PDF formatting/rendering, report data consistency, GeoIP presentation/enrichment).  
**Out of Scope**: Phase 4+ (Sandbox infrastructure, security/integrity hardening, deployment scripts, threat feed expansion) — all strictly untouched.

---

## 1. Executive Summary

Phase 3 addressed report truthfulness, PDF document layout stability, recommendation precision, evidence timeline consistency, MalwareBazaar family normalization, and offline GeoIP status transparency (A11–A16). Development strictly followed the Test-Driven Development (TDD) cycle:

1. **15 targeted regression tests** were authored in `backend/tests/test_phase3_regression.py` before modifying production code.
2. Baseline execution against Phase 2 code recorded **11 failures and 4 passes** (trace preserved in `audit/phase3/baseline-failures.txt`).
3. Targeted, minimal production changes were applied to:
   - `backend/app/sandbox.py` (A11)
   - `backend/app/analysis.py` (A12, A13, A14, A15)
   - `backend/app/geoip.py` (A16)
   - `agents/investigation_engine/investigation_engine.py` (A12)
   - `frontend/src/lib/reportPdf.tsx` (A11, A13, A14, A16)
4. Post-fix execution of `test_phase3_regression.py` resulted in **15 passed, 0 failed (100% PASS)**.
5. The combined Phase 1 + Phase 2 + Phase 3 regression suites produced **79 passed, 0 failed**.
6. The entire repository test suite (`pytest`) passed with **915 passed, 0 failed, 1 warning** in 113.47s.
7. The isolated `sandbox-host/tests` suite passed with **11 passed, 0 failed**.
8. Frontend typecheck (`tsc --noEmit`) and production build (`vite build`) completed with **0 errors**.

---

## 2. Issues Summary Table

| Issue ID | Description | Root Cause | Baseline Failure Count | Status |
| :--- | :--- | :--- | :--- | :--- |
| **A11** | Duplicate dynamic failure prefix & `Duration: nulls` | `sandbox.py` returned `failure_reason="Dynamic analysis not performed: SANDBOX_API_URL is not configured"`, while `reportPdf.tsx` prepended `"Dynamic analysis not performed: "` again. `reportPdf.tsx` checked `duration_seconds !== undefined`, evaluating true for `null` and printing `"Duration: nulls"`. | 1 failing test | **PASS** |
| **A12** | Redundant isolation advice, sinkholing `index.html`, missing firewall rules & persistence hunt | `analysis.py` and `investigation_engine.py` emitted un-deduplicated isolation advice; `c2_domains` contained non-domain filenames like `index.html`; C2 IPs lacked structured firewall rules (`iptables`); static persistence paths were not recommended for remediation when dynamic was absent. | 3 failing tests | **PASS** |
| **A13** | Timeline layout & caption distortion | `submitted_at` was assigned to both "Sample received" and "Static analysis completed" identically; an 80-character explanation sentence was placed directly into the `timestamp` cell; table lacked separate `Seq #` column and caption. | 2 failing tests | **PASS** |
| **A14** | PDF page 2 footer overflow on 100+ strings | `reportPdf.tsx` dumped all `explainedStrings` into a single list without truncation or capacity limits, overflowing beneath the fixed 1123px page container footer. | 1 failing test | **PASS** |
| **A15** | Raw MalwareBazaar rule name shown (`Linux_Trojan_Gafgyt_...`) | Raw rule strings from MalwareBazaar community YARA rules were used directly in threat assessment and LLM prompts, displaying hash suffixes and triggering false family classification disagreements. | 1 failing test | **PASS** |
| **A16** | GeoIP missing-database handling | `geoip.py:lookup_ip()` and `lookup()` returned `None` for both unconfigured DB and unmapped IP; `reportPdf.tsx` displayed identical fallback dashes (`—`), obscuring database configuration failure. | 3 failing tests | **PASS** |

---

## 3. Deep Dive: Bug, Root Cause, Implementation & Verification

### A11 — Duplicate Dynamic Failure String & `Duration: nulls`
- **Bug**: The PDF report rendered `"Dynamic analysis not performed: Dynamic analysis not performed: SANDBOX_API_URL is not configured"` and `"Duration: nulls"` when dynamic execution was unconfigured or returned null duration.
- **Root Cause**:
  1. `backend/app/sandbox.py:127`: `failure_reason` was initialized with the redundant prefix `"Dynamic analysis not performed: SANDBOX_API_URL is not configured"`.
  2. `frontend/src/lib/reportPdf.tsx:316`: Prepend operation unconditionally concatenated `"Dynamic analysis not performed: "` to `reason`.
  3. `frontend/src/lib/reportPdf.tsx:327`: Checked `if (d.duration_seconds !== undefined)`. Since JSON/Python passes `null` for unset numbers, `null !== undefined` is `true`, causing `String(null) + "s"` to render as `"nulls"`.
- **Implementation**:
  - In `backend/app/sandbox.py`: Cleaned `failure_reason` to `"SANDBOX_API_URL is not configured"`.
  - In `frontend/src/lib/reportPdf.tsx`: Sanitized `reason` by stripping any leading `"Dynamic analysis not performed: "` prefix before rendering; updated duration check to `if (d.duration_seconds != null && d.duration_seconds !== undefined && !isNaN(Number(d.duration_seconds)))`.
- **Verification Tests**:
  - `TestA11DynamicFailureAndDuration::test_a11_unconfigured_sandbox_failure_reason_no_redundant_prefix`
  - `TestA11DynamicFailureAndDuration::test_a11_null_duration_seconds_is_none`

---

### A12 — Recommendations Correctness, Deduplication, Firewall Rules & Persistence Hunt
- **Bug**: Recommendations repeatedly advised host isolation with conflicting phrasing (`"Isolate the affected device..."` vs `"Isolate infected endpoint(s)..."`), recommended sinkholing non-domains like `index.html` at internal DNS, omitted structured perimeter firewall rules for confirmed C2 IPs, and failed to recommend hunting for static persistence paths when dynamic analysis was not run.
- **Root Cause**:
  1. `backend/app/analysis.py:_generate_recommendations()` added its own isolation string without checking if `existing_recommendations` already contained an isolation action.
  2. Domain sinkhole extraction did not run `_is_valid_domain()` validation, permitting filenames like `index.html` or `rc.local`.
  3. `c2_ips` were only listed as prose without structured firewall blocking instructions (`iptables -A OUTPUT -d <IP> -j DROP`).
  4. Persistence removal was only emitted from `dynamic_output.persistence_artifacts` or `dynamic_output.registry_changes`; static persistence paths were ignored.
- **Implementation**:
  - In `backend/app/analysis.py:_generate_recommendations()`:
    - Added deduplication: checked `has_existing_isolation = any("isolate" in r.lower() for r in recs)` before appending isolation advice.
    - Added domain validation: filtered `suspicious_doms = [d for d in c2_domains if _is_valid_domain(d) and not any(d.endswith(x) for x in ...)]`.
    - Structured perimeter firewall rules: formatted each confirmed C2 IP into `f"Block outbound traffic to confirmed C2 IP {ip} at perimeter firewalls (iptables -A OUTPUT -d {ip} -j DROP)."`.
    - Added `static_persistence_paths: Optional[list[str]] = None` parameter: when dynamic artifacts are absent, emits `f"Audit and remove suspected static persistence artifacts: {'; '.join(str(p) for p in static_persistence_paths[:3])}."`.
  - In `agents/investigation_engine/investigation_engine.py`: Added domain extension filter rejecting `.html`, `.htm`, `.php`, `.txt`, `.bin`, `.sh`, `.py`, `.so`, `.exe` and slashes.
- **Verification Tests**:
  - `TestA12RecommendationsCorrectness::test_a12_deduplicates_isolation_advice`
  - `TestA12RecommendationsCorrectness::test_a12_does_not_sinkhole_index_html_or_non_domains`
  - `TestA12RecommendationsCorrectness::test_a12_structured_perimeter_firewall_rules_for_c2_ips`
  - `TestA12RecommendationsCorrectness::test_a12_static_persistence_hunt_when_dynamic_absent`

---

### A13 — Evidence Timeline Layout, Timestamps & Sequence Numbering
- **Bug**: "Sample received" and "Static analysis completed" displayed identical timestamps (`submitted_at`); runtime events with unrecorded timestamps inserted an 80-character prose sentence (`Approximate relative execution sequence...`) into the `timestamp` cell; table lacked separate `Seq #` column and top-level disclaimer caption.
- **Root Cause**:
  - `backend/app/analysis.py:_build_evidence_timeline()` set `{"timestamp": submitted_at}` for both initial events, and inserted `ts = f"Approximate relative execution sequence (event timestamps unrecorded) [Seq #{event_idx}]"` as the timestamp cell string.
  - `frontend/src/lib/reportPdf.tsx` rendered the timeline table with only 4 columns (`Timestamp`, `Event`, `Source`, `Indicator`) and no disclaimer.
- **Implementation**:
  - In `backend/app/analysis.py:_build_evidence_timeline()`:
    - Offset `static_ts` from `submitted_at` by +1 second (or sequential delta) so ingestion and static completion are distinct and chronologically ordered.
    - Added integer sequence numbers (`"seq": 1`, `"seq": 2`, ...).
    - Replaced the 80-character prose string in the `timestamp` cell with clean relative sequence markers (e.g. `+1s (approx)` or clean relative delta).
  - In `frontend/src/lib/reportPdf.tsx`:
    - Added a dedicated `#` (`Seq #`) column with constrained width (`36px`).
    - Added top-level disclaimer caption: `"* Event timestamps for runtime trace reflect approximate execution sequence where exact timestamps were unrecorded."`.
- **Verification Tests**:
  - `TestA13EvidenceTimelineLayout::test_a13_sample_received_and_static_analysis_timestamps_distinguishable`
  - `TestA13EvidenceTimelineLayout::test_a13_timestamp_cell_is_clean_not_long_sentence`

---

### A14 — PDF Page 2 Footer Overflow on Static Explained Strings
- **Bug**: When a binary contained 100+ explained strings, Unit 5 (Static Analysis) rendered all strings in a single continuous `<ul>`, overflowing the fixed 1123px page container and printing under the fixed footer.
- **Root Cause**: `frontend/src/lib/reportPdf.tsx` lacked truncation or pagination bounds for `activeCase.explainedStrings`.
- **Implementation**:
  - In `backend/app/analysis.py`: Added `_format_pdf_static_strings(explained_strings, max_items=20)` returning `(truncated_list, overflow_count)`.
  - In `frontend/src/lib/reportPdf.tsx`: Capped Unit 5 `explainedStrings` to top 20 items and added an informative summary note:
    `Showing top 20 of N explained strings (+X additional strings omitted for PDF layout; complete list preserved in raw JSON).`
- **Verification Tests**:
  - `TestA14StaticStringsTruncation::test_a14_explained_strings_capped`
  - Full frontend production build verification (`npm run build` completed cleanly).

---

### A15 — Malware Family Normalization from MalwareBazaar YARA Rules
- **Bug**: Community YARA rules from MalwareBazaar (e.g., `Linux_Trojan_Gafgyt_0cd591cd`) were passed verbatim to threat assessment key findings and LLM prompts. This exposed internal hash suffixes to the user and caused false family classification disagreements when MalwareBazaar signature was `Gafgyt` but the YARA rule was named `Linux_Trojan_Gafgyt_0cd591cd`.
- **Root Cause**: `_build_threat_assessment` in `backend/app/analysis.py` did not normalize family names from rule strings before comparing or printing them.
- **Implementation**:
  - Authored `normalize_malware_family(rule_name: str) -> str`:
    - Strips `[MalwareBazaar]` prefixes.
    - Preserves generic/community indicators (e.g. `Community_Yara`).
    - Strips OS/architecture tokens (`linux`, `win32`, `elf`, etc.), category tokens (`trojan`, `backdoor`, `worm`, etc.), and hex hashes (`_0cd591cd`).
    - Normalizes known malware families (`Mirai`, `Gafgyt`, `Mozi`, `Tsunami`, `Qbot`, etc.).
  - In `_build_threat_assessment`: Used `normalize_malware_family` for both MalwareBazaar signature and YARA rule names. False disagreement is suppressed when normalized families agree; true disagreements cite clean family names rather than raw rule strings.
- **Verification Tests**:
  - `TestA15MalwareFamilyNormalization::test_a15_normalize_malware_family_names`
  - `TestA15MalwareFamilyNormalization::test_a15_no_false_family_disagreement_when_normalized_names_match`
  - `TestA15MalwareFamilyNormalization::test_a15_flags_family_disagreement_with_normalized_name_when_truly_different`

---

### A16 — GeoIP Missing Database Handling vs Unmapped IP
- **Bug**: When `GEOIP_DB_PATH` was unset or missing, `lookup()` returned `None`. This was indistinguishable from an IP having no record in an active MaxMind database. Both cases produced fallback dashes (`—`), hiding database configuration failure from analysts.
- **Root Cause**: `backend/app/geoip.py` lacked explicit status modeling and lacked a dedicated `lookup_ip()` function returning status metadata (`database_not_configured`, `no_record`, `private`, `resolved`).
- **Implementation**:
  - In `backend/app/geoip.py`:
    - Added `get_status() -> dict` returning database configuration state, availability, and configured paths.
    - Added `lookup_ip(ip: str) -> Optional[dict]` returning explicit `status`:
      - `private`: RFC 1918 / RFC 4193 private IP.
      - `database_not_configured`: local MaxMind database reader is not loaded.
      - `no_record`: MaxMind database is loaded, but IP has no geolocation record.
      - `resolved`: IP successfully attributed.
    - Guarded external HTTP fallback behind `GEOIP_HTTP_FALLBACK` environment variable to ensure strict air-gap compliance by default.
  - In `frontend/src/lib/reportPdf.tsx`:
    - When database is unconfigured, displays an unconfigured banner:
      `"Offline GeoIP database is not configured. Geographic and ASN attribution is unavailable."`
    - In the table row, displays `"Database unconfigured"` in the Location and ISP/ASN cells rather than blank dashes (`—`).
- **Verification Tests**:
  - `TestA16GeoIPStatusDistinction::test_a16_lookup_ip_unconfigured_database`
  - `TestA16GeoIPStatusDistinction::test_a16_lookup_ip_private_ip`
  - `TestA16GeoIPStatusDistinction::test_a16_get_status`

---

## 4. Test Suite Execution & Evidence

### Phase 3 Regression Suite (`backend/tests/test_phase3_regression.py`)
```text
============================= test session starts =============================
platform win32 -- Python 3.11.3, pytest-8.4.2, pluggy-1.6.0
rootdir: C:\Users\Neil\Downloads\E_Rakshak_v4.1\E-Rakshak_v3.0\E-Rakshak_v2.8
configfile: pytest.ini

backend/tests/test_phase3_regression.py::TestA11DynamicFailureAndDuration::test_a11_unconfigured_sandbox_failure_reason_no_redundant_prefix PASSED [  6%]
backend/tests/test_phase3_regression.py::TestA11DynamicFailureAndDuration::test_a11_null_duration_seconds_is_none PASSED [ 13%]
backend/tests/test_phase3_regression.py::TestA12RecommendationsCorrectness::test_a12_deduplicates_isolation_advice PASSED [ 20%]
backend/tests/test_phase3_regression.py::TestA12RecommendationsCorrectness::test_a12_does_not_sinkhole_index_html_or_non_domains PASSED [ 26%]
backend/tests/test_phase3_regression.py::TestA12RecommendationsCorrectness::test_a12_structured_perimeter_firewall_rules_for_c2_ips PASSED [ 33%]
backend/tests/test_phase3_regression.py::TestA12RecommendationsCorrectness::test_a12_static_persistence_hunt_when_dynamic_absent PASSED [ 40%]
backend/tests/test_phase3_regression.py::TestA13EvidenceTimelineLayout::test_a13_sample_received_and_static_analysis_timestamps_distinguishable PASSED [ 46%]
backend/tests/test_phase3_regression.py::TestA13EvidenceTimelineLayout::test_a13_timestamp_cell_is_clean_not_long_sentence PASSED [ 53%]
backend/tests/test_phase3_regression.py::TestA14StaticStringsTruncation::test_a14_explained_strings_capped PASSED [ 60%]
backend/tests/test_phase3_regression.py::TestA15MalwareFamilyNormalization::test_a15_normalize_malware_family_names PASSED [ 66%]
backend/tests/test_phase3_regression.py::TestA15MalwareFamilyNormalization::test_a15_no_false_family_disagreement_when_normalized_names_match PASSED [ 73%]
backend/tests/test_phase3_regression.py::TestA15MalwareFamilyNormalization::test_a15_flags_family_disagreement_with_normalized_name_when_truly_different PASSED [ 80%]
backend/tests/test_phase3_regression.py::TestA16GeoIPStatusDistinction::test_a16_lookup_ip_unconfigured_database PASSED [ 86%]
backend/tests/test_phase3_regression.py::TestA16GeoIPStatusDistinction::test_a16_lookup_ip_private_ip PASSED [ 93%]
backend/tests/test_phase3_regression.py::TestA16GeoIPStatusDistinction::test_a16_get_status PASSED [100%]

============================= 15 passed in 1.43s ==============================
```

### Cumulative Regression Suite (Phase 1 + Phase 2 + Phase 3)
```text
collected 79 items
backend/tests/test_phase1_regression.py .................................... [ 45%]
backend/tests/test_phase2_regression.py ............................         [ 81%]
backend/tests/test_phase3_regression.py ...............                      [100%]
============================= 79 passed in 3.08s ==============================
```

### Full Repository Test Suite (`pytest`)
```text
================================ test session starts ================================
platform win32 -- Python 3.11.3, pytest-8.4.2, pluggy-1.6.0
rootdir: C:\Users\Neil\Downloads\E_Rakshak_v4.1\E-Rakshak_v3.0\E-Rakshak_v2.8
configfile: pytest.ini
915 passed, 1 warning in 113.47s (0:01:53)
```

### Sandbox Host Test Suite (`pytest sandbox-host/tests`)
```text
sandbox-host/tests/test_sandbox_host.py ...........                      [100%]
============================= 11 passed in 2.66s ==============================
```

### Frontend Build & Typecheck
```text
> react-example@0.0.0 lint
> tsc --noEmit
(Exit code 0, 0 errors)

> react-example@0.0.0 build
> vite build
✓ built in 15.80s
(Exit code 0)
```

---

## 5. Non-Regression & Scope Boundary Adherence

- **Untouched Scope**:
  - `audit/phase0/`, `audit/phase1/`, `audit/phase2/` preserved byte-for-byte.
  - No changes made to EXE or APK parsers or format handlers.
  - Phase 4+ tasks (sandbox infrastructure, guest runners, security locks, threat feeds) were NOT started.
- **TDD Compliance**: All baseline failures were documented and committed before production code adjustments.
- **Evidence Truth**: All 15 Phase 3 tests and all 915 repository tests passed without skipping, weakening, or deleting tests.

---

## 6. Phase 3 Conclusion

Phase 3 is **COMPLETE and PASS**. All audit items **A11 through A16** are resolved and proven by passing automated tests and clean frontend build verification.

**STOP**: As instructed, stopping now before Phase 4.
