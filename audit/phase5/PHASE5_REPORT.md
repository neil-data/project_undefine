# Phase 5 Audit Report — Threat Intelligence, Narrative & IoC Coverage (Fixes B4–B5)

**Date**: 2026-10-03  
**Status**: **PASS**  
**Target Scope**: Fixes B4 and B5 only:
- **B4 (Threat Intelligence)**: External feed lookup correctness, transparent cache handling of negative and offline results, vendor verdict extraction (`malware_family`, `status`, `threat_name`), explicit threat assessment reporting when external TI is unavailable or novel, structured `threat_intelligence` metadata in case output, elimination of fabricated threat intelligence (e.g. hardcoded Emotet/Google LLC records).
- **B5 (Narrative, IoC & Detection-Rule Coverage)**: Complete forensic IoC table extraction (guaranteed file hashes `HASH_SHA256`, `HASH_MD5`, `HASH_SHA1` regardless of TI state; static and dynamic persistence artifacts surfaced as `PERSISTENCE_PATH`; dynamic process tree executions surfaced as `PROCESS`), quiet run narrative accuracy (never inventing `(unclassified)` threat intelligence matches when feeds return no match or are offline).  
**Out of Scope**: Phase 6 (live multi-node hypervisor orchestration, external feed sync daemons, auto-scaling sandbox clusters) — strictly untouched and deferred.

---

## 1. Executive Summary

Phase 5 remediated threat intelligence handling, indicator of compromise (IoC) extraction and normalization, and behavioral narrative reporting across the E-Rakshak pipeline (B4–B5).

The implementation strictly followed the mandatory Test-Driven Development (TDD) workflow:

1. **9 targeted regression tests** were authored in `backend/tests/test_phase5_regression.py` before modifying production code.
2. Baseline execution against Phase 4 code recorded **9 failures and 0 passes** (evidence preserved in `audit/phase5/baseline-failures.txt`).
3. Minimal, surgical production improvements were implemented across:
   - `backend/app/malware_bazaar.py` (preserved negative and offline cached results; expanded vendor verdicts parser to cover `malware_family` and `status` fields).
   - `backend/app/ioc_extractor.py` (removed hardcoded `Emotet`, `AS15169`, `Google LLC`, `reputation_score=95` fabrication; retained honest `known_c2=True` classification without unevidenced attribution).
   - `backend/app/analysis.py` (guaranteed file hashes in `_build_ioc_intelligence`; added persistence artifacts and process execution IoCs; added explicit feed status finding in `_build_threat_assessment`; implemented and populated structured `_build_threat_intelligence_summary` in case data).
   - `agents/narrative_agent/narrative.py` (remediated quiet run narrative to accurately communicate static-only rule basis when TI is absent or negative, eliminating fabricated `threat-intelligence matches (unclassified)` statements).
4. Re-running `backend/tests/test_phase5_regression.py` achieved **9 passed, 0 failed (100% PASS)** in 3.01s.
5. All cumulative regression suites (Phases 1 through 5) executed together achieved **101 passed, 0 failed (100% PASS)** in 7.31s.
6. The entire repository test suite (`pytest`) passed with **937 passed, 0 failed, 1 warning** in 120.69s.
7. The isolated `sandbox-host/tests` suite passed with **11 passed, 0 failed** in 3.44s.
8. Frontend type check (`npx tsc --noEmit`) completed with **0 errors**.

---

## 2. Issues Summary Table

| Issue ID | Description | Root Cause | Baseline Failure Count | Status |
| :--- | :--- | :--- | :--- | :--- |
| **B4** | Threat intelligence cache swallowing, vendor verdict truncation, missing offline/novel findings & hardcoded TI fabrication | `malware_bazaar.py` discarded negative cache hits with `if cached.get("found") else None`, causing subsequent queries to return `None`; vendor parser dropped verdicts keyed on `malware_family` or `status`; `_build_threat_assessment` stayed completely silent when TI was offline or novel; `ioc_extractor.py` hardcoded `Emotet` and `Google LLC` for known C2 IPs/domains; `case_data` lacked dedicated structured TI schema. | 5 failing tests | **PASS** |
| **B5** | Incomplete IoC coverage & quiet run narrative fabricating unclassified TI matches | `_build_ioc_intelligence` only added `HASH_SHA256` if `malware_bazaar.get("found")` was True, omitting sample file hashes when TI was negative/offline; persistence paths and dynamic process executions were omitted from `ioc_intelligence`; `narrative.py` emitted `threat-intelligence matches (unclassified)` on quiet runs with no TI match. | 4 failing tests | **PASS** |

---

## 3. Deep Dive: Findings, Root Causes, Implementation & Verification

### B4 — Threat Intelligence

#### 1. Negative & Offline Cache Retention
- **Finding**: In `backend/app/malware_bazaar.py`, negative query responses (`{"found": False, "query_status": "hash_not_found"}` or `"offline"`) were saved in memory and Redis cache, but cache lookup lines 93 and 103 performed:
  ```python
  return cached if cached.get("found") else None
  ```
  This swallowed the cached negative dictionary into `None`, stripping callers of error codes, offline states, and query status on subsequent calls.
- **Root Cause**: Premature truthiness check on `cached.get("found")` inside the cache lookup rather than returning the structured payload.
- **Remediation**:
  Updated `backend/app/malware_bazaar.py` lines 91-103 to return `cached` directly from memory and Redis cache.

#### 2. Multi-Vendor Verdict Parsing
- **Finding**: Vendor verdicts returned by MalwareBazaar frequently contain different keys depending on the vendor (e.g. Triage returns `{"malware_family": "mirai"}`, Kaspersky returns `{"status": "HEUR:..."}`). `malware_bazaar.py` previously only checked `verdict`, `detection`, or `threat_name`, dropping key vendor verdicts.
- **Root Cause**: Incomplete key extraction in `vendor_intel` parser.
- **Remediation**:
  Expanded `vendor_verdicts` parser in `backend/app/malware_bazaar.py` to extract `verdict`, `detection`, `threat_name`, `malware_family`, and `status`.

#### 3. Transparent Offline & Novel Sample Reporting in Threat Assessment
- **Finding**: When MalwareBazaar returned negative or offline, `_build_threat_assessment` produced no finding regarding threat feeds. Analysts could not distinguish whether the sample was checked and novel, or if the external threat feed was offline/unreachable.
- **Root Cause**: `_build_threat_assessment` only branched on `if malware_bazaar and malware_bazaar.get("found"):`.
- **Remediation**:
  Added an `elif malware_bazaar:` branch to `_build_threat_assessment` in `backend/app/analysis.py`:
  - When `query_status` is `offline`, `timeout`, or error: records `"Threat intelligence feed offline or unreachable; results based on local analysis."`
  - When `query_status == "hash_not_found"`: records `"Sample hash not present in threat intelligence feeds (unreported/novel sample)."`
  - Otherwise: records `"Threat intelligence query returned no matching records ({query_status})."`

#### 4. Elimination of Fabricated Threat Intelligence
- **Finding**: `backend/app/ioc_extractor.py` hardcoded `threat_family="Emotet"`, `organization="Google LLC"`, `asn="AS15169"`, and `reputation_score=95` whenever a network event matched `KNOWN_C2_IPS` or `KNOWN_C2_DOMAINS`.
- **Root Cause**: Legacy mock data left in production code.
- **Remediation**:
  Removed hardcoded strings in `backend/app/ioc_extractor.py`. When matching `KNOWN_C2_IPS` or `KNOWN_C2_DOMAINS`, it now sets `ThreatIntelligence(known_c2=True)` without fabricating families, ASNs, organizations, or confidence numbers.

#### 5. Dedicated Structured Threat Intelligence in Case Data
- **Finding**: Case output had raw `malware_bazaar` dictionary but lacked a standardized, schema-compliant `threat_intelligence` section with provider, status, evidence_state, and provenance.
- **Remediation**:
  Implemented `_build_threat_intelligence_summary(sha256, malware_bazaar)` in `backend/app/analysis.py` and included `"threat_intelligence"` across all case construction branches and pipeline returns.

---

### B5 — Narrative, IoC & Detection-Rule Coverage

#### 1. Guaranteed File Hashes in IoC Intelligence
- **Finding**: In `backend/app/analysis.py`, `_build_ioc_intelligence` only recorded `HASH_SHA256` if `malware_bazaar.get("found")` was True. Samples not listed in MalwareBazaar or analyzed offline had no hash IoCs in `ioc_intelligence`.
- **Root Cause**: Conditioned hash IoC inclusion entirely on positive threat intelligence hits.
- **Remediation**:
  Refactored `_build_ioc_intelligence` in `backend/app/analysis.py` to always include `raw_static["sha256"]` as a `HASH_SHA256` IoC. If corroborated by MalwareBazaar, it receives `evidence_state="INTEL"`, `source="MalwareBazaar (abuse.ch)"`, `classification="MALICIOUS"`; otherwise, it receives `evidence_state="STATIC"`, `source="Static Analysis"`, `classification="SUSPICIOUS"` (if malware/high score) or `"UNKNOWN"`. Also added `HASH_MD5` and `HASH_SHA1` if present in static output.

#### 2. Persistence Paths and Dynamic Processes Surfaced as IoCs
- **Finding**: Persistence artifacts and dynamic process executions were detected by the pipeline and sandbox but never converted into formal indicators in `ioc_intelligence`.
- **Remediation**:
  - Integrated `_extract_persistence_artifacts(raw_static, dynamic_output)` into `_build_ioc_intelligence` to surface persistence mechanisms as `type="PERSISTENCE_PATH"`, with `evidence_state="OBSERVED"` for dynamic artifacts and `"STATIC"` for static artifacts.
  - Added process execution records from `dyn_dict.get("process_tree")` as `type="PROCESS"`, with `evidence_state="OBSERVED"` and PID context.

#### 3. Defensible Narrative Generation on Quiet Runs
- **Finding**: In `agents/narrative_agent/narrative.py`, quiet runs without dynamic behavior fell back to:
  ```python
  sig = (malware_bazaar or {}).get("signature") or "unclassified"
  return f"Specific behavior could not be determined from the available evidence; classification rests on threat-intelligence matches ({sig}) and static rule hits."
  ```
  When MalwareBazaar returned no match, this falsely stated: `classification rests on threat-intelligence matches (unclassified)`.
- **Root Cause**: Lack of conditional check on whether a real threat-intelligence match actually existed.
- **Remediation**:
  Updated quiet run narrative logic in `agents/narrative_agent/narrative.py`:
  - If `malware_bazaar.get("found")` and `sig`: states classification rests on confirmed threat intelligence match (`{sig}`) and static rules.
  - If no TI match: explicitly states classification rests strictly on static rule hits as no external threat intelligence match was found.

---

## 4. Verification & Test Evidence

### 1. Phase 5 Regression Suite (`test_phase5_regression.py`)
```text
backend/tests/test_phase5_regression.py::test_b4_malware_bazaar_cache_preserves_negative_status PASSED [ 11%]
backend/tests/test_phase5_regression.py::test_b4_vendor_intel_parsing_covers_malware_family PASSED [ 22%]
backend/tests/test_phase5_regression.py::test_b4_threat_assessment_surfaces_unavailable_or_unmatched_ti PASSED [ 33%]
backend/tests/test_phase5_regression.py::test_b4_structured_threat_intelligence_summary PASSED [ 44%]
backend/tests/test_phase5_regression.py::test_b4_no_fabricated_emotet_in_ioc_extractor PASSED [ 55%]
backend/tests/test_phase5_regression.py::test_b5_file_hashes_always_in_ioc_intelligence PASSED [ 66%]
backend/tests/test_phase5_regression.py::test_b5_persistence_artifacts_surfaced_in_ioc_intelligence PASSED [ 77%]
backend/tests/test_phase5_regression.py::test_b5_process_indicators_in_ioc_intelligence PASSED [ 88%]
backend/tests/test_phase5_regression.py::test_b5_quiet_run_narrative_does_not_claim_unclassified_ti_match PASSED [100%]

============================== 9 passed in 3.01s ==============================
```

### 2. Cumulative Regression Suite (Phases 1 through 5)
```text
backend/tests/test_phase1_regression.py (21 tests) PASSED
backend/tests/test_phase2_regression.py (42 tests) PASSED
backend/tests/test_phase3_regression.py (16 tests) PASSED
backend/tests/test_phase4_regression.py (13 tests) PASSED
backend/tests/test_phase5_regression.py (9 tests)  PASSED

======================= 101 passed, 1 warning in 7.31s ========================
```

### 3. Full Repository Test Suite
```text
pytest
937 passed, 1 warning in 120.69s (0:02:00)
```

### 4. Sandbox-Host Test Suite
```text
pytest sandbox-host/tests -v
11 passed, 1 warning in 3.44s
```

### 5. Frontend Type Check
```text
npx tsc --noEmit
Exit code 0 (clean, 0 errors)
```

---

## 5. Non-Fabrication & Evidence Provenance Guarantees

In accordance with strict forensic integrity rules:
1. **No Invented Threat Intelligence**: All provider results reflect actual lookups or explicit offline/negative status codes.
2. **No Hardcoded Family Attribution**: Removed legacy mock Emotet and Google LLC attributions.
3. **Rigorous Evidence State Tracking**: Every IoC emitted clearly indicates its provenance:
   - `STATIC`: File hashes from static extraction, static persistence path strings.
   - `OBSERVED`: Dynamic network connections, dropped files, dynamic persistence artifacts, process tree executions.
   - `INTEL`: Verified external intelligence matches from MalwareBazaar.
4. **Honest Behavioral Narratives**: Narratives explicitly communicate static-only evidentiary basis when dynamic runs observe no behaviors and threat intelligence is unavailable or novel.
