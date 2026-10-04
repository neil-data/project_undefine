# Day 2 E2E Baseline Matrix: Before vs After

## 1. Test × Fixture Results Matrix

| Fixture Name | test_no_fake_dynamic | test_source_separation | test_narrative | test_iocs | test_score (Day 3) | test_timeline_meta (Day 3) | test_recommendations (Day 3) | test_mitre | test_layout |
|---|---|---|---|---|---|---|---|---|---|
| `clean_control` | PASS | PASS | PASS | PASS | PASS | PASS | PASS | PASS | SKIPPED |
| `synthetic_mirai_droppee` | PASS | PASS | PASS | PASS | **FAIL** (Static cap >20 pts) | **FAIL** (Duplicate TS) | PASS | PASS | SKIPPED |
| `base64_and_system_libs_as_paths` | PASS | PASS | PASS | PASS | PASS | PASS | PASS | PASS | SKIPPED |
| `benign_hosts_suspicious` | PASS | PASS | PASS | PASS | PASS | PASS | PASS | PASS | SKIPPED |
| `credential_advice_no_evidence` | PASS | PASS | PASS | PASS | PASS | PASS | **FAIL** (Credential advice without evidence) | PASS | SKIPPED |
| `critical_all_vendors_clean` | PASS | PASS | PASS | PASS | **FAIL** (CRITICAL score without intel/observed) | PASS | PASS | PASS | SKIPPED |
| `duplicate_timestamps_synthetic_offset` | PASS | PASS | PASS | PASS | PASS | **FAIL** (Duplicate TS) | PASS | PASS | SKIPPED |
| `fabricated_narrative` | PASS | PASS | PASS | PASS | PASS | PASS | PASS | PASS | SKIPPED |
| `go_symbols_as_domains` | PASS | PASS | PASS | PASS | PASS | PASS | PASS | PASS | SKIPPED |
| `llm_refusal` | PASS | PASS | PASS | PASS | PASS | PASS | PASS | PASS | SKIPPED |
| `random_fragment_domains` | PASS | PASS | PASS | PASS | PASS | PASS | PASS | PASS | SKIPPED |
| `static_cap_exceeded` | PASS | PASS | PASS | PASS | **FAIL** (Static cap >20 pts) | PASS | PASS | PASS | SKIPPED |
| `static_rule_labeled_intel` | PASS | PASS | PASS | PASS | PASS | PASS | PASS | PASS | SKIPPED |

---

## 2. Summary of Contract Status

- **Day 2 Target Contracts**:
  * `test_no_fake_dynamic`: **13 / 13 PASS (100%)**
  * `test_source_separation`: **13 / 13 PASS (100%)**
  * `test_narrative`: **13 / 13 PASS (100%)**
  * `test_iocs`: **13 / 13 PASS (100%)**
- **Unit Test Suite**:
  * `tests/unit/test_day2_b1_evidence_model.py`: 7 PASS
  * `tests/unit/test_day2_b2_narrative_pipeline.py`: 7 PASS
  * `tests/unit/test_day2_b3_ioc_classifier.py`: 13 PASS
  * Total Unit Tests: **27 / 27 PASS (100%)**
- **LLM Failure Handling E2E Test**:
  * `tests/e2e/test_day2_llm_failure_handling.py`: **5 / 5 PASS (100%)**
  * Verified across refusal phrase, empty text, non-JSON text, truncated JSON, and fabricated ungrounded CVE claims in the real `analyze_and_save` entrypoint.
- **Day 3 Out-of-Scope Deferred Failures (6 total)**:
  1. `test_score[critical_all_vendors_clean]`: CRITICAL risk score 90 claimed without threat intel or observed execution (Day 3 gating).
  2. `test_score[static_cap_exceeded]`: Static MITRE + capability points exceed 20 pts (Day 3 static cap).
  3. `test_score[synthetic_mirai_droppee]`: Static MITRE + capability points exceed 20 pts (Day 3 static cap).
  4. `test_timeline_meta[duplicate_timestamps_synthetic_offset]`: Duplicate timestamp without distinguishing label (Day 3 timeline).
  5. `test_timeline_meta[synthetic_mirai_droppee]`: Duplicate timestamp without distinguishing label (Day 3 timeline).
  6. `test_recommendations[credential_advice_no_evidence]`: Credential rotation recommended without credential theft evidence (Day 3 recommendation rules).

---

## 3. Root Cause & Architectural Fixes Applied (Day 2)

### B1. Evidence Model (Single Source of Truth)
- Canonical `EvidenceFinding` defined in `analysis/scoring/orchestrator/schema.py` with `source_type` (`STATIC`, `DYNAMIC`, `INTEL`), `source`, `evidence_state`, `confidence` (0.0–1.0), and `provenance`.
- Enforced invariants via `@model_validator`:
  * STATIC findings cannot have `OBSERVED` or `DYNAMIC` state.
  * Static rule matches (YARA, regexes) cannot claim `INTEL`.
  * YARA findings are strictly `STATIC`, with confidence bounded to `<= 0.80` (never confirmed, never intel).
- `_cap_c2_communication` in `capability_rules.py` assigns `STATIC` state and `0.65` confidence for static/YARA rules, and only awards `OBSERVED` / confirmed upon observed beacon or dynamic C2 connections.
- `_build_evidence_correlations` in `apps/backend/app/analysis.py` strictly emits `STATIC` evidence state for YARA rule hits.

### B2. Narrative Pipeline Wiring
- Replaced heuristic string patching in `analysis/scoring/narrative_agent/narrative.py` with strict structured JSON schema validation (`executive_summary` + `technical_steps`).
- Guardrails enforced:
  * Delimited `<DATA_BLOCK>` input wrapping with anti-prompt-injection system instructions.
  * Refusal detection (`REFUSAL_PHRASES`) and truncation detection (missing terminal punctuation).
  * Exact-token grounding validator: mechanisms and identifiers must match whole tokens in evidence ("xor" does not match "extractor").
  * CVE and IP grounding validation against evidence sets.
  * Stated risk score and victim impact reconciliation against deterministic engine values.
  * One-shot retry prompt providing exact contract violation messages.
  * Fallback to deterministic summary if retry fails, keeping threat score and pipeline execution intact.
  * Code-rendered steps format eliminating markdown table bars (`| Step`, `|---`) and HTML tags (`<br>`).
  * Quiet-run detection: deterministic fallback for executions without dynamic behavior.

### B3. IoC Classifier & Allowlists
- Implemented `packages/shared/allowlist.py` with authoritative, dated allowlists:
  * Public DNS resolvers (`8.8.8.8`, `1.1.1.1`, `9.9.9.9`, etc.)
  * Benign vendor and developer infrastructure hosts (`go.dev`, `microsoft.com`, `android.googlesource.com`, etc.)
  * Systemd unit suffixes (`.service`, `.target`, `.socket`, etc.)
  * Common file extensions misidentified as TLDs (`.dll`, `.exe`, `.so`, `.sh`, `.json`, etc.)
  * Go runtime and standard library package prefixes (`fmt`, `io`, `os`, `runtime`, `net`, etc.)
  * Windows and POSIX system libraries (`kernel32.dll`, `ntdll.dll`, `libc.so`, etc.)
- Implemented `packages/shared/ioc_classifier.py` (`IoCClassifier.classify(...)`):
  * URL normalization with glued hex stripping (`strip_glued_hex`) for leading/trailing hex and null offsets.
  * Domain validation using offline `publicsuffixlist` (PSL) snapshot with private suffix checks and minimum 3-character SLD requirement. Rejection of mixed-case TLDs and fragments.
  * Rejection of Go symbols (classified as `SYMBOL`).
  * Rejection of Base64 blobs (>32 chars) as file/persistence paths (classified as `BASE64`).
  * Rejection of system libraries as install/persistence paths (classified as `LIBRARY`).
  * Public DNS resolvers typed as `SYSTEM_INFRASTRUCTURE` with `LOW` confidence and never flagged as C2.
  * Benign vendor hosts typed as `SYSTEM_INFRASTRUCTURE` / `BENIGN` ensuring non-suspicious status.
  * Stripping of pre-existing `…(N more)` truncation markers to prevent emitting literal truncation strings as IoCs.
