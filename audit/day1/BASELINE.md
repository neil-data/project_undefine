# Day 1 — E2E Baseline Test Report

## 1. Execution & CI Isolation

- **E2E Test Suite Command**:
  ```bash
  pytest tests/e2e -q --tb=line -rf
  ```
- **CI Isolation**:
  - `pytest.ini` defines `testpaths = analysis apps/backend/tests apps/ingestion sandbox/host/tests`.
  - Normal unit and integration CI runs (`pytest`) run unit/component tests and bypass `tests/e2e/`.
  - All E2E tests are marked with `@pytest.mark.e2e`.

---

## 2. Stored Fixture Status

All synthetic and control fixtures are stored in `tests/e2e/fixtures/`:
1. `clean_control`: Zero-defect baseline fixture; asserts positive contract adherence across all tests.
2. `go_symbols_as_domains`: Negative fixture with Go standard library/runtime symbols (`fmt.pp`, `go.shape`, `io.pipe`, `os.file`) presented as domains.
3. `random_fragment_domains`: Negative fixture with string fragment pseudo-domains (`jC.bn`, `QMrS.lg`, `XB.kr`).
4. `benign_hosts_suspicious`: Negative fixture asserting benign domains (`go.dev`, `microsoft.com`, `android.googlesource.com`) are not falsely flagged as suspicious/malicious.
5. `fabricated_narrative`: Negative fixture with hallucinated execution steps, raw markdown table syntax (`| Step`, `|------`), `<br>` HTML tags, and truncated ending.
6. `llm_refusal`: Negative fixture with AI model safety refusal string (`I'm sorry, but I can't help with that.`).
7. `static_rule_labeled_intel`: Negative fixture asserting static YARA rules are never misclassified as INTEL and ungrounded C2 is not confirmed.
8. `static_cap_exceeded`: Negative fixture with static-derived capability + MITRE points exceeding the 20-point ceiling.
9. `critical_all_vendors_clean`: Negative fixture claiming CRITICAL verdict without threat intel, dynamic evidence, or family hit.
10. `credential_advice_no_evidence`: Negative fixture providing credential/OAuth rotation recommendations without credential theft capability evidence.
11. `base64_and_system_libs_as_paths`: Negative fixture misidentifying base64 blobs and standard system libraries (`kernel32.dll`) as installed malware paths.
12. `duplicate_timestamps_synthetic_offset`: Negative fixture with unsequenced duplicate timestamps and synthetic relative offsets (`+5s (approx)`).
13. `synthetic_mirai_droppee`: Renamed from `mirai_droppee.json` with `"synthetic": true` metadata following dynamic section provenance verification (originating from `http://testserver-sandbox` test harness stub).

---

## 3. Baseline Test Matrix (Test × Fixture)

| Test | Fixture | Status | Failure Reason / Baseline Note |
| :--- | :--- | :---: | :--- |
| `test_no_fake_dynamic` | `base64_and_system_libs_as_paths` | **PASS** | Contract verified cleanly |
| `test_no_fake_dynamic` | `benign_hosts_suspicious` | **PASS** | Contract verified cleanly |
| `test_no_fake_dynamic` | `clean_control` | **PASS** | Contract verified cleanly |
| `test_no_fake_dynamic` | `credential_advice_no_evidence` | **PASS** | Contract verified cleanly |
| `test_no_fake_dynamic` | `critical_all_vendors_clean` | **PASS** | Contract verified cleanly |
| `test_no_fake_dynamic` | `duplicate_timestamps_synthetic_offset` | **PASS** | Contract verified cleanly |
| `test_no_fake_dynamic` | `fabricated_narrative` | **PASS** | Contract verified cleanly |
| `test_no_fake_dynamic` | `go_symbols_as_domains` | **PASS** | Contract verified cleanly |
| `test_no_fake_dynamic` | `llm_refusal` | **PASS** | Contract verified cleanly |
| `test_no_fake_dynamic` | `random_fragment_domains` | **PASS** | Contract verified cleanly |
| `test_no_fake_dynamic` | `static_cap_exceeded` | **PASS** | Contract verified cleanly |
| `test_no_fake_dynamic` | `static_rule_labeled_intel` | **PASS** | Contract verified cleanly |
| `test_no_fake_dynamic` | `synthetic_mirai_droppee` | **PASS** | Contract verified cleanly |
| `test_source_separation` | `base64_and_system_libs_as_paths` | **PASS** | Contract verified cleanly |
| `test_source_separation` | `benign_hosts_suspicious` | **PASS** | Contract verified cleanly |
| `test_source_separation` | `clean_control` | **PASS** | Contract verified cleanly |
| `test_source_separation` | `credential_advice_no_evidence` | **PASS** | Contract verified cleanly |
| `test_source_separation` | `critical_all_vendors_clean` | **PASS** | Contract verified cleanly |
| `test_source_separation` | `duplicate_timestamps_synthetic_offset` | **PASS** | Contract verified cleanly |
| `test_source_separation` | `fabricated_narrative` | **PASS** | Contract verified cleanly |
| `test_source_separation` | `go_symbols_as_domains` | **PASS** | Contract verified cleanly |
| `test_source_separation` | `llm_refusal` | **PASS** | Contract verified cleanly |
| `test_source_separation` | `random_fragment_domains` | **PASS** | Contract verified cleanly |
| `test_source_separation` | `static_cap_exceeded` | **PASS** | Contract verified cleanly |
| `test_source_separation` | `static_rule_labeled_intel` | **FAIL** | Static-derived capability 'c2_communication' labeled as 'INTEL' instead of STATIC |
| `test_source_separation` | `synthetic_mirai_droppee` | **PASS** | Contract verified cleanly |
| `test_narrative` | `base64_and_system_libs_as_paths` | **PASS** | Contract verified cleanly |
| `test_narrative` | `benign_hosts_suspicious` | **PASS** | Contract verified cleanly |
| `test_narrative` | `clean_control` | **PASS** | Contract verified cleanly |
| `test_narrative` | `credential_advice_no_evidence` | **PASS** | Contract verified cleanly |
| `test_narrative` | `critical_all_vendors_clean` | **PASS** | Contract verified cleanly |
| `test_narrative` | `duplicate_timestamps_synthetic_offset` | **PASS** | Contract verified cleanly |
| `test_narrative` | `fabricated_narrative` | **FAIL** | Raw markdown table syntax '| Step' found in narrative |
| `test_narrative` | `go_symbols_as_domains` | **PASS** | Contract verified cleanly |
| `test_narrative` | `llm_refusal` | **FAIL** | LLM refusal phrase 'i'm sorry' detected in narrative |
| `test_narrative` | `random_fragment_domains` | **PASS** | Contract verified cleanly |
| `test_narrative` | `static_cap_exceeded` | **PASS** | Contract verified cleanly |
| `test_narrative` | `static_rule_labeled_intel` | **PASS** | Contract verified cleanly |
| `test_narrative` | `synthetic_mirai_droppee` | **FAIL** | Narrative appears truncated; ends with ', indicating outbound traffic)' without sentence terminal punctuation |
| `test_iocs` | `base64_and_system_libs_as_paths` | **FAIL** | Invalid path IoC 'aW52YWxpZGJhc2U2NGJsb2J0aGF0aXNsb25nZXJ0aGFuMzJjaGFycw==': Base64 blob detected as path: aW52YWxpZGJhc2U2NGJsb2J0aGF0aXNsb25nZXJ0aGFuMzJjaGFycw== |
| `test_iocs` | `benign_hosts_suspicious` | **FAIL** | Whitelisted benign domain 'go.dev' marked as suspicious/malicious |
| `test_iocs` | `clean_control` | **PASS** | Contract verified cleanly |
| `test_iocs` | `credential_advice_no_evidence` | **PASS** | Contract verified cleanly |
| `test_iocs` | `critical_all_vendors_clean` | **PASS** | Contract verified cleanly |
| `test_iocs` | `duplicate_timestamps_synthetic_offset` | **PASS** | Contract verified cleanly |
| `test_iocs` | `fabricated_narrative` | **PASS** | Contract verified cleanly |
| `test_iocs` | `go_symbols_as_domains` | **FAIL** | Invalid domain IoC 'fmt.pp': Go symbol/package prefix detected as domain: fmt.pp |
| `test_iocs` | `llm_refusal` | **PASS** | Contract verified cleanly |
| `test_iocs` | `random_fragment_domains` | **FAIL** | Invalid domain IoC 'jC.bn': Mixed-case SLD fragment: jC.bn |
| `test_iocs` | `static_cap_exceeded` | **PASS** | Contract verified cleanly |
| `test_iocs` | `static_rule_labeled_intel` | **PASS** | Contract verified cleanly |
| `test_iocs` | `synthetic_mirai_droppee` | **PASS** | Contract verified cleanly |
| `test_score` | `base64_and_system_libs_as_paths` | **PASS** | Contract verified cleanly |
| `test_score` | `benign_hosts_suspicious` | **PASS** | Contract verified cleanly |
| `test_score` | `clean_control` | **PASS** | Contract verified cleanly |
| `test_score` | `credential_advice_no_evidence` | **PASS** | Contract verified cleanly |
| `test_score` | `critical_all_vendors_clean` | **FAIL** | CRITICAL risk score (90) claimed without threat intel, observed execution, or family match |
| `test_score` | `duplicate_timestamps_synthetic_offset` | **PASS** | Contract verified cleanly |
| `test_score` | `fabricated_narrative` | **PASS** | Contract verified cleanly |
| `test_score` | `go_symbols_as_domains` | **PASS** | Contract verified cleanly |
| `test_score` | `llm_refusal` | **PASS** | Contract verified cleanly |
| `test_score` | `random_fragment_domains` | **PASS** | Contract verified cleanly |
| `test_score` | `static_cap_exceeded` | **FAIL** | Static-derived MITRE+capability points (35) exceeded maximum allowed 20 points (mitre=10, caps=25) |
| `test_score` | `static_rule_labeled_intel` | **PASS** | Contract verified cleanly |
| `test_score` | `synthetic_mirai_droppee` | **FAIL** | Static-derived MITRE+capability points (31) exceeded maximum allowed 20 points (mitre=8, caps=23) |
| `test_timeline_meta` | `base64_and_system_libs_as_paths` | **PASS** | Contract verified cleanly |
| `test_timeline_meta` | `benign_hosts_suspicious` | **PASS** | Contract verified cleanly |
| `test_timeline_meta` | `clean_control` | **PASS** | Contract verified cleanly |
| `test_timeline_meta` | `credential_advice_no_evidence` | **PASS** | Contract verified cleanly |
| `test_timeline_meta` | `critical_all_vendors_clean` | **PASS** | Contract verified cleanly |
| `test_timeline_meta` | `duplicate_timestamps_synthetic_offset` | **FAIL** | Duplicate identical timestamp '2026-10-03T04:49:39.910085+00:00' lacks distinguishing label |
| `test_timeline_meta` | `fabricated_narrative` | **PASS** | Contract verified cleanly |
| `test_timeline_meta` | `go_symbols_as_domains` | **PASS** | Contract verified cleanly |
| `test_timeline_meta` | `llm_refusal` | **PASS** | Contract verified cleanly |
| `test_timeline_meta` | `random_fragment_domains` | **PASS** | Contract verified cleanly |
| `test_timeline_meta` | `static_cap_exceeded` | **PASS** | Contract verified cleanly |
| `test_timeline_meta` | `static_rule_labeled_intel` | **PASS** | Contract verified cleanly |
| `test_timeline_meta` | `synthetic_mirai_droppee` | **FAIL** | Duplicate identical timestamp '2026-10-03T04:49:45.980983+00:00' lacks distinguishing label |
| `test_recommendations` | `base64_and_system_libs_as_paths` | **PASS** | Contract verified cleanly |
| `test_recommendations` | `benign_hosts_suspicious` | **PASS** | Contract verified cleanly |
| `test_recommendations` | `clean_control` | **PASS** | Contract verified cleanly |
| `test_recommendations` | `credential_advice_no_evidence` | **FAIL** | Credential rotation recommended without credential theft evidence: 'Rotate all domain passwords and OAuth tokens immediately.' |
| `test_recommendations` | `critical_all_vendors_clean` | **PASS** | Contract verified cleanly |
| `test_recommendations` | `duplicate_timestamps_synthetic_offset` | **PASS** | Contract verified cleanly |
| `test_recommendations` | `fabricated_narrative` | **PASS** | Contract verified cleanly |
| `test_recommendations` | `go_symbols_as_domains` | **PASS** | Contract verified cleanly |
| `test_recommendations` | `llm_refusal` | **PASS** | Contract verified cleanly |
| `test_recommendations` | `random_fragment_domains` | **PASS** | Contract verified cleanly |
| `test_recommendations` | `static_cap_exceeded` | **PASS** | Contract verified cleanly |
| `test_recommendations` | `static_rule_labeled_intel` | **PASS** | Contract verified cleanly |
| `test_recommendations` | `synthetic_mirai_droppee` | **PASS** | Contract verified cleanly |
| `test_mitre` | `base64_and_system_libs_as_paths` | **PASS** | Contract verified cleanly |
| `test_mitre` | `benign_hosts_suspicious` | **PASS** | Contract verified cleanly |
| `test_mitre` | `clean_control` | **PASS** | Contract verified cleanly |
| `test_mitre` | `credential_advice_no_evidence` | **PASS** | Contract verified cleanly |
| `test_mitre` | `critical_all_vendors_clean` | **PASS** | Contract verified cleanly |
| `test_mitre` | `duplicate_timestamps_synthetic_offset` | **PASS** | Contract verified cleanly |
| `test_mitre` | `fabricated_narrative` | **PASS** | Contract verified cleanly |
| `test_mitre` | `go_symbols_as_domains` | **PASS** | Contract verified cleanly |
| `test_mitre` | `llm_refusal` | **PASS** | Contract verified cleanly |
| `test_mitre` | `random_fragment_domains` | **PASS** | Contract verified cleanly |
| `test_mitre` | `static_cap_exceeded` | **PASS** | Contract verified cleanly |
| `test_mitre` | `static_rule_labeled_intel` | **PASS** | Contract verified cleanly |
| `test_mitre` | `synthetic_mirai_droppee` | **PASS** | Contract verified cleanly |
| `test_layout` | `base64_and_system_libs_as_paths` | **SKIPPED** | manual: headless PDF generation is not available in backend Python environment |
| `test_layout` | `benign_hosts_suspicious` | **SKIPPED** | manual: headless PDF generation is not available in backend Python environment |
| `test_layout` | `clean_control` | **SKIPPED** | manual: headless PDF generation is not available in backend Python environment |
| `test_layout` | `credential_advice_no_evidence` | **SKIPPED** | manual: headless PDF generation is not available in backend Python environment |
| `test_layout` | `critical_all_vendors_clean` | **SKIPPED** | manual: headless PDF generation is not available in backend Python environment |
| `test_layout` | `duplicate_timestamps_synthetic_offset` | **SKIPPED** | manual: headless PDF generation is not available in backend Python environment |
| `test_layout` | `fabricated_narrative` | **SKIPPED** | manual: headless PDF generation is not available in backend Python environment |
| `test_layout` | `go_symbols_as_domains` | **SKIPPED** | manual: headless PDF generation is not available in backend Python environment |
| `test_layout` | `llm_refusal` | **SKIPPED** | manual: headless PDF generation is not available in backend Python environment |
| `test_layout` | `random_fragment_domains` | **SKIPPED** | manual: headless PDF generation is not available in backend Python environment |
| `test_layout` | `static_cap_exceeded` | **SKIPPED** | manual: headless PDF generation is not available in backend Python environment |
| `test_layout` | `static_rule_labeled_intel` | **SKIPPED** | manual: headless PDF generation is not available in backend Python environment |
| `test_layout` | `synthetic_mirai_droppee` | **SKIPPED** | manual: headless PDF generation is not available in backend Python environment |

---

## 4. Summary

- **Total Cases**: 117
- **Passed**: 90
- **Failed**: 14 (all matching bug fixtures fail as expected; zero false passes on bug fixtures)
- **Skipped**: 13 (manual headless PDF layout tests)
