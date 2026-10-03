# Day 1 — E2E Baseline Test Report

## 1. Execution & CI Isolation

- **E2E Test Suite Command**:
  ```bash
  pytest tests/e2e -q --tb=line -rf
  ```
- **CI Isolation**:
  - `pytest.ini` defines `testpaths = analysis apps/backend/tests apps/ingestion sandbox/host/tests`.
  - Normal unit and integration CI runs (`pytest`) run only the 1,066 unit/component tests and bypass `tests/e2e/`.
  - All E2E tests are marked with `@pytest.mark.e2e`.

---

## 2. Stored Fixture Status

All database instances and repository report directories were searched for the 5 sample hashes requested:
- `elf_gafgyt` (`4faccd95d23724469122505b90cdfd280ff552528be38e73e2b969be90eb7380`): **MISSING** (not stored in DB or reports dir; per instruction, data was not invented).
- `elf_arm` (`72d99759c2faadc567bab9af18d8fadea564223f58d66362967629b01a3c1145`): **MISSING** (not stored in DB or reports dir; per instruction, data was not invented).
- `pe_go` (`12c9f247e46d3ee8f3b26c2abe3c545d8dca48886925a646981ed8328c5e8eef`): **MISSING** (not stored in DB or reports dir; per instruction, data was not invented).
- `apk` (`de9d9663fa7293fca6e75ffd75f69b2119269020dc0985b3d11b2c7f0af9af2e`): **MISSING** (not stored in DB or reports dir; per instruction, data was not invented).
- `macho` (`4458ab2eb26c8c155cf530136e0a7cf1ddee41f26547a56bc093d61a83c0a382`): **MISSING** (not stored in DB or reports dir; per instruction, data was not invented).

**Available Stored Report Fixtures in Repository (`reports/examples/`)**:
1. `control_benign`: `e945cee65f43402a97a9c0725237bc7605306c0a5402b48a50759ce1f0aba776`
2. `mirai_droppee`: `87ace603b502bb8f30125c26922000d10576e5fd42fd1e4937e78a0b7e522d28`

---

## 3. Baseline Test Matrix (Test × Fixture)

| Test | Fixture | Status | Failure Reason / Baseline Note |
| :--- | :--- | :---: | :--- |
| `test_no_fake_dynamic` | `control_benign` | **PASS** | Dynamic execution completed cleanly; 0 ungrounded dynamic events or OBSERVED states |
| `test_no_fake_dynamic` | `mirai_droppee` | **PASS** | Dynamic execution completed cleanly; 0 ungrounded dynamic events or OBSERVED states |
| `test_source_separation` | `control_benign` | **PASS** | YARA/metadata findings labeled STATIC; no ungrounded INTEL labels |
| `test_source_separation` | `mirai_droppee` | **PASS** | Static findings labeled STATIC; C2 communication supported |
| `test_narrative` | `control_benign` | **PASS** | Grounded fallback narrative without raw table tags, refusals, or truncation |
| `test_narrative` | `mirai_droppee` | **FAIL** | Narrative truncated mid-sentence ending with `, indicating outbound traffic)` |
| `test_iocs` | `control_benign` | **PASS** | No invalid domains, no Go symbols or base64 paths, public DNS not C2 |
| `test_iocs` | `mirai_droppee` | **PASS** | Valid domain and path extraction, no system libraries as install paths |
| `test_score` | `control_benign` | **PASS** | Points sum (15+25) == 40; static-derived points (0) <= 20 |
| `test_score` | `mirai_droppee` | **FAIL** | Static-derived MITRE + capability points (8+23 = 31) exceeded limit of 20 |
| `test_timeline_meta` | `control_benign` | **FAIL** | Duplicate identical timestamp `2026-10-03T04:49:39.910085+00:00` lacks distinguishing label |
| `test_timeline_meta` | `mirai_droppee` | **FAIL** | Duplicate identical timestamp `2026-10-03T04:49:45.980983+00:00` lacks distinguishing label |
| `test_recommendations` | `control_benign` | **PASS** | No credential rotation without credential theft evidence, no duplicate actions |
| `test_recommendations` | `mirai_droppee` | **PASS** | Recommendations grounded in evidence; no non-domain sinkholing |
| `test_mitre` | `control_benign` | **PASS** | MITRE techniques list empty / no unvalidated technique claims |
| `test_mitre` | `mirai_droppee` | **PASS** | T1071 traceable to validated network/C2 capabilities |
| `test_layout` | `control_benign` | **SKIPPED** | manual: headless PDF generation is not available in backend Python environment |
| `test_layout` | `mirai_droppee` | **SKIPPED** | manual: headless PDF generation is not available in backend Python environment |

**Summary**: 12 Passed, 4 Failed, 2 Skipped (Manual).
