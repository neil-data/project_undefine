# A1–A16 Baseline Test Coverage Matrix

Assessment of existing test coverage across the known audit issues A1–A16 prior to any code changes.

| ID | Issue | Existing test? | Test location | Current result | Coverage confidence |
|---|---|---|---|---|---|
| **A1** | Static findings incorrectly labeled OBSERVED | Partial (reinforces bug) | `backend/tests/test_evidence_correlation.py` | PASS (asserts `evidence_state == "OBSERVED"` for static/empty dynamic) | **None** (zero test verifying static-only produces 0 OBSERVED labels) |
| **A2** | LLM refusal appears in report | No | `agents/narrative_agent/test_narrative_agent.py` | PASS (tests exception fallback only; no test for LLM 200 refusal text) | **None** |
| **A3** | Capabilities incorrectly confirmed from static strings | Partial (permits bug) | `agents/capability_classifier/test_capability_rules.py` | PASS (permits `data_exfiltration` and `c2_communication` on static strings) | **None** |
| **A4** | Confidence should be 71 | Partial | `backend/tests/test_elf_pipeline_defensible.py` | PASS (tests benign verdict strings "clean"/"unrated"; misses "Legit File" and 71 agreement) | **Low** |
| **A5** | Combined static MITRE/capability cap | No | `agents/orchestrator/test_risk_scoring.py` | PASS (static cap 20 only applied to YARA; MITRE+Cap added uncapped) | **None** |
| **A6** | `index.html` / `rc.local` classified as domains | No | `static-analysis/tests/test_ioc_extraction.py`, `backend/tests/test_part2_integration.py` | PASS (does not test `.html` or `.local` rejection against TLD/extension list) | **None** |
| **A7** | `8.8.8.8` classified as C2 | No | `backend/tests/test_part2_integration.py` | PASS (no test asserting 8.8.8.8 is excluded from C2/block recs and labeled Public DNS) | **None** |
| **A8** | GeoIP severity disagrees with IoC severity | No | `backend/tests/test_elf_pipeline_defensible.py` | PASS (no test verifying GeoIP "Network context" matches IoC classification without INTEL) | **None** |
| **A9** | Proxy ports incorrectly treated as suspicious/C2 | No | None | N/A (no test checking neutral hardcoded endpoint classification for proxy ports) | **None** |
| **A10** | Persistence paths not surfaced | No | `agents/orchestrator/test_cross_platform_rules.py` | PASS (only tests dynamic persistence; no test for static qv3b paths in recs/caps/MITRE) | **None** |
| **A11** | Duplicate dynamic failure / `nulls` duration | No | `backend/tests/test_pdf_generation.py` | PASS (tests PDF creation without verifying string prefix deduplication or nulls formatting) | **None** |
| **A12** | Recommendations incorrect/repeated | No | `agents/investigation_engine/test_investigation_engine.py` | PASS (no deduplication test across pipeline or formatting test for IP/persistence recs) | **None** |
| **A13** | Timeline/caption layout issue | No | `backend/tests/test_part2_integration.py` | PASS (does not verify timestamp uniqueness, Seq # column, or caption placement above table) | **None** |
| **A14** | PDF page 2 footer overflow | No | `backend/tests/test_pdf_generation.py` | PASS (only tests basic pypdf page count/text extract; does not check text bounding box vs footer) | **None** |
| **A15** | Raw MalwareBazaar rule name shown | No | None | N/A (no test verifying family normalization from raw YARA rule names) | **None** |
| **A16** | GeoIP missing-database handling | No | `backend/tests/test_part2_integration.py` | PASS (tests private IP lookup; no test for distinct "GeoIP database not configured" message) | **None** |

---

### Key Takeaway
All 847 existing tests are passing, but **none** of the existing tests cover or prevent the regressions described in A1–A16. In multiple cases (`test_evidence_correlation.py`, `test_capability_rules.py`, `risk_scoring.py`), existing tests directly test or permit the legacy buggy behavior.
