# Day 2 Notes — Dynamic Sandbox Provenance & Fixture Verification

## A1. Dynamic Execution Provenance Analysis: `mirai_droppee`

### Investigation Findings
- **Sample Hash**: `87ace603b502bb8f30125c26922000d10576e5fd42fd1e4937e78a0b7e522d28`
- **Initial Introduction**: Commit `dd885821bdc86cb671a316ee7ce41abd0be920c2` (*"feat: real dynamic sandbox microservice, multi-arch QEMU, HMAC manifest binding, zero-simulation purge"*).
- **Dynamic Analysis Section**:
  - `execution_mode`: `"real"`
  - `dynamic_status`: `"completed"`
  - `task_id`: `"d2dcec1c-5f25-4d0c-b64c-ee51a40cccfc"`
  - `sandbox_url`: `"http://testserver-sandbox"`
  - `process_tree`: `[{"pid": 1000, "name": "sample.bin", "cmdline": "./sample.bin", "timestamp": "+0.000s", "status": "completed"}]`
  - `api_calls`: `["sys_execve", "sys_brk", "sys_write", "sys_exit_group"]`

### Verdict: Non-Real Detonation (Mock / Test Harness Stub)
1. `sandbox_url` points to `http://testserver-sandbox`. This URI is explicitly injected via `monkeypatch.setenv("SANDBOX_API_URL", "http://testserver-sandbox")` in `apps/backend/tests/test_sandbox_integration_stage3.py` for ASGI test client routing (`httpx.ASGITransport(app=sandbox_app)`).
2. The execution was run through the in-process test transport rather than a live external QEMU / hardware sandbox isolation environment.
3. The dynamic findings represent mock/test harness trace generation.

### Remediation Applied
- Fixture `tests/e2e/fixtures/mirai_droppee.json` renamed to `tests/e2e/fixtures/synthetic_mirai_droppee.json`.
- Set `"synthetic": true` in top-level metadata and fixture root.
- Retrospective correction note appended to `docs/phases/audit/phase6/PHASE6_REPORT.md`.
- `reports/examples/README.md` created documenting synthetic test fixture provenance.

---

## A2. Fixture Exercise & Verification Log

Each of the 13 e2e fixtures was evaluated against the updated engine contracts:

1. **`clean_control.json`**:
   - Baseline clean sample. Passes all contracts (`test_no_fake_dynamic`, `test_source_separation`, `test_narrative`, `test_iocs`, `test_score`, `test_timeline_meta`, `test_recommendations`).
2. **`synthetic_mirai_droppee.json`**:
   - Narrative terminal punctuation fixed (`.` appended to closing sentence).
   - Source separation verified: YARA matches strictly STATIC (0.65–0.70 confidence).
   - `test_source_separation`, `test_narrative`, and `test_iocs` PASS.
   - Deferred Day 3 items: duplicate timestamp, static score cap (>20 pts).
3. **`base64_and_system_libs_as_paths.json`**:
   - Reclassified: base64 string (`aW52YWxpZGJhc2U2NGJsb2J0aGF0aXNsb25nZXJ0aGFuMzJjaGFycw==`) classified as `BASE64`, and `kernel32.dll` classified as `LIBRARY`.
   - B3 classifier and path validator verified that neither is admitted as a filesystem persistence/install path.
   - All Day 2 contracts PASS.
4. **`benign_hosts_suspicious.json`**:
   - Benign vendor hosts (`go.dev`, `microsoft.com`, `android.googlesource.com`) validated via authoritative allowlist.
   - Indicator typed as `SYSTEM_INFRASTRUCTURE` / `BENIGN`. Sample status set to `clean` / `CLEAN` / `LOW`.
   - All Day 2 contracts PASS.
5. **`go_symbols_as_domains.json`**:
   - Go standard library symbols (`fmt.pp`, `go.shape`, `io.pipe`, `os.file`) identified and rejected from `network_indicators.domains`.
   - Classified as `SYMBOL` in `ioc_intelligence`.
   - All Day 2 contracts PASS.
6. **`random_fragment_domains.json`**:
   - Short SLD fragments (`jC.bn`, `XB.kr`) and invalid TLD (`QMrS.lg`) rejected by PSL / 3-character SLD validator.
   - Network domain indicator list cleared; typed as `UNKNOWN` in `ioc_intelligence`.
   - All Day 2 contracts PASS.
7. **`static_rule_labeled_intel.json`**:
   - YARA / static rule capability match updated to canonical `evidence_state: "STATIC"`, `confidence: 0.65`, `confidence_level: "medium"`.
   - B1 invariant verified: no static rule hit can claim `INTEL` or `confirmed`.
   - All Day 2 contracts PASS.
8. **`fabricated_narrative.json`**:
   - Raw markdown table (`| Step`, `|---`) and `<br>` syntax replaced with code-rendered grounded forensic narrative.
   - Narrative pipeline grounding validator verified.
   - All Day 2 contracts PASS.
9. **`llm_refusal.json`**:
   - LLM refusal phrase (`I'm sorry, but I can't help with that`) detected by refusal phrase filter and replaced with deterministic fallback narrative.
   - All Day 2 contracts PASS.
10. **`static_cap_exceeded.json`**:
    - Day 2 contracts (`test_no_fake_dynamic`, `test_source_separation`, `test_narrative`, `test_iocs`) PASS.
    - Deferred Day 3 item: static MITRE+capability score cap (35 pts > 20 pts max).
11. **`critical_all_vendors_clean.json`**:
    - Day 2 contracts (`test_no_fake_dynamic`, `test_source_separation`, `test_narrative`, `test_iocs`) PASS.
    - Deferred Day 3 item: CRITICAL score without threat intel or observed execution.
12. **`duplicate_timestamps_synthetic_offset.json`**:
    - Day 2 contracts (`test_no_fake_dynamic`, `test_source_separation`, `test_narrative`, `test_iocs`) PASS.
    - Deferred Day 3 item: duplicate identical timestamp without distinguishing label.
13. **`credential_advice_no_evidence.json`**:
    - Day 2 contracts (`test_no_fake_dynamic`, `test_source_separation`, `test_narrative`, `test_iocs`) PASS.
    - Deferred Day 3 item: credential rotation recommendation without credential theft evidence.
