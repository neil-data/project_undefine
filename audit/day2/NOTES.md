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
