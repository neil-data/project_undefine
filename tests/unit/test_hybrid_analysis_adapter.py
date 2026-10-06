"""Layer-2 tests for Hybrid Analysis adapter using recorded real responses."""
import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from providers.dynamic.base import DynamicState, NormalizedProviderResult
from providers.dynamic.hybrid_analysis import HybridAnalysisAdapter
from providers.dynamic.pipeline import DynamicAnalysisPipeline
from providers.dynamic.trust_boundary import normalize_provider_result

FIXTURES_DIR = Path(__file__).resolve().parents[1] / "fixtures" / "providers" / "hybrid_analysis"


def load_fixture(name: str):
    path = FIXTURES_DIR / name
    assert path.exists(), f"Recorded fixture {name} must exist"
    return json.loads(path.read_text(encoding="utf-8"))


def test_recorded_overview_summary_gives_intel_verdict_and_zero_dynamic_evidence():
    """Real recorded overview summary with verdict='malicious' produces INTEL, zero dynamic findings."""
    raw_overview = load_fixture("overview_summary_4faccd95.json")
    adapter = HybridAnalysisAdapter(api_key="mocked-valid-key")

    normalized = adapter.normalize(raw_overview)
    result = normalize_provider_result(
        adapter, normalized, task_id="task-4faccd95", environment="Linux (Ubuntu 24.04, 64 bit)"
    )

    assert result.state == DynamicState.COMPLETED
    assert not result.observation.has_behavior()
    assert len(result.findings) == 0  # Zero dynamic evidence findings
    assert result.verdict is not None
    assert result.verdict.source_type == "INTEL"
    assert result.verdict.evidence_state == "INTEL"
    assert result.verdict.source == "provider:hybrid_analysis"
    assert "malicious" in result.verdict.evidence
    assert result.narrative == "A provider verdict was reported, but no behavior was observed."


def test_recorded_lookup_no_result_and_empty_reports():
    """Real recorded 404 response produces NO_RESULT state."""
    raw_404 = load_fixture("lookup_random_no_result.json")
    adapter = HybridAnalysisAdapter(api_key="mocked-valid-key")

    normalized = adapter.normalize(raw_404)
    result = normalize_provider_result(adapter, normalized, task_id="task-no-result", environment="Windows")

    assert result.state == DynamicState.NO_RESULT
    assert not result.findings
    assert result.verdict is None

    # Empty reports also produces NO_RESULT
    raw_empty = load_fixture("lookup_12c9f247.json")
    norm_empty = adapter.normalize(raw_empty)
    result_empty = normalize_provider_result(adapter, norm_empty, task_id="task-empty", environment="Windows")
    assert result_empty.state == DynamicState.NO_RESULT


def test_recorded_environments_selects_dynamic_environments_dynamically():
    """Environment list is parsed from recorded environment list, never hardcoded."""
    raw_envs = load_fixture("environments.json")
    adapter = HybridAnalysisAdapter(api_key="mocked-valid-key", environments_data=raw_envs)

    linux_env = adapter.get_environment_for_platform("ELF", "x86_64")
    assert linux_env is not None
    assert linux_env.get("environment_id") == 330
    assert "Linux" in linux_env.get("description", "")

    win_env = adapter.get_environment_for_platform("EXE", "x86_64")
    assert win_env is not None
    assert win_env.get("environment_id") in (160, 140, 100, 110, 120)


def test_ha_hash_lookup_behavior_shaped_payload_is_intel_only():
    """Hash lookup payloads cannot prove an execution task or produce DYNAMIC evidence."""
    adapter = HybridAnalysisAdapter(api_key="mocked-valid-key")

    mock_response = {
        "verdict": "malicious",
        "threat_score": 90,
        "behavior": {
            "processes": [{"name": "evil.elf", "pid": 1234}],
            "network": [{"domain": "malicious-c2.test", "port": 443}],
            "dns": [{"name": "malicious-c2.test"}],
        },
    }

    with patch.object(adapter, "lookup_by_hash", return_value=mock_response):
        pipeline = DynamicAnalysisPipeline(providers={"hybrid_analysis": adapter})
        result = pipeline.run("a" * 64, platform="ELF", architecture="x86_64")

        assert result.state == DynamicState.COMPLETED
        assert not result.observation.has_behavior()
        assert not result.findings
        assert result.verdict is not None
        assert result.verdict.source_type == "INTEL"
        assert result.provenance["task_id"] is None


def test_ha_adapter_all_failure_states_handled_cleanly():
    """All 10 failure/status states produce clean lines without unhandled exceptions."""
    adapter = HybridAnalysisAdapter(api_key="mocked-valid-key")

    states = [
        DynamicState.NO_RESULT,
        DynamicState.KEY_RESTRICTED,
        DynamicState.SUBMISSION_DISABLED,
        DynamicState.RATE_LIMITED,
        DynamicState.TIMEOUT,
        DynamicState.PROVIDER_UNAVAILABLE,
        DynamicState.INVALID_RESPONSE,
        DynamicState.KEY_MISSING,
        DynamicState.NOT_SUPPORTED_PLATFORM,
    ]

    for st in states:
        res = adapter.make_result_for_state(st)
        assert isinstance(res, NormalizedProviderResult)
        assert res.state == st
        assert res.report_line is not None
        assert "Dynamic analysis" in res.report_line or "not performed" in res.report_line


def test_ha_budget_limits_block_excess_requests(tmp_path):
    """Daily request limit prevents excessive provider calls."""
    adapter = HybridAnalysisAdapter(
        api_key="mocked-valid-key",
        daily_request_limit=3,
        budget_file=str(tmp_path / "budget.json"),
    )

    with patch("requests.get") as mock_get:
        mock_resp = MagicMock()
        mock_resp.status_code = 404
        mock_resp.json.return_value = {"message": "Requested hash not found"}
        mock_get.return_value = mock_resp

        # First 3 should work
        for i in range(3):
            res = adapter.lookup_by_hash(f"{i:064x}")
            assert "state" not in res or res.get("state") != DynamicState.RATE_LIMITED

        # 4th request must be rate limited by local budget
        res4 = adapter.lookup_by_hash("f" * 64)
        assert res4.get("state") == DynamicState.RATE_LIMITED


def test_ha_submission_disabled_by_default(monkeypatch):
    """Submission is blocked when ALLOW_EXTERNAL_SUBMISSION is not true."""
    monkeypatch.setenv("ALLOW_EXTERNAL_SUBMISSION", "false")
    adapter = HybridAnalysisAdapter(api_key="mocked-valid-key")

    res = adapter.submit(b"test-bytes")
    assert res.get("state") == DynamicState.SUBMISSION_DISABLED


def test_render_production_configuration_opts_in_without_exposing_ha_secret():
    """The production blueprint enables HA submissions and keeps the key in Render secrets."""
    import yaml

    blueprint = yaml.safe_load((Path(__file__).resolve().parents[2] / "render.yaml").read_text(encoding="utf-8"))
    backend = next(service for service in blueprint["services"] if service["name"] == "e-rakshak-backend")
    settings = {entry["key"]: entry for entry in backend["envVars"]}
    assert settings["ALLOW_EXTERNAL_SUBMISSION"]["value"] == "true"
    assert settings["HYBRID_ANALYSIS_API_KEY"]["sync"] is False


def test_missing_key_and_explicit_disable_keep_submission_blocked(monkeypatch):
    monkeypatch.setenv("HYBRID_ANALYSIS_API_KEY", "")
    monkeypatch.setenv("ALLOW_EXTERNAL_SUBMISSION", "true")
    adapter = HybridAnalysisAdapter(api_key="", budget_file="unused-test-budget.json")
    assert adapter.submit("sample.exe")["state"] == DynamicState.KEY_MISSING.value

    monkeypatch.setenv("HYBRID_ANALYSIS_API_KEY", "test-key")
    monkeypatch.setenv("ALLOW_EXTERNAL_SUBMISSION", "false")
    adapter = HybridAnalysisAdapter(budget_file="unused-test-budget.json")
    assert adapter.submit("sample.exe")["state"] == DynamicState.SUBMISSION_DISABLED.value


def test_real_execution_lifecycle_requires_task_and_normalizes_report(tmp_path, monkeypatch):
    """Only a submitted task's completed report can pass behavior to the trust boundary."""
    import hashlib
    from types import SimpleNamespace

    sample = tmp_path / "controlled.exe"
    sample.write_bytes(b"controlled sample bytes")
    digest = hashlib.sha256(sample.read_bytes()).hexdigest()
    monkeypatch.setenv("ALLOW_EXTERNAL_SUBMISSION", "true")
    adapter = HybridAnalysisAdapter(api_key="test-key", budget_file=str(tmp_path / "budget.json"), poll_interval=0.1)

    submitted = SimpleNamespace(status_code=201)
    submitted.json = lambda: {"job_id": "real-job-123", "submission_id": "submission-1", "environment_id": 160, "sha256": digest}
    pending = SimpleNamespace(status_code=200)
    pending.json = lambda: {"state": "IN_PROGRESS"}
    complete = SimpleNamespace(status_code=200)
    complete.json = lambda: {"state": "SUCCESS"}
    report = SimpleNamespace(status_code=200, content=json.dumps({
        "processes": [{"name": "sample.exe", "uid": "1", "parentuid": "0", "command_line": "sample.exe"}],
        "domains": ["example.test"], "hosts": ["203.0.113.9"],
        "extracted_files": [{"file_path": "C:/temp/drop.bin", "sha256": "a" * 64}],
    }).encode())
    with patch("requests.post", return_value=submitted) as post, patch("requests.get", side_effect=[pending, complete, report]) as get:
        raw = adapter.execute_sample(sample, "EXE", "x86_64", timeout_seconds=3, poll_interval=0.1)

    assert raw["state"] == "COMPLETED"
    assert raw["task_id"] == "real-job-123"
    assert post.call_args.args[0].endswith("/api/v2/submit/file")
    assert get.call_args_list[0].args[0].endswith("/api/v2/report/real-job-123/state")
    assert get.call_args_list[-1].args[0].endswith("/api/v2/report/real-job-123/report/json")
    pipeline = DynamicAnalysisPipeline(providers={"hybrid_analysis": adapter})
    with patch.object(adapter, "execute_sample", return_value=raw):
        normalized = pipeline.run_execution(sample, digest, "EXE", "x86_64")
    assert normalized.state == DynamicState.COMPLETED
    assert normalized.provenance["task_id"] == "real-job-123"
    assert normalized.findings
    assert all(f.source_type == "DYNAMIC" and f.evidence_state == "OBSERVED" for f in normalized.findings)
    assert normalized.observation.process[0]["name"] == "sample.exe"
    assert {row["name"] for row in normalized.observation.network} == {"example.test", "203.0.113.9"}
    assert normalized.observation.file[0]["file_path"] == "C:/temp/drop.bin"


def test_completed_task_without_behavior_never_becomes_dynamic(tmp_path, monkeypatch):
    monkeypatch.setenv("ALLOW_EXTERNAL_SUBMISSION", "true")
    adapter = HybridAnalysisAdapter(api_key="test-key", budget_file=str(tmp_path / "budget.json"))
    monkeypatch.setattr(adapter, "submit_sample", lambda *args: {"state": "SUBMITTED", "task_id": "actual-task"})
    monkeypatch.setattr(adapter, "get_status", lambda task: {"state": "COMPLETED", "provider_state": "SUCCESS"})
    monkeypatch.setattr(adapter, "get_report", lambda task: {"state": "COMPLETED", "report": {"verdict": "malicious"}})
    raw = adapter.execute_sample("sample.exe", "EXE", "x86_64", timeout_seconds=1)
    assert raw["state"] == DynamicState.INVALID_RESPONSE.value
    assert raw["task_id"] == "actual-task"


def test_task_failure_reason_is_preserved(tmp_path, monkeypatch):
    adapter = HybridAnalysisAdapter(api_key="test-key", budget_file=str(tmp_path / "budget.json"))
    monkeypatch.setattr(adapter, "submit_sample", lambda *args: {"state": "SUBMITTED", "task_id": "actual-task"})
    monkeypatch.setattr(adapter, "get_status", lambda task: {"state": DynamicState.PROVIDER_UNAVAILABLE.value, "reason": "unsupported sample by provider"})
    raw = adapter.execute_sample("sample.dll", "DLL", "x86_64", timeout_seconds=1)
    assert raw["state"] == DynamicState.PROVIDER_UNAVAILABLE.value
    assert raw["reason"] == "unsupported sample by provider"
    assert raw["task_id"] == "actual-task"
