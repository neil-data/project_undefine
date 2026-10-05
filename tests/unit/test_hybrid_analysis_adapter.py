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


def test_ha_adapter_pipeline_flow_with_behavior():
    """Test full pipeline lookup -> normalize -> trust boundary -> evidence with behavior."""
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
        assert result.observation.has_behavior()
        assert len(result.findings) > 0
        assert all(f.source_type == "DYNAMIC" for f in result.findings)
        assert all(f.evidence_state == "OBSERVED" for f in result.findings)
        assert all(f.source == "provider:hybrid_analysis" for f in result.findings)
        assert result.verdict is not None
        assert result.verdict.source_type == "INTEL"


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
