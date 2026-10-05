import importlib.util
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_pytest_discovers_top_level_tests():
    config = (ROOT / "pytest.ini").read_text(encoding="utf-8")
    assert "testpaths =" in config
    section = config.split("testpaths =", 1)[1].split("\n\n", 1)[0]
    assert "tests" in section.split()


def test_example_lists_provider_environment_names_only():
    example = (ROOT / ".env.example").read_text(encoding="utf-8")
    names = {
        "HYBRID_ANALYSIS_API_KEY",
        "ALLOW_EXTERNAL_SUBMISSION",
        "PROVIDER_DAILY_REQUEST_LIMIT",
        "PROVIDER_DAILY_SUBMISSION_LIMIT",
        "PROVIDER_DYNAMIC_MAX_CONFIDENCE",
        "MOBSF_URL",
        "MOBSF_API_KEY",
        "MOBSF_DYNAMIC",
        "MOBSF_DYNAMIC_ISOLATION_CONFIRMED",
        "MOBSF_DYNAMIC_TIMEOUT",
    }
    for name in names:
        assert f"{name}=" in example


def test_selfcheck_redacts_keys_and_reports_unverified_operations(monkeypatch, capsys):
    monkeypatch.setenv("HYBRID_ANALYSIS_API_KEY", "unit-test-fake-key-do-not-print")
    monkeypatch.delenv("MOBSF_URL", raising=False)
    monkeypatch.delenv("MOBSF_API_KEY", raising=False)
    path = ROOT / "scripts" / "provider_selfcheck.py"
    spec = importlib.util.spec_from_file_location("provider_selfcheck", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    assert module.main() == 0
    output = capsys.readouterr().out
    assert "PASS" in output and "key present" in output
    assert "UNVERIFIED" in output
    assert "unit-test-fake-key-do-not-print" not in output
