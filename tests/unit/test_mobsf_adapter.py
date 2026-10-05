"""Layer-2 tests for MobSF adapter using verified schema and real pipeline entrypoint."""
import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from providers.dynamic.base import DynamicState
from providers.dynamic.trust_boundary import normalize_provider_result
from sandbox.adapters.mobsf.adapter import MobSFAdapter

FIXTURES_DIR = Path(__file__).resolve().parents[1] / "fixtures" / "providers"


SAMPLE_MOBSF_STATIC_REPORT = {
    "package_name": "com.example.harmless.test",
    "version_name": "1.0.0",
    "version_code": "1",
    "min_sdk": "21",
    "target_sdk": "33",
    "max_sdk": "",
    "permissions": {
        "android.permission.INTERNET": {
            "status": "normal",
            "info": "Allows applications to open network sockets.",
            "description": "Full Internet access",
        },
        "android.permission.READ_EXTERNAL_STORAGE": {
            "status": "dangerous",
            "info": "Allows an application to read from external storage.",
            "description": "Read external storage",
        },
    },
    "exported_activities": ["com.example.harmless.MainActivity"],
    "activities": ["com.example.harmless.MainActivity", "com.example.harmless.SettingsActivity"],
    "services": [],
    "receivers": [],
    "providers": [],
    "certificate_analysis": {
        "certificate_info": "Subject: CN=Android Debug, O=Android, C=US\nIssuer: CN=Android Debug",
        "certificate_summary": {
            "subject": "CN=Android Debug, O=Android, C=US",
            "issuer": "CN=Android Debug, O=Android, C=US",
            "sha256": "112233445566778899aabbccddeeff00112233445566778899aabbccddeeff00",
            "is_debug_or_self_signed": True,
        },
    },
    "native_libraries": ["libsample.so"],
    "findings": [
        {"title": "Application is Debuggable", "severity": "high", "description": "The binary has android:debuggable=true"}
    ],
}


def test_mobsf_static_normalization_extracts_all_verified_fields():
    """MobSF static report is normalized into static evidence attributed to MobSF."""
    adapter = MobSFAdapter(url="http://localhost:8003", api_key="test-key")
    normalized = adapter.normalize_static_report(SAMPLE_MOBSF_STATIC_REPORT)

    assert normalized["package"] == "com.example.harmless.test"
    assert normalized["version"] == "1.0.0"
    assert normalized["min_sdk"] == "21"
    assert normalized["target_sdk"] == "33"
    assert "android.permission.READ_EXTERNAL_STORAGE" in normalized["dangerous_permissions"]
    assert "android.permission.INTERNET" in normalized["permissions"]
    assert "com.example.harmless.MainActivity" in normalized["exported_components"]
    assert normalized["certificate"]["is_debug_or_self_signed"] is True
    assert "libsample.so" in normalized["native_libraries"]
    assert len(normalized["findings"]) == 1
    assert normalized["findings"][0]["title"] == "Application is Debuggable"


def test_mobsf_dynamic_skipped_when_emulator_not_ready(monkeypatch):
    """When emulator is offline/not ready, dynamic analysis is skipped with clean reason."""
    monkeypatch.setenv("MOBSF_DYNAMIC", "true")
    monkeypatch.setenv("MOBSF_DYNAMIC_ISOLATION_CONFIRMED", "true")
    monkeypatch.setenv("MOBSF_DYNAMIC_TIMEOUT", "30")

    adapter = MobSFAdapter(url="http://localhost:8003", api_key="test-key")

    # Mock emulator ready probe returning False
    with patch.object(adapter, "is_dynamic_ready", return_value=False):
        ready, reason = adapter.check_dynamic_eligibility()
        assert not ready
        assert "analyzer/emulator not ready" in reason

        # Even with dynamic disabled/unready, static still runs
        result = adapter.make_result_for_static(
            SAMPLE_MOBSF_STATIC_REPORT,
            task_id="mobsf-task-1",
            dynamic_reason=reason,
        )
        assert result.state == DynamicState.COMPLETED
        assert result.report_line is not None
        assert "Dynamic analysis not performed: analyzer/emulator not ready" in result.narrative


def test_mobsf_dynamic_skipped_when_flags_missing(monkeypatch):
    """Dynamic analysis is skipped if MOBSF_DYNAMIC or isolation confirmation is missing."""
    monkeypatch.setenv("MOBSF_DYNAMIC", "false")
    adapter = MobSFAdapter(url="http://localhost:8003", api_key="test-key")
    ready, reason = adapter.check_dynamic_eligibility()
    assert not ready
    assert "dynamic analysis disabled" in reason

    monkeypatch.setenv("MOBSF_DYNAMIC", "true")
    monkeypatch.delenv("MOBSF_DYNAMIC_ISOLATION_CONFIRMED", raising=False)
    ready, reason = adapter.check_dynamic_eligibility()
    assert not ready
    assert "isolation not confirmed" in reason


def test_mobsf_scan_always_attempts_deletion():
    """Scan deletion is always attempted, and delete failure is logged rather than fatal."""
    adapter = MobSFAdapter(url="http://localhost:8003", api_key="test-key")

    with patch.object(adapter, "upload_file", return_value={"hash": "scan-hash-123"}), \
         patch.object(adapter, "trigger_scan", return_value={}), \
         patch.object(adapter, "get_report_json", return_value=SAMPLE_MOBSF_STATIC_REPORT), \
         patch.object(adapter, "delete_scan", side_effect=Exception("network timeout on delete")) as mock_del:

        result = adapter.analyze_apk_content(b"fake-apk-bytes", filename="test.apk")
        mock_del.assert_called_once_with("scan-hash-123")
        assert result.state == DynamicState.COMPLETED
