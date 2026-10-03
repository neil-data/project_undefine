"""
conftest.py — Shared fixtures for the agent-layer test suite.

Fixtures build StaticAnalysisOutput / DynamicAnalysisOutput objects
directly in code (not from JSON files) so tests are fast, isolated,
and don't depend on mock_data/ files existing or staying unchanged.
"""

import pytest

from agents.orchestrator.schema import (
    StaticAnalysisOutput,
    DynamicAnalysisOutput,
    AndroidManifestInfo,
    PEAnalysisInfo,
    BinaryAnalysisInfo,
    ExtractedStrings,
    MLClassifierResult,
    YaraMatch,
)


@pytest.fixture
def benign_static():
    return StaticAnalysisOutput(
        sample_id="benign001", sha256="0" * 64, platform="android", file_type="apk",
        file_size_bytes=1200000, submitted_at="2026-07-17T10:00:00Z",
        yara_matches=[],
        android_manifest=AndroidManifestInfo(
            package_name="com.example.calculator",
            permissions=["android.permission.INTERNET"],
            requested_sdk=34, exported_components=[],
        ),
        pe_analysis=None,
        extracted_strings=ExtractedStrings(),
        ml_classifier=MLClassifierResult(model="isolation_forest_v1", anomaly_score=0.05, classification="benign"),
        static_risk_flags=[],
    )


@pytest.fixture
def android_malicious_static():
    return StaticAnalysisOutput(
        sample_id="a3f9c2b1e4d5f6a7b8c9d0e1f2a3b4c5", sha256="a" * 64, platform="android", file_type="apk",
        file_size_bytes=4821376, submitted_at="2026-07-11T10:15:00Z",
        yara_matches=[
            YaraMatch(rule_name="india_scam_sms_permission_overlay", category="india_scam_rules",
                       severity="high", description="SMS + overlay pattern"),
        ],
        android_manifest=AndroidManifestInfo(
            package_name="com.quickloan.easyapp",
            permissions=[
                "android.permission.READ_SMS", "android.permission.RECEIVE_SMS",
                "android.permission.SYSTEM_ALERT_WINDOW", "android.permission.READ_CONTACTS",
                "android.permission.ACCESS_FINE_LOCATION",
            ],
            requested_sdk=33, exported_components=["com.quickloan.easyapp.SmsReceiver"],
        ),
        pe_analysis=None,
        extracted_strings=ExtractedStrings(
            urls=["http://185.220.101.45/api/collect"], ips=["185.220.101.45"],
            suspicious_keywords=["sms_forward", "otp_capture", "device_admin"],
        ),
        ml_classifier=MLClassifierResult(model="isolation_forest_v1", anomaly_score=0.87, classification="likely_malicious"),
        static_risk_flags=["requests_sms_and_overlay_together", "hardcoded_c2_ip", "matches_india_scam_yara_rule"],
    )


@pytest.fixture
def android_malicious_dynamic():
    return DynamicAnalysisOutput(
        sample_id="a3f9c2b1e4d5f6a7b8c9d0e1f2a3b4c5",
        process_tree=[{"pid": 1, "name": "app_process", "children": [2]}],
        api_calls=[
            "SmsManager.getAllMessagesFromIcc", "ContentResolver.query(content://sms/inbox)",
            "HttpURLConnection.connect", "LocationManager.requestLocationUpdates",
            "DevicePolicyManager.isAdminActive",
        ],
        network_connections=[
            {"dest_ip": "185.220.101.45", "dest_port": 443, "protocol": "https",
             "bytes_sent": 18420, "interval_seconds": 40, "flagged_c2": True}
        ],
        files_written=["/data/data/com.quickloan.easyapp/shared_prefs/sms_cache.xml"],
        registry_changes=[],
        c2_endpoints_detected=["185.220.101.45:443"],
    )


@pytest.fixture
def windows_malicious_static():
    return StaticAnalysisOutput(
        sample_id="win_pe_001", sha256="1" * 64, platform="windows", file_type="exe",
        file_size_bytes=850000, submitted_at="2026-07-17T10:05:00Z",
        yara_matches=[
            YaraMatch(rule_name="generic_trojan_dropper", category="generic",
                       severity="high", description="Matches known dropper pattern"),
        ],
        android_manifest=None,
        pe_analysis=PEAnalysisInfo(imports=["WININET.dll", "ADVAPI32.dll"],
                                     sections=[".text", ".data", ".rsrc"],
                                     compile_timestamp="2026-06-01T00:00:00Z"),
        extracted_strings=ExtractedStrings(
            urls=["http://malicious-c2.example/gate.php"], ips=["45.9.20.11"],
            suspicious_keywords=["keylog", "screenshot"],
        ),
        ml_classifier=MLClassifierResult(model="isolation_forest_v1", anomaly_score=0.91, classification="likely_malicious"),
        static_risk_flags=["hardcoded_c2_ip"],
    )


@pytest.fixture
def windows_malicious_dynamic():
    return DynamicAnalysisOutput(
        sample_id="win_pe_001",
        process_tree=[{"pid": 1, "name": "sample.exe", "children": []}],
        api_calls=["RegSetValueEx", "CreateRemoteThread", "GetKeyboardState"],
        network_connections=[
            {"dest_ip": "45.9.20.11", "dest_port": 8080, "protocol": "tcp",
             "bytes_sent": 5000, "interval_seconds": 30, "flagged_c2": True}
        ],
        files_written=["C:\\Users\\victim\\AppData\\Roaming\\svc.exe"],
        registry_changes=["HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\svc"],
        c2_endpoints_detected=["45.9.20.11:8080"],
    )


@pytest.fixture
def empty_dynamic():
    """Dynamic output exists (sandbox ran) but found nothing notable."""
    return DynamicAnalysisOutput(
        sample_id="empty001", process_tree=[], api_calls=[],
        network_connections=[], files_written=[], registry_changes=[],
        c2_endpoints_detected=[],
    )


@pytest.fixture
def sparse_static():
    """Minimal valid object — tests nothing assumes optional fields exist."""
    return StaticAnalysisOutput(
        sample_id="sparse001", sha256="3" * 64, platform="android", file_type="apk",
        file_size_bytes=500000, submitted_at="2026-07-17T10:15:00Z",
        yara_matches=[],
        android_manifest=AndroidManifestInfo(package_name="com.unknown.app", permissions=[],
                                               requested_sdk=None, exported_components=[]),
        pe_analysis=None,
        extracted_strings=ExtractedStrings(),
        ml_classifier=None,
        static_risk_flags=[],
    )


@pytest.fixture
def linux_elf_static():
    return StaticAnalysisOutput(
        sample_id="elf001", sha256="4" * 64, platform="linux", file_type="elf",
        file_size_bytes=45000, submitted_at="2026-07-17T11:00:00Z",
        yara_matches=[
            YaraMatch(rule_name="linux_reverse_shell_pattern", category="generic",
                       severity="high", description="ELF binary with shell spawn + network pattern"),
        ],
        android_manifest=None,
        pe_analysis=None,
        binary_analysis=BinaryAnalysisInfo(
            format="ELF", imports=["execve", "socket", "setuid", "connect"],
            sections=[".text", ".data", ".bss"], architecture="x86_64", is_signed=None,
        ),
        extracted_strings=ExtractedStrings(
            urls=[], ips=["103.45.11.9"], suspicious_keywords=["LD_PRELOAD"],
        ),
        ml_classifier=MLClassifierResult(model="isolation_forest_v1", anomaly_score=0.88, classification="likely_malicious"),
        static_risk_flags=["hardcoded_c2_ip"],
    )


@pytest.fixture
def linux_elf_dynamic():
    return DynamicAnalysisOutput(
        sample_id="elf001",
        process_tree=[{"pid": 1, "name": "sample_elf", "children": [2]},
                       {"pid": 2, "name": "/bin/sh", "children": []}],
        api_calls=["setuid(0)", "socket()", "connect()"],
        network_connections=[
            {"dest_ip": "103.45.11.9", "dest_port": 4444, "protocol": "tcp",
             "bytes_sent": 2000, "interval_seconds": 20, "flagged_c2": True}
        ],
        files_written=["/tmp/.hidden_payload"],
        registry_changes=[],
        persistence_artifacts=["/etc/cron.d/system-update"],
        c2_endpoints_detected=["103.45.11.9:4444"],
    )


@pytest.fixture
def macos_machO_static():
    return StaticAnalysisOutput(
        sample_id="macho001", sha256="5" * 64, platform="macos", file_type="macho",
        file_size_bytes=98000, submitted_at="2026-07-17T11:05:00Z",
        yara_matches=[],
        android_manifest=None,
        pe_analysis=None,
        binary_analysis=BinaryAnalysisInfo(
            format="MachO", imports=["NSTask", "URLSession"],
            sections=["__TEXT", "__DATA"], architecture="arm64", is_signed=False,
        ),
        extracted_strings=ExtractedStrings(urls=["http://mac-c2.example/beacon"], ips=[], suspicious_keywords=[]),
        ml_classifier=MLClassifierResult(model="isolation_forest_v1", anomaly_score=0.7, classification="suspicious"),
        static_risk_flags=[],
    )


@pytest.fixture
def macos_machO_dynamic():
    return DynamicAnalysisOutput(
        sample_id="macho001",
        process_tree=[{"pid": 1, "name": "sample_macho", "children": []}],
        api_calls=["NSTask.launch"],
        network_connections=[
            {"dest_ip": "51.68.10.4", "dest_port": 443, "protocol": "https",
             "bytes_sent": 3000, "interval_seconds": 60, "flagged_c2": True}
        ],
        files_written=[],
        registry_changes=[],
        persistence_artifacts=["~/Library/LaunchAgents/com.fakeupdate.plist"],
        c2_endpoints_detected=["51.68.10.4:443"],
    )