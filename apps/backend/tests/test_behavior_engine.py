from backend.app.behavior import infer_static_behaviors


def _by_category(profile):
    return {finding["category"]: finding for finding in profile["findings"]}


def test_failed_dynamic_analysis_uses_sample_specific_exe_evidence():
    static = {
        "file_type": "exe",
        "platform": "windows",
        "format_details": {
            "imports": [{"library": "kernel32.dll", "functions": [
                "CreateProcessW", "CreateFileW", "WriteFile", "GetComputerNameW",
                "IsDebuggerPresent", "RegSetValueExW", "VirtualAllocEx", "WriteProcessMemory",
            ]}],
        },
        "extracted_strings": {"suspicious_keywords": [
            "powershell.exe -NoProfile", "cmd.exe /c whoami",
            r"C:\Users\Public\Desktop\payload.exe", "https://cdn.example.invalid/update",
            "password", "%APPDATA%\\Microsoft\\Windows\\Start Menu\\Programs\\Startup",
        ]},
        "yara_matches": [{"rule_name": "AntiVM_Behavior", "category": "anti_vm",
                          "description": "Generic rule prose mentioning persistence."}],
    }

    profile = infer_static_behaviors(static, {"dynamic_status": "failed", "failure_reason": "sandbox unavailable"})
    categories = _by_category(profile)

    assert profile["mode"] == "BEHAVIORAL SIMULATION"
    assert {"execution", "command", "network", "dns_http", "file_activity", "persistence",
            "discovery", "credential_data", "anti_debug", "anti_vm", "injection"} <= categories.keys()
    assert all(item["source"] == "behavioral_simulation" for item in profile["findings"])
    assert all(item["runtime_verified"] is False for item in profile["findings"])
    assert all("pid" not in " ".join(item["evidence"]).lower() for item in profile["findings"])


def test_different_samples_produce_different_profiles():
    powershell = {"file_type": "exe", "extracted_strings": {"all": ["powershell.exe -EncodedCommand ABC"]}}
    credential_reader = {"file_type": "exe", "format_details": {"imports": [{"functions": ["CredEnumerateW", "CryptUnprotectData"]}]}}
    elf_shell = {"file_type": "elf", "format_details": {"symbols": ["execve", "ptrace", "PTRACE_TRACEME"]}}

    first = infer_static_behaviors(powershell, {"dynamic_status": "unavailable"})
    different_exe = infer_static_behaviors(credential_reader, {"dynamic_status": "unavailable"})
    second = infer_static_behaviors(elf_shell, {"dynamic_status": "unavailable"})

    assert {item["category"] for item in first["findings"]} != {item["category"] for item in different_exe["findings"]}
    assert {item["category"] for item in first["findings"]} != {item["category"] for item in second["findings"]}
    assert "command" in {item["category"] for item in first["findings"]}
    assert "credential_data" in {item["category"] for item in different_exe["findings"]}
    assert "anti_debug" not in {item["category"] for item in first["findings"]}
    assert "anti_debug" in {item["category"] for item in second["findings"]}


def test_apk_manifest_permissions_and_components_are_platform_evidence():
    static = {
        "file_type": "apk", "platform": "android",
        "format_details": {
            "requested_permissions": ["android.permission.RECEIVE_SMS", "android.permission.RECEIVE_BOOT_COMPLETED"],
            "services": [{"name": "com.example.SyncService", "exported": True}],
            "receivers": ["com.example.BootReceiver"],
        },
    }

    categories = _by_category(infer_static_behaviors(static, {"dynamic_status": "unavailable"}))

    assert "credential_data" in categories
    assert "persistence" in categories
    assert all("android" in item["rationale"].lower() for item in categories.values())


def test_pe_dll_imports_and_elf_symbols_are_normalized():
    pe = {"file_type": "pe", "platform": "windows", "format_details": {"imports": [{"functions": ["CreateProcessW"]}]}}
    dll = {"file_type": "dll", "platform": "windows", "format_details": {"imports": [{"functions": ["LoadLibraryW", "CreateProcessW"]}]}}
    elf = {"file_type": "elf", "platform": "linux", "format_details": {"symbols": ["execve", "ptrace", "PTRACE_TRACEME"], "needed_libraries": ["libc.so.6"]}}

    pe_categories = {item["category"] for item in infer_static_behaviors(pe)["findings"]}
    dll_categories = {item["category"] for item in infer_static_behaviors(dll)["findings"]}
    elf_categories = {item["category"] for item in infer_static_behaviors(elf)["findings"]}

    assert "execution" in pe_categories
    assert "execution" in dll_categories
    assert {"execution", "anti_debug"} <= elf_categories


def test_runtime_observations_are_preserved_and_fused_with_static_evidence():
    profile = infer_static_behaviors(
        {"file_type": "exe", "format_details": {"imports": [{"functions": ["WinHttpOpen"]}]}},
        {"dynamic_status": "completed", "network_connections": [{"ip": "203.0.113.50", "port": 443}],
         "process_tree": [{"process_name": "powershell.exe", "cmdline": "powershell.exe -NoProfile"}]},
    )

    assert profile["mode"] == "MIXED EVIDENCE"
    observed = [finding for finding in profile["findings"] if finding["runtime_verified"]]
    assert observed and observed[0]["source"] == "dynamic_analysis"
    network_observation = next(item for item in observed if item["category"] == "network")
    assert "203.0.113.50" in " ".join(network_observation["evidence"])
    assert any(item["category"] == "command" and item["runtime_verified"] for item in profile["findings"])
    assert any(finding.get("corroborated_by_runtime") for finding in profile["static_findings"])


def test_completed_empty_runtime_uses_static_assessment_not_simulation():
    profile = infer_static_behaviors(
        {"file_type": "elf", "format_details": {"symbols": ["execve"]}},
        {"dynamic_status": "no_behavior_observed"},
    )

    assert profile["mode"] == "STATIC ASSESSMENT"
    assert all(item["source"] == "static_assessment" for item in profile["findings"])
    assert not any(item["runtime_verified"] for item in profile["findings"])


def test_yara_description_alone_cannot_claim_persistence():
    profile = infer_static_behaviors({
        "file_type": "exe",
        "yara_matches": [{"rule_name": "generic_rule", "category": "malware",
                          "description": "Sample creates a service and persists using Run keys."}],
    }, {"dynamic_status": "failed"})

    assert profile["mode"] == "INSUFFICIENT EVIDENCE"
    assert profile["findings"] == []


def test_unsupported_architecture_activates_static_fallback():
    profile = infer_static_behaviors(
        {"file_type": "elf", "platform": "linux", "format_details": {"symbols": ["execve"]}},
        {"dynamic_status": "not_supported_platform", "failure_reason": "unsupported architecture"},
    )

    assert profile["mode"] == "BEHAVIORAL SIMULATION"
    assert profile["fallback_reason"] == "unsupported architecture"
    assert all(item["runtime_verified"] is False for item in profile["findings"])
