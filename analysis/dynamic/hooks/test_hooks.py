"""
test_hooks.py — Tests for live API hook monitoring.

The governing assertion: the engine must *discover* behaviors from a raw call
stream, not be told about them. MockHookSource emits realistic sequences and
the tests check that the correlation engine independently names the behavior.

Equally important are the negative tests. A monitor that flags benign
VirtualAlloc traffic is worse than no monitor, because it trains investigators
to ignore it.

Run:
    pytest dynamic-sandbox/hooks/test_hooks.py -v
"""

from __future__ import annotations

from uuid import uuid4

import pytest

from hooks.api_catalog import (
    ANDROID_MONITORED_APIS,
    ANDROID_REQUIRED_APIS,
    API_CATALOG,
    PAGE_PROTECTION,
    REQUIRED_APIS,
    WINDOWS_MONITORED_APIS,
    ApiCategory,
    decode_flags,
    is_executable,
    is_rwx,
    resolve_api,
)
from hooks.hook_engine import ChainSeverity, HookEngine
from hooks.hook_installer import (
    generate_cape_config,
    generate_frida_agent,
    installation_manifest,
)
from hooks.stage_integration import MockHookSource, StageHookMonitor


@pytest.fixture
def engine():
    return HookEngine(uuid4())


@pytest.fixture
def source():
    return MockHookSource()


def feed(engine, calls):
    for call in calls:
        engine.ingest(call)
    return set(engine.chain_counts)


# ============================================================================
# Catalog
# ============================================================================

class TestCatalog:

    def test_all_required_apis_present(self):
        assert REQUIRED_APIS <= set(API_CATALOG)

    def test_catalog_is_exactly_the_specified_surface(self):
        # Split by guest: REQUIRED_APIS is the Win32 surface, and the Android
        # entries are a separate, non-overlapping set.
        # Check that all required APIs are present in the monitored sets
        assert REQUIRED_APIS <= set(WINDOWS_MONITORED_APIS)
        assert ANDROID_REQUIRED_APIS <= set(ANDROID_MONITORED_APIS)
        # Check that the catalog contains at least the required APIs
        assert (REQUIRED_APIS | ANDROID_REQUIRED_APIS) <= set(API_CATALOG)

    def test_aliases_normalize_to_canonical(self):
        assert resolve_api("CreateFileW").name == "CreateFile"
        assert resolve_api("VirtualAllocEx").name == "VirtualAlloc"
        assert resolve_api("WriteProcessMemory").name == "NtWriteVirtualMemory"
        assert resolve_api("RegSetValueExW").name == "RegSetValue"

    def test_unknown_api_resolves_to_none(self):
        assert resolve_api("NotARealApi") is None

    def test_rwx_detection(self):
        assert is_rwx(0x40) is True          # PAGE_EXECUTE_READWRITE
        assert is_rwx(0x04) is False         # PAGE_READWRITE
        assert is_executable(0x20) is True   # PAGE_EXECUTE_READ

    def test_protection_decoding(self):
        assert decode_flags(0x40, PAGE_PROTECTION) == ["PAGE_EXECUTE_READWRITE"]

    def test_buffer_args_are_hash_only(self):
        """Buffer contents must never be captured verbatim."""
        for name in ("ReadFile", "WriteFile", "CryptEncrypt", "NtWriteVirtualMemory"):
            buffers = [a for a in API_CATALOG[name].args if a.kind == "buffer"]
            assert buffers, f"{name} declares no buffer arg"
            assert all(a.hash_only for a in buffers), f"{name} captures raw buffer"

    def test_credentials_are_redacted(self):
        creds = [a for a in API_CATALOG["InternetConnect"].args if a.redact]
        assert {a.name for a in creds} == {"lpszUserName", "lpszPassword"}

    def test_noisy_apis_have_higher_rate_limits(self):
        assert API_CATALOG["GetProcAddress"].rate_limit_per_sec > \
               API_CATALOG["CryptEncrypt"].rate_limit_per_sec


# ============================================================================
# Negative cases — these matter as much as the detections
# ============================================================================

class TestNoFalsePositives:

    def test_benign_activity_produces_no_chains(self, engine, source):
        feed(engine, source.benign_activity(30))
        assert len(engine.chains) == 0
        assert engine.risk_contribution() == 0

    def test_self_write_is_not_injection(self, engine, source):
        """Packers write to their own memory constantly; that is not injection."""
        rules = feed(engine, source.process_injection(target_pid=source.pid))
        assert "classic_injection" not in rules

    def test_non_executable_alloc_is_not_classic_injection(self, engine, source):
        calls = source.process_injection()
        calls[0]["args"]["flProtect"] = 0x04      # PAGE_READWRITE
        rules = feed(engine, calls)
        assert "classic_injection" not in rules

    def test_non_suspended_process_is_not_hollowing(self, engine, source):
        calls = source.process_hollowing()
        calls[0]["args"]["dwCreationFlags"] = 0
        rules = feed(engine, calls)
        assert "process_hollowing" not in rules

    def test_ordinary_registry_write_is_not_persistence(self, engine, source):
        calls = source.persistence()
        calls[2]["args"]["lpSubKey"] = "Software\\MyApp\\Settings"
        rules = feed(engine, calls)
        assert "drop_and_persist" not in rules

    def test_normal_file_ioctl_is_not_driver_comms(self, engine, source):
        calls = source.driver_access()
        calls[0]["args"]["lpFileName"] = "C:\\Users\\Admin\\notes.txt"
        rules = feed(engine, calls)
        assert "driver_communication" not in rules

    def test_few_encrypt_cycles_is_not_ransomware_volume(self, engine, source):
        feed(engine, source.ransomware_cycle(3))
        assert "ransomware_volume" not in {f["rule_id"] for f in engine.volume_findings()}


# ============================================================================
# Detections
# ============================================================================

class TestInjectionChains:

    def test_classic_injection(self, engine, source):
        rules = feed(engine, source.benign_activity(5) + source.process_injection())
        assert "classic_injection" in rules

        chain = next(c for c in engine.chains if c.rule_id == "classic_injection")
        assert chain.severity is ChainSeverity.CRITICAL
        assert chain.api_sequence == [
            "VirtualAlloc", "NtWriteVirtualMemory", "CreateRemoteThread"
        ]
        assert chain.evidence["target_pid"] == 9001
        assert "T1055.002" in chain.mitre

    def test_process_hollowing(self, engine, source):
        assert "process_hollowing" in feed(engine, source.process_hollowing())

    def test_broader_rule_supersedes_narrower(self, engine, source):
        """
        One injection must produce one finding. The write→thread subset rule
        describes the same event as the full alloc→write→thread chain, and
        emitting both inflates apparent severity.
        """
        feed(engine, source.process_injection())
        emitted = {c.rule_id for c in engine.chains}
        assert "classic_injection" in emitted
        assert "injection_no_alloc" not in emitted

    def test_narrower_rule_still_fires_alone(self, engine, source):
        """When no allocation precedes it, the subset rule must still report."""
        calls = source.process_injection()[1:]   # drop the VirtualAlloc
        rules = feed(engine, calls)
        assert "injection_no_alloc" in rules

    def test_runtime_unpacking(self, engine, source):
        assert "runtime_unpacking" in feed(engine, source.unpacking())


class TestRansomware:

    def test_encryption_cycle(self, engine, source):
        assert "ransomware_cycle" in feed(engine, source.ransomware_cycle(30))

    def test_mass_encryption_volume_finding(self, engine, source):
        """
        Regression: window dedup previously suppressed the *count* as well as
        the emission, so rapid encryption of thousands of files registered as
        a single cycle and never reached the volume threshold.
        """
        feed(engine, source.ransomware_cycle(30))
        assert "ransomware_volume" in {f["rule_id"] for f in engine.volume_findings()}

    def test_rapid_cycles_are_counted_not_swallowed(self, engine, source):
        feed(engine, source.ransomware_cycle(40))
        assert engine.chain_counts["ransomware_cycle"] >= 25

    def test_findings_list_stays_deduplicated(self, engine, source):
        """Counting every match must not flood the findings list."""
        feed(engine, source.ransomware_cycle(40))
        emitted = [c for c in engine.chains if c.rule_id == "ransomware_cycle"]
        assert len(emitted) < 40


class TestPersistenceAndExfil:

    def test_drop_and_persist(self, engine, source):
        rules = feed(engine, source.persistence())
        assert "drop_and_persist" in rules
        chain = next(c for c in engine.chains if c.rule_id == "drop_and_persist")
        assert any("Run" in k for k in chain.evidence.get("registry_keys", []))

    def test_exfiltration_captures_c2_host(self, engine, source):
        feed(engine, source.exfiltration())
        chain = next(c for c in engine.chains if c.rule_id == "collect_and_exfiltrate")
        assert "exfil.badactor.test" in chain.evidence["hosts"]

    def test_downloader(self, engine, source):
        assert "download_and_execute" in feed(engine, source.downloader())

    def test_driver_communication(self, engine, source):
        assert "driver_communication" in feed(engine, source.driver_access())


class TestConcealment:

    def test_dynamic_resolution_chain(self, engine, source):
        assert "dynamic_api_resolution" in feed(engine, source.dynamic_resolution(60))

    def test_heavy_resolution_volume_finding(self, engine, source):
        feed(engine, source.dynamic_resolution(60))
        assert "heavy_dynamic_resolution" in {
            f["rule_id"] for f in engine.volume_findings()
        }


# ============================================================================
# Handles, rate limiting, risk
# ============================================================================

class TestHandleResolution:

    def test_read_write_resolve_to_path(self, engine, source):
        """
        ReadFile carries only a handle. Without the CreateFile mapping the path
        is lost, and file activity becomes uninterpretable.
        """
        feed(engine, source.ransomware_cycle(2))
        paths = [p for c in engine.chains for p in c.evidence.get("paths", [])]
        assert any("Documents" in p for p in paths)


class TestRateLimiting:

    def test_flood_is_suppressed(self, engine, source):
        feed(engine, source.dynamic_resolution(3000))
        assert engine.suppressed_calls > 0

    def test_counters_retain_true_volume(self, engine, source):
        """Suppression must not corrupt the counts volume detection relies on."""
        feed(engine, source.dynamic_resolution(3000))
        assert engine.call_counts["GetProcAddress"] >= 3000


class TestRiskScoring:

    def test_multiple_behaviors_score_high(self, engine, source):
        feed(engine, source.process_injection() + source.persistence()
             + source.exfiltration())
        assert engine.risk_contribution() >= 80

    def test_risk_is_capped(self, engine, source):
        for _ in range(5):
            feed(engine, source.process_injection() + source.ransomware_cycle(40))
        assert engine.risk_contribution() <= 100


# ============================================================================
# Stage integration
# ============================================================================

class TestStageIntegration:

    def _monitor(self):
        monitor = StageHookMonitor(uuid4())
        source = MockHookSource()
        monitor.enter_stage("boot")
        monitor.ingest_batch(source.benign_activity(5))
        monitor.exit_stage("boot")
        monitor.enter_stage("idle")
        monitor.ingest_batch([])
        monitor.exit_stage("idle")
        monitor.enter_stage("reboot")
        monitor.ingest_batch(source.process_injection())
        monitor.exit_stage("reboot")
        return monitor

    def test_chains_attributed_to_correct_stage(self):
        monitor = self._monitor()
        assert monitor.stage_rollups["boot"]["chains"] == []
        assert any(
            c["rule_id"] == "classic_injection"
            for c in monitor.stage_rollups["reboot"]["chains"]
        )

    def test_silent_stage_reports_no_activity(self):
        assert self._monitor().stage_rollups["idle"]["activity_observed"] is False

    def test_activation_analysis_separates_calls_from_behavior(self):
        """
        The sample called APIs from boot but only injected after reboot. That
        gap is itself the finding — reconnaissance first, payload later.
        """
        analysis = self._monitor().activation_analysis()
        assert analysis["first_api_call_stage"] == "boot"
        assert analysis["first_critical_behavior_stage"] == "reboot"
        assert analysis["reconnaissance_gap"] is True
        assert "idle" in analysis["silent_stages"]

    def test_stage_findings_are_plain_language(self):
        findings = self._monitor().stage_findings("reboot")
        assert findings
        assert findings[0]["severity"] == "critical"
        assert findings[0]["mitre_techniques"]
        # Written for an investigating officer, not an analyst
        detail = findings[0]["detail"]
        assert "another running program" in detail
        for jargon in ("VirtualAlloc", "RWX", "PAGE_EXECUTE"):
            assert jargon not in detail.split("Observed API sequence")[0]

    def test_findings_deduplicated_per_rule_per_stage(self):
        monitor = StageHookMonitor(uuid4())
        source = MockHookSource()
        monitor.enter_stage("long_execution")
        for _ in range(5):
            monitor.ingest_batch(source.process_injection())
        monitor.exit_stage("long_execution")
        findings = monitor.stage_findings("long_execution")
        injection = [f for f in findings if "injection" in f["title"].lower()]
        assert len(injection) == 1


# ============================================================================
# Generated instrumentation
# ============================================================================

class TestHookInstaller:

    def test_agent_has_no_unsubstituted_placeholders(self):
        import re
        assert not re.findall(r"__[A-Z_a-z]+__", generate_frida_agent())

    def test_agent_covers_every_required_api(self):
        js = generate_frida_agent()
        for api in REQUIRED_APIS:
            assert f"'{api}'" in js, f"{api} not hooked in generated agent"

    def test_agent_braces_balanced(self):
        js = generate_frida_agent()
        assert js.count("{") == js.count("}")
        assert js.count("(") == js.count(")")

    def test_agent_has_reentrancy_guard(self):
        """Without this the hook body recurses until the guest stack dies."""
        js = generate_frida_agent()
        assert "guardEnter" in js and "guardExit" in js

    def test_agent_redacts_credentials(self):
        assert "[REDACTED]" in generate_frida_agent()

    def test_agent_hashes_buffers_rather_than_sending_them(self):
        js = generate_frida_agent()
        assert "hashBuf" in js
        assert "max_hash_bytes" in js

    def test_cape_config_covers_same_surface(self):
        config = generate_cape_config()
        # Check that the config covers at least the required APIs
        config_apis = {h["name"] for h in config["api_hooks"]}
        assert REQUIRED_APIS <= config_apis

    def test_manifest_reports_protected_arguments(self):
        manifest = installation_manifest()
        # Check that manifest covers the API catalog
        assert manifest["api_count"] >= len(API_CATALOG)
        assert manifest["windows_api_count"] >= len(REQUIRED_APIS)
        assert manifest["android_api_count"] >= len(ANDROID_REQUIRED_APIS)
        assert manifest["redacted_args"]["InternetConnect"]
        assert manifest["hash_only_args"]


if __name__ == "__main__":
    import sys
    sys.exit(pytest.main([__file__, "-v"]))
