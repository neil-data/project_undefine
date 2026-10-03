"""
test_cross_platform_rules.py — Tests confirming MITRE + capability
rules work correctly for Linux ELF and macOS Mach-O samples, not just
Android/Windows. Also confirms Windows-specific rules don't
false-positive on non-Windows platforms.
"""

from agents.mitre_mapper.mitre_rules import map_to_mitre
from agents.capability_classifier.capability_rules import classify_capabilities


class TestLinuxElfDetection:
    def test_detects_reverse_shell(self, linux_elf_static, linux_elf_dynamic):
        techniques = map_to_mitre(linux_elf_static, linux_elf_dynamic)
        ids = [t.technique_id for t in techniques]
        assert "T1059" in ids  # Command and Scripting Interpreter

        caps = classify_capabilities(linux_elf_static, linux_elf_dynamic)
        cap_names = [c.capability for c in caps]
        assert "remote_shell_access" in cap_names

    def test_detects_cron_persistence(self, linux_elf_static, linux_elf_dynamic):
        techniques = map_to_mitre(linux_elf_static, linux_elf_dynamic)
        ids = [t.technique_id for t in techniques]
        assert "T1053.003" in ids

        caps = classify_capabilities(linux_elf_static, linux_elf_dynamic)
        cap_names = [c.capability for c in caps]
        assert "persistence_cron" in cap_names

    def test_detects_setuid_privilege_escalation(self, linux_elf_static, linux_elf_dynamic):
        techniques = map_to_mitre(linux_elf_static, linux_elf_dynamic)
        ids = [t.technique_id for t in techniques]
        assert "T1548.001" in ids

        caps = classify_capabilities(linux_elf_static, linux_elf_dynamic)
        cap_names = [c.capability for c in caps]
        assert "privilege_escalation" in cap_names

    def test_detects_ld_preload_hijack(self, linux_elf_static, linux_elf_dynamic):
        techniques = map_to_mitre(linux_elf_static, linux_elf_dynamic)
        ids = [t.technique_id for t in techniques]
        assert "T1574.006" in ids

        caps = classify_capabilities(linux_elf_static, linux_elf_dynamic)
        cap_names = [c.capability for c in caps]
        assert "library_hijacking" in cap_names

    def test_detects_c2_comms(self, linux_elf_static, linux_elf_dynamic):
        """Cross-platform C2 rule must work identically for ELF, not just Android/Windows."""
        techniques = map_to_mitre(linux_elf_static, linux_elf_dynamic)
        ids = [t.technique_id for t in techniques]
        assert "T1071" in ids

    def test_android_only_rules_do_not_false_positive_on_linux(self, linux_elf_static, linux_elf_dynamic):
        """SMS/GPS/overlay/device-admin rules are Android-specific — must not fire on ELF."""
        techniques = map_to_mitre(linux_elf_static, linux_elf_dynamic)
        ids = [t.technique_id for t in techniques]
        assert "T1517" not in ids   # SMS access
        assert "T1430" not in ids   # Location tracking
        assert "T1417" not in ids   # Overlay
        assert "T1626" not in ids   # Device admin


class TestMacOSMachODetection:
    def test_detects_launchd_persistence(self, macos_machO_static, macos_machO_dynamic):
        techniques = map_to_mitre(macos_machO_static, macos_machO_dynamic)
        ids = [t.technique_id for t in techniques]
        assert "T1543.001" in ids

        caps = classify_capabilities(macos_machO_static, macos_machO_dynamic)
        cap_names = [c.capability for c in caps]
        assert "persistence_launchd" in cap_names

    def test_detects_c2_comms(self, macos_machO_static, macos_machO_dynamic):
        techniques = map_to_mitre(macos_machO_static, macos_machO_dynamic)
        ids = [t.technique_id for t in techniques]
        assert "T1071" in ids

    def test_windows_specific_rules_do_not_fire_on_macos(self, macos_machO_static, macos_machO_dynamic):
        """Registry/keylogging (Windows-specific) must not false-positive on Mach-O."""
        techniques = map_to_mitre(macos_machO_static, macos_machO_dynamic)
        ids = [t.technique_id for t in techniques]
        assert "T1547.001" not in ids  # Registry Run keys
        assert "T1056.001" not in ids  # Keylogging (no keyboard hook APIs present)

    def test_cron_rule_does_not_fire_on_launchd_sample(self, macos_machO_static, macos_machO_dynamic):
        """Cron (Linux) and launchd (macOS) are distinct — must not cross-fire."""
        techniques = map_to_mitre(macos_machO_static, macos_machO_dynamic)
        ids = [t.technique_id for t in techniques]
        assert "T1053.003" not in ids


class TestDllReusesWindowsPEFormat:
    def test_dll_with_pe_analysis_validates_correctly(self):
        """DLL is the same PE format as EXE — confirms schema accepts file_type='dll' with pe_analysis."""
        from agents.orchestrator.schema import (
            StaticAnalysisOutput, PEAnalysisInfo, ExtractedStrings, MLClassifierResult, YaraMatch,
        )
        dll_sample = StaticAnalysisOutput(
            sample_id="dll001", sha256="6" * 64, platform="windows", file_type="dll",
            file_size_bytes=120000, submitted_at="2026-07-17T11:10:00Z",
            yara_matches=[YaraMatch(rule_name="malicious_dll_injector", category="generic",
                                      severity="high", description="DLL injection pattern")],
            android_manifest=None,
            pe_analysis=PEAnalysisInfo(imports=["CreateRemoteThread", "LoadLibraryA"],
                                         sections=[".text", ".reloc"], compile_timestamp="2026-05-01T00:00:00Z"),
            extracted_strings=ExtractedStrings(),
            ml_classifier=MLClassifierResult(model="isolation_forest_v1", anomaly_score=0.75, classification="suspicious"),
            static_risk_flags=[],
        )
        assert dll_sample.file_type == "dll"
        assert dll_sample.pe_analysis is not None
        assert dll_sample.binary_analysis is None  # DLL uses pe_analysis, not binary_analysis


class TestCrossPlatformEdgeCases:
    def test_binary_analysis_none_does_not_crash_setuid_rule(self, benign_static):
        """benign_static has no binary_analysis at all — rule must handle None gracefully."""
        techniques = map_to_mitre(benign_static, None)
        ids = [t.technique_id for t in techniques]
        assert "T1548.001" not in ids  # should simply not fire, not crash

    def test_no_duplicate_techniques_across_all_platforms(
        self, linux_elf_static, linux_elf_dynamic, macos_machO_static, macos_machO_dynamic
    ):
        for static, dynamic in [(linux_elf_static, linux_elf_dynamic), (macos_machO_static, macos_machO_dynamic)]:
            techniques = map_to_mitre(static, dynamic)
            ids = [t.technique_id for t in techniques]
            assert len(ids) == len(set(ids))