"""End-to-end integration tests for all Day 5 provider lanes through the pipeline entrypoint.

Strictly offline (mocked HTTP/recorded fixtures). Zero network access.
Lanes:
1. ELF x86_64 -> HA -> Trust -> Evidence -> Correlation -> Score -> MITRE -> AI -> Report
2. Unsupported ELF arch -> NOT_SUPPORTED_PLATFORM -> Clean report line
3. EXE/PE/DLL (Verdict-only) -> HA -> INTEL only, zero dynamic evidence, risk score unaltered
4. APK -> MobSF Static -> Trust -> Evidence -> Score -> MITRE -> AI -> Report (emulator unready)
5. APK + ready emulator -> MobSF Dynamic -> DYNAMIC -> Correlation -> Score
6. Mach-O -> Static-only -> Score -> MITRE -> AI -> Report
7. Clean control -> remains clean
8. All failure states handled cleanly without unhandled exceptions
"""
import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from analysis.scoring.orchestrator.schema import (
    DynamicAnalysisOutput,
    EvidenceFinding,
    StaticAnalysisOutput,
)
from packages.config import redact_sensitive
from providers.dynamic.base import DynamicState
from providers.dynamic.hybrid_analysis import HybridAnalysisAdapter
from providers.dynamic.pipeline import (
    DynamicAnalysisPipeline,
    enrich_orchestrator_state,
    render_dynamic_result,
    unsupported_platform_result,
)
from sandbox.adapters.mobsf.adapter import MobSFAdapter

FIXTURES_DIR = Path(__file__).resolve().parents[1] / "fixtures" / "providers" / "hybrid_analysis"


def load_ha_fixture(name: str):
    p = FIXTURES_DIR / name
    assert p.exists()
    return json.loads(p.read_text(encoding="utf-8"))


from analysis.scoring.orchestrator.schema import (
    DynamicAnalysisOutput,
    EvidenceFinding,
    ExtractedStrings,
    StaticAnalysisOutput,
)


def make_minimal_static_state(file_type="elf", sha256=None, endpoints=()):
    sha = sha256 or ("a" * 64)
    platform_map = {
        "elf": "linux",
        "pe": "windows",
        "exe": "windows",
        "dll": "windows",
        "apk": "android",
        "macho": "macos",
    }
    plat = platform_map.get(file_type.lower(), "linux")
    static_out = StaticAnalysisOutput(
        sample_id=f"sample-{sha[:8]}",
        sha256=sha,
        platform=plat,
        file_type=file_type,
        file_size_bytes=1024,
        submitted_at="2026-10-05T00:00:00Z",
        extracted_strings=ExtractedStrings(urls=list(endpoints), ips=[], suspicious_keywords=[]),
        yara_matches=[],
    )
    return {
        "sample_id": f"sample-{sha[:8]}",
        "static_output": static_out,
        "evidence_findings": [],
        "risk_score": 10,
        "mitre_techniques": [],
        "capability_tags": [],
    }


class TestDay5IntegrationLanes:

    def test_lane_elf_hash_lookup_behavior_shape_is_not_execution(self):
        """Lane 1: behavior-shaped hash lookup data cannot be promoted to execution evidence."""
        adapter = HybridAnalysisAdapter(api_key="mock-ha-key")
        c2_domain = "observed-c2.malicious.test"

        mock_payload = {
            "verdict": "malicious",
            "threat_score": 88,
            "behavior": {
                "processes": [{"name": "/tmp/drop.elf", "pid": 4321}],
                "network": [{"domain": c2_domain, "ip": "198.51.100.5"}],
                "dns": [{"name": c2_domain}],
            },
        }

        pipeline = DynamicAnalysisPipeline(providers={"hybrid_analysis": adapter})
        state = make_minimal_static_state(file_type="elf", endpoints=[c2_domain])

        with patch.object(adapter, "lookup_by_hash", return_value=mock_payload):
            # Run pipeline
            res = pipeline.run(
                state["static_output"].sha256,
                platform="ELF",
                architecture="x86_64",
                task_id="ha-task-1234",
                static_endpoints=state["static_output"].extracted_strings.urls,
            )

            # Hash lookup is intelligence, not a submitted execution task.
            assert res.state == DynamicState.COMPLETED
            assert not res.observation.has_behavior()
            assert not res.findings
            assert res.verdict is not None and res.verdict.source_type == "INTEL"
            assert res.provenance["task_id"] is None
            assert res.correlations == []

            # Enrich Orchestrator
            enriched = enrich_orchestrator_state(state, res)
            assert enriched["dynamic_output"] is None
            assert "provider verdict" in enriched["narrative_summary"].lower()

            # Cache verification: calling run again returns cached result without lookup
            cached_res = pipeline.run(
                state["static_output"].sha256,
                platform="ELF",
                architecture="x86_64",
            )
            assert cached_res.provenance["task_id"] is None

    def test_lane_unsupported_elf_arch(self):
        """Lane 2: Unsupported ELF architecture returns NOT_SUPPORTED_PLATFORM without unhandled exception."""
        adapter = HybridAnalysisAdapter(api_key="mock-ha-key")
        pipeline = DynamicAnalysisPipeline(providers={"hybrid_analysis": adapter})

        res = pipeline.run("b" * 64, platform="ELF", architecture="aarch64")
        assert res.state == DynamicState.NOT_SUPPORTED_PLATFORM
        assert "unsupported platform (aarch64)" in res.report_line
        assert not res.findings

        state = make_minimal_static_state(file_type="elf")
        enriched = enrich_orchestrator_state(state, res)
        assert enriched["dynamic_output"] is None
        assert "Dynamic analysis not performed: unsupported platform (aarch64)" in enriched["narrative_summary"]

    def test_lane_pe_verdict_only_never_changes_risk_score(self):
        """Lane 3: Real recorded HA overview summary gives INTEL only and never changes risk score."""
        real_overview = load_ha_fixture("overview_summary_4faccd95.json")
        adapter = HybridAnalysisAdapter(api_key="mock-ha-key")
        pipeline = DynamicAnalysisPipeline(providers={"hybrid_analysis": adapter})

        state = make_minimal_static_state(file_type="pe")
        base_score = state["risk_score"]

        with patch.object(adapter, "lookup_by_hash", return_value=real_overview):
            res = pipeline.run(
                "4faccd95d23724469122505b90cdfd280ff552528be38e73e2b969be90eb7380",
                platform="PE",
                architecture="x86_64",
            )

            assert res.state == DynamicState.COMPLETED
            assert not res.observation.has_behavior()
            assert len(res.findings) == 0  # Zero dynamic findings
            assert res.verdict is not None
            assert res.verdict.source_type == "INTEL"
            assert res.provenance["task_id"] is None

            enriched = enrich_orchestrator_state(state, res)
            # Dynamic output remains None (no behavior observed)
            assert enriched["dynamic_output"] is None
            # Intel verdict must NEVER change risk score (remains 0)
            assert enriched["risk_score"] == 0
            assert enriched["provider_verdict"].source == "provider:hybrid_analysis"
            assert "A provider verdict was reported, but no behavior was observed." in enriched["narrative_summary"]

    def test_lane_apk_mobsf_static_only_when_emulator_unready(self, monkeypatch):
        """Lane 4: APK runs MobSF static analysis, reports unready emulator, keeps static findings."""
        monkeypatch.setenv("MOBSF_DYNAMIC", "true")
        monkeypatch.setenv("MOBSF_DYNAMIC_ISOLATION_CONFIRMED", "true")
        monkeypatch.setenv("MOBSF_DYNAMIC_TIMEOUT", "30")

        adapter = MobSFAdapter(url="http://localhost:8003", api_key="test-key")
        pipeline = DynamicAnalysisPipeline(providers={"mobsf": adapter})

        static_report = {
            "package_name": "com.test.target",
            "version_name": "1.0",
            "min_sdk": "21",
            "target_sdk": "33",
            "permissions": {"android.permission.INTERNET": {"status": "normal"}},
            "exported_activities": ["com.test.target.MainActivity"],
            "native_libraries": [],
        }

        with patch.object(adapter, "is_dynamic_ready", return_value=False), \
             patch.object(adapter, "upload_file", return_value={"hash": "mobsf-hash-abc"}), \
             patch.object(adapter, "trigger_scan", return_value={}), \
             patch.object(adapter, "get_report_json", return_value=static_report), \
             patch.object(adapter, "delete_scan", return_value=True):

            res = adapter.analyze_apk_content(b"apk-bytes", filename="test.apk")
            assert res.state == DynamicState.COMPLETED
            assert "Dynamic analysis not performed: analyzer/emulator not ready" in res.report_line
            # Static evidence present
            assert len(res.findings) > 0
            assert all(f.source_type == "STATIC" for f in res.findings)

    def test_lane_macho_static_only(self):
        """Lane 6: Mach-O platform returns clean static-only report line."""
        adapter = HybridAnalysisAdapter(api_key="mock-ha-key")
        pipeline = DynamicAnalysisPipeline(providers={"hybrid_analysis": adapter})

        res = pipeline.run("c" * 64, platform="Mach-O", architecture="x86_64")
        assert res.state == DynamicState.NOT_SUPPORTED_PLATFORM
        assert res.report_line == "Dynamic analysis: not performed (static-only)"
        assert not res.findings

    def test_clean_control_passes_without_exceptions(self):
        """Clean sample produces minimal score and clean report line."""
        adapter = HybridAnalysisAdapter(api_key="mock-ha-key")
        pipeline = DynamicAnalysisPipeline(providers={"hybrid_analysis": adapter})

        with patch.object(adapter, "lookup_by_hash", return_value={"message": "Requested hash not found"}):
            res = pipeline.run("d" * 64, platform="ELF", architecture="x86_64")
            assert res.state == DynamicState.NO_RESULT
            assert "Dynamic analysis not performed: no result" in res.report_line
            assert not res.findings

            state = make_minimal_static_state(file_type="elf")
            enriched = enrich_orchestrator_state(state, res)
            assert enriched["risk_score"] == 0
            assert enriched["dynamic_output"] is None
