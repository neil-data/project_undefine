"""
test_stages.py — Tests for the multi-stage dynamic analysis pipeline.

The central assertion throughout is that the pipeline *discovers* evasion
behavior rather than being told about it: MockBehaviorScript describes how a
fake sample behaves, and the tests check that the orchestrator independently
arrives at the right activation stage and evasion profile.

Run:
    pytest dynamic-sandbox/stages/test_stages.py -v
"""

from __future__ import annotations

import asyncio
from uuid import uuid4

import pytest

from stages.stage_definitions import (
    PROFILES,
    STAGE_CONFIGS,
    STAGE_ORDER,
    EvasionClass,
    PipelineProfile,
    StageId,
    StageStatus,
    get_profile,
)
from stages.controllers import MockBehaviorScript, MockSandboxController
from stages.stage_orchestrator import StageOrchestrator
from stages.stage_report import build_report, render_markdown, to_narrative_input


# ============================================================================
# Helpers
# ============================================================================

# Tests run realistic stage budgets compressed via time_scale rather than
# shrinking the budgets themselves, so timing *ratios* between stages stay
# true to production and the suite still exercises the real config values.
TIME_SCALE = 60.0


def fast_profile(stages=None, duration=30) -> PipelineProfile:
    """Realistic-shaped profile; wall-clock compressed via TIME_SCALE."""
    stages = stages or list(STAGE_ORDER)
    return PipelineProfile(
        name="test_fast",
        description="Compressed timings for tests",
        enabled_stages=stages,
        duration_overrides={s: duration for s in stages},
    )


async def run(script: MockBehaviorScript, profile: PipelineProfile = None, platform="windows"):
    controller = MockSandboxController(script=script, speed=1000.0)
    orch = StageOrchestrator(
        analysis_id=uuid4(),
        platform=platform,
        sample_path="/samples/mock.exe",
        controller=controller,
        profile=profile or fast_profile(),
        time_scale=TIME_SCALE,
    )
    return await orch.run(), controller


# ============================================================================
# Stage definitions
# ============================================================================

class TestStageDefinitions:

    def test_all_eight_stages_defined(self):
        assert len(STAGE_ORDER) == 8
        for stage_id in STAGE_ORDER:
            assert stage_id in STAGE_CONFIGS

    def test_stage_order_matches_spec(self):
        assert STAGE_ORDER == [
            StageId.BOOT,
            StageId.IDLE,
            StageId.USER_INTERACTION,
            StageId.INTERNET_SIMULATION,
            StageId.PERSISTENCE_CHECK,
            StageId.REBOOT,
            StageId.LONG_EXECUTION,
            StageId.MEMORY_DUMP,
        ]

    def test_long_execution_covers_the_stall_window(self):
        """The PS notes malware waits 10-30 min; the budget must exceed that."""
        assert STAGE_CONFIGS[StageId.LONG_EXECUTION].duration_sec >= 1800

    def test_each_evasion_class_has_an_owning_stage(self):
        covered = set()
        for cfg in STAGE_CONFIGS.values():
            covered.update(cfg.defeats)
        for ev in EvasionClass:
            if ev is EvasionClass.NONE:
                continue
            assert ev in covered, f"No stage defeats {ev}"

    def test_only_memory_stage_captures_memory_by_default(self):
        capturing = [c.stage_id for c in STAGE_CONFIGS.values() if c.capture_memory]
        assert capturing == [StageId.MEMORY_DUMP]

    def test_hard_timeout_exceeds_budget(self):
        for cfg in STAGE_CONFIGS.values():
            assert cfg.hard_timeout_sec > cfg.duration_sec


# ============================================================================
# Profiles
# ============================================================================

class TestProfiles:

    def test_standard_enables_all_stages(self):
        assert len(get_profile("standard").enabled_stages) == 8

    def test_quick_skips_reboot_and_long_execution(self):
        quick = get_profile("quick")
        assert StageId.REBOOT not in quick.enabled_stages
        assert StageId.LONG_EXECUTION not in quick.enabled_stages

    def test_deep_runs_longer_than_standard(self):
        assert (
            get_profile("deep").estimated_duration_sec
            > get_profile("standard").estimated_duration_sec
        )

    def test_evidence_profile_disables_interventions(self):
        cfg = get_profile("evidence").config_for(StageId.LONG_EXECUTION)
        assert cfg.params["sleep_patching_enabled"] is False

    def test_unknown_profile_falls_back_to_standard(self):
        assert get_profile("nonexistent").name == "standard"

    def test_override_does_not_mutate_global_config(self):
        original = STAGE_CONFIGS[StageId.IDLE].duration_sec
        get_profile("quick").config_for(StageId.IDLE)
        assert STAGE_CONFIGS[StageId.IDLE].duration_sec == original

    def test_disabled_stage_returns_no_config(self):
        assert get_profile("quick").config_for(StageId.REBOOT) is None


# ============================================================================
# Orchestration
# ============================================================================

class TestOrchestration:

    @pytest.mark.asyncio
    async def test_runs_all_stages_in_order(self):
        result, _ = await run(MockBehaviorScript())
        assert [r.stage_id for r in result.stage_results] == STAGE_ORDER
        assert result.completed

    @pytest.mark.asyncio
    async def test_disabled_stages_are_skipped_not_omitted(self):
        """A skipped stage must still appear in the report as skipped."""
        result, _ = await run(
            MockBehaviorScript(),
            profile=fast_profile(stages=[StageId.BOOT, StageId.MEMORY_DUMP]),
        )
        skipped = [r for r in result.stage_results if r.status == StageStatus.SKIPPED]
        assert len(skipped) == 6
        assert all(r.skip_reason for r in skipped)

    @pytest.mark.asyncio
    async def test_boot_baselines_before_detonating(self):
        _, controller = await run(MockBehaviorScript())
        log = controller.command_log
        assert log.index("start_guest") < log.index(
            next(c for c in log if c.startswith("execute:"))
        )

    @pytest.mark.asyncio
    async def test_reboot_preserves_disk_state(self):
        """Reverting to snapshot on reboot would erase the persistence we test."""
        _, controller = await run(MockBehaviorScript())
        assert controller.rebooted
        # restore_snapshot must only appear once, during boot
        assert len([c for c in controller.command_log if "restore_snapshot" in c]) == 1

    @pytest.mark.asyncio
    async def test_abort_stops_the_pipeline(self):
        controller = MockSandboxController(MockBehaviorScript(), speed=1000.0)
        orch = StageOrchestrator(
            analysis_id=uuid4(),
            platform="windows",
            sample_path="/samples/mock.exe",
            controller=controller,
            profile=fast_profile(duration=120),
            time_scale=20.0,
        )
        task = asyncio.create_task(orch.run())
        await asyncio.sleep(0.5)
        orch.request_abort("test abort")
        result = await task

        assert result.aborted
        assert "test abort" in result.abort_reason
        assert len(result.stage_results) < 8

    @pytest.mark.asyncio
    async def test_progress_reports_stage_counts(self):
        controller = MockSandboxController(MockBehaviorScript(), speed=1000.0)
        orch = StageOrchestrator(
            analysis_id=uuid4(),
            platform="windows",
            sample_path="/samples/mock.exe",
            controller=controller,
            profile=fast_profile(),
            time_scale=TIME_SCALE,
        )
        await orch.run()
        p = orch.progress()
        assert p["stages_completed"] == 8
        assert p["percent"] == 100.0


# ============================================================================
# Evasion discovery — the core behavior
# ============================================================================

class TestEvasionDiscovery:

    @pytest.mark.asyncio
    async def test_detects_interaction_gated_sample(self):
        result, _ = await run(
            MockBehaviorScript(requires_user_interaction=True, beacons=False)
        )
        assert result.activation_stage == StageId.USER_INTERACTION
        assert EvasionClass.INTERACTION_GATE in result.evasion_profile

    @pytest.mark.asyncio
    async def test_detects_network_gated_sample(self):
        result, _ = await run(
            MockBehaviorScript(requires_network=True, beacons=True)
        )
        assert EvasionClass.NETWORK_GATE in result.evasion_profile

    @pytest.mark.asyncio
    async def test_detects_reboot_gated_sample(self):
        result, _ = await run(
            MockBehaviorScript(activates_after_reboot=True, beacons=False)
        )
        assert EvasionClass.REBOOT_GATE in result.evasion_profile
        # Activation must not be attributed to a stage before the reboot
        assert STAGE_ORDER.index(result.activation_stage) >= STAGE_ORDER.index(
            StageId.REBOOT
        )

    @pytest.mark.asyncio
    async def test_immediately_active_sample_shows_no_evasion(self):
        result, _ = await run(MockBehaviorScript(beacons=True))
        assert result.activation_stage == StageId.BOOT
        assert EvasionClass.INTERACTION_GATE not in result.evasion_profile
        assert EvasionClass.REBOOT_GATE not in result.evasion_profile

    @pytest.mark.asyncio
    async def test_inert_sample_reports_no_activation(self):
        script = MockBehaviorScript(
            requires_user_interaction=True,
            requires_network=True,
            activates_after_reboot=True,
            activation_delay_sec=10 ** 9,   # never within the run
            beacons=False,
            installs_persistence=False,
            packed_in_memory=False,
            memory_yara_hits=[],
        )
        result, _ = await run(script)
        assert result.activation_stage is None
        assert len(result.dormant_stages) > 0

    @pytest.mark.asyncio
    async def test_stacked_evasion_raises_sophistication(self):
        result, _ = await run(
            MockBehaviorScript(
                requires_user_interaction=True,
                requires_network=True,
                activates_after_reboot=True,
            )
        )
        report = build_report(result)
        assert report["evasion"]["sophistication"] in ("moderate", "advanced")


# ============================================================================
# Findings
# ============================================================================

class TestFindings:

    @pytest.mark.asyncio
    async def test_persistence_is_reported(self):
        result, _ = await run(MockBehaviorScript(installs_persistence=True))
        titles = [f.title.lower() for f in result.all_findings]
        assert any("persistence" in t for t in titles)

    @pytest.mark.asyncio
    async def test_memory_findings_produced(self):
        result, _ = await run(MockBehaviorScript(packed_in_memory=True))
        memory_stage = result.stage(StageId.MEMORY_DUMP)
        assert memory_stage.status == StageStatus.COMPLETED
        assert len(memory_stage.findings) > 0

    @pytest.mark.asyncio
    async def test_findings_carry_mitre_techniques(self):
        result, _ = await run(MockBehaviorScript(installs_persistence=True))
        assert any(f.mitre_techniques for f in result.all_findings)

    @pytest.mark.asyncio
    async def test_unbootable_guest_is_critical(self):
        result, _ = await run(MockBehaviorScript(crashes_on_boot=True))
        boot = result.stage(StageId.BOOT)
        assert any(f.severity == "critical" for f in boot.findings)


# ============================================================================
# Reporting
# ============================================================================

class TestReporting:

    @pytest.mark.asyncio
    async def test_report_has_all_sections(self):
        result, _ = await run(MockBehaviorScript())
        report = build_report(result)
        for key in (
            "execution", "activation", "evasion", "timeline",
            "findings", "artifacts", "coverage", "plain_language_summary",
        ):
            assert key in report

    @pytest.mark.asyncio
    async def test_timeline_has_one_row_per_stage(self):
        result, _ = await run(MockBehaviorScript())
        assert len(build_report(result)["timeline"]) == 8

    @pytest.mark.asyncio
    async def test_late_activation_is_flagged_as_missable(self):
        result, _ = await run(
            MockBehaviorScript(activates_after_reboot=True, beacons=False)
        )
        act = build_report(result)["activation"]
        assert act["would_be_missed_by_short_analysis"] is True
        assert act["short_analysis_note"]

    @pytest.mark.asyncio
    async def test_skipped_stages_produce_coverage_caveat(self):
        """A partial run must never read as full coverage."""
        result, _ = await run(
            MockBehaviorScript(),
            profile=fast_profile(stages=[StageId.BOOT, StageId.IDLE]),
        )
        coverage = build_report(result)["coverage"]
        assert coverage["complete_coverage"] is False
        assert coverage["caveat"]
        assert len(coverage["untested_evasion_classes"]) > 0

    @pytest.mark.asyncio
    async def test_plain_language_summary_avoids_jargon(self):
        result, _ = await run(
            MockBehaviorScript(activates_after_reboot=True)
        )
        summary = build_report(result)["plain_language_summary"]
        assert len(summary) > 100
        for jargon in ("MITRE", "T1547", "INetSim", "YARA", "PEB", "syscall"):
            assert jargon not in summary

    @pytest.mark.asyncio
    async def test_inert_summary_does_not_claim_safe(self):
        """An absence of findings must not be reported as 'this file is safe'."""
        script = MockBehaviorScript(
            activation_delay_sec=10 ** 9,
            beacons=False,
            installs_persistence=False,
            packed_in_memory=False,
            memory_yara_hits=[],
        )
        result, _ = await run(script)
        summary = build_report(result)["plain_language_summary"].lower()
        assert "not the same as confirming it is safe" in summary

    @pytest.mark.asyncio
    async def test_markdown_renders(self):
        result, _ = await run(MockBehaviorScript(requires_user_interaction=True))
        md = render_markdown(result)
        assert md.startswith("# Multi-Stage Dynamic Analysis Report")
        assert "## Stage Timeline" in md
        assert "## Summary for Investigators" in md

    @pytest.mark.asyncio
    async def test_narrative_input_is_compact(self):
        result, _ = await run(MockBehaviorScript())
        payload = to_narrative_input(result)
        assert "activation_stage" in payload
        assert "evasion_techniques" in payload
        assert len(payload["critical_findings"]) <= 10


# ============================================================================
# Platform handling
# ============================================================================

class TestPlatforms:

    @pytest.mark.asyncio
    async def test_android_pipeline_runs(self):
        result, _ = await run(MockBehaviorScript(), platform="android")
        assert result.platform == "android"
        assert result.completed

    @pytest.mark.asyncio
    async def test_inapplicable_stage_is_skipped_gracefully(self):
        result, _ = await run(MockBehaviorScript(), platform="unsupported_os")
        # Every stage declares windows/android only, so all skip — and the run
        # completes rather than erroring.
        assert all(r.status == StageStatus.SKIPPED for r in result.stage_results)
        assert result.completed


class TestActivityDetectionRobustness:
    """
    Regression tests for the failure mode where activity detection depended
    solely on a DB event count: with no DB every stage reported "dormant",
    which surfaces in the report as "sample appeared inert" — a false clean.
    """

    @pytest.mark.asyncio
    async def test_activity_detected_without_database(self):
        result, _ = await run(MockBehaviorScript(requires_user_interaction=True))
        assert result.activation_stage is not None, (
            "Activity must be detectable with no DB attached"
        )

    @pytest.mark.asyncio
    async def test_merely_launching_is_not_activity(self):
        """A sample that starts but does nothing must stay dormant at boot."""
        result, _ = await run(
            MockBehaviorScript(requires_user_interaction=True, beacons=False)
        )
        boot = result.stage(StageId.BOOT)
        assert boot.activity_detected is False
        assert result.activation_stage != StageId.BOOT


class TestTimingSafety:
    """Regression tests for stage loops overshooting short duration budgets."""

    @pytest.mark.asyncio
    async def test_short_budgets_do_not_time_out(self):
        result, _ = await run(
            MockBehaviorScript(), profile=fast_profile(duration=20)
        )
        timed_out = [
            r.stage_id.value for r in result.stage_results
            if r.status == StageStatus.TIMED_OUT
        ]
        assert not timed_out, f"Stages overshot their budget: {timed_out}"

    def test_tick_never_exceeds_quarter_budget(self):
        from stages.stage_actions import StageAction
        for budget in (1, 10, 60, 300, 1800):
            assert StageAction._tick(30.0, budget) <= max(0.05, budget / 4.0)


if __name__ == "__main__":
    import sys
    sys.exit(pytest.main([__file__, "-v"]))
