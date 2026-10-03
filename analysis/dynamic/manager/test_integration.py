"""
test_integration.py — The manager driving the real eight-stage pipeline.

Everything else in this package is tested against fakes, which proves the
manager's own logic and nothing about whether it fits the pipeline it exists to
drive. These tests use the real `run_pipeline`, the real stage definitions and
the scriptable mock guest, so a signature change in either half fails here
rather than in production.

The mock guest is scriptable on purpose: the sample's activation condition is
declared, and the pipeline has to *discover* it. A test that told the pipeline
when the sample woke up would be testing nothing.

Run:
    pytest dynamic-sandbox/manager/test_integration.py -v
"""

from __future__ import annotations

import json

import pytest

from manager import (
    DetonationManager,
    JobPriority,
    JobState,
    Platform,
    RunResultRepository,
    Sandbox,
    SandboxPool,
)
from stages.controllers import MockBehaviorScript, MockSandboxController
from stages.stage_orchestrator import run_pipeline


@pytest.fixture
def sample(tmp_path):
    path = tmp_path / "suspect.exe"
    path.write_bytes(b"MZ" + b"\x00" * 128 + b"payload")
    return path


def build_manager(tmp_path, controller, profile_default="quick"):
    pool = SandboxPool()
    pool.register(Sandbox(sandbox_id="win-01", platform=Platform.WINDOWS))

    async def runner(**kwargs):
        # time_scale compresses the pipeline's real waits; the stage logic and
        # its ordering are unchanged, which is what is under test here.
        return await run_pipeline(**kwargs, time_scale=600.0)

    manager = DetonationManager(
        pool,
        repository=RunResultRepository(tmp_path / "runs"),
        artifact_root=tmp_path / "evidence",
        controller_factory=lambda sandbox, job: controller,
        pipeline_runner=runner,
    )
    return manager, pool


class ManagedMockController(MockSandboxController):
    """The mock guest plus the lifecycle calls the manager makes."""

    def __init__(self, script=None):
        super().__init__(script=script, speed=1000.0)
        self.restores = 0

    async def restore_snapshot(self, snapshot="golden"):
        self.restores += 1
        return True

    async def await_agent(self, timeout_sec):
        return True

    async def close(self):
        return None


@pytest.mark.asyncio
async def test_manager_runs_the_real_pipeline_end_to_end(tmp_path, sample):
    controller = ManagedMockController(MockBehaviorScript(installs_persistence=True))
    manager, _ = build_manager(tmp_path, controller)

    manager.submit(sample, profile="quick", case_reference="CYB/2026/0001")
    job = await manager.run_next()

    assert job.state is JobState.COMPLETED
    assert job.result_path

    stored = json.loads(open(job.result_path, encoding="utf-8").read())
    assert stored["sha256"] == job.sha256
    assert stored["platform"] == "windows"
    assert stored["case_reference"] == "CYB/2026/0001"
    assert stored["timeline"]["event_count"] > 0


@pytest.mark.asyncio
async def test_the_pipeline_discovers_a_reboot_gated_sample(tmp_path, sample):
    """
    The sample is scripted to activate only after a reboot; nothing tells the
    pipeline that. Finding it is the entire value of the multi-stage design.
    """
    controller = ManagedMockController(MockBehaviorScript(activates_after_reboot=True))
    manager, _ = build_manager(tmp_path, controller)

    manager.submit(sample, profile="standard")
    job = await manager.run_next()

    stored = json.loads(open(job.result_path, encoding="utf-8").read())
    assert controller.rebooted
    assert stored["activation_stage"] is not None


@pytest.mark.asyncio
async def test_timeline_is_built_from_the_real_stage_results(tmp_path, sample):
    controller = ManagedMockController(MockBehaviorScript(installs_persistence=True))
    manager, _ = build_manager(tmp_path, controller)

    manager.submit(sample, profile="quick")
    job = await manager.run_next()
    timeline = json.loads(open(job.result_path, encoding="utf-8").read())["timeline"]

    assert timeline["events"]
    assert "stage" in timeline["by_source"]
    assert timeline["summary"]


@pytest.mark.asyncio
async def test_guest_is_reverted_before_and_after_every_run(tmp_path, sample):
    """One revert to reach a known-clean state, one to leave it clean."""
    controller = ManagedMockController()
    manager, pool = build_manager(tmp_path, controller)

    manager.submit(sample, profile="quick")
    await manager.run_next()

    assert controller.restores >= 2
    assert pool.get("win-01").is_available


@pytest.mark.asyncio
async def test_two_samples_run_sequentially_on_one_guest(tmp_path):
    """
    Cross-contamination is the failure this ordering prevents: the second
    sample must not inherit the first one's persistence entries.
    """
    controller = ManagedMockController(MockBehaviorScript(installs_persistence=True))
    manager, _ = build_manager(tmp_path, controller)

    for index in range(2):
        path = tmp_path / f"sample{index}.exe"
        path.write_bytes(b"MZ" + bytes([index]) * 200)
        manager.submit(path, profile="quick")

    first = await manager.run_next()
    second = await manager.run_next()

    assert first.state is JobState.COMPLETED
    assert second.state is JobState.COMPLETED
    assert first.analysis_id != second.analysis_id
    assert controller.restores >= 4


@pytest.mark.asyncio
async def test_urgent_case_work_overtakes_a_bulk_rescan(tmp_path):
    bulk = tmp_path / "bulk.exe"
    bulk.write_bytes(b"MZ" + b"\x01" * 200)
    urgent = tmp_path / "urgent.exe"
    urgent.write_bytes(b"MZ" + b"\x02" * 200)

    controller = ManagedMockController()
    manager, _ = build_manager(tmp_path, controller)

    manager.submit(bulk, priority=JobPriority.BULK, profile="quick")
    manager.submit(urgent, priority=JobPriority.URGENT, profile="quick")

    first = await manager.run_next()
    assert first.file_name == "urgent.exe"
