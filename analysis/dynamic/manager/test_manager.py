"""
test_manager.py — Intake, queueing, sandbox selection and the run lifecycle.

The invariants this suite exists to hold, in order of how much they cost when
broken:

  1. Nothing detonates on a guest that was not just reverted. A failed restore
     aborts the job rather than proceeding onto a possibly dirty guest — the
     findings would be a mixture of two samples with no way to separate them.
  2. Every guest is released, whatever happened. A leaked lease removes a
     guest from the fleet silently and permanently.
  3. A guest that keeps failing is taken out of service, so one broken
     hypervisor cannot turn a queue of samples into a queue of failed results.

Run:
    pytest dynamic-sandbox/manager/test_manager.py -v
"""

from __future__ import annotations

import asyncio
import zipfile
from uuid import uuid4

import pytest

from manager import (
    AnalysisJob,
    DetonationManager,
    JobPriority,
    JobQueue,
    JobState,
    Platform,
    RunResultRepository,
    Sandbox,
    SandboxPool,
    SandboxState,
    SampleRejected,
    detect_platform,
    receive_sample,
)


# ============================================================================
# Fakes
# ============================================================================

class FakeController:
    """A guest that does what it is told, and can be told to fail."""

    def __init__(self, *, restore_ok=True, start_ok=True, agent_ok=True,
                 drop_ok=True, post_restore_ok=True):
        self.restore_ok = restore_ok
        self.start_ok = start_ok
        self.agent_ok = agent_ok
        self.drop_ok = drop_ok
        self.post_restore_ok = post_restore_ok

        self.calls: list[str] = []
        self.restores = 0

    async def restore_snapshot(self, snapshot="golden"):
        self.calls.append("restore")
        self.restores += 1
        # The first restore is the pre-run revert; later ones are teardown.
        return self.restore_ok if self.restores == 1 else self.post_restore_ok

    async def start_guest(self):
        self.calls.append("start")
        return self.start_ok

    async def await_agent(self, timeout_sec):
        self.calls.append("agent")
        return self.agent_ok

    async def drop_sample(self, sample_path):
        self.calls.append("drop")
        return f"C:\\guest\\{sample_path.split('/')[-1]}" if self.drop_ok else ""

    async def stop_guest(self):
        self.calls.append("stop")
        return True

    async def close(self):
        self.calls.append("close")


class FakePipelineResult:
    def __init__(self, risk=70):
        self.completed = True
        self.aborted = False
        self.final_risk_score = risk
        self.total_duration_sec = 12.0
        self.stage_results = []
        self.activation_stage = None
        self.dormant_stages = []
        self.evasion_profile = []
        self.all_findings = []


async def fake_pipeline(**kwargs):
    return FakePipelineResult()


async def exploding_pipeline(**kwargs):
    raise RuntimeError("guest hung during detonation")


@pytest.fixture
def pool():
    pool = SandboxPool()
    pool.register(Sandbox(sandbox_id="win-01", platform=Platform.WINDOWS))
    return pool


@pytest.fixture
def pe_sample(tmp_path):
    sample = tmp_path / "suspect.exe"
    sample.write_bytes(b"MZ" + b"\x00" * 200 + b"This program cannot be run")
    return sample


@pytest.fixture
def apk_sample(tmp_path):
    sample = tmp_path / "suspect.apk"
    with zipfile.ZipFile(sample, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("AndroidManifest.xml", b"manifest")
        archive.writestr("classes.dex", b"dex\n035\x00payload")
    return sample


def build_manager(pool, controller=None, pipeline=fake_pipeline, **kwargs):
    controller = controller or FakeController()
    return DetonationManager(
        pool,
        controller_factory=lambda sandbox, job: controller,
        pipeline_runner=pipeline,
        **kwargs,
    ), controller


# ============================================================================
# Intake
# ============================================================================

class TestIntake:

    def test_pe_routed_to_windows(self, pe_sample):
        assert detect_platform(pe_sample) is Platform.WINDOWS

    def test_apk_routed_to_android(self, apk_sample):
        assert detect_platform(apk_sample) is Platform.ANDROID

    def test_zip_without_a_manifest_is_not_an_apk(self, tmp_path):
        """A JAR and a plain archive share the APK's magic bytes."""
        archive = tmp_path / "docs.zip"
        with zipfile.ZipFile(archive, "w") as handle:
            handle.writestr("notes.txt", b"nothing here")
        assert detect_platform(archive) is Platform.UNKNOWN

    def test_extension_does_not_decide_platform(self, tmp_path):
        """A PE named .pdf is the ordinary case, not the unusual one."""
        disguised = tmp_path / "invoice.pdf"
        disguised.write_bytes(b"MZ" + b"\x00" * 100)
        assert detect_platform(disguised) is Platform.WINDOWS

    def test_job_carries_identity_and_provenance(self, pe_sample):
        job = receive_sample(pe_sample, submitted_by="insp.sharma",
                             case_reference="CYB/2026/0142")
        assert len(job.sha256) == 64
        assert job.file_size == pe_sample.stat().st_size
        assert job.case_reference == "CYB/2026/0142"
        assert job.state is JobState.QUEUED

    @pytest.mark.parametrize("content,reason", [
        (b"", "empty"),
        (b"just some text that is not executable", "No sandbox"),
    ])
    def test_unrunnable_submissions_are_rejected_with_a_reason(self, tmp_path, content, reason):
        sample = tmp_path / "thing.bin"
        sample.write_bytes(content)
        with pytest.raises(SampleRejected, match=reason):
            receive_sample(sample)

    def test_missing_file_is_rejected(self, tmp_path):
        with pytest.raises(SampleRejected, match="not found"):
            receive_sample(tmp_path / "absent.exe")

    def test_oversized_sample_is_rejected(self, pe_sample):
        with pytest.raises(SampleRejected, match="intake limit"):
            receive_sample(pe_sample, max_bytes=10)


# ============================================================================
# Queue
# ============================================================================

class TestQueue:

    def _job(self, sha: str, platform=Platform.WINDOWS, priority=JobPriority.NORMAL):
        return AnalysisJob(sample_path=f"/samples/{sha}.exe", sha256=sha,
                           platform=platform, priority=priority, file_name=f"{sha}.exe")

    def test_priority_before_arrival_order(self):
        queue = JobQueue()
        queue.submit(self._job("a" * 64, priority=JobPriority.BULK))
        urgent = queue.submit(self._job("b" * 64, priority=JobPriority.URGENT))
        assert queue.next_for([Platform.WINDOWS]).job_id == urgent.job_id

    def test_identical_sample_is_detonated_once(self):
        """Three districts submitting one APK is one run, not three."""
        queue = JobQueue()
        first = queue.submit(self._job("c" * 64))
        second = queue.submit(self._job("c" * 64))

        assert second.job_id == first.job_id
        assert len(queue) == 1
        assert queue.duplicate_submissions == 1

    def test_duplicate_submission_provenance_is_kept(self):
        queue = JobQueue()
        first = queue.submit(self._job("d" * 64))
        duplicate = self._job("d" * 64)
        duplicate.case_reference = "CYB/2026/0199"
        queue.submit(duplicate)

        recorded = first.metadata["duplicate_submissions"]
        assert recorded[0]["case_reference"] == "CYB/2026/0199"

    def test_urgent_duplicate_lifts_the_pending_run(self):
        """The second submitter should not inherit the first one's low priority."""
        queue = JobQueue()
        first = queue.submit(self._job("e" * 64, priority=JobPriority.BULK))
        queue.submit(self._job("e" * 64, priority=JobPriority.URGENT))
        assert first.priority is JobPriority.URGENT

    def test_platform_filtering_does_not_block_a_free_guest(self):
        """An Android job at the head must not stall an idle Windows guest."""
        queue = JobQueue()
        queue.submit(self._job("f" * 64, platform=Platform.ANDROID,
                               priority=JobPriority.URGENT))
        windows = queue.submit(self._job("0" * 64, platform=Platform.WINDOWS))
        assert queue.next_for([Platform.WINDOWS]).job_id == windows.job_id

    def test_aging_promotes_starved_work(self):
        """
        Strict priority starves bulk work forever under a steady trickle of
        case submissions, so a job that has waited long enough is promoted.
        """
        from datetime import timedelta

        queue = JobQueue(aging_promotion_sec=600.0)
        old_bulk = self._job("1" * 64, priority=JobPriority.BULK)
        old_bulk.submitted_at -= timedelta(seconds=1200)
        queue.submit(old_bulk)
        queue.submit(self._job("2" * 64, priority=JobPriority.NORMAL))

        assert queue.next_for([Platform.WINDOWS]).job_id == old_bulk.job_id

    def test_fresh_bulk_work_does_not_jump_the_queue(self):
        queue = JobQueue(aging_promotion_sec=600.0)
        queue.submit(self._job("7" * 64, priority=JobPriority.BULK))
        normal = queue.submit(self._job("8" * 64, priority=JobPriority.NORMAL))
        assert queue.next_for([Platform.WINDOWS]).job_id == normal.job_id

    def test_expiry_is_reported_not_silent(self):
        queue = JobQueue()
        queue.submit(self._job("3" * 64))
        expired = queue.expire_older_than(0.0)
        assert len(expired) == 1
        assert expired[0].state is JobState.EXPIRED
        assert len(queue) == 0

    def test_depth_is_reported_per_platform(self):
        queue = JobQueue()
        queue.submit(self._job("4" * 64, platform=Platform.ANDROID))
        queue.submit(self._job("5" * 64, platform=Platform.ANDROID))
        queue.submit(self._job("6" * 64, platform=Platform.WINDOWS))
        assert queue.depth_by_platform() == {"android": 2, "windows": 1}


# ============================================================================
# Pool
# ============================================================================

class TestPool:

    def test_lease_is_exclusive(self, pool):
        """Two samples on one guest cross-contaminate; neither result stands."""
        assert pool.acquire(Platform.WINDOWS, uuid4()) is not None
        assert pool.acquire(Platform.WINDOWS, uuid4()) is None

    def test_release_does_not_return_a_dirty_guest_to_service(self, pool):
        pool.acquire(Platform.WINDOWS, uuid4())
        pool.release("win-01", succeeded=True)

        assert pool.get("win-01").state is SandboxState.REVERTING
        assert pool.acquire(Platform.WINDOWS, uuid4()) is None

    def test_reverted_guest_becomes_assignable(self, pool):
        pool.acquire(Platform.WINDOWS, uuid4())
        pool.release("win-01", succeeded=True)
        pool.mark_reverted("win-01")
        assert pool.acquire(Platform.WINDOWS, uuid4()) is not None

    def test_platform_matching(self, pool):
        assert pool.acquire(Platform.ANDROID, uuid4()) is None

    def test_repeated_failures_quarantine_the_guest(self, pool):
        for _ in range(3):
            pool.acquire(Platform.WINDOWS, uuid4())
            pool.release("win-01", succeeded=False)
            pool.mark_reverted("win-01")

        sandbox = pool.get("win-01")
        assert sandbox.state is SandboxState.OFFLINE
        assert "consecutive" in sandbox.offline_reason
        assert pool.acquire(Platform.WINDOWS, uuid4()) is None

    def test_success_resets_the_failure_streak(self, pool):
        for succeeded in (False, False, True):
            pool.acquire(Platform.WINDOWS, uuid4())
            pool.release("win-01", succeeded=succeeded)
            pool.mark_reverted("win-01")
        assert pool.get("win-01").consecutive_failures == 0
        assert pool.get("win-01").state is SandboxState.IDLE

    def test_quarantined_guest_can_be_restored_by_an_operator(self, pool):
        pool.mark_offline("win-01", "manual")
        assert pool.restore("win-01")
        assert pool.get("win-01").is_available

    def test_abandoned_lease_is_reclaimed_for_reversion(self):
        """A manager that died mid-run must not strand the guest."""
        pool = SandboxPool(lease_timeout_sec=0.0)
        pool.register(Sandbox(sandbox_id="win-02", platform=Platform.WINDOWS))
        pool.acquire(Platform.WINDOWS, uuid4())

        pool.acquire(Platform.WINDOWS, uuid4())     # triggers reclamation
        assert pool.get("win-02").state is SandboxState.REVERTING

    def test_least_recently_used_guest_is_chosen(self):
        """Rotating surfaces a subtly broken guest instead of masking it."""
        pool = SandboxPool()
        pool.register(Sandbox(sandbox_id="a", platform=Platform.WINDOWS))
        pool.register(Sandbox(sandbox_id="b", platform=Platform.WINDOWS))

        first = pool.acquire(Platform.WINDOWS, uuid4())
        pool.release(first.sandbox_id, succeeded=True)
        pool.mark_reverted(first.sandbox_id)

        second = pool.acquire(Platform.WINDOWS, uuid4())
        assert second.sandbox_id != first.sandbox_id


# ============================================================================
# Run lifecycle
# ============================================================================

class TestRunLifecycle:

    @pytest.mark.asyncio
    async def test_happy_path_walks_the_full_chain(self, pool, pe_sample):
        manager, controller = build_manager(pool)
        manager.submit(pe_sample)
        job = await manager.run_next()

        assert job.state is JobState.COMPLETED
        assert controller.calls[:4] == ["restore", "start", "agent", "drop"]
        assert "stop" in controller.calls
        assert [t.state for t in job.history][:5] == [
            JobState.QUEUED, JobState.ASSIGNED, JobState.PREPARING,
            JobState.RUNNING, JobState.COLLECTING,
        ]

    @pytest.mark.asyncio
    async def test_sample_is_transferred_only_after_a_clean_boot(self, pool, pe_sample):
        manager, controller = build_manager(pool)
        manager.submit(pe_sample)
        await manager.run_next()

        assert controller.calls.index("drop") > controller.calls.index("agent")

    @pytest.mark.asyncio
    async def test_failed_restore_aborts_before_the_sample_is_transferred(self, pool, pe_sample):
        """
        The invariant that matters most: never detonate on a guest of unknown
        state. Findings from a dirty guest cannot be attributed to a sample.
        """
        manager, controller = build_manager(pool, FakeController(restore_ok=False))
        job = manager.submit(pe_sample)
        job.max_attempts = 1
        await manager.run_next()

        assert "drop" not in controller.calls
        assert job.state is JobState.FAILED
        assert "did not restore" in job.error

    @pytest.mark.asyncio
    async def test_agent_timeout_fails_the_job(self, pool, pe_sample):
        manager, controller = build_manager(pool, FakeController(agent_ok=False))
        job = manager.submit(pe_sample)
        job.max_attempts = 1
        await manager.run_next()

        assert job.state is JobState.FAILED
        assert "did not report ready" in job.error
        assert "drop" not in controller.calls

    @pytest.mark.asyncio
    async def test_guest_is_released_even_when_the_run_explodes(self, pool, pe_sample):
        manager, controller = build_manager(pool, pipeline=exploding_pipeline)
        job = manager.submit(pe_sample)
        job.max_attempts = 1
        await manager.run_next()

        assert job.state is JobState.FAILED
        assert "stop" in controller.calls
        assert pool.get("win-01").current_job is None

    @pytest.mark.asyncio
    async def test_retryable_failure_is_requeued(self, pool, pe_sample):
        manager, _ = build_manager(pool, pipeline=exploding_pipeline)
        job = manager.submit(pe_sample)
        job.max_attempts = 2
        await manager.run_next()

        assert job.state is JobState.QUEUED
        assert job.attempts == 1
        assert len(manager.queue) == 1

    @pytest.mark.asyncio
    async def test_job_fails_after_its_attempt_limit(self, pool, pe_sample):
        manager, _ = build_manager(pool, pipeline=exploding_pipeline)
        job = manager.submit(pe_sample)
        job.max_attempts = 2

        for _ in range(3):
            pool.mark_reverted("win-01")
            await manager.run_next()

        assert job.state is JobState.FAILED
        assert "after 2 attempt" in job.error

    @pytest.mark.asyncio
    async def test_failed_post_run_revert_takes_the_guest_offline(self, pool, pe_sample):
        """A guest that will not revert must not receive the next sample."""
        manager, _ = build_manager(pool, FakeController(post_restore_ok=False))
        manager.submit(pe_sample)
        await manager.run_next()

        sandbox = pool.get("win-01")
        assert sandbox.state is SandboxState.OFFLINE
        assert "may still hold" in sandbox.offline_reason

    @pytest.mark.asyncio
    async def test_no_matching_guest_leaves_the_job_queued(self, pool, apk_sample):
        manager, _ = build_manager(pool)
        job = manager.submit(apk_sample)

        assert await manager.run_next() is None
        assert job.state is JobState.QUEUED
        assert manager.status()["blocked_platforms"] == {"android": 1}

    @pytest.mark.asyncio
    async def test_results_are_stored(self, pool, pe_sample, tmp_path):
        repository = RunResultRepository(tmp_path / "runs")
        manager, _ = build_manager(pool, repository=repository)
        manager.submit(pe_sample)
        job = await manager.run_next()

        stored = repository.load(str(job.analysis_id))
        assert stored["sha256"] == job.sha256
        assert stored["final_risk_score"] == 70
        assert stored["job"]["state"] == "completed"

    @pytest.mark.asyncio
    async def test_stored_run_is_findable_by_sample_hash(self, pool, pe_sample, tmp_path):
        repository = RunResultRepository(tmp_path / "runs")
        manager, _ = build_manager(pool, repository=repository)
        manager.submit(pe_sample)
        job = await manager.run_next()

        runs = repository.runs_for_sample(job.sha256)
        assert len(runs) == 1
        assert runs[0]["analysis_id"] == str(job.analysis_id)

    @pytest.mark.asyncio
    async def test_drain_processes_the_queue(self, tmp_path):
        pool = SandboxPool()
        pool.register(Sandbox(sandbox_id="win-01", platform=Platform.WINDOWS))
        manager, _ = build_manager(pool)

        for index in range(3):
            sample = tmp_path / f"s{index}.exe"
            sample.write_bytes(b"MZ" + bytes([index]) * 100)
            manager.submit(sample)

        # One guest, so each run must complete and revert before the next.
        processed = []
        for _ in range(3):
            job = await manager.run_next()
            if job:
                processed.append(job)
            pool.mark_reverted("win-01")

        assert len(processed) == 3
        assert all(job.state is JobState.COMPLETED for job in processed)

    @pytest.mark.asyncio
    async def test_status_reports_something_an_operator_can_act_on(self, pool, apk_sample):
        manager, _ = build_manager(pool)
        manager.submit(apk_sample)
        status = manager.status()

        assert status["queue"]["pending"] == 1
        assert status["pool"]["available"] == 1
        assert status["blocked_platforms"]["android"] == 1
