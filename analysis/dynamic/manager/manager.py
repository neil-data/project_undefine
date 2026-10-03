"""
manager.py — The detonation manager.

WHAT IT OWNS
------------
Everything around a run, so the pipeline can keep owning only the run itself:

    receive → queue → select a guest → restore → transfer → detonate
            → collect → shut down → store

WHY THE ORDER IS RIGID
----------------------
Two invariants make the results admissible, and both are enforced here rather
than trusted to the caller.

**Nothing runs on a guest that was not just reverted.** The lease is taken
before the restore, and the sample is transferred only after the restore
reports success. A failed restore aborts the job — it never proceeds onto a
guest that may still hold the previous sample's persistence entries, because
the resulting findings would be a mixture of two samples and there would be no
way to tell afterwards.

**Every guest is released, whatever happened.** The teardown runs in a
`finally`, so a crash mid-detonation still returns the guest for reversion. A
leaked lease removes a guest from the fleet permanently and silently, and the
queue just gets slower for reasons nobody can see.

FAILURE IS EXPECTED, NOT EXCEPTIONAL
------------------------------------
Guests hang, snapshots fail to restore, agents never come up. A retryable
failure requeues the job — safe precisely because the next attempt begins with
a fresh revert — up to its attempt limit, after which the job fails with the
reason attached. A guest that fails repeatedly is quarantined by the pool, so
one broken hypervisor cannot convert a queue of samples into a queue of
failed results.
"""

from __future__ import annotations

import asyncio
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional
from uuid import UUID

from .intake import receive_sample
from .models import (
    RETRYABLE_STATES,
    AnalysisJob,
    JobPriority,
    JobState,
    Platform,
    Sandbox,
)
from .pool import SandboxPool
from .queue import JobQueue
from .results import RunResultRepository

_LOGGER = logging.getLogger(__name__)


class SandboxUnavailable(RuntimeError):
    """No guest could run this job right now."""


class PreparationFailed(RuntimeError):
    """The guest could not be brought to a known-clean, ready state."""


class DetonationManager:
    """Drives samples from submission to stored result."""

    def __init__(
        self,
        pool: SandboxPool,
        *,
        queue: Optional[JobQueue] = None,
        repository: Optional[RunResultRepository] = None,
        artifact_root: Optional[str | Path] = None,
        controller_factory: Optional[Callable[[Sandbox, AnalysisJob], Any]] = None,
        pipeline_runner: Optional[Callable[..., Any]] = None,
        agent_timeout_sec: int = 180,
    ) -> None:
        self.pool = pool
        self.queue = queue or JobQueue()
        self.repository = repository
        self.artifact_root = Path(artifact_root) if artifact_root else None
        self._controller_factory = controller_factory
        self._pipeline_runner = pipeline_runner
        self._agent_timeout = agent_timeout_sec

        self.completed: List[AnalysisJob] = []
        self.failed: List[AnalysisJob] = []

    # ------------------------------------------------------------------
    # Intake
    # ------------------------------------------------------------------

    def submit(
        self,
        sample_path: str | Path,
        *,
        priority: JobPriority = JobPriority.NORMAL,
        profile: str = "standard",
        submitted_by: str = "",
        case_reference: str = "",
    ) -> AnalysisJob:
        """
        Receive a sample and queue it.

        Returns the job that will run, which may be an existing one: an
        identical sample already waiting is not detonated twice.
        """
        job = receive_sample(
            sample_path,
            priority=priority,
            profile=profile,
            submitted_by=submitted_by,
            case_reference=case_reference,
        )
        return self.queue.submit(job)

    # ------------------------------------------------------------------
    # Dispatch
    # ------------------------------------------------------------------

    async def run_next(self) -> Optional[AnalysisJob]:
        """
        Take one runnable job and see it through.

        Returns None when nothing can run — either the queue is empty or no
        guest matching a queued job's platform is free. Those are different
        situations and `status()` distinguishes them; here both simply mean
        "not now".
        """
        platforms = self.pool.platforms_available()
        if not platforms:
            return None

        job = self.queue.next_for(platforms)
        if job is None:
            return None

        return await self.run_job(job)

    async def drain(self, max_jobs: int = 100) -> List[AnalysisJob]:
        """Run queued work until nothing more can be dispatched."""
        processed: List[AnalysisJob] = []
        for _ in range(max_jobs):
            job = await self.run_next()
            if job is None:
                break
            processed.append(job)
        return processed

    async def run_job(self, job: AnalysisJob) -> AnalysisJob:
        """Execute one job end to end, releasing the guest whatever happens."""
        job.attempts += 1
        sandbox = self.pool.acquire(job.platform, job.job_id)

        if sandbox is None:
            self.queue.requeue(job, f"No {job.platform.value} sandbox available")
            return job

        job.sandbox_id = sandbox.sandbox_id
        job.transition(JobState.ASSIGNED, f"Assigned to {sandbox.sandbox_id}")

        controller = None
        succeeded = False
        try:
            controller = self._build_controller(sandbox, job)

            job.transition(JobState.PREPARING, "Restoring snapshot and transferring sample")
            guest_path = await self._prepare(controller, sandbox, job)

            job.transition(JobState.RUNNING, f"Detonating {job.file_name}")
            result = await self._detonate(controller, job, guest_path)

            job.transition(JobState.COLLECTING, "Collecting artifacts and building timeline")
            report = await self._collect(controller, job, sandbox, result)

            # Marked complete *before* the report is written, so the stored
            # record does not freeze the job at 'collecting' forever. If the
            # write then fails the outer handler re-transitions to FAILED, and
            # the history shows both — which is the accurate account.
            job.transition(JobState.COMPLETED, "Run complete")
            report["state"] = JobState.COMPLETED.value
            report["job"] = job.to_dict()

            if self.repository is not None:
                job.result_path = str(self.repository.save(report))

            self.completed.append(job)
            succeeded = True

        except PreparationFailed as error:
            self._handle_failure(job, f"Preparation failed: {error}")
        except SandboxUnavailable as error:
            self._handle_failure(job, f"Sandbox unavailable: {error}")
        except asyncio.CancelledError:
            job.transition(JobState.CANCELLED, "Run cancelled")
            raise
        except Exception as error:  # noqa: BLE001 - one bad run must not stop the queue
            _LOGGER.exception("Job %s failed", job.job_id)
            self._handle_failure(job, f"Run failed: {error}")

        finally:
            # Teardown always runs. A guest left leased is a guest permanently
            # removed from the fleet, and nothing else in the system would
            # report why the queue got slower.
            await self._teardown(controller, sandbox, succeeded)

        return job

    # ------------------------------------------------------------------
    # Run phases
    # ------------------------------------------------------------------

    def _build_controller(self, sandbox: Sandbox, job: AnalysisJob) -> Any:
        if self._controller_factory is None:
            raise SandboxUnavailable(
                "No controller factory configured; the manager cannot reach a guest"
            )
        controller = self._controller_factory(sandbox, job)
        if controller is None:
            raise SandboxUnavailable(f"No controller for sandbox {sandbox.sandbox_id}")
        return controller

    async def _prepare(self, controller: Any, sandbox: Sandbox, job: AnalysisJob) -> str:
        """Revert, boot, wait for the agent, then transfer the sample."""
        if not await controller.restore_snapshot(sandbox.snapshot):
            raise PreparationFailed(
                f"Snapshot '{sandbox.snapshot}' did not restore on {sandbox.sandbox_id}; "
                f"refusing to detonate on a guest of unknown state"
            )
        if not await controller.start_guest():
            raise PreparationFailed(f"Guest {sandbox.sandbox_id} did not start")
        if not await controller.await_agent(self._agent_timeout):
            raise PreparationFailed(
                f"Agent on {sandbox.sandbox_id} did not report ready within "
                f"{self._agent_timeout}s"
            )

        # Transfer happens only after a confirmed clean boot: a sample dropped
        # onto a guest that then fails to come up is a sample sitting on disk
        # in an unknown state.
        guest_path = await controller.drop_sample(job.sample_path)
        if not guest_path:
            raise PreparationFailed("Sample transfer to the guest failed")
        return guest_path

    async def _detonate(self, controller: Any, job: AnalysisJob, guest_path: str) -> Any:
        """Hand off to the stage pipeline, which owns everything inside the run."""
        if self._pipeline_runner is None:
            raise SandboxUnavailable("No pipeline runner configured")

        return await self._pipeline_runner(
            analysis_id=job.analysis_id,
            platform=job.platform.value,
            sample_path=guest_path,
            controller=controller,
            profile_name=job.profile,
        )

    async def _collect(
        self, controller: Any, job: AnalysisJob, sandbox: Sandbox, result: Any
    ) -> Dict[str, Any]:
        """Assemble the stored report from the run's own output."""
        report: Dict[str, Any] = {
            "analysis_id": str(job.analysis_id),
            "job_id": str(job.job_id),
            "sha256": job.sha256,
            "file_name": job.file_name,
            "file_size": job.file_size,
            "platform": job.platform.value,
            "profile": job.profile,
            "sandbox_id": sandbox.sandbox_id,
            "case_reference": job.case_reference,
            "submitted_by": job.submitted_by,
            "submitted_at": job.submitted_at.isoformat(),
            "queue_wait_sec": round(job.queue_wait_sec, 2),
            "state": JobState.COMPLETED.value,
            "job": job.to_dict(),
        }

        report.update(self._summarize_pipeline(result))

        if self.artifact_root is not None:
            report["artifacts"] = self._collect_artifacts(job, result)
            report["artifact_count"] = len(report["artifacts"].get("artifacts", []))
            # A memory image nobody reads is a large file, not evidence. This
            # is where a packed sample's decrypted payload actually surfaces.
            report["memory_analysis"] = self._analyze_memory(job, report["artifacts"])

        report["timeline"] = self._build_timeline(job, result)
        return report

    def _analyze_memory(self, job: AnalysisJob, artifacts: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Run signature and indicator extraction over every captured dump."""
        from artifacts.memory import MemoryDumpAnalyzer

        dumps = [
            artifact for artifact in artifacts.get("artifacts", [])
            if artifact.get("artifact_type") == "memdump"
        ]
        if not dumps:
            return []

        analyzer = MemoryDumpAnalyzer()
        disk_indicators = list(job.metadata.get("static_indicators", []))

        results = []
        for dump in dumps:
            analysis = analyzer.analyze(dump["stored_path"], disk_indicators)
            results.append(analysis.to_dict())
            if analysis.revealed_hidden_payload:
                _LOGGER.info(
                    "Memory image %s revealed %d indicator(s) absent from the file itself",
                    dump["name"], len(analysis.indicators_absent_from_disk),
                )
        return results

    @staticmethod
    def _summarize_pipeline(result: Any) -> Dict[str, Any]:
        """Pull the reportable facts out of a PipelineResult, tolerating absence."""
        if result is None:
            return {"completed": False, "final_risk_score": 0}

        activation = getattr(result, "activation_stage", None)
        return {
            "completed": bool(getattr(result, "completed", False)),
            "aborted": bool(getattr(result, "aborted", False)),
            "final_risk_score": int(getattr(result, "final_risk_score", 0)),
            "total_duration_sec": float(getattr(result, "total_duration_sec", 0.0)),
            "activation_stage": getattr(activation, "value", None),
            "dormant_stages": [
                getattr(stage, "value", str(stage))
                for stage in getattr(result, "dormant_stages", []) or []
            ],
            "evasion_profile": [
                getattr(evasion, "value", str(evasion))
                for evasion in getattr(result, "evasion_profile", []) or []
            ],
            "findings": [
                {
                    "title": getattr(finding, "title", ""),
                    "detail": getattr(finding, "detail", ""),
                    "severity": getattr(finding, "severity", "info"),
                    "stage_id": getattr(getattr(finding, "stage_id", None), "value", None),
                    "mitre": list(getattr(finding, "mitre_techniques", []) or []),
                }
                for finding in getattr(result, "all_findings", []) or []
            ],
        }

    def _collect_artifacts(self, job: AnalysisJob, result: Any) -> Dict[str, Any]:
        """Take custody of every file the run produced, hashing as we go."""
        from artifacts.store import ArtifactError, ArtifactStore

        store = ArtifactStore(self.artifact_root, job.analysis_id)
        for stage_result in getattr(result, "stage_results", []) or []:
            stage_id = getattr(getattr(stage_result, "stage_id", None), "value", None)
            for artifact in getattr(stage_result, "artifacts", []) or []:
                path = getattr(artifact, "path", None)
                if not path or not Path(path).is_file():
                    continue
                try:
                    store.register(
                        path,
                        getattr(artifact, "artifact_type", "log"),
                        stage_id=stage_id,
                        description=f"Captured during {stage_id}",
                    )
                except (ArtifactError, OSError) as error:
                    _LOGGER.warning("Could not take custody of %s: %s", path, error)

        job.artifact_manifest = str(store.manifest_path)
        payload = store.to_dict()
        payload["verification"] = store.verify()
        return payload

    @staticmethod
    def _build_timeline(job: AnalysisJob, result: Any) -> Dict[str, Any]:
        """
        Merge every stream the run produced into one account.

        Hook chains and network events are taken from the result when the
        pipeline carried them — a run with hook monitoring attached produces a
        far richer timeline, and one without still produces a correct one.
        """
        from timeline.builder import TimelineBuilder

        builder = TimelineBuilder(str(job.analysis_id))
        builder.add_stage_results(getattr(result, "stage_results", []) or [])

        chains = getattr(result, "behavior_chains", None)
        if chains:
            builder.add_behavior_chains(chains)

        network_events = getattr(result, "network_events", None)
        if network_events:
            builder.add_network_events(network_events)

        return builder.build()

    async def _teardown(self, controller: Any, sandbox: Sandbox, succeeded: bool) -> None:
        """
        Stop the guest and hand it back for reversion.

        Errors here are logged and swallowed: the run's results are already in
        hand, and raising would replace a completed analysis with a teardown
        failure.
        """
        if controller is not None:
            try:
                await controller.stop_guest()
            except Exception as error:  # noqa: BLE001
                _LOGGER.warning("Guest %s did not stop cleanly: %s",
                                sandbox.sandbox_id, error)
            close = getattr(controller, "close", None)
            if close is not None:
                try:
                    await close()
                except Exception:  # noqa: BLE001
                    pass

        self.pool.release(sandbox.sandbox_id, succeeded=succeeded)

        # The guest is only assignable again once it has been reverted. On a
        # failed run the revert is attempted immediately; if it does not take,
        # the guest stays out of service rather than receiving the next sample.
        if controller is not None:
            try:
                if await controller.restore_snapshot(sandbox.snapshot):
                    self.pool.mark_reverted(sandbox.sandbox_id)
                else:
                    self.pool.mark_offline(
                        sandbox.sandbox_id,
                        "Post-run snapshot restore failed; guest may still hold "
                        "the previous sample's changes",
                    )
            except Exception as error:  # noqa: BLE001
                self.pool.mark_offline(
                    sandbox.sandbox_id, f"Post-run revert errored: {error}"
                )
        else:
            self.pool.mark_reverted(sandbox.sandbox_id)

    def _handle_failure(self, job: AnalysisJob, reason: str) -> None:
        """Requeue a retryable failure, or record a final one."""
        if job.can_retry:
            _LOGGER.warning("Job %s attempt %d failed (%s); requeueing",
                            job.job_id, job.attempts, reason)
            self.queue.requeue(job, reason)
            return

        job.transition(
            JobState.FAILED,
            f"{reason} (after {job.attempts} attempt(s))",
        )
        self.failed.append(job)

    # ------------------------------------------------------------------
    # Status
    # ------------------------------------------------------------------

    def status(self) -> Dict[str, Any]:
        """
        A snapshot an operator can act on.

        `blocked_platforms` is the number that matters when the queue is not
        draining: work is waiting for a platform with no free guest, which is a
        capacity problem, not a stuck queue.
        """
        available = set(self.pool.platforms_available())
        depth = self.queue.depth_by_platform()

        return {
            "queue": self.queue.stats(),
            "pool": self.pool.stats(),
            "completed": len(self.completed),
            "failed": len(self.failed),
            "blocked_platforms": {
                platform: count
                for platform, count in depth.items()
                if Platform(platform) not in available
            },
            "at": datetime.now(timezone.utc).isoformat(),
        }

    def job(self, job_id: UUID) -> Optional[AnalysisJob]:
        found = self.queue.get(job_id)
        if found is not None:
            return found
        for job in (*self.completed, *self.failed):
            if job.job_id == job_id:
                return job
        return None
