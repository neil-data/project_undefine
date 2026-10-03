"""
Detonation manager — everything around a run, so the pipeline owns only the run.

    receive → queue → select a guest → restore → transfer → detonate
            → collect → shut down → store

Usage
-----
    from manager import DetonationManager, JobPriority, Sandbox, SandboxPool, Platform

    pool = SandboxPool()
    pool.register(Sandbox(sandbox_id="win-01", platform=Platform.WINDOWS))

    manager = DetonationManager(
        pool,
        repository=RunResultRepository("run_results"),
        artifact_root="evidence",
        controller_factory=lambda sandbox, job: CapeSandboxController(...),
        pipeline_runner=run_pipeline,
    )

    manager.submit("suspect.apk", priority=JobPriority.HIGH)
    await manager.drain()
"""

from .intake import SampleRejected, detect_platform, receive_sample, sha256_of
from .manager import DetonationManager, PreparationFailed, SandboxUnavailable
from .models import (
    RETRYABLE_STATES,
    TERMINAL_STATES,
    AnalysisJob,
    JobPriority,
    JobState,
    JobTransition,
    Platform,
    Sandbox,
    SandboxState,
)
from .pool import SandboxPool
from .queue import JobQueue
from .results import RunResultRepository

__all__ = (
    "AnalysisJob",
    "DetonationManager",
    "JobPriority",
    "JobQueue",
    "JobState",
    "JobTransition",
    "Platform",
    "PreparationFailed",
    "RETRYABLE_STATES",
    "RunResultRepository",
    "SampleRejected",
    "Sandbox",
    "SandboxPool",
    "SandboxState",
    "SandboxUnavailable",
    "TERMINAL_STATES",
    "detect_platform",
    "receive_sample",
    "sha256_of",
)
