"""
models.py — Job and sandbox contracts for the detonation manager.

WHY A JOB EXISTS AT ALL
-----------------------
The eight-stage pipeline already knew how to detonate one sample in one guest.
What was missing is everything around it: a submitted file has to become a
unit of work that can be queued, prioritized, assigned to a guest that can
actually run it, retried when a guest dies mid-run, and accounted for
afterwards.

That unit is the job, and it is deliberately separate from the pipeline
result. A job outlives its run — it records that a sample was received at a
given time, waited, ran on a named guest, and produced named artifacts. In a
chain-of-custody system that history is part of the evidence, not bookkeeping.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional
from uuid import UUID, uuid4


def _now() -> datetime:
    return datetime.now(timezone.utc)


class Platform(str, Enum):
    """Guest platform a sample requires."""

    WINDOWS = "windows"
    ANDROID = "android"
    LINUX = "linux"
    UNKNOWN = "unknown"


class JobPriority(int, Enum):
    """
    Queue precedence.

    An investigator waiting at a desk with a victim's phone outranks a bulk
    re-scan of last month's corpus, and the queue has to know that.
    """

    BULK = 0            # Corpus re-analysis, overnight work
    NORMAL = 1
    HIGH = 2            # Active case
    URGENT = 3          # Officer waiting, live incident


class JobState(str, Enum):
    """
    Where a job is in its life.

    Failure is split three ways on purpose. `FAILED` means the sample was
    analyzed and the run broke; `REJECTED` means it never should have been
    queued; `EXPIRED` means it waited past the point of usefulness. Collapsing
    them loses the distinction between a broken sandbox and a bad submission.
    """

    QUEUED = "queued"
    ASSIGNED = "assigned"           # A sandbox is reserved, run not started
    PREPARING = "preparing"         # Snapshot restore, sample transfer
    RUNNING = "running"
    COLLECTING = "collecting"       # Artifacts, memory, timeline
    COMPLETED = "completed"
    FAILED = "failed"
    REJECTED = "rejected"
    EXPIRED = "expired"
    CANCELLED = "cancelled"


TERMINAL_STATES = frozenset({
    JobState.COMPLETED, JobState.FAILED, JobState.REJECTED,
    JobState.EXPIRED, JobState.CANCELLED,
})

# States from which a crashed run can be safely retried: the guest is reverted
# to a golden snapshot before every run, so nothing carries over.
RETRYABLE_STATES = frozenset({
    JobState.ASSIGNED, JobState.PREPARING, JobState.RUNNING, JobState.COLLECTING,
})


@dataclass
class JobTransition:
    """One recorded state change, with why."""

    state: JobState
    at: datetime
    detail: str = ""


@dataclass
class AnalysisJob:
    """One sample's journey from submission to stored result."""

    sample_path: str
    sha256: str

    job_id: UUID = field(default_factory=uuid4)
    analysis_id: UUID = field(default_factory=uuid4)

    platform: Platform = Platform.UNKNOWN
    profile: str = "standard"
    priority: JobPriority = JobPriority.NORMAL

    file_name: str = ""
    file_size: int = 0
    submitted_by: str = ""
    case_reference: str = ""

    state: JobState = JobState.QUEUED
    submitted_at: datetime = field(default_factory=_now)
    started_at: Optional[datetime] = None
    finished_at: Optional[datetime] = None

    sandbox_id: Optional[str] = None
    attempts: int = 0
    max_attempts: int = 2

    error: Optional[str] = None
    result_path: Optional[str] = None
    artifact_manifest: Optional[str] = None

    history: List[JobTransition] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def transition(self, state: JobState, detail: str = "") -> None:
        """Move to a new state, recording when and why."""
        self.state = state
        self.history.append(JobTransition(state=state, at=_now(), detail=detail))

        if state is JobState.PREPARING and self.started_at is None:
            self.started_at = _now()
        if state in TERMINAL_STATES:
            self.finished_at = _now()
        if state is JobState.FAILED:
            self.error = detail or self.error

    @property
    def is_terminal(self) -> bool:
        return self.state in TERMINAL_STATES

    @property
    def can_retry(self) -> bool:
        return self.attempts < self.max_attempts

    @property
    def queue_wait_sec(self) -> float:
        reference = self.started_at or _now()
        return max(0.0, (reference - self.submitted_at).total_seconds())

    @property
    def runtime_sec(self) -> float:
        if self.started_at is None:
            return 0.0
        return max(0.0, ((self.finished_at or _now()) - self.started_at).total_seconds())

    def to_dict(self) -> Dict[str, Any]:
        return {
            "job_id": str(self.job_id),
            "analysis_id": str(self.analysis_id),
            "sha256": self.sha256,
            "file_name": self.file_name,
            "file_size": self.file_size,
            "platform": self.platform.value,
            "profile": self.profile,
            "priority": self.priority.name,
            "state": self.state.value,
            "sandbox_id": self.sandbox_id,
            "attempts": self.attempts,
            "submitted_at": self.submitted_at.isoformat(),
            "started_at": self.started_at.isoformat() if self.started_at else None,
            "finished_at": self.finished_at.isoformat() if self.finished_at else None,
            "queue_wait_sec": round(self.queue_wait_sec, 2),
            "runtime_sec": round(self.runtime_sec, 2),
            "error": self.error,
            "result_path": self.result_path,
            "artifact_manifest": self.artifact_manifest,
            "case_reference": self.case_reference,
            "submitted_by": self.submitted_by,
            "history": [
                {"state": t.state.value, "at": t.at.isoformat(), "detail": t.detail}
                for t in self.history
            ],
        }


class SandboxState(str, Enum):
    """Availability of one guest."""

    IDLE = "idle"
    LEASED = "leased"
    REVERTING = "reverting"     # Snapshot restore after a run
    OFFLINE = "offline"         # Health check failed or manually disabled


@dataclass
class Sandbox:
    """
    One detonation guest.

    `consecutive_failures` drives automatic quarantine. A guest whose snapshot
    restore is silently failing will fail every job handed to it, and a manager
    that keeps assigning work to it converts one broken VM into a queue of
    broken results.
    """

    sandbox_id: str
    platform: Platform

    snapshot: str = "golden"
    description: str = ""
    max_consecutive_failures: int = 3

    state: SandboxState = SandboxState.IDLE
    current_job: Optional[UUID] = None
    leased_at: Optional[datetime] = None

    runs_completed: int = 0
    runs_failed: int = 0
    consecutive_failures: int = 0
    last_used_at: Optional[datetime] = None
    offline_reason: str = ""

    @property
    def is_available(self) -> bool:
        return self.state is SandboxState.IDLE

    @property
    def should_quarantine(self) -> bool:
        return self.consecutive_failures >= self.max_consecutive_failures

    def to_dict(self) -> Dict[str, Any]:
        return {
            "sandbox_id": self.sandbox_id,
            "platform": self.platform.value,
            "state": self.state.value,
            "snapshot": self.snapshot,
            "current_job": str(self.current_job) if self.current_job else None,
            "runs_completed": self.runs_completed,
            "runs_failed": self.runs_failed,
            "consecutive_failures": self.consecutive_failures,
            "last_used_at": self.last_used_at.isoformat() if self.last_used_at else None,
            "offline_reason": self.offline_reason,
        }
