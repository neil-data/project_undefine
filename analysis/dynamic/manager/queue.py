"""
queue.py — The pending-work queue.

WHY NOT JUST A LIST
-------------------
Three properties the naive version gets wrong, each of which costs real
sandbox time:

**Priority with fairness.** Strict priority starves bulk work forever: a
steady trickle of case submissions means an overnight corpus re-scan never
runs. Jobs therefore age — a job that has waited long enough is promoted, so
the queue drains under load instead of stalling at the bottom.

**Deduplication by content.** The same APK submitted from three districts is
one detonation, not three. It is deduplicated on SHA-256 while pending, and
the duplicate submissions are recorded against the original job so each
district's case still links to the result.

**Per-platform visibility.** A queue of forty Android jobs and one Windows job
is not "41 pending" when the only free guest is a Windows one. Depth is
reported per platform because that is the number that predicts a wait.
"""

from __future__ import annotations

import logging
import threading
from collections import defaultdict
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from uuid import UUID

from .models import AnalysisJob, JobPriority, JobState, Platform

_LOGGER = logging.getLogger(__name__)

# A job waiting this long is promoted one priority level. Long enough that it
# does not undercut genuine urgency, short enough that bulk work still drains.
AGING_PROMOTION_SEC = 1800.0


class JobQueue:
    """Thread-safe priority queue of pending analysis jobs."""

    def __init__(self, aging_promotion_sec: float = AGING_PROMOTION_SEC) -> None:
        self._lock = threading.RLock()
        self._pending: List[AnalysisJob] = []
        self._by_id: Dict[UUID, AnalysisJob] = {}
        self._pending_by_hash: Dict[str, UUID] = {}
        self._aging_sec = aging_promotion_sec

        self.duplicate_submissions = 0

    # -- submission --------------------------------------------------------

    def submit(self, job: AnalysisJob) -> AnalysisJob:
        """
        Queue a job, or fold it into the identical one already waiting.

        Returns the job that will actually run — the caller must use the
        returned object, which may not be the one passed in.
        """
        with self._lock:
            existing_id = self._pending_by_hash.get(job.sha256)
            if existing_id is not None:
                existing = self._by_id[existing_id]
                self._record_duplicate(existing, job)
                self.duplicate_submissions += 1
                _LOGGER.info(
                    "Duplicate submission of %s folded into job %s",
                    job.sha256[:12], existing.job_id,
                )
                return existing

            self._pending.append(job)
            self._by_id[job.job_id] = job
            self._pending_by_hash[job.sha256] = job.job_id
            return job

    @staticmethod
    def _record_duplicate(existing: AnalysisJob, duplicate: AnalysisJob) -> None:
        """Keep every submission's provenance against the single run."""
        submissions = existing.metadata.setdefault("duplicate_submissions", [])
        submissions.append({
            "job_id": str(duplicate.job_id),
            "file_name": duplicate.file_name,
            "submitted_by": duplicate.submitted_by,
            "case_reference": duplicate.case_reference,
            "submitted_at": duplicate.submitted_at.isoformat(),
        })
        # A duplicate arriving with real urgency lifts the pending run: the
        # second submitter should not wait behind the first one's priority.
        if duplicate.priority > existing.priority:
            existing.priority = duplicate.priority

    # -- dispatch ----------------------------------------------------------

    def next_for(self, platforms: List[Platform]) -> Optional[AnalysisJob]:
        """
        Take the highest-priority job runnable on one of `platforms`.

        Platform filtering happens here rather than at the caller because an
        idle Windows guest must not be blocked by an Android job at the head
        of the queue.
        """
        with self._lock:
            candidates = [job for job in self._pending if job.platform in platforms]
            if not candidates:
                return None

            candidates.sort(key=lambda job: (-self._effective_priority(job),
                                             job.submitted_at))
            chosen = candidates[0]
            self._remove(chosen)
            return chosen

    def _effective_priority(self, job: AnalysisJob) -> int:
        """Base priority plus one level once the job has aged past the limit."""
        waited = (datetime.now(timezone.utc) - job.submitted_at).total_seconds()
        bonus = 1 if waited >= self._aging_sec else 0
        return min(int(JobPriority.URGENT), int(job.priority) + bonus)

    def requeue(self, job: AnalysisJob, reason: str = "") -> None:
        """Return a job to the queue after a retryable failure."""
        with self._lock:
            job.transition(JobState.QUEUED, reason or "Requeued after failure")
            job.sandbox_id = None
            self._pending.append(job)
            self._by_id[job.job_id] = job
            self._pending_by_hash.setdefault(job.sha256, job.job_id)

    def cancel(self, job_id: UUID, reason: str = "Cancelled") -> bool:
        with self._lock:
            job = self._by_id.get(job_id)
            if job is None or job not in self._pending:
                return False
            self._remove(job)
            job.transition(JobState.CANCELLED, reason)
            return True

    def expire_older_than(self, max_wait_sec: float) -> List[AnalysisJob]:
        """
        Drop jobs that waited past the point of usefulness.

        Reported rather than silently discarded: a queue quietly shedding work
        looks identical to a queue that is keeping up.
        """
        now = datetime.now(timezone.utc)
        expired: List[AnalysisJob] = []
        with self._lock:
            for job in list(self._pending):
                if (now - job.submitted_at).total_seconds() >= max_wait_sec:
                    self._remove(job)
                    job.transition(
                        JobState.EXPIRED,
                        f"Waited {int((now - job.submitted_at).total_seconds())}s "
                        f"without an available sandbox",
                    )
                    expired.append(job)
        if expired:
            _LOGGER.warning("Expired %d queued job(s)", len(expired))
        return expired

    def _remove(self, job: AnalysisJob) -> None:
        if job in self._pending:
            self._pending.remove(job)
        if self._pending_by_hash.get(job.sha256) == job.job_id:
            del self._pending_by_hash[job.sha256]

    # -- inspection --------------------------------------------------------

    def get(self, job_id: UUID) -> Optional[AnalysisJob]:
        with self._lock:
            return self._by_id.get(job_id)

    def pending(self) -> List[AnalysisJob]:
        with self._lock:
            return list(self._pending)

    def __len__(self) -> int:
        with self._lock:
            return len(self._pending)

    def depth_by_platform(self) -> Dict[str, int]:
        with self._lock:
            counts: Dict[str, int] = defaultdict(int)
            for job in self._pending:
                counts[job.platform.value] += 1
            return dict(counts)

    def stats(self) -> Dict[str, Any]:
        with self._lock:
            now = datetime.now(timezone.utc)
            waits = [(now - job.submitted_at).total_seconds() for job in self._pending]
            by_priority: Dict[str, int] = defaultdict(int)
            for job in self._pending:
                by_priority[job.priority.name] += 1

            return {
                "pending": len(self._pending),
                "by_platform": self.depth_by_platform(),
                "by_priority": dict(by_priority),
                "oldest_wait_sec": round(max(waits), 1) if waits else 0.0,
                "mean_wait_sec": round(sum(waits) / len(waits), 1) if waits else 0.0,
                "duplicate_submissions": self.duplicate_submissions,
            }
