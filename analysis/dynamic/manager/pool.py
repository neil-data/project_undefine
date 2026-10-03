"""
pool.py — Sandbox selection and leasing.

THE PROPERTY THIS EXISTS TO ENFORCE
-----------------------------------
**One sample per guest at a time, always from a known-clean snapshot.**

Two samples sharing a guest cross-contaminate: the second one's "persistence
entry created" may be the first one's, and neither result is admissible. So a
lease is exclusive, and a guest returns to the pool only after it has been
reverted — `release()` puts it in REVERTING, and only `mark_reverted()` makes
it assignable again. A crash between those two points leaves the guest out of
service, which is the correct direction to fail.

**A guest that keeps failing is taken out of service.** A VM whose snapshot
restore is silently broken fails every job it touches. Without quarantine, one
broken hypervisor turns a queue of samples into a queue of failed results, and
the failure looks like it came from the samples.
"""

from __future__ import annotations

import logging
import threading
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from uuid import UUID

from .models import Platform, Sandbox, SandboxState

_LOGGER = logging.getLogger(__name__)

# A lease held longer than this is assumed abandoned — the manager process
# died mid-run. Comfortably longer than the deepest profile.
DEFAULT_LEASE_TIMEOUT_SEC = 5400.0


class SandboxPool:
    """Owns the set of detonation guests and hands out exclusive leases."""

    def __init__(self, lease_timeout_sec: float = DEFAULT_LEASE_TIMEOUT_SEC) -> None:
        self._lock = threading.RLock()
        self._sandboxes: Dict[str, Sandbox] = {}
        self._lease_timeout = lease_timeout_sec

    # -- registration ------------------------------------------------------

    def register(self, sandbox: Sandbox) -> Sandbox:
        with self._lock:
            if sandbox.sandbox_id in self._sandboxes:
                raise ValueError(f"Sandbox already registered: {sandbox.sandbox_id}")
            self._sandboxes[sandbox.sandbox_id] = sandbox
            _LOGGER.info("Registered %s sandbox %s",
                         sandbox.platform.value, sandbox.sandbox_id)
            return sandbox

    def get(self, sandbox_id: str) -> Optional[Sandbox]:
        with self._lock:
            return self._sandboxes.get(sandbox_id)

    def all(self) -> List[Sandbox]:
        with self._lock:
            return list(self._sandboxes.values())

    def platforms_available(self) -> List[Platform]:
        """Platforms with at least one idle guest — what the queue can be asked for."""
        with self._lock:
            return sorted(
                {s.platform for s in self._sandboxes.values() if s.is_available},
                key=lambda platform: platform.value,
            )

    # -- leasing -----------------------------------------------------------

    def acquire(self, platform: Platform, job_id: UUID) -> Optional[Sandbox]:
        """
        Reserve an idle guest for `platform`, or None when none is free.

        Selection prefers the least recently used guest. Rotating rather than
        always taking the first keeps wear even, and — more usefully — means a
        guest with a subtly corrupted snapshot surfaces across the fleet
        instead of being masked by one healthy machine absorbing every job.
        """
        with self._lock:
            self._reclaim_expired_leases()

            candidates = [
                sandbox for sandbox in self._sandboxes.values()
                if sandbox.platform is platform and sandbox.is_available
            ]
            if not candidates:
                return None

            candidates.sort(key=lambda s: (s.last_used_at or datetime.min.replace(
                tzinfo=timezone.utc)))
            chosen = candidates[0]

            chosen.state = SandboxState.LEASED
            chosen.current_job = job_id
            chosen.leased_at = datetime.now(timezone.utc)
            _LOGGER.info("Leased sandbox %s to job %s", chosen.sandbox_id, job_id)
            return chosen

    def release(self, sandbox_id: str, *, succeeded: bool) -> None:
        """
        End a lease and send the guest for reversion.

        The guest does not become assignable here — a dirty guest must never
        be handed to the next sample. `mark_reverted()` is the only way back
        into service.
        """
        with self._lock:
            sandbox = self._sandboxes.get(sandbox_id)
            if sandbox is None:
                return

            sandbox.current_job = None
            sandbox.leased_at = None
            sandbox.last_used_at = datetime.now(timezone.utc)

            if succeeded:
                sandbox.runs_completed += 1
                sandbox.consecutive_failures = 0
            else:
                sandbox.runs_failed += 1
                sandbox.consecutive_failures += 1

            if sandbox.should_quarantine:
                sandbox.state = SandboxState.OFFLINE
                sandbox.offline_reason = (
                    f"Quarantined after {sandbox.consecutive_failures} consecutive "
                    f"failed runs — the guest, not the samples, is the likely cause"
                )
                _LOGGER.error("Sandbox %s quarantined: %s",
                              sandbox_id, sandbox.offline_reason)
                return

            sandbox.state = SandboxState.REVERTING

    def mark_reverted(self, sandbox_id: str) -> None:
        """Confirm the snapshot restore completed; return the guest to service."""
        with self._lock:
            sandbox = self._sandboxes.get(sandbox_id)
            if sandbox is None or sandbox.state is not SandboxState.REVERTING:
                return
            sandbox.state = SandboxState.IDLE

    def mark_offline(self, sandbox_id: str, reason: str) -> None:
        with self._lock:
            sandbox = self._sandboxes.get(sandbox_id)
            if sandbox is None:
                return
            sandbox.state = SandboxState.OFFLINE
            sandbox.offline_reason = reason
            sandbox.current_job = None
            _LOGGER.warning("Sandbox %s offline: %s", sandbox_id, reason)

    def restore(self, sandbox_id: str) -> bool:
        """Bring a quarantined guest back after an operator has repaired it."""
        with self._lock:
            sandbox = self._sandboxes.get(sandbox_id)
            if sandbox is None or sandbox.state is not SandboxState.OFFLINE:
                return False
            sandbox.state = SandboxState.IDLE
            sandbox.consecutive_failures = 0
            sandbox.offline_reason = ""
            _LOGGER.info("Sandbox %s returned to service", sandbox_id)
            return True

    def _reclaim_expired_leases(self) -> None:
        """
        Recover guests whose manager died mid-run.

        Reclaimed guests go to REVERTING, never straight to IDLE: whatever was
        detonating on them was still running when contact was lost.
        """
        now = datetime.now(timezone.utc)
        for sandbox in self._sandboxes.values():
            if sandbox.state is not SandboxState.LEASED or sandbox.leased_at is None:
                continue
            if (now - sandbox.leased_at).total_seconds() < self._lease_timeout:
                continue

            _LOGGER.error(
                "Lease on %s expired after %.0fs; job %s abandoned",
                sandbox.sandbox_id, self._lease_timeout, sandbox.current_job,
            )
            sandbox.state = SandboxState.REVERTING
            sandbox.current_job = None
            sandbox.leased_at = None
            sandbox.runs_failed += 1
            sandbox.consecutive_failures += 1

    # -- inspection --------------------------------------------------------

    def stats(self) -> Dict[str, Any]:
        with self._lock:
            by_state: Dict[str, int] = {}
            by_platform: Dict[str, int] = {}
            for sandbox in self._sandboxes.values():
                by_state[sandbox.state.value] = by_state.get(sandbox.state.value, 0) + 1
                by_platform[sandbox.platform.value] = (
                    by_platform.get(sandbox.platform.value, 0) + 1
                )

            return {
                "total": len(self._sandboxes),
                "by_state": by_state,
                "by_platform": by_platform,
                "available": len([s for s in self._sandboxes.values() if s.is_available]),
                "quarantined": [
                    {"sandbox_id": s.sandbox_id, "reason": s.offline_reason}
                    for s in self._sandboxes.values()
                    if s.state is SandboxState.OFFLINE
                ],
                "sandboxes": [s.to_dict() for s in self._sandboxes.values()],
            }
