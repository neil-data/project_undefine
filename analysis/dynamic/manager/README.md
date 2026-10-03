# Detonation Manager

Everything around a run, so the eight-stage pipeline can keep owning only the
run itself.

```
receive → queue → select a guest → restore → transfer → detonate
        → collect → shut down → store
```

## Two invariants, enforced here rather than trusted to the caller

**Nothing detonates on a guest that was not just reverted.** The lease is taken
before the restore, and the sample is transferred only after the restore
reports success and the agent answers. A failed restore aborts the job — it
never proceeds onto a guest that may still hold the previous sample's
persistence entries, because the resulting findings would be a mixture of two
samples with no way to separate them afterwards.

**Every guest is released, whatever happened.** Teardown runs in a `finally`,
so a crash mid-detonation still returns the guest for reversion. A leaked lease
removes a guest from the fleet permanently and silently; nothing else in the
system would report why the queue got slower.

A guest is not assignable again just because a run ended. `release()` puts it
in `REVERTING`; only `mark_reverted()` returns it to service. If the post-run
revert fails, the guest goes `OFFLINE` rather than receiving the next sample.

## Intake decides three things before any guest is touched

| Question | Why it is answered here |
|----------|------------------------|
| Is this the same sample? | The same APK arrives from three districts under three names. One detonation, three linked submissions — not 135 minutes of sandbox time |
| Which guest can run it? | Decided from the file's bytes. A PE named `invoice.pdf` is the ordinary case |
| Should it be queued at all? | An empty file rejected at intake costs nothing; discovered after a snapshot restore it costs eight minutes |

## The queue is not a list

**Priority with fairness.** Strict priority starves bulk work forever: a
trickle of case submissions means an overnight corpus re-scan never runs. Jobs
age, so the queue drains under load instead of stalling at the bottom.

**Deduplication by content.** Folded on SHA-256 while pending, with every
submission's provenance recorded against the single run — each district's case
still links to the result. A duplicate arriving with real urgency lifts the
pending job's priority; the second submitter should not inherit the first's.

**Per-platform depth.** Forty Android jobs and one Windows job is not "41
pending" when the only free guest is a Windows one.

## Failure is expected

| Failure | Response |
|---------|----------|
| Snapshot restore fails | Job aborts before transfer; guest quarantined on repetition |
| Agent never comes up | Job fails with the timeout stated; sample never transferred |
| Run crashes | Requeued — safe because the next attempt begins with a fresh revert |
| Attempt limit reached | Job fails with the reason and attempt count attached |
| Manager dies mid-run | Lease expires; guest reclaimed to `REVERTING`, never to `IDLE` |
| Guest fails 3 runs in a row | Quarantined — one broken hypervisor must not become a queue of failed results |

## Usage

```python
from manager import DetonationManager, JobPriority, Platform, Sandbox, SandboxPool, RunResultRepository
from stages.stage_orchestrator import run_pipeline

pool = SandboxPool()
pool.register(Sandbox(sandbox_id="win-01", platform=Platform.WINDOWS))
pool.register(Sandbox(sandbox_id="droid-01", platform=Platform.ANDROID))

manager = DetonationManager(
    pool,
    repository=RunResultRepository("run_results"),
    artifact_root="evidence",
    controller_factory=lambda sandbox, job: CapeSandboxController(...),
    pipeline_runner=run_pipeline,
)

manager.submit("suspect.apk", priority=JobPriority.URGENT, case_reference="CYB/2026/0142")
await manager.drain()
```

`status()` reports what an operator can act on — in particular
`blocked_platforms`, which distinguishes a stuck queue from a capacity problem:

```python
{
  "queue": {"pending": 12, "by_platform": {"android": 11, "windows": 1}, "oldest_wait_sec": 2140},
  "pool":  {"available": 1, "quarantined": [{"sandbox_id": "droid-02", "reason": "..."}]},
  "blocked_platforms": {"android": 11}
}
```

## Files

| File | Contents |
|------|----------|
| `models.py` | `AnalysisJob`, `Sandbox`, states and transitions |
| `intake.py` | Validation, hashing, platform detection from bytes |
| `queue.py` | Priority, aging, content deduplication, expiry |
| `pool.py` | Exclusive leasing, reversion gating, quarantine |
| `manager.py` | The run lifecycle |
| `results.py` | Atomic per-run JSON storage, indexed by sample |
| `test_manager.py` | Unit tests against fakes (40) |
| `test_integration.py` | The real pipeline and mock guest (6) |
