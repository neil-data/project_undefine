# Phase 2 — Complete Dynamic Sandbox

## Overview

The eight-stage pipeline already knew how to detonate one sample in one guest,
capture events through Frida/CAPE hooks, and produce a staged report. What was
missing was everything around the run — the part that turns a detonation
harness into something a police cyber-crime unit can put samples into.

```
receive → job → select sandbox → restore → transfer → detonate
        → collect events → capture network → capture memory
        → timeline → shutdown → store
```

## What was found

### 1. There was no job, no queue and no sandbox selection

A `test_sandbox_manager.py` at the repository root said so directly (it has
since been removed — see *Stale test script replaced* below):

```python
# The orchestrator and controllers have complex relative imports...
ORCHESTRATOR_AVAILABLE = False
```

The pipeline had to be handed an already-chosen controller and an already-known
platform. Nothing decided which guest could run a sample, nothing queued work,
nothing prevented two samples sharing a guest, and nothing recovered a guest
whose run had crashed.

### 2. Memory dumps were captured and never read

`dump_memory()` returned a path and the path was recorded. A memory image
nobody examines is a large file, not evidence — and it is precisely where a
packed sample's decrypted payload lives.

### 3. Artifacts had no custody

`StageArtifact` carried an optional `sha256` that nothing populated. No
manifest, no verification, no protection against a captured exhibit being
overwritten or removed.

### 4. There was a stage table, not a timeline

`stage_report._stage_timeline` produces eight rows, one per stage. The four
streams a run actually produces — stage transitions, hook events and behaviour
chains, network activity, artifacts — were never merged, so the sequence that
makes a case ("persistence written, then immediately an outbound connection")
had to be reconstructed by hand across four tables.

### 5. Nothing stored the result

Same gap the static engine had: `PipelineResult` was returned to the caller and
that was the end of it.

### 6. Twenty-nine stage tests had never executed  ← the one that mattered

`pytest.ini` sets `asyncio_mode = auto`, but `pytest-asyncio` was not
installed, so every async stage test errored at collection. Installing it
revealed **two genuine failures** that had been invisible since the tests were
written.

## The defect those tests were hiding

`StageOrchestrator` scaled its stage timeout by `time_scale`:

```python
timeout=config.hard_timeout_sec / self.time_scale
```

A stage's *waiting* compresses — that is what `time_scale` is for. Its *work*
does not: the input synthesizer still issues several hundred calls and each one
costs what it costs. At `time_scale=1000` a stage was given 50ms of wall clock
to do roughly a second of real work, so it was killed and recorded as
`TIMED_OUT`.

That reaches the dashboard as a stage that hung — instability, or an evasion
signal — when nothing of the sort happened. Every compressed run (CI, demos,
and the `quick` triage profile) was affected.

Fixed with a floor, so the timeout still does its actual job of catching a
genuinely wedged stage:

```python
return max(config.hard_timeout_sec / self.time_scale, MIN_STAGE_TIMEOUT_SEC)
```

All 43 stage tests pass.

## What was implemented

### `dynamic-sandbox/manager/`

| File | Contents |
|------|----------|
| `models.py` | `AnalysisJob` with full state history, `Sandbox`, failure states split three ways (failed / rejected / expired) |
| `intake.py` | Validation, streaming SHA-256, platform detection from bytes — never from the extension |
| `queue.py` | Priority with aging, content deduplication, per-platform depth, expiry |
| `pool.py` | Exclusive leasing, reversion gating, quarantine, abandoned-lease reclamation |
| `manager.py` | The run lifecycle, with teardown in `finally` |
| `results.py` | Atomic per-run JSON, indexed by sample hash |

Two invariants are enforced by the manager rather than trusted to callers:

**Nothing detonates on a guest that was not just reverted.** A failed restore
aborts the job before the sample is transferred. Findings from a dirty guest
are a mixture of two samples with no way to separate them afterwards.

**Every guest is released, whatever happened.** A leaked lease removes a guest
from the fleet permanently and silently. `release()` sends it to `REVERTING`;
only a confirmed revert returns it to service, and a failed post-run revert
takes it `OFFLINE`.

### `dynamic-sandbox/artifacts/`

Hash-chained custody: each artifact records the digest of the one before it, so
the manifest detects its own reordering or truncation. Re-registering the same
name with different bytes is refused rather than overwritten — losing the
original is the one failure that cannot be undone.

`memory.py` runs the Phase 1 static engine over captured images. The finding is
not "here are strings from memory" but the **difference**: indicators present
in the dump and absent from the file on disk are exactly what the sample kept
encrypted until it ran. When the static package is not installed on the
detonation plane, this reports `engine_unavailable` — never an empty result,
which would be indistinguishable from a clean dump.

### `dynamic-sandbox/timeline/`

Merges all four streams onto one axis, normalizing three different timestamp
conventions along the way. Two things are computed that no single stream can
produce:

**Correlation** — events within five seconds across different streams are
grouped, so a chain match, the connection it caused and the artifact that
captured it read as one moment.

**Silence** — a gap where nothing happened is evidence. Stage markers are
excluded from what counts as activity, because the pipeline announcing a stage
is the harness talking, not the sample; counting it would erase exactly the
silence being looked for.

## Bug caught by its own test

`TimelineBuilder.add_behavior_chains` pre-extracted `.value` from the severity
before passing it to the normalizer, so a chain whose severity arrived as a
plain string — after any JSON round-trip — was silently downgraded to `info`.
Critical behaviours would have vanished from the "significant events" list.

## Stale test script replaced

The root-level `test_sandbox_manager.py` was removed. Of its eight tests:

- **Five never executed.** They were gated behind `ORCHESTRATOR_AVAILABLE =
  False`, hardcoded because the script loaded package modules by file path via
  `importlib.util.spec_from_file_location` and relative imports then failed.
  One of them, `test_sandbox_orchestrator`, also caught `asyncio.TimeoutError`
  and returned success — so even had it run, a hung pipeline would have passed.
- **One asserted nothing.** `test_platform_determination` compared string
  literals to themselves (`assert "android" == "android"`). Real coverage now
  lives in `manager/test_manager.py::TestIntake`, which decides platform from
  the file's bytes.
- **Two had genuine coverage**, of `HealthMonitor` and `ResourceMonitor` — the
  only two modules in `dynamic-sandbox/stages/` without a test module.

Those two were ported to `stages/test_monitors.py` and extended from 2 tests to
50. The originals drove the monitors through real `asyncio.sleep` calls and
asserted on whatever the built-in randomized simulator happened to produce,
which made them slow and non-deterministic and only ever exercised the healthy
path. The ported tests drive the collection step directly and pin the
threshold bands, the status-precedence rules, the empty-state behaviour and
the alerting — in 0.22s rather than ~6s.

## Dead code removed from HealthMonitor

Writing the monitor tests surfaced `HealthMonitor._update_overall_status()`: it
computed the overall status in all three branches, assigned it to a local, and
returned nothing. It was called on every check pass, so it read as though it
maintained state while doing nothing at all.

Nothing depended on it — the live path is `_calculate_overall_status()`, called
on demand by `get_health_snapshot()` and `is_healthy()`. The method and its call
site were removed, along with an unused `timedelta` import in both
`health_monitor.py` and `resource_monitor.py`.

Two regression tests pin the behaviour so a cached variant cannot quietly
return: one changes a component's status with no intervening check pass and
asserts the snapshot reflects it, the other asserts the instance carries no
stored overall-status attribute at all.

## Testing

| Suite | Tests |
|-------|-------|
| `manager/test_manager.py` | 40 |
| `manager/test_integration.py` (real pipeline, mock guest) | 6 |
| `artifacts/test_artifacts.py` | 20 |
| `timeline/test_timeline.py` | 17 |
| `stages/test_stages.py` (now executing) | 43 |
| `stages/test_monitors.py` (ported and extended) | 52 |
| `hooks/` (Phase 6, unchanged) | 183 |
| **dynamic-sandbox total** | **361** |

The integration tests run the *real* `run_pipeline` against the scriptable mock
guest, so a signature change on either side fails here rather than in
production. The mock's activation condition is declared and the pipeline has to
discover it — a test that told the pipeline when the sample woke up would be
testing nothing.

## Verification

```bash
pip install pytest-asyncio
python -m pytest dynamic-sandbox -v
```

## Status

Complete. `pytest-asyncio` is now a required test dependency — without it the
async stage and manager suites do not run at all, and a suite that does not run
looks exactly like a suite that passes.
