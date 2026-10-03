# Multi-Stage Dynamic Analysis

Eight sequenced stages that defeat evasion-aware malware. A single-shot
detonation — run the sample for two minutes, dump the log — misses most modern
samples, because they are built specifically to outlast that.

## Why eight stages

Each stage exists to defeat one class of evasion:

| # | Stage | Defeats | Budget |
|---|-------|---------|--------|
| 1 | Boot | — (baseline + first contact) | 2 min |
| 2 | Idle | Time delay (isolates autonomous behavior) | 5 min |
| 3 | User Interaction | Interaction gating, environment checks | 4 min |
| 4 | Internet Simulation | Network gating | 5 min |
| 5 | Persistence Check | Reboot gating (enumerates footholds) | 2 min |
| 6 | Reboot | Reboot gating | 5 min |
| 7 | Long Execution | Time delay / sleep stalls | 30 min |
| 8 | Memory Dump | In-memory-only payloads | 10 min |

Standard profile total: ~63 minutes.

Stage 7's budget is 30 minutes because samples commonly stall 10–30 minutes
precisely to outlive sandboxes that give up at the 2–5 minute mark.

## The output that matters

The pipeline's headline result is **when the sample woke up**:

```python
result.activation_stage    # StageId.REBOOT
result.dormant_stages      # [BOOT, IDLE, USER_INTERACTION, INTERNET_SIMULATION]
result.evasion_profile     # [REBOOT_GATE, IN_MEMORY_ONLY]
```

"Silent through four stages, first activity after reboot" is a finding a
single-shot sandbox structurally cannot produce. It is also the sentence an
investigating officer can act on, because it explains why the device looked
clean when they first checked it.

## Usage

```python
from stages import run_pipeline, CapeSandboxController, render_markdown

result = await run_pipeline(
    analysis_id=analysis_id,
    platform="windows",
    sample_path="/samples/suspect.exe",
    controller=CapeSandboxController(base_url=..., task_id=...),
    profile_name="standard",
    redis_client=redis_client,   # streams stage markers to the live dashboard
    db_session=session,          # enables per-stage event attribution
)

print(render_markdown(result))
```

## Profiles

| Profile | Duration | Use |
|---------|----------|-----|
| `quick` | ~9 min | Bulk triage. **Skips reboot and long execution**, so it will miss reboot- and sleep-gated payloads. |
| `standard` | ~63 min | Default for casework. |
| `deep` | ~146 min | Samples that stayed dormant through a standard run. |
| `evidence` | ~63 min | All interventions disabled (no sleep patching, no adaptive network) for an unmodified timeline. |

## Testing without a hypervisor

`MockSandboxController` runs the entire pipeline with no VM. It is scriptable:
you describe how the fake sample behaves and assert that the pipeline
*discovers* that profile on its own.

```python
script = MockBehaviorScript(
    activates_after_reboot=True,
    requires_user_interaction=True,
)
result, _ = await run(script)
assert EvasionClass.REBOOT_GATE in result.evasion_profile
```

`time_scale` compresses wall-clock so a 63-minute pipeline runs in seconds
while keeping stage timing *ratios* intact. Practical ceiling is ~60x — past
that, fixed controller round-trip overhead no longer fits the scaled timeout.

```bash
pytest test_stages.py -v
```

## Two design decisions worth knowing

**Activity detection uses two independent signals.** A stage counts as active
if the DB event count crosses threshold *or* the stage action directly observed
behavior. Requiring both would mean any telemetry degradation reports the
sample as dormant — and a false "dormant" reads as "clean", which is the one
wrong answer this system cannot afford to give.

**Skipped stages are reported as blind spots, never as silence.** If Stage 6
did not run, the report states that reboot-gated behavior was not tested. A
partial run must never read as full coverage:

```python
report["coverage"]["complete_coverage"]        # False
report["coverage"]["untested_evasion_classes"] # [{reboot_gate, ...}]
report["coverage"]["caveat"]                   # explicit warning text
```

## Files

| File | Contents |
|------|----------|
| `stage_definitions.py` | Stage configs, profiles, result models |
| `stage_actions.py` | Per-stage guest operations |
| `stage_orchestrator.py` | Pipeline driver, evasion inference, live-stream markers |
| `controllers.py` | CAPE / Android / Mock controllers |
| `stage_report.py` | Structured report, Markdown, narrative-agent payload |
| `test_stages.py` | Test suite |

## Integration

Stage boundaries are published to `analysis:{id}:events` as `pipeline` events
(`stage_start` / `stage_end`), so the live dashboard renders a stage timeline
inline with raw events. `to_narrative_input()` produces a trimmed payload for
the LLM narrative agent — a small set of high-signal facts produces better
prose than the full event dump.
