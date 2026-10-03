# Unified Timeline

Merges the four streams a run produces into one chronological account.

## Why merge

The run produces stage transitions, API hook events and the behaviour chains
built from them, network activity, and captured artifacts. Each is readable
alone; none of them answers the question an investigator actually asks, which
is *what happened, in what order*.

The answer only exists across streams:

```
14:02:11  reboot stage begins
14:02:48  persistence entry written to Run key
14:02:49  first outbound connection to 45.13.223.9
14:02:51  memory dump captured
```

Those four lines are one event. Split across four tables they are four
unrelated facts, and the causal link — the sample armed itself at reboot and
immediately called home — has to be reconstructed by hand.

## What it computes

**Correlation.** Events within five seconds of each other across different
streams are grouped, so a chain match, the connection it caused and the
artifact that captured it read as one moment rather than three coincidences.

**Silence.** A gap where nothing happened is evidence in its own right. Forty
minutes of nothing followed by a burst at reboot is a gated payload — and it
is only visible once every stream is on one axis.

Stage markers are deliberately excluded from what counts as activity. The
pipeline announcing a new stage is the harness talking, not the sample;
counting it as activity would erase exactly the silence being looked for.

## Usage

```python
from timeline import TimelineBuilder

builder = TimelineBuilder(str(analysis_id))
builder.add_stage_results(result.stage_results)
builder.add_behavior_chains(hook_monitor.engine.chains)
builder.add_network_events(network_events)

timeline = builder.build()
timeline["significant"]   # HIGH and CRITICAL only
timeline["gaps"]          # silence worth naming
timeline["summary"]       # one paragraph, no jargon
```

## Notes

Raw API calls default to chain members only. A raw call stream is tens of
thousands of lines, and burying four significant events in it is how a timeline
stops being read.

Timestamps arrive in three conventions — `datetime`, ISO string, POSIX float —
and naive values are treated as UTC, which is what the hook engine records.
