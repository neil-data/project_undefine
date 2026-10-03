"""
test_timeline.py — The merged account of a run.

Two things are being verified, and only the second is obvious.

**Ordering across streams.** Stage transitions, behaviour chains, network
activity and artifacts arrive from four sources with four notions of time.
They must end up on one axis, in the right order, whatever shape their
timestamps had.

**Silence.** A gap where nothing happened is evidence — forty minutes of
nothing followed by a burst at reboot is a gated payload, and it is only
visible once every stream is on the same axis. Stage markers are deliberately
excluded from what counts as activity: the pipeline announcing a stage is the
harness talking, not the sample, and counting it would erase exactly the
silence being looked for.

Run:
    pytest dynamic-sandbox/timeline/test_timeline.py -v
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from timeline import EventSeverity, EventSource, TimelineBuilder, TimelineEvent

BASE = datetime(2026, 3, 1, 14, 0, 0, tzinfo=timezone.utc)


def at(seconds: float) -> datetime:
    return BASE + timedelta(seconds=seconds)


class FakeStage:
    def __init__(self, stage_id, started_at, activity=False, findings=(), artifacts=()):
        self.stage_id = stage_id
        self.started_at = started_at
        self.activity_detected = activity
        self.findings = list(findings)
        self.artifacts = list(artifacts)
        self.status = "completed"
        self.event_count = 12


class FakeFinding:
    def __init__(self, title, observed_at, severity="warning", mitre=()):
        self.title = title
        self.detail = f"{title} detail"
        self.observed_at = observed_at
        self.severity = severity
        self.mitre_techniques = list(mitre)


class FakeArtifact:
    def __init__(self, artifact_type, path, captured_at):
        self.artifact_type = artifact_type
        self.path = path
        self.captured_at = captured_at
        self.sha256 = "a" * 64


class FakeChain:
    def __init__(self, name, completed_at, severity="critical", stage_id=None):
        self.name = name
        self.description = f"{name} was observed"
        self.severity = severity
        self.completed_at = completed_at
        self.stage_id = stage_id
        self.mitre = ["T1055.002"]
        self.api_sequence = ["VirtualAlloc", "NtWriteVirtualMemory"]
        self.pid = 4242
        self.evidence = {"target_pid": 9001}


@pytest.fixture
def builder():
    return TimelineBuilder("analysis-1")


# ============================================================================
# Merging and ordering
# ============================================================================

class TestMerging:

    def test_streams_land_on_one_axis_in_order(self, builder):
        builder.add_stage_results([FakeStage("boot", at(0))])
        builder.add_behavior_chains([FakeChain("Process injection", at(30))])
        builder.add_network_events([{"timestamp": at(20), "destination": "45.13.223.9"}])

        events = builder.build()["events"]
        assert [e["source"] for e in events] == ["stage", "network", "behavior_chain"]

    def test_mixed_timestamp_formats_are_normalized(self, builder):
        """Each stream reports time in whatever shape it has."""
        builder.add_network_events([
            {"timestamp": at(10).isoformat(), "destination": "a.test"},
            {"timestamp": at(5), "destination": "b.test"},
            {"timestamp": at(1).timestamp(), "destination": "c.test"},
        ])
        titles = [e["title"] for e in builder.build()["events"]]
        assert titles[0].endswith("c.test")
        assert titles[-1].endswith("a.test")

    def test_naive_timestamps_are_treated_as_utc(self, builder):
        """The hook engine records naive UTC; comparing it must not raise."""
        naive = datetime(2026, 3, 1, 14, 0, 30)
        builder.add_behavior_chains([FakeChain("Injection", naive)])
        assert builder.build()["event_count"] == 1

    def test_findings_and_artifacts_come_through_the_stage_stream(self, builder):
        builder.add_stage_results([FakeStage(
            "reboot", at(0), activity=True,
            findings=[FakeFinding("Persistence installed", at(48), mitre=["T1547.001"])],
            artifacts=[FakeArtifact("memdump", "/evidence/mem.raw", at(51))],
        )])

        sources = {e["source"] for e in builder.build()["events"]}
        assert sources == {"stage", "finding", "artifact"}

    def test_raw_api_calls_are_excluded_unless_part_of_a_chain(self, builder):
        """A raw call stream buries four significant events in ten thousand."""
        class Call:
            def __init__(self, chained):
                self.part_of_chain = chained
                self.timestamp = at(5)
                self.api_name = "VirtualAlloc"
                self.decoded_args = {}
                self.stage_id = "boot"
                self.pid = 1
                self.mitre = []

        builder.add_api_calls([Call(False), Call(True), Call(False)])
        assert builder.build()["event_count"] == 1


# ============================================================================
# Correlation
# ============================================================================

class TestCorrelation:

    def test_near_simultaneous_cross_stream_events_group(self, builder):
        builder.add_behavior_chains([FakeChain("Persistence", at(100))])
        builder.add_network_events([{"timestamp": at(101), "destination": "45.13.223.9"}])
        builder.add_stage_results([FakeStage(
            "reboot", at(0),
            artifacts=[FakeArtifact("memdump", "/e/mem.raw", at(102))],
        )])

        events = builder.build()["events"]
        groups = {e["title"]: e["group"] for e in events}
        assert groups["Persistence"] == groups["Outbound connection to 45.13.223.9"]
        assert groups["memdump captured"] == groups["Persistence"]

    def test_distant_events_are_separate_groups(self, builder):
        builder.add_behavior_chains([
            FakeChain("First", at(0)),
            FakeChain("Second", at(600)),
        ])
        events = builder.build()["events"]
        assert events[0]["group"] != events[1]["group"]


# ============================================================================
# Silence
# ============================================================================

class TestGaps:

    def test_long_silence_is_reported(self, builder):
        builder.add_behavior_chains([
            FakeChain("Initial probe", at(10), severity="info"),
            FakeChain("Payload activated", at(2400), stage_id="reboot"),
        ])
        result = builder.build()

        assert result["gaps"]
        gap = result["gaps"][0]
        assert gap["duration_sec"] == pytest.approx(2390, abs=1)
        assert gap["following_stage"] == "reboot"
        assert "short automated analysis" in gap["interpretation"]

    def test_stage_markers_do_not_fill_a_gap(self, builder):
        """
        The pipeline announcing stages is the harness talking. Counting it as
        activity would erase the silence the gap analysis exists to find.
        """
        builder.add_behavior_chains([
            FakeChain("Early", at(0)),
            FakeChain("Late", at(3000)),
        ])
        builder.add_stage_results([
            FakeStage("idle", at(600)),
            FakeStage("interaction", at(1200)),
            FakeStage("reboot", at(1800)),
        ])
        assert builder.build()["gaps"]

    def test_continuous_activity_produces_no_gap(self, builder):
        builder.add_behavior_chains([FakeChain(f"Event {i}", at(i * 10))
                                     for i in range(10)])
        assert builder.build()["gaps"] == []


# ============================================================================
# Output
# ============================================================================

class TestOutput:

    def test_significant_events_are_pulled_out(self, builder):
        builder.add_behavior_chains([
            FakeChain("Injection", at(10), severity="critical"),
            FakeChain("Library load", at(20), severity="low"),
        ])
        significant = builder.build()["significant"]
        assert [e["title"] for e in significant] == ["Injection"]

    def test_counts_by_source_and_severity(self, builder):
        builder.add_stage_results([FakeStage("boot", at(0))])
        builder.add_behavior_chains([FakeChain("Injection", at(10))])
        result = builder.build()

        assert result["by_source"] == {"stage": 1, "behavior_chain": 1}
        assert result["by_severity"]["critical"] == 1

    def test_summary_names_when_the_sample_woke_up(self, builder):
        builder.add_stage_results([FakeStage("boot", at(0))])
        builder.add_behavior_chains([
            FakeChain("Process injection", at(2400), stage_id="reboot"),
        ])
        summary = builder.build()["summary"]

        assert "Process injection" in summary
        assert "reboot" in summary

    def test_empty_run_says_so_without_implying_safety(self, builder):
        summary = builder.build()["summary"]
        assert "did not execute" in summary or "gated" in summary

    def test_duration_spans_first_to_last(self, builder):
        builder.add_behavior_chains([
            FakeChain("First", at(0)),
            FakeChain("Last", at(900)),
        ])
        assert builder.build()["duration_sec"] == pytest.approx(900, abs=1)

    def test_output_is_json_serializable(self, builder):
        import json

        builder.add_stage_results([FakeStage(
            "reboot", at(0), activity=True,
            findings=[FakeFinding("Persistence", at(10))],
        )])
        builder.add_behavior_chains([FakeChain("Injection", at(20))])
        assert json.loads(json.dumps(builder.build(), default=str))

    def test_custom_events_can_be_added_directly(self, builder):
        builder.add(TimelineEvent(
            at=at(5), source=EventSource.NETWORK,
            title="DNS resolution", severity=EventSeverity.MEDIUM,
        ))
        assert builder.build()["event_count"] == 1
