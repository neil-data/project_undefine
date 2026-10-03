"""
builder.py — One chronological account of the run.

WHY MERGE AT ALL
----------------
The run produces four separate streams: stage transitions, API hook events and
the behaviour chains built from them, network activity, and captured
artifacts. Each is readable on its own and none of them answers the question
an investigator actually asks, which is *what happened, in what order*.

The answer only exists across streams:

    14:02:11  reboot stage begins
    14:02:48  persistence entry written to Run key
    14:02:49  first outbound connection to 45.13.223.9
    14:02:51  memory dump captured

Those four lines are one event. Split across four tables they are four
unrelated facts, and the causal link — the sample armed itself at reboot and
immediately called home — has to be reconstructed by hand.

THE TWO THINGS THIS COMPUTES
----------------------------
**Correlation.** Events within a few seconds of each other, across different
streams, are grouped: a chain match, the network connection it caused and the
artifact that captured it belong together.

**Silence.** A gap where nothing happened is evidence in its own right. Forty
minutes of silence followed by a burst at reboot is the signature of a gated
payload, and it is only visible once every stream is on one axis.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Any, Dict, Iterable, List, Optional

_LOGGER = logging.getLogger(__name__)

# Events from different streams within this window describe one moment.
CORRELATION_WINDOW_SEC = 5.0

# Silence longer than this is worth naming in the report.
NOTABLE_GAP_SEC = 120.0


class EventSource(str, Enum):
    """Which stream an entry came from."""

    STAGE = "stage"
    API_CALL = "api_call"
    BEHAVIOR_CHAIN = "behavior_chain"
    NETWORK = "network"
    ARTIFACT = "artifact"
    FINDING = "finding"


class EventSeverity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


_SEVERITY_RANK = {
    EventSeverity.CRITICAL: 4, EventSeverity.HIGH: 3, EventSeverity.MEDIUM: 2,
    EventSeverity.LOW: 1, EventSeverity.INFO: 0,
}


def _as_utc(value: Any) -> datetime:
    """Normalize whatever a stream reports into one comparable instant."""
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    if isinstance(value, str):
        try:
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
            return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)
        except ValueError:
            pass
    if isinstance(value, (int, float)):
        return datetime.fromtimestamp(value, tz=timezone.utc)
    return datetime.now(timezone.utc)


@dataclass
class TimelineEvent:
    """One thing that happened, from whichever stream saw it."""

    at: datetime
    source: EventSource
    title: str
    detail: str = ""
    severity: EventSeverity = EventSeverity.INFO

    stage_id: Optional[str] = None
    mitre: List[str] = field(default_factory=list)
    evidence: Dict[str, Any] = field(default_factory=dict)

    # Filled by the builder: index of the correlation group this belongs to.
    group: Optional[int] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "at": self.at.isoformat(),
            "source": self.source.value,
            "title": self.title,
            "detail": self.detail,
            "severity": self.severity.value,
            "stage_id": self.stage_id,
            "mitre": list(self.mitre),
            "evidence": self.evidence,
            "group": self.group,
        }


@dataclass
class TimelineGap:
    """A stretch where the sample did nothing."""

    start: datetime
    end: datetime
    duration_sec: float
    preceding_stage: Optional[str] = None
    following_stage: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "start": self.start.isoformat(),
            "end": self.end.isoformat(),
            "duration_sec": round(self.duration_sec, 1),
            "preceding_stage": self.preceding_stage,
            "following_stage": self.following_stage,
            "interpretation": self.interpretation,
        }

    @property
    def interpretation(self) -> str:
        minutes = int(self.duration_sec // 60)
        return (
            f"The sample did nothing observable for {minutes} minute(s)"
            + (f", then acted once the {self.following_stage} stage began"
               if self.following_stage else "")
            + ". Silence of this length before activity is how a sample avoids "
              "short automated analysis — a three-minute sandbox run would have "
              "recorded nothing at all."
        )


class TimelineBuilder:
    """Collects events from every stream and produces one ordered account."""

    def __init__(self, analysis_id: str) -> None:
        self.analysis_id = analysis_id
        self._events: List[TimelineEvent] = []

    # -- ingestion ---------------------------------------------------------

    def add(self, event: TimelineEvent) -> None:
        self._events.append(event)

    def add_stage_results(self, stage_results: Iterable[Any]) -> None:
        """Stage boundaries — the frame everything else is read against."""
        for result in stage_results:
            stage_id = getattr(getattr(result, "stage_id", None), "value", None) or str(
                getattr(result, "stage_id", "")
            )
            started = getattr(result, "started_at", None)
            if started is None:
                continue

            status = getattr(getattr(result, "status", None), "value", "")
            activity = bool(getattr(result, "activity_detected", False))
            self.add(TimelineEvent(
                at=_as_utc(started),
                source=EventSource.STAGE,
                title=f"Stage '{stage_id}' began",
                detail=(
                    f"Status {status}; "
                    + ("the sample was active during this stage."
                       if activity else "the sample stayed silent through it.")
                ),
                stage_id=stage_id,
                evidence={"event_count": getattr(result, "event_count", 0)},
            ))

            for finding in getattr(result, "findings", []) or []:
                self.add(TimelineEvent(
                    at=_as_utc(getattr(finding, "observed_at", started)),
                    source=EventSource.FINDING,
                    title=getattr(finding, "title", "Finding"),
                    detail=getattr(finding, "detail", ""),
                    severity=self._severity(getattr(finding, "severity", "info")),
                    stage_id=stage_id,
                    mitre=list(getattr(finding, "mitre_techniques", []) or []),
                ))

            for artifact in getattr(result, "artifacts", []) or []:
                self.add(TimelineEvent(
                    at=_as_utc(getattr(artifact, "captured_at", started)),
                    source=EventSource.ARTIFACT,
                    title=f"{getattr(artifact, 'artifact_type', 'artifact')} captured",
                    detail=str(getattr(artifact, "path", "")),
                    stage_id=stage_id,
                    evidence={"sha256": getattr(artifact, "sha256", None)},
                ))

    def add_behavior_chains(self, chains: Iterable[Any]) -> None:
        """Named behaviours from the hook engine — the strongest entries here."""
        for chain in chains:
            # `_severity` already unwraps an enum; pre-extracting `.value` here
            # meant a chain whose severity arrived as a plain string — after a
            # JSON round-trip, say — was silently downgraded to info.
            severity = self._severity(getattr(chain, "severity", "info"))
            self.add(TimelineEvent(
                at=_as_utc(getattr(chain, "completed_at", None)),
                source=EventSource.BEHAVIOR_CHAIN,
                title=getattr(chain, "name", "Behaviour"),
                detail=getattr(chain, "description", ""),
                severity=severity,
                stage_id=getattr(chain, "stage_id", None),
                mitre=list(getattr(chain, "mitre", []) or []),
                evidence={
                    "api_sequence": list(getattr(chain, "api_sequence", []) or []),
                    "pid": getattr(chain, "pid", None),
                    **(getattr(chain, "evidence", {}) or {}),
                },
            ))

    def add_api_calls(self, calls: Iterable[Any], only_chained: bool = True) -> None:
        """
        Individual API calls.

        Defaults to chain members only. A raw call stream is tens of thousands
        of lines and burying four significant events in it is how a timeline
        stops being read.
        """
        for call in calls:
            if only_chained and not getattr(call, "part_of_chain", False):
                continue
            self.add(TimelineEvent(
                at=_as_utc(getattr(call, "timestamp", None)),
                source=EventSource.API_CALL,
                title=getattr(call, "api_name", "API call"),
                detail=str(getattr(call, "decoded_args", {}) or {})[:200],
                severity=EventSeverity.INFO,
                stage_id=getattr(call, "stage_id", None),
                mitre=list(getattr(call, "mitre", []) or []),
                evidence={"pid": getattr(call, "pid", None)},
            ))

    def add_network_events(self, events: Iterable[Dict[str, Any]]) -> None:
        """Connections, resolutions and requests observed on the wire."""
        for event in events:
            destination = event.get("destination") or event.get("host") or event.get("ip", "")
            self.add(TimelineEvent(
                at=_as_utc(event.get("timestamp")),
                source=EventSource.NETWORK,
                title=event.get("title") or f"Outbound connection to {destination}",
                detail=event.get("detail", ""),
                severity=self._severity(event.get("severity", "medium")),
                stage_id=event.get("stage_id"),
                evidence={
                    key: event[key]
                    for key in ("destination", "port", "protocol", "bytes", "domain")
                    if key in event
                },
            ))

    # -- output ------------------------------------------------------------

    def build(self) -> Dict[str, Any]:
        """Produce the ordered, grouped, gap-annotated account."""
        events = sorted(self._events, key=lambda e: (e.at, e.source.value, e.title))
        self._group(events)
        gaps = self._gaps(events)

        return {
            "analysis_id": self.analysis_id,
            "event_count": len(events),
            "events": [event.to_dict() for event in events],
            "gaps": [gap.to_dict() for gap in gaps],
            "first_event_at": events[0].at.isoformat() if events else None,
            "last_event_at": events[-1].at.isoformat() if events else None,
            "duration_sec": (
                round((events[-1].at - events[0].at).total_seconds(), 1) if events else 0.0
            ),
            "by_source": self._count_by(events, lambda e: e.source.value),
            "by_severity": self._count_by(events, lambda e: e.severity.value),
            "significant": [
                event.to_dict() for event in events
                if _SEVERITY_RANK[event.severity] >= _SEVERITY_RANK[EventSeverity.HIGH]
            ],
            "summary": self._summary(events, gaps),
        }

    @staticmethod
    def _group(events: List[TimelineEvent]) -> None:
        """Number bursts of near-simultaneous cross-stream activity."""
        group = 0
        window = timedelta(seconds=CORRELATION_WINDOW_SEC)
        for index, event in enumerate(events):
            if index > 0 and (event.at - events[index - 1].at) > window:
                group += 1
            event.group = group

    @staticmethod
    def _gaps(events: List[TimelineEvent]) -> List[TimelineGap]:
        """
        Find stretches of silence worth reporting.

        Stage markers are excluded from what counts as activity: the pipeline
        announcing a new stage is the harness talking, not the sample, and
        counting it would erase exactly the silence being looked for.
        """
        activity = [e for e in events if e.source is not EventSource.STAGE]
        gaps: List[TimelineGap] = []

        for previous, current in zip(activity, activity[1:]):
            seconds = (current.at - previous.at).total_seconds()
            if seconds < NOTABLE_GAP_SEC:
                continue
            gaps.append(TimelineGap(
                start=previous.at,
                end=current.at,
                duration_sec=seconds,
                preceding_stage=previous.stage_id,
                following_stage=current.stage_id,
            ))
        return gaps

    @staticmethod
    def _count_by(events: List[TimelineEvent], key) -> Dict[str, int]:
        counts: Dict[str, int] = {}
        for event in events:
            value = key(event)
            counts[value] = counts.get(value, 0) + 1
        return counts

    @staticmethod
    def _summary(events: List[TimelineEvent], gaps: List[TimelineGap]) -> str:
        if not events:
            return (
                "Nothing was observed during the run. The sample either did not "
                "execute or is gated on a condition the pipeline did not provide."
            )

        significant = [e for e in events
                       if _SEVERITY_RANK[e.severity] >= _SEVERITY_RANK[EventSeverity.HIGH]]
        first_significant = significant[0] if significant else None

        parts = [f"{len(events)} events were recorded across the run."]

        if first_significant is not None:
            elapsed = (first_significant.at - events[0].at).total_seconds()
            stage = first_significant.stage_id or "the run"
            parts.append(
                f"The first serious behaviour — {first_significant.title} — appeared "
                f"{int(elapsed // 60)} minute(s) in, during {stage}."
            )
        else:
            parts.append("No behaviour rose above routine activity.")

        if gaps:
            longest = max(gaps, key=lambda gap: gap.duration_sec)
            parts.append(
                f"The longest period of silence lasted "
                f"{int(longest.duration_sec // 60)} minute(s)"
                + (f" and ended when the {longest.following_stage} stage began."
                   if longest.following_stage else ".")
            )

        return " ".join(parts)

    @staticmethod
    def _severity(value: Any) -> EventSeverity:
        text = str(getattr(value, "value", value)).lower()
        mapping = {
            "critical": EventSeverity.CRITICAL,
            "high": EventSeverity.HIGH,
            "warning": EventSeverity.HIGH,
            "medium": EventSeverity.MEDIUM,
            "low": EventSeverity.LOW,
            "info": EventSeverity.INFO,
        }
        return mapping.get(text, EventSeverity.INFO)
