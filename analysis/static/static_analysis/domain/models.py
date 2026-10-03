"""Analyzer-neutral report schema models.

These objects define the in-memory report contract only; serialization belongs to a
future delivery adapter.
"""

from dataclasses import dataclass, field
from datetime import datetime
from typing import Mapping, Sequence

from static_analysis.domain.enums import AnalysisStatus, Severity, TargetFormat


@dataclass(frozen=True, slots=True)
class AnalysisTarget:
    """A target supplied to an analyzer after a future intake layer identifies it."""

    reference: str
    declared_format: TargetFormat | None = None
    attributes: Mapping[str, str] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class AnalysisContext:
    """Execution-scoped inputs shared with analyzers without coupling to runtime code."""

    correlation_id: str
    requested_at: datetime
    options: Mapping[str, str] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class Evidence:
    """A source-locatable observation supporting a finding."""

    kind: str
    value: str
    location: str | None = None
    attributes: Mapping[str, str] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class Finding:
    """A normalized observation produced by an analyzer."""

    identifier: str
    title: str
    severity: Severity
    summary: str
    category: str | None = None
    evidence: Sequence[Evidence] = ()
    attributes: Mapping[str, str] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class AnalyzerOutcome:
    """The complete output contract of one analyzer invocation."""

    analyzer_id: str
    status: AnalysisStatus
    findings: Sequence[Finding] = ()
    artifacts: Sequence[Evidence] = ()
    warnings: Sequence[str] = ()
    attributes: Mapping[str, str] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class AnalyzerReportSection:
    """Provenance and outcome for a single report contributor."""

    analyzer_id: str
    analyzer_version: str
    outcome: AnalyzerOutcome


@dataclass(frozen=True, slots=True)
class AnalysisReport:
    """Root schema that future orchestration and serialization layers populate."""

    schema_version: str
    report_id: str
    status: AnalysisStatus
    target: AnalysisTarget
    created_at: datetime
    analyzer_sections: Sequence[AnalyzerReportSection] = ()
    warnings: Sequence[str] = ()
    attributes: Mapping[str, str] = field(default_factory=dict)
