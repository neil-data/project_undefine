"""Data contracts for YARA signature scanning."""

from dataclasses import dataclass, field
from enum import Enum

from static_analysis.detection.models import ConfidenceLevel
from static_analysis.domain.enums import Severity


class YaraStatus(str, Enum):
    """Why a scan produced the result it did — never silently 'no matches'."""

    COMPLETED = "completed"
    ENGINE_UNAVAILABLE = "engine_unavailable"   # yara-python not installed
    NO_RULES = "no_rules"                       # Rule directory empty or missing
    COMPILE_FAILED = "compile_failed"
    SCAN_FAILED = "scan_failed"


@dataclass(frozen=True, slots=True)
class YaraStringHit:
    """One matched string instance inside the sample."""

    identifier: str
    offset: int
    matched: str


@dataclass(frozen=True, slots=True)
class YaraMatch:
    """One rule that fired, with its curated metadata resolved."""

    rule_name: str
    namespace: str
    description: str
    severity: Severity
    confidence: ConfidenceLevel
    family: str = ""
    category: str = ""
    platform: str = ""
    mitre: tuple[str, ...] = ()
    tags: tuple[str, ...] = ()
    string_hits: tuple[YaraStringHit, ...] = ()

    @property
    def is_india_scam_rule(self) -> bool:
        """India-specific fraud signatures, reported as their own section."""
        return self.category == "india_scam" or self.namespace == "india_scam_rules"


@dataclass(frozen=True, slots=True)
class YaraScanResult:
    """Complete signature-scan outcome for one sample."""

    source: str
    status: YaraStatus
    matches: tuple[YaraMatch, ...] = ()
    rules_loaded: int = 0
    rule_files: tuple[str, ...] = ()
    error: str | None = None
    warnings: tuple[str, ...] = field(default_factory=tuple)

    @property
    def india_scam_matches(self) -> tuple[YaraMatch, ...]:
        return tuple(match for match in self.matches if match.is_india_scam_rule)

    @property
    def families(self) -> tuple[str, ...]:
        return tuple(sorted({match.family for match in self.matches if match.family}))

    @property
    def mitre_techniques(self) -> tuple[str, ...]:
        techniques: set[str] = set()
        for match in self.matches:
            techniques.update(match.mitre)
        return tuple(sorted(techniques))

    @property
    def highest_severity(self) -> Severity | None:
        order = (Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM,
                 Severity.LOW, Severity.INFO)
        for severity in order:
            if any(match.severity is severity for match in self.matches):
                return severity
        return None
