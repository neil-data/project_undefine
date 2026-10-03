"""Structured outputs for the shared, format-agnostic rule engine."""

from dataclasses import dataclass, field
from enum import Enum
from typing import Mapping

from static_analysis.detection.models import ConfidenceLevel
from static_analysis.domain.enums import Severity
from static_analysis.strings.models import ExtractedString


class RuleCategory(str, Enum):
    """Closed vocabulary describing what aspect of a target a rule inspects."""

    SUSPICIOUS_IMPORT = "suspicious_import"
    DANGEROUS_PERMISSION = "dangerous_permission"
    HIGH_ENTROPY = "high_entropy"
    PACKED_BINARY = "packed_binary"
    SUSPICIOUS_STRING = "suspicious_string"
    NETWORK_INDICATOR = "network_indicator"
    EXECUTABLE_WRITABLE_SECTION = "executable_writable_section"
    UNSIGNED_BINARY = "unsigned_binary"
    SUSPICIOUS_METADATA = "suspicious_metadata"


@dataclass(frozen=True, slots=True)
class RuleContext:
    """Analyzer-neutral facts a format-specific analyzer normalizes for evaluation.

    Every field is optional so that PE, APK, ELF, Mach-O, or any future analyzer can
    populate only the facts it is able to compute without the engine knowing about
    any format-specific model.
    """

    analyzer_id: str
    suspicious_apis: tuple[str, ...] = ()
    dangerous_permissions: tuple[str, ...] = ()
    strings: tuple[ExtractedString, ...] = ()
    section_entropies: Mapping[str, float] = field(default_factory=dict)
    high_entropy_threshold: float = 7.2
    executable_writable_sections: tuple[str, ...] = ()
    suspicious_section_names: tuple[str, ...] = ()
    is_stripped: bool = False
    is_signed: bool | None = None
    packed_indicators: tuple[str, ...] = ()
    suspicious_metadata: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class RuleMatch:
    """A single rule that fired against a `RuleContext`."""

    rule_id: str
    title: str
    category: RuleCategory
    severity: Severity
    confidence: ConfidenceLevel
    description: str
    evidence: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class RiskScore:
    """A bounded, explainable aggregate score derived from matched rules."""

    value: int
    band: Severity
    contributing_rules: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if not 0 <= self.value <= 100:
            raise ValueError("Risk score value must be between 0 and 100")


@dataclass(frozen=True, slots=True)
class RuleEngineResult:
    """Complete rule-evaluation output for one analyzed target."""

    matches: tuple[RuleMatch, ...]
    risk_score: RiskScore
