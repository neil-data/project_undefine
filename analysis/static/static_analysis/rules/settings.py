"""Configurable, immutable scoring parameters for the rule engine.

Kept local to the `rules` package so the shared engine can be tuned without
modifying the existing top-level `config` module used by prior components.
"""

from dataclasses import dataclass, field
from typing import Mapping

from static_analysis.detection.models import ConfidenceLevel
from static_analysis.domain.enums import Severity

_DEFAULT_SEVERITY_WEIGHTS: Mapping[Severity, int] = {
    Severity.INFO: 2,
    Severity.LOW: 8,
    Severity.MEDIUM: 20,
    Severity.HIGH: 35,
    Severity.CRITICAL: 50,
}

_DEFAULT_CONFIDENCE_MULTIPLIERS: Mapping[ConfidenceLevel, float] = {
    ConfidenceLevel.HIGH: 1.0,
    ConfidenceLevel.MEDIUM: 0.7,
    ConfidenceLevel.LOW: 0.4,
    ConfidenceLevel.NONE: 0.0,
}

_DEFAULT_BAND_THRESHOLDS: tuple[tuple[int, Severity], ...] = (
    (80, Severity.CRITICAL),
    (55, Severity.HIGH),
    (30, Severity.MEDIUM),
    (10, Severity.LOW),
    (0, Severity.INFO),
)


@dataclass(frozen=True, slots=True)
class RuleEngineSettings:
    """Weights and thresholds controlling how matches accumulate into a score."""

    severity_weights: Mapping[Severity, int] = field(default_factory=lambda: dict(_DEFAULT_SEVERITY_WEIGHTS))
    confidence_multipliers: Mapping[ConfidenceLevel, float] = field(
        default_factory=lambda: dict(_DEFAULT_CONFIDENCE_MULTIPLIERS)
    )
    band_thresholds: tuple[tuple[int, Severity], ...] = _DEFAULT_BAND_THRESHOLDS
    max_score: int = 100

    def __post_init__(self) -> None:
        if self.max_score < 1:
            raise ValueError("max_score must be positive")
        if not self.band_thresholds:
            raise ValueError("band_thresholds cannot be empty")

    def weight_for(self, severity: Severity, confidence: ConfidenceLevel) -> float:
        """Return the score contribution for one matched rule."""
        base = self.severity_weights.get(severity, 0)
        multiplier = self.confidence_multipliers.get(confidence, 0.0)
        return base * multiplier

    def band_for(self, value: int) -> Severity:
        """Return the qualitative severity band for a computed score."""
        for threshold, severity in sorted(self.band_thresholds, key=lambda item: -item[0]):
            if value >= threshold:
                return severity
        return Severity.INFO
