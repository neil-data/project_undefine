"""Abstract contracts implemented by future analyzer plugins."""

from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import FrozenSet

from static_analysis.domain.enums import TargetFormat
from static_analysis.domain.models import AnalysisContext, AnalysisTarget, AnalyzerOutcome


@dataclass(frozen=True, slots=True)
class AnalyzerDescriptor:
    """Static, inspectable metadata used by the registry and orchestrator."""

    identifier: str
    version: str
    supported_formats: FrozenSet[TargetFormat]
    description: str = ""

    def __post_init__(self) -> None:
        if not self.identifier:
            raise ValueError("Analyzer identifier cannot be empty")
        if not self.version:
            raise ValueError("Analyzer version cannot be empty")
        if not self.supported_formats:
            raise ValueError("An analyzer must declare a supported format")


class Analyzer(ABC):
    """Format-specific extension point; implementations own all analysis behavior."""

    @property
    @abstractmethod
    def descriptor(self) -> AnalyzerDescriptor:
        """Return immutable metadata for this analyzer."""

    @abstractmethod
    def supports(self, target: AnalysisTarget) -> bool:
        """State whether this analyzer accepts an already-classified target."""

    @abstractmethod
    def analyze(self, target: AnalysisTarget, context: AnalysisContext) -> AnalyzerOutcome:
        """Produce one normalized outcome for a supported target."""
