"""Extension contracts for independently deployable signature detectors."""

from abc import ABC, abstractmethod

from static_analysis.detection.models import DetectionResult
from static_analysis.detection.source import BinarySource


class FileDetector(ABC):
    """A detector that recognizes one binary family from its canonical signatures."""

    @property
    @abstractmethod
    def identifier(self) -> str:
        """Return the stable detector identifier used for provenance."""

    @property
    def priority(self) -> int:
        """Higher-priority detectors are evaluated first."""
        return 0

    @abstractmethod
    def detect(self, source: BinarySource) -> DetectionResult | None:
        """Return a classification, or None if the signature is not recognized."""
