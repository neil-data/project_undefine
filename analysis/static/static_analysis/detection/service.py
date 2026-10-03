"""Application service for detection and analyzer-registry integration."""

from collections.abc import Iterable
from pathlib import Path

from static_analysis.analyzers.base import Analyzer
from static_analysis.core.registry import AnalyzerRegistry
from static_analysis.detection.models import DetectionResult
from static_analysis.detection.registry import FileDetectorRegistry
from static_analysis.detection.source import BinarySource


class FileTypeDetectionService:
    """Coordinates signature detectors and maps recognized formats to analyzers."""

    def __init__(self, detectors: FileDetectorRegistry, analyzers: AnalyzerRegistry | None = None) -> None:
        self._detectors = detectors
        self._analyzers = analyzers

    def detect(self, path: str | Path) -> DetectionResult:
        """Classify a readable local file; unreadable or unsupported input is unknown."""
        source = BinarySource(Path(path))
        try:
            for detector in self._detectors.detectors():
                result = detector.detect(source)
                if result is not None:
                    return result
        except (OSError, ValueError):
            return DetectionResult.unknown()
        return DetectionResult.unknown()

    def candidate_analyzers(self, result: DetectionResult) -> Iterable[Analyzer]:
        """Return registered analyzers declared for a recognized target format."""
        if self._analyzers is None or result.target_format is None:
            return ()
        return self._analyzers.for_format(result.target_format)
