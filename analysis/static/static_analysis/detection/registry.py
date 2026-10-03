"""Extensible registry for file detector plugins."""

from collections.abc import Callable

from static_analysis.detection.contracts import FileDetector

DetectorFactory = Callable[[], FileDetector]


class DuplicateDetectorError(ValueError):
    """Raised when a detector identifier is registered more than once."""


class FileDetectorRegistry:
    """Maintains detector factories without coupling to a particular file format."""

    def __init__(self) -> None:
        self._factories: dict[str, DetectorFactory] = {}

    def register(self, factory: DetectorFactory) -> None:
        """Register a detector factory after validating its unique identifier."""
        detector = factory()
        if detector.identifier in self._factories:
            raise DuplicateDetectorError(f"Detector already registered: {detector.identifier}")
        self._factories[detector.identifier] = factory

    def detectors(self) -> tuple[FileDetector, ...]:
        """Create detectors in priority order with deterministic tie breaking."""
        created = [factory() for factory in self._factories.values()]
        return tuple(sorted(created, key=lambda item: (-item.priority, item.identifier)))
