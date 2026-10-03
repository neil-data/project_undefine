"""Factory for the built-in detection service and its extensible registry."""

from static_analysis.core.registry import AnalyzerRegistry
from static_analysis.detection.detectors import ApkDetector, ElfDetector, MachODetector, PeDetector
from static_analysis.detection.registry import FileDetectorRegistry
from static_analysis.detection.service import FileTypeDetectionService


def create_file_type_detector(analyzers: AnalyzerRegistry | None = None) -> FileTypeDetectionService:
    """Assemble the built-in signature detectors without registering analyzers."""
    registry = FileDetectorRegistry()
    registry.register(ApkDetector)
    registry.register(PeDetector)
    registry.register(ElfDetector)
    registry.register(MachODetector)
    return FileTypeDetectionService(detectors=registry, analyzers=analyzers)
