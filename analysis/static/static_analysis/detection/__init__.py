"""Signature-based file type detection and analyzer selection."""

from static_analysis.detection.models import (
    Architecture,
    ConfidenceLevel,
    DetectedFileType,
    DetectionResult,
    FileFormat,
    Platform,
)
from static_analysis.detection.registry import FileDetectorRegistry
from static_analysis.detection.service import FileTypeDetectionService

__all__ = (
    "Architecture",
    "ConfidenceLevel",
    "DetectedFileType",
    "DetectionResult",
    "FileDetectorRegistry",
    "FileFormat",
    "FileTypeDetectionService",
    "Platform",
)
