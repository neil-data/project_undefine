"""Factory for the registry-compatible static APK analyzer."""

from static_analysis.apk.analyzer import ApkAnalyzer
from static_analysis.core.registry import AnalyzerRegistry
from static_analysis.detection.bootstrap import create_file_type_detector
from static_analysis.metadata.bootstrap import create_metadata_extractor
from static_analysis.strings.bootstrap import create_string_extractor


def create_apk_analyzer(analyzers: AnalyzerRegistry | None = None) -> ApkAnalyzer:
    """Assemble the APK analyzer from existing shared services."""
    metadata = create_metadata_extractor(analyzers=analyzers)
    return ApkAnalyzer(
        detector=create_file_type_detector(analyzers=analyzers),
        metadata_service=metadata,
        string_service=create_string_extractor(analyzers=analyzers),
    )
