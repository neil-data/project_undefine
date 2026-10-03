"""Composition helper for the generic metadata extraction service."""

from static_analysis.core.registry import AnalyzerRegistry
from static_analysis.detection.bootstrap import create_file_type_detector
from static_analysis.hashing.bootstrap import create_hash_engine
from static_analysis.metadata.service import MetadataExtractionService


def create_metadata_extractor(analyzers: AnalyzerRegistry | None = None) -> MetadataExtractionService:
    """Assemble metadata extraction from the shared detector and hash engine."""
    return MetadataExtractionService(
        detector=create_file_type_detector(analyzers=analyzers),
        hasher=create_hash_engine(),
    )
