"""Composition helper for the shared string extraction service."""

from static_analysis.core.registry import AnalyzerRegistry
from static_analysis.metadata.bootstrap import create_metadata_extractor
from static_analysis.strings.service import StringExtractionService


def create_string_extractor(
    analyzers: AnalyzerRegistry | None = None,
    minimum_length: int = 4,
    chunk_size: int = 1024 * 1024,
) -> StringExtractionService:
    """Assemble a generic extractor over the existing metadata composition root."""
    return StringExtractionService(
        metadata_service=create_metadata_extractor(analyzers=analyzers),
        minimum_length=minimum_length,
        chunk_size=chunk_size,
    )
