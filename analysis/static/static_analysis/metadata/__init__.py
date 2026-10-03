"""Generic file metadata extraction composed from shared engine services."""

from static_analysis.metadata.models import MetadataFailure, MetadataResult, MetadataStatus
from static_analysis.metadata.service import MetadataExtractionService

__all__ = ("MetadataExtractionService", "MetadataFailure", "MetadataResult", "MetadataStatus")
