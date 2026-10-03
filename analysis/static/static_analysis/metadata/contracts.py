"""Reusable metadata extraction service contract."""

from pathlib import Path
from typing import Protocol

from static_analysis.metadata.models import MetadataResult


class MetadataService(Protocol):
    """Extracts generic metadata without performing format-specific analysis."""

    def extract(self, path: str | Path) -> MetadataResult:
        """Return one structured metadata result for the requested local file."""
