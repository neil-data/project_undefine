"""Service contract for reusable string extraction."""

from pathlib import Path
from typing import Protocol

from static_analysis.metadata.models import MetadataResult
from static_analysis.strings.models import StringExtractionResult


class StringExtractionServiceContract(Protocol):
    """Extracts encoded strings and indicators from a local binary source."""

    def extract(
        self, path: str | Path, metadata: MetadataResult | None = None
    ) -> StringExtractionResult:
        """Return extracted values, optionally reusing existing metadata."""
