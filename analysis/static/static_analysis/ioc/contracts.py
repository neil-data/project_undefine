"""Abstract boundary for indicator extraction."""

from abc import ABC, abstractmethod
from collections.abc import Sequence

from static_analysis.ioc.models import IocExtractionResult
from static_analysis.strings.models import ExtractedString


class IocExtractor(ABC):
    """Derives actionable indicators from already-extracted strings."""

    @abstractmethod
    def extract(self, source: str, strings: Sequence[ExtractedString]) -> IocExtractionResult:
        """Return the deduplicated, classified indicator inventory for one sample."""
