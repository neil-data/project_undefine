"""Explicit assembly for the entropy analysis service."""

from static_analysis.entropy.models import PACKED_FLOOR
from static_analysis.entropy.service import EntropyAnalysisService


def create_entropy_analyzer(
    window_size: int = 8192,
    high_entropy_threshold: float = PACKED_FLOOR,
) -> EntropyAnalysisService:
    """Create the default entropy analyzer."""
    return EntropyAnalysisService(
        window_size=window_size,
        high_entropy_threshold=high_entropy_threshold,
    )
