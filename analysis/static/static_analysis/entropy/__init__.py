"""Whole-file, windowed and container-member byte-entropy analysis."""

from static_analysis.entropy.bootstrap import create_entropy_analyzer
from static_analysis.entropy.models import (
    EmbeddedBlob,
    EntropyClass,
    EntropyRegion,
    EntropyResult,
    EntropyStatus,
    EntropyWindow,
)
from static_analysis.entropy.service import (
    EntropyAnalysisService,
    classify_entropy,
    shannon_entropy,
)

__all__ = (
    "EmbeddedBlob",
    "EntropyAnalysisService",
    "EntropyClass",
    "EntropyRegion",
    "EntropyResult",
    "EntropyStatus",
    "EntropyWindow",
    "classify_entropy",
    "create_entropy_analyzer",
    "shannon_entropy",
)
