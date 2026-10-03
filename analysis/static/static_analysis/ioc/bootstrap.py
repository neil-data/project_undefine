"""Explicit assembly for the indicator extraction service."""

from static_analysis.ioc.extractor import StringIocExtractor


def create_ioc_extractor(max_indicators_per_type: int = 500) -> StringIocExtractor:
    """Create the default string-driven indicator extractor."""
    return StringIocExtractor(max_indicators_per_type=max_indicators_per_type)
