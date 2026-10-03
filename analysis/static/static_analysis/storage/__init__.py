"""Persistence for completed static analysis reports."""

from pathlib import Path

from static_analysis.storage.repository import AnalysisResultRepository


def create_result_repository(root: str | Path = "analysis_results") -> AnalysisResultRepository:
    """Create the default file-backed report repository."""
    return AnalysisResultRepository(root)


__all__ = ("AnalysisResultRepository", "create_result_repository")
