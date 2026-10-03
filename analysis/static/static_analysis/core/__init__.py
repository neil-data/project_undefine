"""Composition and extension infrastructure."""

from static_analysis.core.engine import StaticAnalysisEngine
from static_analysis.core.registry import AnalyzerRegistry

__all__ = ("AnalyzerRegistry", "StaticAnalysisEngine")
