"""Public package boundary for the static analysis engine foundation."""

from static_analysis.bootstrap import create_engine
from static_analysis.core.engine import StaticAnalysisEngine

__all__ = ("StaticAnalysisEngine", "create_engine")
