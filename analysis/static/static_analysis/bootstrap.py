"""Explicit assembly functions for dependency injection at application boundaries."""

from pathlib import Path

from static_analysis.config.settings import EngineSettings
from static_analysis.core.engine import StaticAnalysisEngine
from static_analysis.core.registry import AnalyzerRegistry
from static_analysis.storage.repository import AnalysisResultRepository


def create_engine(
    settings: EngineSettings | None = None,
    results_directory: str | Path | None = None,
    rules_directory: str | Path | None = None,
) -> StaticAnalysisEngine:
    """
    Assemble the complete static analysis engine.

    `results_directory` is optional: pass it to persist every report, omit it
    for one-off runs and tests that only want the returned document.
    """
    effective_settings = settings or EngineSettings()
    repository = (
        AnalysisResultRepository(results_directory) if results_directory is not None else None
    )

    scanner = None
    if rules_directory is not None:
        from static_analysis.yara_scan.bootstrap import create_yara_scanner

        scanner = create_yara_scanner(rules_directory)

    return StaticAnalysisEngine(
        registry=AnalyzerRegistry(effective_settings.registry),
        repository=repository,
        yara_scanner=scanner,
    )
