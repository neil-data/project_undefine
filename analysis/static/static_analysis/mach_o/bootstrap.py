"""Composition helper for the static Mach-O analyzer."""

from static_analysis.core.registry import AnalyzerRegistry
from static_analysis.mach_o.analyzer import MachOAnalyzer
from static_analysis.metadata.bootstrap import create_metadata_extractor
from static_analysis.rules.bootstrap import create_rule_engine
from static_analysis.strings.bootstrap import create_string_extractor


def create_mach_o_analyzer(analyzers: AnalyzerRegistry | None = None) -> MachOAnalyzer:
    """Assemble the Mach-O analyzer from existing shared services and the rule engine."""
    return MachOAnalyzer(
        create_metadata_extractor(analyzers),
        create_string_extractor(analyzers),
        create_rule_engine(),
    )
