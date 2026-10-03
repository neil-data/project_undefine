"""Composition helper for the static ELF analyzer."""

from static_analysis.core.registry import AnalyzerRegistry
from static_analysis.elf.analyzer import ElfAnalyzer
from static_analysis.metadata.bootstrap import create_metadata_extractor
from static_analysis.rules.bootstrap import create_rule_engine
from static_analysis.strings.bootstrap import create_string_extractor


def create_elf_analyzer(analyzers: AnalyzerRegistry | None = None) -> ElfAnalyzer:
    """Assemble the ELF analyzer from existing shared services and the rule engine."""
    return ElfAnalyzer(
        create_metadata_extractor(analyzers),
        create_string_extractor(analyzers),
        create_rule_engine(),
    )
