"""Composition helper for the static PE analyzer."""
from static_analysis.core.registry import AnalyzerRegistry
from static_analysis.metadata.bootstrap import create_metadata_extractor
from static_analysis.pe.analyzer import PeAnalyzer
from static_analysis.rules.bootstrap import create_rule_engine
from static_analysis.strings.bootstrap import create_string_extractor
def create_pe_analyzer(analyzers:AnalyzerRegistry|None=None)->PeAnalyzer:
    return PeAnalyzer(create_metadata_extractor(analyzers),create_string_extractor(analyzers),create_rule_engine())
