"""Analyzer adapter that composes PE parsing with shared services."""

from pathlib import Path
import struct

from static_analysis.analyzers.base import Analyzer, AnalyzerDescriptor
from static_analysis.domain.enums import AnalysisStatus, TargetFormat
from static_analysis.domain.models import AnalysisContext, AnalysisTarget, AnalyzerOutcome
from static_analysis.metadata.contracts import MetadataService
from static_analysis.metadata.models import MetadataStatus
from static_analysis.pe.models import PeAnalysisResult, PeInfo
from static_analysis.pe.parser import PeParser, PeParseError
from static_analysis.rules.engine import RuleEngine
from static_analysis.rules.models import RuleContext
from static_analysis.strings.contracts import StringExtractionServiceContract
from static_analysis.strings.models import ExtractedString


class PeAnalyzer(Analyzer):
    """Static analyzer for Windows PE executables (.exe) and libraries (.dll)."""

    def __init__(
        self,
        metadata_service: MetadataService,
        string_service: StringExtractionServiceContract,
        rule_engine: RuleEngine | None = None,
        parser: PeParser | None = None,
    ) -> None:
        self._metadata = metadata_service
        self._strings = string_service
        self._rules = rule_engine
        self._parser = parser or PeParser()

    @property
    def descriptor(self) -> AnalyzerDescriptor:
        return AnalyzerDescriptor("pe.static", "1.0", frozenset({TargetFormat.EXE, TargetFormat.DLL}), "Static PE analyzer")

    def supports(self, target: AnalysisTarget) -> bool:
        return target.declared_format in {TargetFormat.EXE, TargetFormat.DLL}

    def analyze(self, target: AnalysisTarget, context: AnalysisContext) -> AnalyzerOutcome:
        result = self.extract(target.reference)
        attributes = {"machine": result.info.machine} if result.info else {}
        if result.rules is not None:
            attributes["risk_score"] = str(result.rules.risk_score.value)
        return AnalyzerOutcome(
            analyzer_id=self.descriptor.identifier,
            status=AnalysisStatus.COMPLETED if result.info else AnalysisStatus.FAILED,
            warnings=(result.error,) if result.error else (),
            attributes=attributes,
        )

    def extract(self, path: str | Path) -> PeAnalysisResult:
        source = Path(path)
        metadata = self._metadata.extract(source)
        if metadata.status is MetadataStatus.FAILED:
            return PeAnalysisResult(str(source), None, metadata, (), None, metadata.failure.value if metadata.failure else "metadata_failed")

        strings = self._strings.extract(source, metadata).strings
        try:
            with source.open("rb") as stream:
                data = stream.read()
            info = self._parser.parse(data)
        except (OSError, PeParseError, struct.error):
            return PeAnalysisResult(str(source), None, metadata, strings, None, "parse_error")

        rule_result = self._rules.evaluate(self._build_rule_context(info, strings)) if self._rules else None
        return PeAnalysisResult(str(source), info, metadata, strings, rule_result)

    def _build_rule_context(self, info: PeInfo, strings: tuple[ExtractedString, ...]) -> RuleContext:
        indicators = info.indicators
        section_entropies = {section.name: section.entropy for section in info.sections}
        executable_writable_sections = tuple(section.name for section in info.sections if section.rwx)
        suspicious_section_names = tuple(section.name for section in info.sections if section.suspicious)
        suspicious_metadata = list(indicators.anti_analysis_indicators)
        if indicators.missing_imports:
            suspicious_metadata.append("missing_imports")
        if indicators.invalid_headers:
            suspicious_metadata.append("invalid_headers")
        return RuleContext(
            analyzer_id=self.descriptor.identifier,
            suspicious_apis=indicators.suspicious_imports,
            strings=strings,
            section_entropies=section_entropies,
            executable_writable_sections=executable_writable_sections,
            suspicious_section_names=suspicious_section_names,
            is_stripped=False,
            is_signed=info.security.has_digital_signature,
            packed_indicators=("packed_heuristic",) if indicators.packed else (),
            suspicious_metadata=tuple(suspicious_metadata),
        )
