"""Analyzer adapter that composes Mach-O parsing with shared services."""

from pathlib import Path

from static_analysis.analyzers.base import Analyzer, AnalyzerDescriptor
from static_analysis.domain.enums import AnalysisStatus, TargetFormat
from static_analysis.domain.models import AnalysisContext, AnalysisTarget, AnalyzerOutcome
from static_analysis.mach_o.models import MachOAnalysisResult, MachOInfo
from static_analysis.mach_o.parser import MachOParseError, MachOParser
from static_analysis.metadata.contracts import MetadataService
from static_analysis.metadata.models import MetadataStatus
from static_analysis.rules.engine import RuleEngine
from static_analysis.rules.models import RuleContext
from static_analysis.strings.contracts import StringExtractionServiceContract
from static_analysis.strings.models import ExtractedString


class MachOAnalyzer(Analyzer):
    """Static analyzer for Mach-O executables, dylibs, bundles, and FAT binaries."""

    def __init__(
        self,
        metadata_service: MetadataService,
        string_service: StringExtractionServiceContract,
        rule_engine: RuleEngine,
        parser: MachOParser | None = None,
    ) -> None:
        self._metadata = metadata_service
        self._strings = string_service
        self._rules = rule_engine
        self._parser = parser or MachOParser()

    @property
    def descriptor(self) -> AnalyzerDescriptor:
        return AnalyzerDescriptor("mach_o.static", "1.0", frozenset({TargetFormat.MACH_O}), "Static Mach-O analyzer")

    def supports(self, target: AnalysisTarget) -> bool:
        return target.declared_format is TargetFormat.MACH_O

    def analyze(self, target: AnalysisTarget, context: AnalysisContext) -> AnalyzerOutcome:
        result = self.extract(target.reference)
        attributes = {}
        if result.info:
            attributes["file_type"] = result.info.file_type
            attributes["universal"] = str(result.info.is_universal)
        if result.rules is not None:
            attributes["risk_score"] = str(result.rules.risk_score.value)
        return AnalyzerOutcome(
            analyzer_id=self.descriptor.identifier,
            status=AnalysisStatus.COMPLETED if result.info else AnalysisStatus.FAILED,
            warnings=(result.error,) if result.error else (),
            attributes=attributes,
        )

    def extract(self, path: str | Path) -> MachOAnalysisResult:
        """Return Mach-O-specific static facts, an error, or a partial failure."""
        source = Path(path)
        metadata = self._metadata.extract(source)
        if metadata.status is MetadataStatus.FAILED:
            failure = metadata.failure.value if metadata.failure else "metadata_failed"
            return MachOAnalysisResult(str(source), None, metadata, (), None, failure)

        strings = self._strings.extract(source, metadata).strings
        try:
            with source.open("rb") as stream:
                data = stream.read()
            info = self._parser.parse(data)
        except (OSError, MachOParseError):
            return MachOAnalysisResult(str(source), None, metadata, strings, None, "parse_error")

        rule_result = self._rules.evaluate(self._build_rule_context(info, strings))
        return MachOAnalysisResult(str(source), info, metadata, strings, rule_result)

    def _build_rule_context(self, info: MachOInfo, strings: tuple[ExtractedString, ...]) -> RuleContext:
        section_entropies: dict[str, float] = {}
        exec_writable: list[str] = []
        suspicious_commands: list[str] = []
        packed_any = False
        unsigned_any = False
        for architecture in info.architectures:
            for segment in architecture.segments:
                for section in segment.sections:
                    key = f"{architecture.header.cpu_type}:{segment.name}/{section.section_name}"
                    section_entropies[key] = section.entropy
            exec_writable.extend(f"{architecture.header.cpu_type}:{item}" for item in architecture.indicators.executable_writable_sections)
            suspicious_commands.extend(architecture.indicators.suspicious_load_commands)
            packed_any = packed_any or architecture.indicators.packed
            unsigned_any = unsigned_any or not architecture.code_signature.present

        return RuleContext(
            analyzer_id=self.descriptor.identifier,
            strings=strings,
            section_entropies=section_entropies,
            executable_writable_sections=tuple(exec_writable),
            is_signed=not unsigned_any,
            packed_indicators=("packed_heuristic",) if packed_any else (),
            suspicious_metadata=tuple(sorted(set(suspicious_commands))),
        )
