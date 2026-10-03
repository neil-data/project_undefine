"""Analyzer adapter that composes ELF parsing with shared services."""

from pathlib import Path

from static_analysis.analyzers.base import Analyzer, AnalyzerDescriptor
from static_analysis.domain.enums import AnalysisStatus, TargetFormat
from static_analysis.domain.models import AnalysisContext, AnalysisTarget, AnalyzerOutcome
from static_analysis.elf.models import ElfAnalysisResult, ElfInfo
from static_analysis.elf.parser import ElfParseError, ElfParser
from static_analysis.metadata.contracts import MetadataService
from static_analysis.metadata.models import MetadataStatus
from static_analysis.rules.engine import RuleEngine
from static_analysis.rules.models import RuleContext
from static_analysis.strings.contracts import StringExtractionServiceContract
from static_analysis.strings.models import ExtractedString

_SUSPICIOUS_API_NAMES = frozenset({
    "ptrace", "fork", "vfork", "execve", "execl", "execve", "mprotect", "mmap",
    "dlopen", "dlsym", "system", "popen", "socket", "connect", "setuid", "setgid",
    "prctl", "ld_preload", "getenv",
})


class ElfAnalyzer(Analyzer):
    """Static analyzer for ELF executables and shared objects."""

    def __init__(
        self,
        metadata_service: MetadataService,
        string_service: StringExtractionServiceContract,
        rule_engine: RuleEngine,
        parser: ElfParser | None = None,
    ) -> None:
        self._metadata = metadata_service
        self._strings = string_service
        self._rules = rule_engine
        self._parser = parser or ElfParser()

    @property
    def descriptor(self) -> AnalyzerDescriptor:
        return AnalyzerDescriptor("elf.static", "1.0", frozenset({TargetFormat.ELF}), "Static ELF analyzer")

    def supports(self, target: AnalysisTarget) -> bool:
        return target.declared_format is TargetFormat.ELF

    def analyze(self, target: AnalysisTarget, context: AnalysisContext) -> AnalyzerOutcome:
        result = self.extract(target.reference)
        attributes = {"architecture": result.info.architecture} if result.info else {}
        if result.rules is not None:
            attributes["risk_score"] = str(result.rules.risk_score.value)
        return AnalyzerOutcome(
            analyzer_id=self.descriptor.identifier,
            status=AnalysisStatus.COMPLETED if result.info else AnalysisStatus.FAILED,
            warnings=(result.error,) if result.error else (),
            attributes=attributes,
        )

    def extract(self, path: str | Path) -> ElfAnalysisResult:
        """Return ELF-specific static facts, an error, or a partial failure."""
        source = Path(path)
        metadata = self._metadata.extract(source)
        if metadata.status is MetadataStatus.FAILED:
            failure = metadata.failure.value if metadata.failure else "metadata_failed"
            return ElfAnalysisResult(str(source), None, metadata, (), None, failure)

        strings = self._strings.extract(source, metadata).strings
        try:
            with source.open("rb") as stream:
                data = stream.read()
            info = self._parser.parse(data)
        except (OSError, ElfParseError) as error:
            return ElfAnalysisResult(str(source), None, metadata, strings, None, "parse_error")

        rule_result = self._rules.evaluate(self._build_rule_context(info, strings))
        return ElfAnalysisResult(str(source), info, metadata, strings, rule_result)

    def _build_rule_context(self, info: ElfInfo, strings: tuple[ExtractedString, ...]) -> RuleContext:
        suspicious_apis = tuple(sorted({
            symbol.name for symbol in (*info.symbols, *info.dynamic_symbols) if symbol.name in _SUSPICIOUS_API_NAMES
        }))
        section_entropies = {section.name: section.entropy for section in info.sections}
        suspicious_metadata = []
        if info.indicators.missing_build_id:
            suspicious_metadata.append("missing_build_id")
        if info.indicators.no_dynamic_symbols:
            suspicious_metadata.append("no_dynamic_symbols_in_shared_object")
        return RuleContext(
            analyzer_id=self.descriptor.identifier,
            suspicious_apis=suspicious_apis,
            strings=strings,
            section_entropies=section_entropies,
            executable_writable_sections=info.indicators.executable_writable_sections,
            suspicious_section_names=info.indicators.suspicious_section_names,
            is_stripped=info.indicators.stripped,
            is_signed=None,
            packed_indicators=("packed_heuristic",) if info.indicators.packed else (),
            suspicious_metadata=tuple(suspicious_metadata),
        )
