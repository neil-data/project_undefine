"""Structured artifacts extracted from a Portable Executable image."""

from dataclasses import dataclass
from datetime import datetime

from static_analysis.metadata.models import MetadataResult
from static_analysis.rules.models import RuleEngineResult
from static_analysis.strings.models import ExtractedString


@dataclass(frozen=True, slots=True)
class PeSection:
    name: str; virtual_address: int; virtual_size: int; raw_size: int; raw_offset: int; characteristics: int; entropy: float; rwx: bool; suspicious: bool
@dataclass(frozen=True, slots=True)
class PeImport:
    library: str; functions: tuple[str, ...]; delayed: bool = False
@dataclass(frozen=True, slots=True)
class PeExport:
    name: str | None; ordinal: int; address: int
@dataclass(frozen=True, slots=True)
class PeResourceInfo:
    resource_types: tuple[str, ...]; has_icon: bool; has_version_info: bool; has_manifest: bool
@dataclass(frozen=True, slots=True)
class PeSecurityInfo:
    has_digital_signature: bool; authenticode_offset: int | None; authenticode_size: int | None; tls_callbacks: tuple[int, ...]; has_rich_header: bool
@dataclass(frozen=True, slots=True)
class PeIndicators:
    packed: bool; high_entropy_sections: tuple[str, ...]; suspicious_imports: tuple[str, ...]; missing_imports: bool; overlay_size: int; invalid_headers: bool; anti_analysis_indicators: tuple[str, ...]
@dataclass(frozen=True, slots=True)
class PeInfo:
    file_type: str; dos_magic: str; pe_signature: str; machine: str; entry_point: int; image_base: int; subsystem: str; characteristics: int; compile_timestamp: datetime; number_of_sections: int; optional_header_magic: int; sections: tuple[PeSection, ...]; imports: tuple[PeImport, ...]; exports: tuple[PeExport, ...]; resources: PeResourceInfo; security: PeSecurityInfo; indicators: PeIndicators
@dataclass(frozen=True, slots=True)
class PeAnalysisResult:
    source: str; info: PeInfo | None; metadata: MetadataResult; strings: tuple[ExtractedString, ...]; rules: RuleEngineResult | None = None; error: str | None = None
