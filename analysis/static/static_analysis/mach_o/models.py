"""Structured artifacts extracted from a Mach-O image (thin or universal/FAT)."""

from dataclasses import dataclass

from static_analysis.metadata.models import MetadataResult
from static_analysis.rules.models import RuleEngineResult
from static_analysis.strings.models import ExtractedString


@dataclass(frozen=True, slots=True)
class MachOHeader:
    """Raw and decoded fields from the Mach-O `mach_header(_64)`."""

    magic: str
    is_64_bit: bool
    cpu_type: str
    cpu_subtype: str
    file_type: str
    number_of_load_commands: int
    size_of_load_commands: int
    flags: int


@dataclass(frozen=True, slots=True)
class MachOSection:
    """One section entry belonging to a `LC_SEGMENT(_64)` load command."""

    segment_name: str
    section_name: str
    address: int
    size: int
    offset: int
    align: int
    reloff: int
    number_of_relocations: int
    flags: int
    entropy: float
    executable: bool
    writable: bool
    suspicious: bool


@dataclass(frozen=True, slots=True)
class MachOSegment:
    """One `LC_SEGMENT(_64)` load command and the sections it contains."""

    name: str
    vm_address: int
    vm_size: int
    file_offset: int
    file_size: int
    maximum_protection: int
    initial_protection: int
    flags: int
    sections: tuple[MachOSection, ...]


@dataclass(frozen=True, slots=True)
class MachOLoadCommand:
    """A generic, normalized view of one load command."""

    command: str
    command_id: int
    size: int
    details: str = ""


@dataclass(frozen=True, slots=True)
class MachODylib:
    """One linked dynamic library referenced by an `LC_LOAD_DYLIB` family command."""

    name: str
    command: str
    current_version: str
    compatibility_version: str


@dataclass(frozen=True, slots=True)
class MachOCodeSignature:
    """Presence and location of an embedded code signature superblob."""

    present: bool
    offset: int | None = None
    size: int | None = None


@dataclass(frozen=True, slots=True)
class MachOEntitlements:
    """Best-effort extraction of an embedded entitlements property list."""

    present: bool
    keys: tuple[str, ...] = ()
    raw_xml: str | None = None


@dataclass(frozen=True, slots=True)
class MachOIndicators:
    """Static heuristics summarizing suspicious structural characteristics."""

    executable_writable_sections: tuple[str, ...]
    suspicious_load_commands: tuple[str, ...]
    high_entropy_sections: tuple[str, ...]
    packed: bool


@dataclass(frozen=True, slots=True)
class MachOArchInfo:
    """Complete static facts extracted from one architecture slice."""

    header: MachOHeader
    entry_point: int | None
    uuid: str | None
    load_commands: tuple[MachOLoadCommand, ...]
    segments: tuple[MachOSegment, ...]
    linked_libraries: tuple[MachODylib, ...]
    code_signature: MachOCodeSignature
    entitlements: MachOEntitlements
    indicators: MachOIndicators


@dataclass(frozen=True, slots=True)
class MachOInfo:
    """Complete static facts extracted from a Mach-O file, thin or universal."""

    file_type: str
    is_universal: bool
    architectures: tuple[MachOArchInfo, ...]


@dataclass(frozen=True, slots=True)
class MachOAnalysisResult:
    """Complete outcome of one Mach-O analyzer invocation."""

    source: str
    info: MachOInfo | None
    metadata: MetadataResult
    strings: tuple[ExtractedString, ...]
    rules: RuleEngineResult | None = None
    error: str | None = None
