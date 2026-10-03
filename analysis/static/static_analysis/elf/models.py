"""Structured artifacts extracted from an ELF executable or shared object."""

from dataclasses import dataclass

from static_analysis.metadata.models import MetadataResult
from static_analysis.rules.models import RuleEngineResult
from static_analysis.strings.models import ExtractedString


@dataclass(frozen=True, slots=True)
class ElfHeader:
    """Raw and decoded fields from the ELF identification and file header."""

    ei_class: str
    ei_data: str
    ei_version: int
    ei_osabi: str
    ei_abiversion: int
    e_type: str
    e_machine: str
    e_version: int
    e_entry: int
    e_phoff: int
    e_shoff: int
    e_flags: int
    e_ehsize: int
    e_phentsize: int
    e_phnum: int
    e_shentsize: int
    e_shnum: int
    e_shstrndx: int


@dataclass(frozen=True, slots=True)
class ElfProgramHeader:
    """One entry from the program header table describing a loadable segment."""

    type: str
    flags: int
    offset: int
    vaddr: int
    paddr: int
    filesz: int
    memsz: int
    align: int
    readable: bool
    writable: bool
    executable: bool


@dataclass(frozen=True, slots=True)
class ElfSection:
    """One section header combined with content-derived indicators."""

    name: str
    type: str
    flags: int
    address: int
    offset: int
    size: int
    link: int
    info: int
    addralign: int
    entsize: int
    entropy: float
    executable: bool
    writable: bool
    suspicious: bool


@dataclass(frozen=True, slots=True)
class ElfSymbol:
    """One entry from a symbol table (`.symtab` or `.dynsym`)."""

    name: str
    value: int
    size: int
    bind: str
    type: str
    visibility: str
    section_index: int


@dataclass(frozen=True, slots=True)
class ElfRelocation:
    """One relocation entry from a `.rel*`/`.rela*` section."""

    section: str
    offset: int
    symbol_index: int
    relocation_type: int
    addend: int | None


@dataclass(frozen=True, slots=True)
class ElfNote:
    """One ELF note entry, typically found in `.note.*` sections."""

    owner: str
    note_type: int
    description_hex: str


@dataclass(frozen=True, slots=True)
class ElfIndicators:
    """Static heuristics summarizing suspicious structural characteristics."""

    stripped: bool
    packed: bool
    high_entropy_sections: tuple[str, ...]
    executable_writable_sections: tuple[str, ...]
    suspicious_section_names: tuple[str, ...]
    missing_build_id: bool
    no_dynamic_symbols: bool


@dataclass(frozen=True, slots=True)
class ElfInfo:
    """Complete static facts extracted from one ELF file."""

    file_type: str
    header: ElfHeader
    architecture: str
    entry_point: int
    program_headers: tuple[ElfProgramHeader, ...]
    sections: tuple[ElfSection, ...]
    symbols: tuple[ElfSymbol, ...]
    dynamic_symbols: tuple[ElfSymbol, ...]
    imported_libraries: tuple[str, ...]
    relocations: tuple[ElfRelocation, ...]
    notes: tuple[ElfNote, ...]
    build_id: str | None
    indicators: ElfIndicators


@dataclass(frozen=True, slots=True)
class ElfAnalysisResult:
    """Complete outcome of one ELF analyzer invocation."""

    source: str
    info: ElfInfo | None
    metadata: MetadataResult
    strings: tuple[ExtractedString, ...]
    rules: RuleEngineResult | None = None
    error: str | None = None
