"""Defensive ELF32/ELF64 parser for static header, section, and symbol inspection.

Handles both endiannesses and both 32-bit and 64-bit classes. All reads are
bounds-checked against the input buffer; malformed input raises `ElfParseError`
so callers can produce a controlled failure result instead of crashing.
"""

import math
import struct

from static_analysis.elf.models import (
    ElfHeader,
    ElfIndicators,
    ElfInfo,
    ElfNote,
    ElfProgramHeader,
    ElfRelocation,
    ElfSection,
    ElfSymbol,
)

_EI_CLASS = {1: "ELF32", 2: "ELF64"}
_EI_DATA = {1: "little", 2: "big"}
_EI_OSABI = {
    0: "sysv", 1: "hpux", 2: "netbsd", 3: "linux", 6: "solaris", 7: "aix",
    8: "irix", 9: "freebsd", 10: "tru64", 12: "openbsd", 13: "openvms",
}
_E_TYPE = {0: "none", 1: "rel", 2: "exec", 3: "dyn", 4: "core"}
_MACHINES = {
    2: "SPARC",
    3: "x86",
    4: "m68k",
    8: "MIPS",
    20: "PPC",
    21: "PPC64",
    40: "ARM",
    42: "SH",
    43: "SPARCV9",
    50: "ia64",
    62: "x86_64",
    183: "AArch64",
    243: "RISC-V",
}
_PT_TYPES = {
    0: "null", 1: "load", 2: "dynamic", 3: "interp", 4: "note", 5: "shlib",
    6: "phdr", 7: "tls", 0x6474E550: "gnu_eh_frame", 0x6474E551: "gnu_stack",
    0x6474E552: "gnu_relro", 0x6474E553: "gnu_property",
}
_SHT_TYPES = {
    0: "null", 1: "progbits", 2: "symtab", 3: "strtab", 4: "rela", 5: "hash",
    6: "dynamic", 7: "note", 8: "nobits", 9: "rel", 10: "shlib", 11: "dynsym",
    14: "init_array", 15: "fini_array", 16: "preinit_array", 17: "group",
    0x6FFFFFF6: "gnu_hash", 0x6FFFFFFD: "gnu_verdef", 0x6FFFFFFE: "gnu_verneed",
    0x6FFFFFFF: "gnu_versym",
}
_STB_BIND = {0: "local", 1: "global", 2: "weak"}
_STT_TYPE = {0: "notype", 1: "object", 2: "func", 3: "section", 4: "file", 5: "common", 6: "tls", 10: "gnu_ifunc"}
_STV_VISIBILITY = {0: "default", 1: "internal", 2: "hidden", 3: "protected"}
_SUSPICIOUS_SECTIONS = {
    "upx0", "upx1", "upx2", ".upx", ".packed", ".petite", ".aspack",
    ".vmp0", ".vmp1", ".themida", ".enigma1", ".enigma2", ".nsp0", ".nsp1", ".nsp2",
}
_SHF_WRITE = 0x1
_SHF_EXECINSTR = 0x4
_PF_X, _PF_W, _PF_R = 0x1, 0x2, 0x4
_DT_NEEDED = 1
_NT_GNU_BUILD_ID = 3
_HIGH_ENTROPY_THRESHOLD = 7.2


class ElfParseError(ValueError):
    """Raised when the input cannot be parsed as a well-formed ELF image."""


class ElfParser:
    """Parses an ELF image into a normalized, analyzer-neutral structure."""

    def parse(self, data: bytes) -> ElfInfo:
        if len(data) < 16 or data[:4] != b"\x7fELF":
            raise ElfParseError("invalid_magic")
        ei_class_raw, ei_data_raw, ei_version, ei_osabi_raw, ei_abiversion = data[4], data[5], data[6], data[7], data[8]
        if ei_class_raw not in _EI_CLASS or ei_data_raw not in _EI_DATA:
            raise ElfParseError("invalid_identification")
        is64 = ei_class_raw == 2
        endian = "<" if ei_data_raw == 1 else ">"
        header_size = 64 if is64 else 52
        if len(data) < header_size:
            raise ElfParseError("truncated_header")

        try:
            if is64:
                fields = struct.unpack_from(endian + "HHIQQQIHHHHHH", data, 16)
            else:
                fields = struct.unpack_from(endian + "HHIIIIIHHHHHH", data, 16)
        except struct.error as error:
            raise ElfParseError("truncated_header") from error
        (
            e_type_raw, e_machine_raw, e_version, e_entry, e_phoff, e_shoff, e_flags,
            e_ehsize, e_phentsize, e_phnum, e_shentsize, e_shnum, e_shstrndx,
        ) = fields

        header = ElfHeader(
            ei_class=_EI_CLASS[ei_class_raw],
            ei_data=_EI_DATA[ei_data_raw],
            ei_version=ei_version,
            ei_osabi=_EI_OSABI.get(ei_osabi_raw, hex(ei_osabi_raw)),
            ei_abiversion=ei_abiversion,
            e_type=_E_TYPE.get(e_type_raw, hex(e_type_raw)),
            e_machine=_MACHINES.get(e_machine_raw, f"e_machine=0x{e_machine_raw:04x} (unmapped)"),
            e_version=e_version,
            e_entry=e_entry,
            e_phoff=e_phoff,
            e_shoff=e_shoff,
            e_flags=e_flags,
            e_ehsize=e_ehsize,
            e_phentsize=e_phentsize,
            e_phnum=e_phnum,
            e_shentsize=e_shentsize,
            e_shnum=e_shnum,
            e_shstrndx=e_shstrndx,
        )

        program_headers = self._program_headers(data, endian, is64, e_phoff, e_phentsize, e_phnum)
        raw_sections, shstrtab = self._section_headers(data, endian, is64, e_shoff, e_shentsize, e_shnum, e_shstrndx)
        sections = tuple(
            self._decorate_section(data, name, raw) for name, raw in self._named_sections(raw_sections, shstrtab)
        )
        if not sections and program_headers:
            synthetic_sections = []
            for i, ph in enumerate(program_headers):
                if ph.type == "load":
                    blob = data[ph.offset : min(len(data), ph.offset + ph.filesz)]
                    entropy = self._entropy(blob)
                    synthetic_sections.append(
                        ElfSection(
                            name=f"PT_LOAD_{i}",
                            type="progbits",
                            flags=ph.flags,
                            address=ph.vaddr,
                            offset=ph.offset,
                            size=ph.filesz,
                            link=0,
                            info=0,
                            addralign=ph.align,
                            entsize=0,
                            entropy=entropy,
                            executable=ph.executable,
                            writable=ph.writable,
                            suspicious=False,
                        )
                    )
            sections = tuple(synthetic_sections)
        by_name = {section.name: section for section in sections}

        symbols = self._symbols(data, endian, is64, by_name.get(".symtab"), by_name.get(".strtab"))
        dynamic_symbols = self._symbols(data, endian, is64, by_name.get(".dynsym"), by_name.get(".dynstr"))
        imported_libraries = self._imported_libraries(data, endian, is64, by_name.get(".dynamic"), by_name.get(".dynstr"))
        relocations = self._all_relocations(data, endian, is64, sections)
        notes = self._all_notes(data, sections)
        build_id = self._build_id(notes)

        high_entropy = tuple(s.name for s in sections if s.entropy >= _HIGH_ENTROPY_THRESHOLD)
        exec_writable = tuple(s.name for s in sections if s.executable and s.writable)
        suspicious_names = tuple(s.name for s in sections if s.suspicious)
        stripped = ".symtab" not in by_name
        no_dynsyms = not dynamic_symbols and header.e_type == "dyn"
        packed = bool(high_entropy) and (stripped or not imported_libraries or len(sections) <= 3)

        indicators = ElfIndicators(
            stripped=stripped,
            packed=packed,
            high_entropy_sections=high_entropy,
            executable_writable_sections=exec_writable,
            suspicious_section_names=suspicious_names,
            missing_build_id=build_id is None,
            no_dynamic_symbols=no_dynsyms,
        )

        file_type = "shared_object" if header.e_type == "dyn" else ("executable" if header.e_type == "exec" else header.e_type)
        return ElfInfo(
            file_type=file_type,
            header=header,
            architecture=header.e_machine,
            entry_point=e_entry,
            program_headers=program_headers,
            sections=sections,
            symbols=symbols,
            dynamic_symbols=dynamic_symbols,
            imported_libraries=imported_libraries,
            relocations=relocations,
            notes=notes,
            build_id=build_id,
            indicators=indicators,
        )

    # -- program headers ---------------------------------------------------

    def _program_headers(
        self, data: bytes, endian: str, is64: bool, offset: int, entsize: int, count: int
    ) -> tuple[ElfProgramHeader, ...]:
        if not offset or not count:
            return ()
        entry_format = endian + ("IIQQQQQQ" if is64 else "IIIIIIII")
        expected_size = struct.calcsize(entry_format)
        result = []
        for index in range(count):
            position = offset + index * (entsize or expected_size)
            if position + expected_size > len(data):
                break
            try:
                if is64:
                    p_type, p_flags, p_offset, p_vaddr, p_paddr, p_filesz, p_memsz, p_align = struct.unpack_from(
                        entry_format, data, position
                    )
                else:
                    p_type, p_offset, p_vaddr, p_paddr, p_filesz, p_memsz, p_flags, p_align = struct.unpack_from(
                        entry_format, data, position
                    )
            except struct.error:
                break
            result.append(
                ElfProgramHeader(
                    type=_PT_TYPES.get(p_type, hex(p_type)),
                    flags=p_flags,
                    offset=p_offset,
                    vaddr=p_vaddr,
                    paddr=p_paddr,
                    filesz=p_filesz,
                    memsz=p_memsz,
                    align=p_align,
                    readable=bool(p_flags & _PF_R),
                    writable=bool(p_flags & _PF_W),
                    executable=bool(p_flags & _PF_X),
                )
            )
        return tuple(result)

    # -- section headers -----------------------------------------------------

    def _section_headers(
        self, data: bytes, endian: str, is64: bool, offset: int, entsize: int, count: int, strndx: int
    ) -> tuple[list[tuple[int, int, int, int, int, int, int, int, int, int]], bytes]:
        if not offset or not count:
            return [], b""
        entry_format = endian + ("IIQQQQIIQQ" if is64 else "IIIIIIIIII")
        expected_size = struct.calcsize(entry_format)
        raw = []
        for index in range(count):
            position = offset + index * (entsize or expected_size)
            if position + expected_size > len(data):
                break
            try:
                raw.append(struct.unpack_from(entry_format, data, position))
            except struct.error:
                break
        shstrtab = b""
        if 0 <= strndx < len(raw):
            name_off, sh_type, _flags, _addr, sh_offset, sh_size = raw[strndx][:6]
            if sh_type != 8 and sh_offset + sh_size <= len(data):
                shstrtab = data[sh_offset : sh_offset + sh_size]
        return raw, shstrtab

    def _named_sections(
        self, raw_sections: list[tuple], shstrtab: bytes
    ) -> list[tuple[str, tuple]]:
        return [(self._cstring(shstrtab, raw[0]), raw) for raw in raw_sections]

    def _decorate_section(self, data: bytes, name: str, raw: tuple) -> ElfSection:
        _name_off, sh_type, sh_flags, sh_addr, sh_offset, sh_size, sh_link, sh_info, sh_addralign, sh_entsize = raw
        blob = b"" if sh_type == 8 else data[sh_offset : min(len(data), sh_offset + sh_size)]
        entropy = self._entropy(blob)
        executable = bool(sh_flags & _SHF_EXECINSTR)
        writable = bool(sh_flags & _SHF_WRITE)
        suspicious = name.lower() in _SUSPICIOUS_SECTIONS
        return ElfSection(
            name=name,
            type=_SHT_TYPES.get(sh_type, hex(sh_type)),
            flags=sh_flags,
            address=sh_addr,
            offset=sh_offset,
            size=sh_size,
            link=sh_link,
            info=sh_info,
            addralign=sh_addralign,
            entsize=sh_entsize,
            entropy=entropy,
            executable=executable,
            writable=writable,
            suspicious=suspicious,
        )

    # -- symbols ---------------------------------------------------------

    def _symbols(
        self, data: bytes, endian: str, is64: bool, symtab: ElfSection | None, strtab: ElfSection | None
    ) -> tuple[ElfSymbol, ...]:
        if symtab is None or symtab.size == 0:
            return ()
        strtab_blob = (
            data[strtab.offset : strtab.offset + strtab.size] if strtab and strtab.offset + strtab.size <= len(data) else b""
        )
        entry_format = endian + ("IBBHQQ" if is64 else "IIIBBH")
        entry_size = struct.calcsize(entry_format)
        count = symtab.size // entry_size if entry_size else 0
        result = []
        for index in range(count):
            position = symtab.offset + index * entry_size
            if position + entry_size > len(data):
                break
            try:
                if is64:
                    st_name, st_info, st_other, st_shndx, st_value, st_size = struct.unpack_from(entry_format, data, position)
                else:
                    st_name, st_value, st_size, st_info, st_other, st_shndx = struct.unpack_from(entry_format, data, position)
            except struct.error:
                break
            result.append(
                ElfSymbol(
                    name=self._cstring(strtab_blob, st_name),
                    value=st_value,
                    size=st_size,
                    bind=_STB_BIND.get(st_info >> 4, hex(st_info >> 4)),
                    type=_STT_TYPE.get(st_info & 0xF, hex(st_info & 0xF)),
                    visibility=_STV_VISIBILITY.get(st_other & 0x3, hex(st_other & 0x3)),
                    section_index=st_shndx,
                )
            )
        return tuple(result)

    # -- dynamic section / imported libraries -----------------------------

    def _imported_libraries(
        self, data: bytes, endian: str, is64: bool, dynamic: ElfSection | None, dynstr: ElfSection | None
    ) -> tuple[str, ...]:
        if dynamic is None or dynamic.size == 0:
            return ()
        dynstr_blob = (
            data[dynstr.offset : dynstr.offset + dynstr.size] if dynstr and dynstr.offset + dynstr.size <= len(data) else b""
        )
        entry_format = endian + ("qQ" if is64 else "iI")
        entry_size = struct.calcsize(entry_format)
        count = dynamic.size // entry_size if entry_size else 0
        libraries = []
        for index in range(count):
            position = dynamic.offset + index * entry_size
            if position + entry_size > len(data):
                break
            try:
                tag, value = struct.unpack_from(entry_format, data, position)
            except struct.error:
                break
            if tag == 0:
                break
            if tag == _DT_NEEDED:
                libraries.append(self._cstring(dynstr_blob, value))
        return tuple(libraries)

    # -- relocations -------------------------------------------------------

    def _all_relocations(
        self, data: bytes, endian: str, is64: bool, sections: tuple[ElfSection, ...]
    ) -> tuple[ElfRelocation, ...]:
        result = []
        for section in sections:
            if section.type == "rela":
                result.extend(self._relocations(data, endian, is64, section, has_addend=True))
            elif section.type == "rel":
                result.extend(self._relocations(data, endian, is64, section, has_addend=False))
        return tuple(result)

    def _relocations(
        self, data: bytes, endian: str, is64: bool, section: ElfSection, has_addend: bool
    ) -> list[ElfRelocation]:
        if has_addend:
            entry_format = endian + ("QQq" if is64 else "IIi")
        else:
            entry_format = endian + ("QQ" if is64 else "II")
        entry_size = struct.calcsize(entry_format)
        count = section.size // entry_size if entry_size else 0
        result = []
        for index in range(min(count, 100_000)):
            position = section.offset + index * entry_size
            if position + entry_size > len(data):
                break
            try:
                unpacked = struct.unpack_from(entry_format, data, position)
            except struct.error:
                break
            r_offset, r_info = unpacked[0], unpacked[1]
            addend = unpacked[2] if has_addend else None
            if is64:
                symbol_index, relocation_type = r_info >> 32, r_info & 0xFFFFFFFF
            else:
                symbol_index, relocation_type = r_info >> 8, r_info & 0xFF
            result.append(ElfRelocation(section.name, r_offset, symbol_index, relocation_type, addend))
        return result

    # -- notes -------------------------------------------------------------

    def _all_notes(self, data: bytes, sections: tuple[ElfSection, ...]) -> tuple[ElfNote, ...]:
        result = []
        for section in sections:
            if section.type != "note" or not section.name.startswith(".note"):
                continue
            blob = data[section.offset : min(len(data), section.offset + section.size)]
            result.extend(self._parse_notes(blob))
        return tuple(result)

    @staticmethod
    def _parse_notes(blob: bytes) -> list[ElfNote]:
        notes = []
        position = 0
        while position + 12 <= len(blob):
            try:
                namesz, descsz, note_type = struct.unpack_from("<III", blob, position)
            except struct.error:
                break
            position += 12
            name_end = position + namesz
            if name_end > len(blob):
                break
            owner = blob[position:name_end].rstrip(b"\x00").decode("ascii", "replace")
            position += (namesz + 3) & ~3
            desc_end = position + descsz
            if desc_end > len(blob):
                break
            description = blob[position:desc_end]
            position += (descsz + 3) & ~3
            notes.append(ElfNote(owner=owner, note_type=note_type, description_hex=description.hex()))
        return notes

    @staticmethod
    def _build_id(notes: tuple[ElfNote, ...]) -> str | None:
        for note in notes:
            if note.owner == "GNU" and note.note_type == _NT_GNU_BUILD_ID:
                return note.description_hex
        return None

    # -- shared helpers ------------------------------------------------------

    @staticmethod
    def _entropy(blob: bytes) -> float:
        if not blob:
            return 0.0
        counts = [blob.count(bytes([i])) for i in range(256)]
        length = len(blob)
        return -sum((n / length) * math.log2(n / length) for n in counts if n)

    @staticmethod
    def _cstring(blob: bytes, offset: int) -> str:
        if offset < 0 or offset >= len(blob):
            return ""
        end = blob.find(b"\x00", offset)
        return blob[offset : end if end >= 0 else len(blob)].decode("ascii", "replace")
