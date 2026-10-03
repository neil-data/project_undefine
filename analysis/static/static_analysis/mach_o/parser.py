"""Defensive Mach-O parser for thin, 32/64-bit, and universal (FAT) images.

All reads are bounds-checked against the input buffer. Malformed input raises
`MachOParseError` so callers can produce a controlled failure result instead of
crashing. Code-signing structures (superblob, blobs) are always big-endian per
the Apple specification, independent of the containing image's byte order.
"""

import math
import re
import struct

from static_analysis.mach_o.models import (
    MachOArchInfo,
    MachOCodeSignature,
    MachODylib,
    MachOEntitlements,
    MachOHeader,
    MachOIndicators,
    MachOInfo,
    MachOLoadCommand,
    MachOSection,
    MachOSegment,
)

_FAT_MAGIC = b"\xca\xfe\xba\xbe"
_FAT_MAGIC_64 = b"\xca\xfe\xba\xbf"
_THIN_MAGICS = {
    b"\xfe\xed\xfa\xce": (">", False),
    b"\xce\xfa\xed\xfe": ("<", False),
    b"\xfe\xed\xfa\xcf": (">", True),
    b"\xcf\xfa\xed\xfe": ("<", True),
}

_CPU_TYPES = {
    7: "x86", 0x01000007: "x86_64", 12: "arm", 0x0100000C: "arm64",
    18: "ppc", 0x01000012: "ppc64",
}
_FILE_TYPES = {
    1: "object", 2: "executable", 3: "fvmlib", 4: "core", 5: "preload",
    6: "dylib", 7: "dylinker", 8: "bundle", 9: "dylib_stub", 10: "dsym", 11: "kext_bundle",
}
_LC_SEGMENT = 0x1
_LC_SYMTAB = 0x2
_LC_DYSYMTAB = 0xB
_LC_LOAD_DYLIB = 0xC
_LC_ID_DYLIB = 0xD
_LC_LOAD_DYLINKER = 0xE
_LC_UNIXTHREAD = 0x5
_LC_SEGMENT_64 = 0x19
_LC_UUID = 0x1B
_LC_RPATH = 0x8000001C
_LC_CODE_SIGNATURE = 0x1D
_LC_ENCRYPTION_INFO = 0x21
_LC_DYLD_INFO = 0x22
_LC_DYLD_INFO_ONLY = 0x80000022
_LC_VERSION_MIN_MACOSX = 0x24
_LC_VERSION_MIN_IPHONEOS = 0x25
_LC_FUNCTION_STARTS = 0x26
_LC_MAIN = 0x80000028
_LC_DATA_IN_CODE = 0x29
_LC_SOURCE_VERSION = 0x2A
_LC_DYLIB_CODE_SIGN_DRS = 0x2B
_LC_ENCRYPTION_INFO_64 = 0x2C
_LC_LINKER_OPTION = 0x2D
_LC_BUILD_VERSION = 0x32
_LC_LOAD_WEAK_DYLIB = 0x80000018
_LC_REEXPORT_DYLIB = 0x8000001F
_LC_LOAD_UPWARD_DYLIB = 0x80000023

_LC_NAMES = {
    _LC_SEGMENT: "LC_SEGMENT", _LC_SYMTAB: "LC_SYMTAB", _LC_DYSYMTAB: "LC_DYSYMTAB",
    _LC_LOAD_DYLIB: "LC_LOAD_DYLIB", _LC_ID_DYLIB: "LC_ID_DYLIB", _LC_LOAD_DYLINKER: "LC_LOAD_DYLINKER",
    _LC_UNIXTHREAD: "LC_UNIXTHREAD", _LC_SEGMENT_64: "LC_SEGMENT_64", _LC_UUID: "LC_UUID",
    _LC_RPATH: "LC_RPATH", _LC_CODE_SIGNATURE: "LC_CODE_SIGNATURE",
    _LC_ENCRYPTION_INFO: "LC_ENCRYPTION_INFO", _LC_DYLD_INFO: "LC_DYLD_INFO",
    _LC_DYLD_INFO_ONLY: "LC_DYLD_INFO_ONLY", _LC_VERSION_MIN_MACOSX: "LC_VERSION_MIN_MACOSX",
    _LC_VERSION_MIN_IPHONEOS: "LC_VERSION_MIN_IPHONEOS", _LC_FUNCTION_STARTS: "LC_FUNCTION_STARTS",
    _LC_MAIN: "LC_MAIN", _LC_DATA_IN_CODE: "LC_DATA_IN_CODE", _LC_SOURCE_VERSION: "LC_SOURCE_VERSION",
    _LC_DYLIB_CODE_SIGN_DRS: "LC_DYLIB_CODE_SIGN_DRS", _LC_ENCRYPTION_INFO_64: "LC_ENCRYPTION_INFO_64",
    _LC_LINKER_OPTION: "LC_LINKER_OPTION", _LC_BUILD_VERSION: "LC_BUILD_VERSION",
    _LC_LOAD_WEAK_DYLIB: "LC_LOAD_WEAK_DYLIB", _LC_REEXPORT_DYLIB: "LC_REEXPORT_DYLIB",
    _LC_LOAD_UPWARD_DYLIB: "LC_LOAD_UPWARD_DYLIB",
}
_DYLIB_COMMANDS = {
    _LC_LOAD_DYLIB, _LC_ID_DYLIB, _LC_LOAD_WEAK_DYLIB, _LC_REEXPORT_DYLIB, _LC_LOAD_UPWARD_DYLIB,
}
_SUSPICIOUS_LOAD_COMMANDS = {_LC_LOAD_WEAK_DYLIB, _LC_REEXPORT_DYLIB, _LC_LOAD_UPWARD_DYLIB}
_SECTION_ATTR_SOME_INSTRUCTIONS = 0x00000400
_S_ATTR_PURE_INSTRUCTIONS = 0x80000000
_VM_PROT_WRITE = 0x2
_CS_SUPERBLOB_MAGIC = 0xFADE0CC0
_CSSLOT_ENTITLEMENTS = 5
_HIGH_ENTROPY_THRESHOLD = 7.2


class MachOParseError(ValueError):
    """Raised when the input cannot be parsed as a well-formed Mach-O image."""


class MachOParser:
    """Parses a Mach-O image, transparently unwrapping FAT/universal containers."""

    def parse(self, data: bytes) -> MachOInfo:
        if len(data) < 8:
            raise MachOParseError("truncated_input")
        magic = data[:4]
        if magic in (_FAT_MAGIC, _FAT_MAGIC_64):
            return self._parse_fat(data, is_64=magic == _FAT_MAGIC_64)
        if magic in _THIN_MAGICS:
            return MachOInfo(
                file_type=self._parse_thin(data, offset=0, size=len(data)).header.file_type,
                is_universal=False,
                architectures=(self._parse_thin(data, offset=0, size=len(data)),),
            )
        raise MachOParseError("invalid_magic")

    def _parse_fat(self, data: bytes, is_64: bool) -> MachOInfo:
        count = struct.unpack_from(">I", data, 4)[0]
        entry_format = ">IIQQI4x" if is_64 else ">IIIII"
        entry_size = struct.calcsize(entry_format)
        architectures = []
        for index in range(count):
            position = 8 + index * entry_size
            if position + entry_size > len(data):
                break
            try:
                fields = struct.unpack_from(entry_format, data, position)
            except struct.error:
                break
            _cputype, _cpusubtype, offset, size = fields[0], fields[1], fields[2], fields[3]
            if offset + size > len(data) or size < 8:
                continue
            try:
                architectures.append(self._parse_thin(data, offset, size))
            except MachOParseError:
                continue
        if not architectures:
            raise MachOParseError("no_valid_architecture_slices")
        return MachOInfo(
            file_type=architectures[0].header.file_type,
            is_universal=True,
            architectures=tuple(architectures),
        )

    def _parse_thin(self, data: bytes, offset: int, size: int) -> MachOArchInfo:
        magic = data[offset : offset + 4]
        if magic not in _THIN_MAGICS:
            raise MachOParseError("invalid_thin_magic")
        endian, is64 = _THIN_MAGICS[magic]
        header_format = endian + "IiiIIII"
        header_size = struct.calcsize(header_format) + (4 if is64 else 0)
        if offset + header_size > len(data):
            raise MachOParseError("truncated_header")
        try:
            magic_value, cputype, cpusubtype, filetype, ncmds, sizeofcmds, flags = struct.unpack_from(
                header_format, data, offset
            )
        except struct.error as error:
            raise MachOParseError("truncated_header") from error

        header = MachOHeader(
            magic=hex(magic_value),
            is_64_bit=is64,
            cpu_type=_CPU_TYPES.get(cputype, hex(cputype & 0xFFFFFFFF)),
            cpu_subtype=hex(cpusubtype & 0x00FFFFFF),
            file_type=_FILE_TYPES.get(filetype, hex(filetype)),
            number_of_load_commands=ncmds,
            size_of_load_commands=sizeofcmds,
            flags=flags,
        )

        commands_offset = offset + header_size
        segments: list[MachOSegment] = []
        load_commands: list[MachOLoadCommand] = []
        dylibs: list[MachODylib] = []
        uuid: str | None = None
        entry_point: int | None = None
        code_signature = MachOCodeSignature(present=False)
        entitlements = MachOEntitlements(present=False)
        suspicious_commands: list[str] = []
        text_vmaddr: int | None = None

        position = commands_offset
        end = min(offset + size, commands_offset + sizeofcmds)
        for _ in range(ncmds):
            if position + 8 > end:
                break
            try:
                cmd, cmdsize = struct.unpack_from(endian + "II", data, position)
            except struct.error:
                break
            if cmdsize < 8 or position + cmdsize > len(data):
                break
            name = _LC_NAMES.get(cmd, f"unknown(0x{cmd:x})")
            load_commands.append(MachOLoadCommand(command=name, command_id=cmd, size=cmdsize))
            if cmd not in _LC_NAMES:
                suspicious_commands.append(name)
            elif cmd in _SUSPICIOUS_LOAD_COMMANDS:
                suspicious_commands.append(name)

            if cmd in (_LC_SEGMENT, _LC_SEGMENT_64):
                segment = self._parse_segment(data, endian, position, cmd == _LC_SEGMENT_64)
                if segment is not None:
                    segments.append(segment)
                    if segment.name == "__TEXT" and text_vmaddr is None:
                        text_vmaddr = segment.vm_address
            elif cmd in _DYLIB_COMMANDS:
                dylib = self._parse_dylib(data, endian, position, cmdsize, name)
                if dylib is not None:
                    dylibs.append(dylib)
            elif cmd == _LC_UUID and cmdsize >= 24:
                uuid = data[position + 8 : position + 24].hex()
            elif cmd == _LC_MAIN and cmdsize >= 24:
                (entryoff,) = struct.unpack_from(endian + "Q", data, position + 8)
                entry_point = (text_vmaddr or 0) + entryoff if text_vmaddr is not None else entryoff
            elif cmd == _LC_CODE_SIGNATURE and cmdsize >= 16:
                dataoff, datasize = struct.unpack_from(endian + "II", data, position + 8)
                code_signature = MachOCodeSignature(present=True, offset=dataoff, size=datasize)
                entitlements = self._parse_entitlements(data, dataoff, datasize)
            elif cmd in (_LC_ENCRYPTION_INFO, _LC_ENCRYPTION_INFO_64) and cmdsize >= 20:
                _cryptoff, _cryptsize, cryptid = struct.unpack_from(endian + "III", data, position + 8)
                if cryptid:
                    suspicious_commands.append(f"encrypted_segment(cryptid={cryptid})")
            position += cmdsize

        exec_writable = tuple(
            f"{seg.name}/{sect.section_name}"
            for seg in segments
            for sect in seg.sections
            if sect.executable and sect.writable
        )
        high_entropy = tuple(
            f"{seg.name}/{sect.section_name}" for seg in segments for sect in seg.sections if sect.entropy >= _HIGH_ENTROPY_THRESHOLD
        )
        packed = bool(high_entropy) and (not dylibs or len(segments) <= 2)
        indicators = MachOIndicators(
            executable_writable_sections=exec_writable,
            suspicious_load_commands=tuple(suspicious_commands),
            high_entropy_sections=high_entropy,
            packed=packed,
        )

        return MachOArchInfo(
            header=header,
            entry_point=entry_point,
            uuid=uuid,
            load_commands=tuple(load_commands),
            segments=tuple(segments),
            linked_libraries=tuple(dylibs),
            code_signature=code_signature,
            entitlements=entitlements,
            indicators=indicators,
        )

    def _parse_segment(self, data: bytes, endian: str, position: int, is64: bool) -> MachOSegment | None:
        if is64:
            header_format = endian + "II16sQQQQiiII"
        else:
            header_format = endian + "II16sIIIIiiII"
        header_size = struct.calcsize(header_format)
        if position + header_size > len(data):
            return None
        try:
            fields = struct.unpack_from(header_format, data, position)
        except struct.error:
            return None
        _cmd, _cmdsize, segname, vmaddr, vmsize, fileoff, filesize, maxprot, initprot, nsects, flags = fields
        name = segname.split(b"\x00", 1)[0].decode("ascii", "replace")
        section_format = endian + ("16s16sQQIIIIIIII" if is64 else "16s16sIIIIIIIII")
        section_size = struct.calcsize(section_format)
        sections = []
        section_position = position + header_size
        for _ in range(nsects):
            if section_position + section_size > len(data):
                break
            try:
                section_fields = struct.unpack_from(section_format, data, section_position)
            except struct.error:
                break
            sectname_raw, segname_raw = section_fields[0], section_fields[1]
            if is64:
                addr, sect_size, sect_offset, align, reloff, nreloc, sect_flags = section_fields[2:9]
            else:
                addr, sect_size, sect_offset, align, reloff, nreloc, sect_flags = section_fields[2:9]
            sections.append(
                self._decorate_section(
                    data, name, sectname_raw, addr, sect_size, sect_offset, align, reloff, nreloc, sect_flags, initprot
                )
            )
            section_position += section_size
        return MachOSegment(
            name=name,
            vm_address=vmaddr,
            vm_size=vmsize,
            file_offset=fileoff,
            file_size=filesize,
            maximum_protection=maxprot,
            initial_protection=initprot,
            flags=flags,
            sections=tuple(sections),
        )

    def _decorate_section(
        self, data: bytes, segment_name: str, sectname_raw: bytes, addr: int, size: int, offset: int, align: int,
        reloff: int, nreloc: int, flags: int, segment_initprot: int,
    ) -> MachOSection:
        section_name = sectname_raw.split(b"\x00", 1)[0].decode("ascii", "replace")
        section_type = flags & 0xFF
        section_attrs = flags & 0xFFFFFF00
        is_zerofill = section_type == 1  # S_ZEROFILL: no file backing, content is not on disk
        blob = b"" if is_zerofill else data[offset : min(len(data), offset + size)]
        entropy = self._entropy(blob) if blob else 0.0
        executable = bool(section_attrs & (_S_ATTR_PURE_INSTRUCTIONS | _SECTION_ATTR_SOME_INSTRUCTIONS))
        writable = bool(segment_initprot & _VM_PROT_WRITE)
        suspicious = section_name.lower() in {"__upx", "__packed", "__enc"}
        return MachOSection(
            segment_name=segment_name,
            section_name=section_name,
            address=addr,
            size=size,
            offset=offset,
            align=align,
            reloff=reloff,
            number_of_relocations=nreloc,
            flags=flags,
            entropy=entropy,
            executable=executable,
            writable=writable,
            suspicious=suspicious,
        )

    def _parse_dylib(self, data: bytes, endian: str, position: int, cmdsize: int, command_name: str) -> MachODylib | None:
        if position + 24 > len(data):
            return None
        try:
            name_offset, _timestamp, current_version, compat_version = struct.unpack_from(endian + "IIII", data, position + 8)
        except struct.error:
            return None
        name_start = position + name_offset
        if name_offset < 8 or name_start >= position + cmdsize or name_start >= len(data):
            return None
        end = data.find(b"\x00", name_start, position + cmdsize)
        name = data[name_start : end if end >= 0 else position + cmdsize].decode("ascii", "replace")
        return MachODylib(
            name=name,
            command=command_name,
            current_version=self._version_string(current_version),
            compatibility_version=self._version_string(compat_version),
        )

    def _parse_entitlements(self, data: bytes, dataoff: int, datasize: int) -> MachOEntitlements:
        if not datasize or dataoff + datasize > len(data) or dataoff + 12 > len(data):
            return MachOEntitlements(present=False)
        try:
            magic, _length, count = struct.unpack_from(">III", data, dataoff)
        except struct.error:
            return MachOEntitlements(present=False)
        if magic != _CS_SUPERBLOB_MAGIC:
            return MachOEntitlements(present=False)
        for index in range(count):
            index_position = dataoff + 12 + index * 8
            if index_position + 8 > len(data):
                break
            try:
                blob_type, blob_offset = struct.unpack_from(">II", data, index_position)
            except struct.error:
                break
            if blob_type != _CSSLOT_ENTITLEMENTS:
                continue
            blob_position = dataoff + blob_offset
            if blob_position + 8 > len(data):
                return MachOEntitlements(present=False)
            try:
                _blob_magic, blob_length = struct.unpack_from(">II", data, blob_position)
            except struct.error:
                return MachOEntitlements(present=False)
            payload = data[blob_position + 8 : min(len(data), blob_position + blob_length)]
            try:
                xml_text = payload.decode("utf-8", "replace")
            except UnicodeDecodeError:
                return MachOEntitlements(present=True)
            keys = tuple(re.findall(r"<key>([^<]+)</key>", xml_text))
            return MachOEntitlements(present=True, keys=keys, raw_xml=xml_text)
        return MachOEntitlements(present=False)

    @staticmethod
    def _version_string(value: int) -> str:
        return f"{(value >> 16) & 0xFFFF}.{(value >> 8) & 0xFF}.{value & 0xFF}"

    @staticmethod
    def _entropy(blob: bytes) -> float:
        if not blob:
            return 0.0
        counts = [blob.count(bytes([i])) for i in range(256)]
        length = len(blob)
        return -sum((n / length) * math.log2(n / length) for n in counts if n)
