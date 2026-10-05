import struct
import zipfile
from io import BytesIO

import pytest

from analysis.static.static_analysis.unified_parser import parse_binary, parser_evidence_hints


def tiny_elf(machine=62, bits=64, section_name=None):
    if bits == 64:
        ident = b"\x7fELF" + bytes([2, 1, 1, 0]) + b"\0" * 8
        header = ident + struct.pack("<HHIQQQIHHHHHH", 2, machine, 1, 0x400000, 0, 64, 0, 64, 0, 0, 64, 3 if section_name else 1, 1 if section_name else 0)
        sh0 = struct.pack("<IIQQQQIIQQ", 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)
    else:
        ident = b"\x7fELF" + bytes([1, 1, 1, 0]) + b"\0" * 8
        header = ident + struct.pack("<HHIIIIIHHHHHH", 2, machine, 1, 0x10000, 0, 52, 0, 52, 0, 0, 40, 3 if section_name else 1, 1 if section_name else 0)
        sh0 = struct.pack("<IIIIIIIIII", 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)
    if not section_name:
        return header + sh0
    if bits == 64:
        fmt, width = "<IIQQQQIIQQ", 64
    else:
        fmt, width = "<IIIIIIIIII", 40
    names = b"\0.shstrtab\0" + section_name.encode() + b"\0"
    names_offset = len(header) + width * 3
    data_offset = names_offset + len(names)
    name_offset = 1 + len(".shstrtab") + 1
    if bits == 64:
        shstr = struct.pack(fmt, 1, 3, 0, 0, names_offset, len(names), 0, 0, 1, 0)
        sec = struct.pack(fmt, name_offset, 1, 6, 0, data_offset, 8, 0, 0, 1, 0)
    else:
        shstr = struct.pack(fmt, 1, 3, 0, 0, names_offset, len(names), 0, 0, 1, 0)
        sec = struct.pack(fmt, name_offset, 1, 6, 0, data_offset, 8, 0, 0, 1, 0)
    return header + sh0 + shstr + sec + names + b"UPX0!!!\0"


def tiny_pe(machine=0x8664):
    data = bytearray(0x80 + 24 + 240)
    data[:2] = b"MZ"
    struct.pack_into("<I", data, 0x3c, 0x80)
    data[0x80:0x84] = b"PE\0\0"
    struct.pack_into("<HHIIIHH", data, 0x84, machine, 0, 0, 0, 0, 240, 0)
    struct.pack_into("<H", data, 0x98, 0x20b)
    return bytes(data)


def tiny_macho(cpu=0x01000007, bits=64):
    magic = b"\xcf\xfa\xed\xfe" if bits == 64 else b"\xce\xfa\xed\xfe"
    fmt = "<IiiIIIII" if bits == 64 else "<IiiIIII"
    fields = [cpu, 3, 2, 0, 0, 0, 0] + ([0] if bits == 64 else [])
    return magic + struct.pack(fmt, *fields)


def tiny_fat_macho():
    first, second = tiny_macho(7, 32), tiny_macho(0x0100000C, 64)
    offset1 = 8 + 2 * 20
    offset2 = offset1 + len(first)
    arch1 = struct.pack(">IIIII", 7, 3, offset1, len(first), 2)
    arch2 = struct.pack(">IIIII", 0x0100000C, 0, offset2, len(second), 3)
    return b"\xca\xfe\xba\xbe" + struct.pack(">I", 2) + arch1 + arch2 + first + second


def test_elf_and_unknown_machine_have_confidence_capped_static_hints():
    x64 = parse_binary(tiny_elf())
    arm = parse_binary(tiny_elf(40, 32))
    unknown = parse_binary(tiny_elf(0x7777))
    assert x64["format"] == "ELF" and x64["architecture"] == "x86_64"
    assert arm["architecture"] == "ARM" and arm["bitness"] == 32
    assert unknown["architecture"] == "e_machine=0x7777 (unmapped)"
    assert x64["confidence"] <= 0.5 and x64["source_type"] == "STATIC"
    assert parser_evidence_hints(x64)[0].confidence <= 0.5


def test_pe_header_timestamp_subsystem_and_sections():
    parsed = parse_binary(tiny_pe())
    assert parsed["format"] == "PE" and parsed["architecture"] == "x64"
    assert parsed["file_type"] == "exe" and parsed["compile_timestamp"] is not None


def test_macho_thin_and_fat_slices_are_reported_independently():
    thin = parse_binary(tiny_macho())
    fat = parse_binary(tiny_fat_macho())
    assert thin["format"] == "Mach-O" and len(thin["slices"]) == 1
    assert fat["format"] == "Mach-O" and len(fat["slices"]) == 2
    assert {item["architecture"] for item in fat["slices"]} == {"x86", "arm64"}


def test_upx_marker_uses_structural_section_name_detection():
    parsed = parse_binary(tiny_elf(section_name="upx0"), format_hint="ELF")
    assert parsed["parse_status"] == "success"
    assert parsed["packing"] == "detected"


def test_minimal_apk_is_partial_when_android_parser_dependency_is_unavailable():
    apk = BytesIO()
    with zipfile.ZipFile(apk, "w") as archive:
        archive.writestr("AndroidManifest.xml", b"\x03\x00\x08\x00")
    parsed = parse_binary(apk.getvalue(), format_hint="APK")
    assert parsed["format"] == "APK" and parsed["parse_status"] == "partial"
    assert "androguard" in parsed["reason"].lower()
    assert "AndroidManifest.xml" not in str(parsed)


@pytest.mark.parametrize("data", [b"", b"not a binary", b"\x7fELF\x02"])
def test_truncated_and_wrong_magic_fail_without_aborting_analysis(data):
    parsed = parse_binary(data)
    assert parsed["parse_status"] in {"failed", "partial"}
    assert parsed["reason"]
