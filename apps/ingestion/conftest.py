"""
ingestion/conftest.py — Shared fixtures for the ingestion-layer test suite.

The gateway validates by magic header, so its tests need bytes that are
*structurally* real — a file named "sample.apk" full of zeros must be rejected,
and only a genuine ZIP-with-AndroidManifest may pass. These builders produce
the minimum byte sequence each detector in ingestion/validation.py accepts:
real headers, no payload. They are deliberately not malware and not fixtures on
disk, so nothing here trips the repo's "never commit real samples" rule.

Every builder pads to at least validation.MIN_SAMPLE_BYTES so that a test
exercising format detection isn't accidentally rejected on size first.
"""

from __future__ import annotations

import io
import struct
import zipfile

import pytest

from ingestion.validation import MIN_SAMPLE_BYTES


def _pad(data: bytes, minimum: int = MIN_SAMPLE_BYTES * 2) -> bytes:
    """Right-pad with a non-zero filler so the result clears the minimum size."""
    if len(data) >= minimum:
        return data
    return data + (b"\x90" * (minimum - len(data)))


def build_elf(elf_type: int = 2, machine: int = 62, bitness: int = 2) -> bytes:
    """
    Minimal ELF: e_ident + e_type/e_machine at offset 16.

    elf_type 2 = ET_EXEC, 3 = ET_DYN (both accepted), 1 = ET_REL (rejected).
    """
    header = bytearray(64)
    header[0:4] = b"\x7fELF"
    header[4] = bitness   # EI_CLASS: 1=32-bit, 2=64-bit
    header[5] = 1         # EI_DATA: little-endian
    header[6] = 1         # EI_VERSION
    struct.pack_into("<HH", header, 16, elf_type, machine)
    return _pad(bytes(header))


def build_pe(characteristics: int = 0x0102, machine: int = 0x8664) -> bytes:
    """
    Minimal PE: MZ stub, e_lfanew at 0x3C pointing to a PE\\0\\0 + COFF header.

    characteristics 0x2000 sets IMAGE_FILE_DLL, which is how the detector
    distinguishes a DLL from an EXE.
    """
    pe_offset = 0x80
    image = bytearray(pe_offset + 24)
    image[0:2] = b"MZ"
    struct.pack_into("<I", image, 0x3C, pe_offset)
    image[pe_offset:pe_offset + 4] = b"PE\x00\x00"
    # COFF: machine, num_sections, timestamp, symtab_ptr, num_symbols,
    #       optional_header_size, characteristics
    struct.pack_into("<HHIIIHH", image, pe_offset + 4, machine, 1, 0, 0, 0, 0, characteristics)
    return _pad(bytes(image))


def build_mach_o(magic: bytes = b"\xcf\xfa\xed\xfe", file_type: int = 2) -> bytes:
    """Minimal thin 64-bit little-endian Mach-O image."""
    image = bytearray(64)
    image[0:4] = magic
    struct.pack_into("<iiI", image, 4, 0x01000007, 3, file_type)  # cpu_type, subtype, filetype
    return _pad(bytes(image))


def build_fat_mach_o(arch_count: int = 2) -> bytes:
    """Minimal universal ("fat") Mach-O — big-endian magic plus an arch count."""
    image = bytearray(64)
    image[0:4] = b"\xca\xfe\xba\xbe"
    struct.pack_into(">I", image, 4, arch_count)
    return _pad(bytes(image))


def build_apk(include_manifest: bool = True) -> bytes:
    """
    Minimal APK: a real ZIP archive containing an AndroidManifest.xml entry.

    With include_manifest=False this produces a structurally valid ZIP that is
    *not* an APK — the case that proves the detector checks archive contents
    rather than stopping at the PK magic bytes.
    """
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
        if include_manifest:
            archive.writestr("AndroidManifest.xml", b"\x03\x00\x08\x00" + b"\x00" * 128)
        archive.writestr("classes.dex", b"dex\n035\x00" + b"\x00" * 128)
        archive.writestr("resources.arsc", b"\x02\x00\x0c\x00" + b"\x00" * 128)
    return _pad(buffer.getvalue())


def build_zip_without_manifest() -> bytes:
    return build_apk(include_manifest=False)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def elf_bytes() -> bytes:
    return build_elf()


@pytest.fixture
def pe_exe_bytes() -> bytes:
    return build_pe()


@pytest.fixture
def pe_dll_bytes() -> bytes:
    return build_pe(characteristics=0x2102)


@pytest.fixture
def mach_o_bytes() -> bytes:
    return build_mach_o()


@pytest.fixture
def apk_bytes() -> bytes:
    return build_apk()


@pytest.fixture
def write_sample(tmp_path):
    """Write bytes to a temp file and return its Path — the shape validate_sample() takes."""
    def _write(data: bytes, name: str = "sample.bin"):
        target = tmp_path / name
        target.write_bytes(data)
        return target

    return _write
