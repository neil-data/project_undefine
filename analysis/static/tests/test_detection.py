"""
tests/test_detection.py — Regression tests for file-type detection.

These exist specifically because of a real bug found during review:
all magic-byte signatures had doubled backslashes (e.g. b"PK\\x03\\x04"
instead of b"PK\x03\x04"), which silently made detection impossible
for every single format. It passed a read-through review but failed
immediately when actually run. These tests exist so that failure mode
can never silently reappear — if any signature regresses, one of
these tests will fail loudly instead of detection just quietly
returning UNKNOWN for everything.
"""

import struct
import zipfile

import pytest

from static_analysis.detection.bootstrap import create_file_type_detector
from static_analysis.detection.models import FileFormat


@pytest.fixture
def detector():
    return create_file_type_detector()


class TestMagicByteDetection:
    """One test per format's real magic bytes — this is exactly what
    the doubled-backslash bug broke for all 5 formats simultaneously.

    Fixtures here build structurally VALID minimal files (not just
    magic bytes + zero padding) because the real detectors correctly
    perform additional validation beyond the magic bytes alone (e.g.
    APK requires a real ZIP containing AndroidManifest.xml; ELF
    requires valid class/version/type fields). A naive all-zeros
    fixture fails that legitimate validation and would falsely look
    like a detection bug.
    """

    def test_zip_apk_magic_detected(self, detector, tmp_path):
        f = tmp_path / "test.apk"
        with zipfile.ZipFile(f, "w") as z:
            z.writestr("AndroidManifest.xml", "<manifest/>")
        result = detector.detect(f)
        assert result.file_format == FileFormat.APK, (
            "ZIP/APK magic bytes not detected — check for doubled "
            "backslashes in detectors.py (b'PK\\\\x03\\\\x04' instead of b'PK\\x03\\x04')"
        )

    def test_pe_magic_detected(self, detector, tmp_path):
        f = tmp_path / "test.exe"
        # DOS header: "MZ" + padding, e_lfanew (offset 0x3C) points to PE header at offset 64
        dos_header = bytearray(64)
        dos_header[0:2] = b"MZ"
        dos_header[0x3C:0x40] = struct.pack("<I", 64)
        # PE header: signature + minimal COFF header (machine, sections, timestamp, etc., characteristics)
        pe_header = b"PE\x00\x00" + struct.pack("<HHIIIHH", 0x8664, 0, 0, 0, 0, 0, 0x0002)
        f.write_bytes(bytes(dos_header) + pe_header)
        result = detector.detect(f)
        assert result.file_format == FileFormat.PE, (
            "PE magic bytes not detected — check for doubled backslashes "
            "in detectors.py (b'PE\\\\x00\\\\x00' instead of b'PE\\x00\\x00')"
        )

    def test_elf_magic_detected(self, detector, tmp_path):
        f = tmp_path / "test.elf"
        # e_ident: magic, class=2 (64-bit), data=1 (little-endian), version=1
        e_ident = b"\x7fELF" + bytes([2, 1, 1]) + b"\x00" * 9
        # e_type=2 (ET_EXEC), e_machine=0x3E (x86-64), at header offset 16
        rest = struct.pack("<HH", 2, 0x3E)
        f.write_bytes(e_ident + rest)
        result = detector.detect(f)
        assert result.file_format == FileFormat.ELF, (
            "ELF magic bytes not detected — check for doubled backslashes "
            "in detectors.py (b'\\\\x7fELF' instead of b'\\x7fELF')"
        )

    def test_macho_64_le_magic_detected(self, detector, tmp_path):
        f = tmp_path / "test.macho"
        # magic + cputype + cpusubtype + filetype(2=MH_EXECUTE), little-endian
        header = b"\xcf\xfa\xed\xfe" + struct.pack("<iiI", 0x01000007, 0, 2)
        f.write_bytes(header + b"\x00" * 16)
        result = detector.detect(f)
        assert result.file_format == FileFormat.MACH_O, (
            "Mach-O magic bytes not detected — check for doubled backslashes "
            "in detectors.py's _THIN_MAGICS dict"
        )

    def test_macho_fat_magic_detected(self, detector, tmp_path):
        f = tmp_path / "test_fat.macho"
        # FAT magic + nfat_arch=1 (big-endian, as real FAT headers are)
        header = b"\xca\xfe\xba\xbe" + struct.pack(">I", 1)
        f.write_bytes(header + b"\x00" * 24)
        result = detector.detect(f)
        assert result.file_format == FileFormat.MACH_O, (
            "Mach-O FAT magic bytes not detected — check for doubled "
            "backslashes in detectors.py's _FAT_MAGICS dict"
        )

    def test_no_false_positive_on_plain_text(self, detector, tmp_path):
        f = tmp_path / "test.txt"
        f.write_bytes(b"This is just a plain text file, not a binary.")
        result = detector.detect(f)
        assert result.file_format == FileFormat.UNKNOWN
