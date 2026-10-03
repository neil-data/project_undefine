"""
ingestion/test_validation.py — Unit tests for the intake validation layer.

Covers the three checks validate_sample() performs (size bounds, magic-header
format detection, MIME derivation) plus the deliberate non-rejections:
extension mismatch and a lying Content-Type are recorded as signal, never used
to accept or refuse a sample.
"""

from __future__ import annotations

import pytest

from ingestion.conftest import (
    build_apk,
    build_elf,
    build_fat_mach_o,
    build_mach_o,
    build_pe,
    build_zip_without_manifest,
)
from ingestion.validation import (
    MIN_SAMPLE_BYTES,
    EmptyFileError,
    FileTooLargeError,
    FileTooSmallError,
    UnsupportedFormatError,
    ValidationError,
    detect_format,
    max_sample_bytes,
    validate_sample,
)


class TestFormatDetection:
    """Each supported format must be recognized from its magic header alone."""

    def test_detects_apk(self, write_sample):
        assert detect_format(write_sample(build_apk(), "app.apk")) == "apk"

    def test_detects_pe_executable(self, write_sample):
        assert detect_format(write_sample(build_pe(), "tool.exe")) == "exe"

    def test_detects_pe_dll_via_characteristics_flag(self, write_sample):
        """IMAGE_FILE_DLL (0x2000) is the only thing separating a DLL from an EXE."""
        assert detect_format(write_sample(build_pe(characteristics=0x2102), "lib.dll")) == "dll"

    def test_detects_elf_executable(self, write_sample):
        assert detect_format(write_sample(build_elf(elf_type=2), "binary")) == "elf"

    def test_detects_elf_shared_object(self, write_sample):
        assert detect_format(write_sample(build_elf(elf_type=3), "lib.so")) == "elf"

    def test_detects_32_bit_elf(self, write_sample):
        assert detect_format(write_sample(build_elf(bitness=1), "binary32")) == "elf"

    def test_detects_thin_mach_o(self, write_sample):
        assert detect_format(write_sample(build_mach_o(), "binary")) == "mach_o"

    def test_detects_universal_mach_o(self, write_sample):
        assert detect_format(write_sample(build_fat_mach_o(), "binary")) == "mach_o"


class TestFormatRejection:
    """Anything the pipeline cannot analyze must be refused at the door."""

    def test_rejects_plain_text(self, write_sample):
        assert detect_format(write_sample(b"just some notes\n" * 32, "notes.txt")) is None

    def test_rejects_zeroed_file_named_apk(self, write_sample):
        """The filename claims APK; the bytes say nothing. Magic wins."""
        assert detect_format(write_sample(b"\x00" * 4096, "malware.apk")) is None

    def test_rejects_zip_without_android_manifest(self, write_sample):
        """A valid ZIP is not an APK — the detector must read the archive listing."""
        assert detect_format(write_sample(build_zip_without_manifest(), "archive.zip")) is None

    def test_rejects_mz_stub_without_pe_signature(self, write_sample):
        """DOS executables start with MZ but have no PE header; not analyzable."""
        assert detect_format(write_sample(b"MZ" + b"\x00" * 512, "old.exe")) is None

    def test_rejects_elf_relocatable_object(self, write_sample):
        """ET_REL (1) is an intermediate object file, not a sample to detonate."""
        assert detect_format(write_sample(build_elf(elf_type=1), "object.o")) is None

    def test_rejects_elf_with_bad_version_byte(self, write_sample):
        data = bytearray(build_elf())
        data[6] = 0  # EI_VERSION must be 1
        assert detect_format(write_sample(bytes(data), "corrupt")) is None

    def test_rejects_fat_mach_o_with_zero_architectures(self, write_sample):
        assert detect_format(write_sample(build_fat_mach_o(arch_count=0), "empty")) is None

    def test_unsupported_format_raises_415(self, write_sample):
        with pytest.raises(UnsupportedFormatError) as excinfo:
            validate_sample(write_sample(b"not a binary\n" * 64, "notes.txt"))
        assert excinfo.value.status_code == 415
        assert excinfo.value.code == "unsupported_format"


class TestSizeBounds:
    def test_empty_file_rejected(self, write_sample):
        with pytest.raises(EmptyFileError) as excinfo:
            validate_sample(write_sample(b"", "empty.exe"))
        assert excinfo.value.status_code == 400

    def test_truncated_file_rejected_as_size_not_format(self, write_sample):
        """
        A 2-byte file has no readable header. Reporting it as "unsupported
        format" would send an investigator hunting for a format problem when
        the real issue is a truncated upload — so the size check runs first.
        """
        with pytest.raises(FileTooSmallError):
            validate_sample(write_sample(b"MZ", "truncated.exe"))

    def test_file_at_minimum_size_boundary_is_accepted(self, write_sample):
        """MIN_SAMPLE_BYTES is inclusive — exactly the minimum must pass."""
        elf = build_elf()[:MIN_SAMPLE_BYTES]
        assert len(elf) == MIN_SAMPLE_BYTES
        result = validate_sample(write_sample(elf, "tiny.elf"))
        assert result.file_format == "elf"

    def test_oversized_file_rejected_with_413(self, write_sample, monkeypatch):
        monkeypatch.setenv("INGESTION_MAX_SAMPLE_BYTES", "512")
        with pytest.raises(FileTooLargeError) as excinfo:
            validate_sample(write_sample(build_pe() + b"\x00" * 1024, "big.exe"))
        assert excinfo.value.status_code == 413

    def test_file_exactly_at_limit_is_accepted(self, write_sample, monkeypatch):
        """The bound is `> limit`, so a sample of exactly `limit` bytes passes."""
        elf = build_elf()
        monkeypatch.setenv("INGESTION_MAX_SAMPLE_BYTES", str(len(elf)))
        assert validate_sample(write_sample(elf, "exact.elf")).size_bytes == len(elf)


class TestSizeLimitConfiguration:
    def test_limit_read_from_environment(self, monkeypatch):
        monkeypatch.setenv("INGESTION_MAX_SAMPLE_BYTES", "4096")
        assert max_sample_bytes() == 4096

    def test_malformed_limit_falls_back_to_default(self, monkeypatch):
        """A typo in deployment config must not disable the size cap entirely."""
        monkeypatch.setenv("INGESTION_MAX_SAMPLE_BYTES", "not-a-number")
        assert max_sample_bytes() == 256 * 1024 * 1024

    def test_non_positive_limit_falls_back_to_default(self, monkeypatch):
        monkeypatch.setenv("INGESTION_MAX_SAMPLE_BYTES", "0")
        assert max_sample_bytes() == 256 * 1024 * 1024


class TestMimeAndPlatformDerivation:
    @pytest.mark.parametrize(
        "builder, name, expected_format, expected_platform, expected_mime",
        [
            (build_apk, "app.apk", "apk", "android", "application/vnd.android.package-archive"),
            (build_pe, "tool.exe", "exe", "windows", "application/vnd.microsoft.portable-executable"),
            (build_elf, "binary.elf", "elf", "linux", "application/x-elf"),
            (build_mach_o, "binary.dylib", "mach_o", "macos", "application/x-mach-binary"),
        ],
    )
    def test_mime_and_platform_follow_detected_format(
        self, write_sample, builder, name, expected_format, expected_platform, expected_mime
    ):
        result = validate_sample(write_sample(builder(), name))
        assert result.file_format == expected_format
        assert result.platform == expected_platform
        assert result.mime_type == expected_mime

    def test_declared_content_type_is_never_trusted(self, write_sample):
        """
        A caller claiming "image/png" for a PE must not change the verdict —
        Content-Type is attacker-controlled.
        """
        result = validate_sample(
            write_sample(build_pe(), "photo.png"),
            declared_content_type="image/png",
        )
        assert result.file_format == "exe"
        assert result.mime_type == "application/vnd.microsoft.portable-executable"
        assert result.declared_content_type == "image/png"


class TestExtensionMismatch:
    """
    Mismatch is investigative signal, not grounds for rejection — a Windows
    trojan named invoice.pdf is precisely what this platform exists to analyze.
    """

    def test_mismatch_flagged_but_sample_accepted(self, write_sample):
        result = validate_sample(
            write_sample(build_pe(), "invoice.pdf"), declared_filename="invoice.pdf"
        )
        assert result.file_format == "exe"
        assert result.extension_mismatch is True

    def test_matching_extension_not_flagged(self, write_sample):
        result = validate_sample(
            write_sample(build_pe(), "tool.exe"), declared_filename="tool.exe"
        )
        assert result.extension_matches is True

    def test_absent_filename_is_not_a_mismatch(self, write_sample):
        """Nothing was declared, so nothing contradicts the magic bytes."""
        result = validate_sample(write_sample(build_pe(), "tool.exe"), declared_filename=None)
        assert result.extension_matches is True

    def test_dll_extension_recognized_for_dll(self, write_sample):
        result = validate_sample(
            write_sample(build_pe(characteristics=0x2102), "lib.dll"), declared_filename="lib.dll"
        )
        assert result.file_format == "dll"
        assert result.extension_matches is True

    def test_apk_extension_recognized(self, write_sample):
        result = validate_sample(write_sample(build_apk(), "app.apk"), declared_filename="app.apk")
        assert result.file_format == "apk"
        assert result.extension_matches is True


class TestErrorContract:
    def test_missing_file_raises_validation_error(self, tmp_path):
        with pytest.raises(ValidationError):
            validate_sample(tmp_path / "does-not-exist.exe")

    def test_error_detail_is_machine_readable(self, write_sample):
        with pytest.raises(UnsupportedFormatError) as excinfo:
            validate_sample(write_sample(b"plain text\n" * 64, "notes.txt"))
        detail = excinfo.value.as_detail()
        assert detail["error"] == "unsupported_format"
        assert isinstance(detail["message"], str) and detail["message"]
