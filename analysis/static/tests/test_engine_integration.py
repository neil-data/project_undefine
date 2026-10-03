"""
tests/test_engine_integration.py — End-to-end regression tests for
`StaticAnalysisEngine.analyze()`.

These exist specifically because of a real bug found during review:
`core/engine.py` tried to read `res.info.__dict__` to pull format-specific
facts (permissions, packing indicators, entropy) into the rule engine, but
every format info model is a frozen, *slotted* dataclass — which has no
`__dict__`. That silently made `format_details` always `{}`, so rules like
`PackedBinaryRule`, `HighEntropyRule`, and `DangerousPermissionsRule` never
fired through the real pipeline despite each format parser computing the
right facts. These tests exist so that failure mode can never silently
reappear — if the bug regresses, these tests fail loudly instead of
packing/permission findings just quietly vanishing.
"""

import gzip
import random
import struct
import zipfile

import pytest

from static_analysis.bootstrap import create_engine


def _build_elf(section_name: str | None = None, packed_payload: bool = False) -> bytes:
    """Build a minimal but structurally valid ELF64 executable, optionally
    with one extra section carrying a packer-style name and high-entropy
    (i.e. random) content."""
    ei = b"\x7fELF" + bytes([2, 1, 1, 0]) + b"\x00" * 8
    e_type, e_machine, e_version = 2, 62, 1
    e_entry, e_phoff, e_shoff, e_flags = 0x400000, 0, 64, 0
    e_ehsize, e_phentsize, e_phnum, e_shentsize = 64, 0, 0, 64
    e_shnum = 3 if section_name else 1
    e_shstrndx = 1 if section_name else 0

    header = ei + struct.pack(
        "<HHIQQQIHHHHHH",
        e_type, e_machine, e_version, e_entry, e_phoff, e_shoff, e_flags,
        e_ehsize, e_phentsize, e_phnum, e_shentsize, e_shnum, e_shstrndx,
    )
    if not section_name:
        sh0 = struct.pack("<IIQQQQIIQQ", 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)
        return header + sh0

    shstrtab = b"\x00" + b".shstrtab\x00" + section_name.encode() + b"\x00"
    shstrtab_off = 64 + 64 * 3
    sh0 = struct.pack("<IIQQQQIIQQ", 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)
    sh1 = struct.pack("<IIQQQQIIQQ", 1, 3, 0, 0, shstrtab_off, len(shstrtab), 0, 0, 1, 0)

    section_name_off = 1 + len(".shstrtab\x00")
    data_off = shstrtab_off + len(shstrtab)
    if packed_payload:
        random.seed(1)
        blob = bytes(random.randrange(256) for _ in range(2000))
    else:
        blob = b"\x00" * 64
    sh2 = struct.pack("<IIQQQQIIQQ", section_name_off, 1, 0x6, 0, data_off, len(blob), 0, 0, 1, 0)

    return header + sh0 + sh1 + sh2 + shstrtab + blob


_MANIFEST_WITH_SMS_PERMISSION = """<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="com.quickloan.easyapp">
    <uses-permission android:name="android.permission.READ_SMS" />
    <application android:label="Quick Loan">
        <activity android:name=".MainActivity" />
    </application>
</manifest>
"""


@pytest.fixture
def engine():
    return create_engine()


class TestFormatDetailsRegression:
    """Regression coverage for the __dict__/asdict bug described above."""

    def test_packed_elf_fires_packed_and_high_entropy_rules(self, engine, tmp_path):
        sample = tmp_path / "packed.elf"
        sample.write_bytes(_build_elf(section_name="upx1", packed_payload=True))

        report = engine.analyze(sample)
        rule_names = {m["rule_name"] for m in report["yara_matches"]}

        assert "builtin.packed_binary" in rule_names
        assert "builtin.high_entropy" in rule_names
        assert report["packing"]["is_packed"] is True
        assert report["packing"]["packer_name"] == "UPX"

    def test_plain_elf_is_not_flagged_as_packed(self, engine, tmp_path):
        sample = tmp_path / "plain.elf"
        sample.write_bytes(_build_elf())

        report = engine.analyze(sample)

        assert report["packing"]["is_packed"] is False
        assert report["packing"]["unpack_attempted"] is False

    def test_apk_dangerous_permission_fires_through_unified_pipeline(self, engine, tmp_path):
        sample = tmp_path / "quickloan.apk"
        with zipfile.ZipFile(sample, "w") as z:
            z.writestr("AndroidManifest.xml", _MANIFEST_WITH_SMS_PERMISSION)
            z.writestr("classes.dex", "irrelevant payload")

        report = engine.analyze(sample)
        rule_names = {m["rule_name"] for m in report["yara_matches"]}

        assert "builtin.dangerous_permissions" in rule_names


class TestUnpackNeverBlocksThePipeline:
    def test_packed_sample_without_upx_installed_still_completes(self, engine, monkeypatch, tmp_path):
        monkeypatch.setattr("shutil.which", lambda name: None)
        sample = tmp_path / "packed.elf"
        sample.write_bytes(_build_elf(section_name="upx1", packed_payload=True))

        report = engine.analyze(sample)

        assert report["packing"]["is_packed"] is True
        assert report["packing"]["unpack_attempted"] is True
        assert report["packing"]["unpack_succeeded"] is False
        assert report["packing"]["unpack_error"] == "upx_not_installed"


class TestCompressedContainerSupport:
    def test_zip_wrapped_executable_is_analyzed_like_the_plain_file(self, engine, tmp_path):
        payload = _build_elf()
        plain = tmp_path / "plain.elf"
        plain.write_bytes(payload)

        wrapped = tmp_path / "sample.zip"
        with zipfile.ZipFile(wrapped, "w") as z:
            z.writestr("sample.elf", payload)

        plain_report = engine.analyze(plain)
        wrapped_report = engine.analyze(wrapped)

        assert wrapped_report["file_type"] == "elf"
        assert wrapped_report["sha256"] == plain_report["sha256"]
        assert wrapped_report["container"] == {"type": "zip", "original_entry": "sample.elf"}
        assert plain_report["container"] is None

    def test_gzip_wrapped_executable_is_analyzed(self, engine, tmp_path):
        payload = _build_elf()
        wrapped = tmp_path / "sample.elf.gz"
        with gzip.open(wrapped, "wb") as f:
            f.write(payload)

        report = engine.analyze(wrapped)

        assert report["file_type"] == "elf"
        assert report["container"]["type"] == "gzip"

    def test_apk_zip_container_still_works_directly(self, engine, tmp_path):
        """APK is itself a ZIP — must be handled by the APK analyzer directly,
        not treated as a generic wrapped container."""
        sample = tmp_path / "quickloan.apk"
        with zipfile.ZipFile(sample, "w") as z:
            z.writestr("AndroidManifest.xml", _MANIFEST_WITH_SMS_PERMISSION)
            z.writestr("classes.dex", "irrelevant payload")

        report = engine.analyze(sample)

        assert report["file_type"] == "apk"
        assert report["container"] is None
