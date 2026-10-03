"""
tests/test_packing.py — Unit tests for packer detection and best-effort
UPX unpacking.

Unpacking must never raise or block the pipeline regardless of whether
`upx` is installed on the host — these tests exercise both the
"upx missing" and "upx present but fails" paths without depending on a
real `upx` binary being available in CI or on a developer's machine.
"""

import pytest

from static_analysis.packing.detector import PackerDetector
from static_analysis.packing.unpacker import UpxUnpacker


class TestPackerDetector:
    def test_not_packed_returns_no_finding(self):
        finding = PackerDetector().detect(is_packed=False)
        assert finding.is_packed is False
        assert finding.packer_name is None

    def test_upx_section_signature_identifies_upx(self):
        finding = PackerDetector().detect(
            is_packed=True,
            suspicious_section_names=("upx1",),
            high_entropy_sections=("upx1",),
        )
        assert finding.is_packed is True
        assert finding.packer_name == "UPX"
        assert finding.confidence == pytest.approx(0.9)
        assert any("upx1" in item for item in finding.evidence)

    def test_themida_section_signature_identified(self):
        finding = PackerDetector().detect(is_packed=True, suspicious_section_names=(".themida",))
        assert finding.packer_name == "Themida"

    def test_packed_without_known_signature_reports_unknown_packer(self):
        finding = PackerDetector().detect(is_packed=True, high_entropy_sections=(".text",))
        assert finding.is_packed is True
        assert finding.packer_name == "unknown_packer"
        assert finding.confidence == pytest.approx(0.55)


class TestUpxUnpacker:
    def test_missing_upx_binary_reports_gracefully(self, monkeypatch, tmp_path):
        monkeypatch.setattr("shutil.which", lambda name: None)
        sample = tmp_path / "sample.exe"
        sample.write_bytes(b"MZ" + b"\x00" * 62)

        result = UpxUnpacker().unpack(sample)

        assert result.attempted is True
        assert result.succeeded is False
        assert result.error == "upx_not_installed"

    def test_nonexistent_source_reports_gracefully(self, monkeypatch, tmp_path):
        monkeypatch.setattr("shutil.which", lambda name: "upx")
        missing = tmp_path / "does_not_exist.exe"

        result = UpxUnpacker().unpack(missing)

        assert result.attempted is True
        assert result.succeeded is False
        assert result.error == "source_not_found"

    def test_unusable_upx_executable_never_raises(self, monkeypatch, tmp_path):
        """A upx path that resolves but can't actually execute (bad install,
        wrong permissions, etc.) must still degrade to a structured result."""
        monkeypatch.setattr("shutil.which", lambda name: "this-upx-binary-does-not-exist")
        sample = tmp_path / "sample.exe"
        sample.write_bytes(b"MZ" + b"\x00" * 62)

        result = UpxUnpacker().unpack(sample)

        assert result.attempted is True
        assert result.succeeded is False
        assert result.error is not None
