"""
tests/test_entropy_analysis.py — Byte-entropy analysis.

The governing negative case: an APK is a zip, so *every* APK measures above 7
bits per byte. If a high overall number were enough to call something packed,
this engine would flag every Android sample it ever saw. What must be detected
is entropy where the file's own structure does not account for it.
"""

from __future__ import annotations

import secrets
import zipfile

import pytest

from static_analysis.entropy import (
    EntropyClass,
    EntropyStatus,
    classify_entropy,
    create_entropy_analyzer,
    shannon_entropy,
)


@pytest.fixture
def analyzer():
    return create_entropy_analyzer()


# ============================================================================
# The primitive
# ============================================================================

class TestShannonEntropy:

    def test_empty_input_is_zero(self):
        assert shannon_entropy(b"") == 0.0

    def test_single_repeated_byte_is_zero(self):
        assert shannon_entropy(b"\x41" * 1000) == 0.0

    def test_uniform_distribution_is_eight(self):
        assert shannon_entropy(bytes(range(256)) * 4) == pytest.approx(8.0)

    def test_english_text_sits_in_the_text_band(self):
        text = b"the quick brown fox jumps over the lazy dog. " * 100
        assert classify_entropy(shannon_entropy(text)) is EntropyClass.TEXT

    def test_random_bytes_classify_as_packed_or_encrypted(self):
        assert classify_entropy(shannon_entropy(secrets.token_bytes(20000))) is (
            EntropyClass.PACKED_OR_ENCRYPTED
        )


# ============================================================================
# Whole-file and windowed analysis
# ============================================================================

class TestFileAnalysis:

    def test_empty_file_is_handled(self, analyzer, tmp_path):
        target = tmp_path / "empty.bin"
        target.write_bytes(b"")
        result = analyzer.analyze(target)
        assert result.status is EntropyStatus.COMPLETED
        assert result.classification is EntropyClass.EMPTY

    def test_missing_file_fails_without_raising(self, analyzer, tmp_path):
        result = analyzer.analyze(tmp_path / "absent.bin")
        assert result.status is EntropyStatus.FAILED
        assert result.error

    def test_plain_text_is_not_packed(self, analyzer, tmp_path):
        target = tmp_path / "notes.txt"
        target.write_bytes(b"ordinary readable content, nothing hidden here. " * 500)
        result = analyzer.analyze(target)
        assert result.classification is EntropyClass.TEXT
        assert not result.is_likely_packed

    def test_appended_encrypted_payload_is_located(self, analyzer, tmp_path):
        """
        The dropper pattern: a normal-looking file with a blob stapled to the
        end. Section-level entropy cannot see it because it belongs to no
        section.
        """
        target = tmp_path / "dropper.bin"
        target.write_bytes(b"MZ" + b"structured header data \x00\x01\x02" * 2000
                           + secrets.token_bytes(40000))
        result = analyzer.analyze(target)

        assert result.is_likely_packed
        trailing = [r for r in result.high_entropy_regions if r.reaches_end_of_file]
        assert trailing and trailing[0].size >= 4096
        assert result.packing_evidence

    def test_windows_cover_the_whole_file(self, analyzer, tmp_path):
        target = tmp_path / "sized.bin"
        target.write_bytes(b"A" * 40000)
        result = analyzer.analyze(target)
        assert sum(window.size for window in result.windows) == 40000


# ============================================================================
# Container members — where Android packing is actually visible
# ============================================================================

class TestContainerAnalysis:

    def _apk(self, path, extra: dict[str, bytes] | None = None):
        with zipfile.ZipFile(path, "w") as archive:
            archive.writestr("AndroidManifest.xml", b"<manifest/>" * 200)
            archive.writestr("classes.dex", b"dex\n035\x00" + b"\x11\x22\x33" * 4000)
            archive.writestr("res/drawable/icon.png",
                             b"\x89PNG\r\n\x1a\n" + secrets.token_bytes(20000))
            for name, payload in (extra or {}).items():
                archive.writestr(name, payload)
        return path

    def test_ordinary_apk_is_not_reported_as_packed(self, analyzer, tmp_path):
        """The whole point: a zip scores high and that means nothing on its own."""
        target = self._apk(tmp_path / "clean.apk")
        result = analyzer.analyze(target)
        assert result.overall_entropy > 6.0
        assert not result.is_likely_packed

    def test_encrypted_asset_disguised_as_json_is_found(self, analyzer, tmp_path):
        target = self._apk(tmp_path / "dropper.apk",
                           {"assets/config.json": secrets.token_bytes(30000)})
        result = analyzer.analyze(target)

        assert result.is_likely_packed
        blob = next(b for b in result.embedded_blobs if b.name == "assets/config.json")
        assert blob.declared_kind == "json"
        assert blob.entropy > 7.8

    def test_png_with_correct_magic_is_left_alone(self, analyzer, tmp_path):
        """Images are meant to be near-random; that is not evidence of anything."""
        target = self._apk(tmp_path / "clean.apk")
        result = analyzer.analyze(target)
        assert not any(b.name.endswith(".png") for b in result.embedded_blobs)

    def test_small_members_are_ignored(self, analyzer, tmp_path):
        """Entropy over a few hundred bytes is noise, not a measurement."""
        target = self._apk(tmp_path / "small.apk",
                           {"assets/tiny.json": secrets.token_bytes(64)})
        result = analyzer.analyze(target)
        assert not any(b.name == "assets/tiny.json" for b in result.embedded_blobs)

    def test_component_entropies_are_carried_through(self, analyzer, tmp_path):
        target = tmp_path / "with_sections.bin"
        target.write_bytes(b"payload" * 1000)
        result = analyzer.analyze(target, {".text": 6.1, ".rsrc": 7.9})
        assert result.component_entropies[".rsrc"] == 7.9
