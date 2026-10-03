"""
test_artifacts.py — Evidence custody and memory-dump post-processing.

Custody is what separates an exhibit from a file. The tests here hold three
properties: an artifact is hashed at capture, the manifest detects its own
alteration, and captured evidence is never silently overwritten.

The memory tests cover the reason memory is captured at all — a packer has to
decrypt itself to run, so the dump contains what the file on disk concealed.
The finding is the *difference* between the two.

Run:
    pytest dynamic-sandbox/artifacts/test_artifacts.py -v
"""

from __future__ import annotations

import json
from uuid import uuid4

import pytest

from artifacts import (
    STATIC_ENGINE_AVAILABLE,
    ArtifactError,
    ArtifactStore,
    MemoryDumpAnalyzer,
    sha256_of,
)


@pytest.fixture
def store(tmp_path):
    return ArtifactStore(tmp_path / "evidence", uuid4())


@pytest.fixture
def pcap(tmp_path):
    path = tmp_path / "capture.pcap"
    path.write_bytes(b"\xd4\xc3\xb2\xa1" + b"\x00" * 500)
    return path


# ============================================================================
# Custody
# ============================================================================

class TestCustody:

    def test_artifact_is_hashed_at_capture(self, store, pcap):
        artifact = store.register(pcap, "pcap", stage_id="network")

        assert artifact.sha256 == sha256_of(pcap)
        assert artifact.size_bytes == pcap.stat().st_size
        assert artifact.stage_id == "network"

    def test_original_is_copied_not_moved_by_default(self, store, pcap):
        """The guest-side path is reverted out from under us by the next run."""
        store.register(pcap, "pcap")
        assert pcap.is_file()

    def test_move_is_available_for_large_artifacts(self, store, tmp_path):
        dump = tmp_path / "memory.raw"
        dump.write_bytes(b"\x00" * 10000)
        store.register(dump, "memdump", move=True)
        assert not dump.exists()

    def test_manifest_is_written_and_parseable(self, store, pcap):
        store.register(pcap, "pcap")
        manifest = json.loads(store.manifest_path.read_text(encoding="utf-8"))
        assert manifest["artifact_count"] == 1
        assert manifest["artifacts"][0]["sha256"]

    def test_chain_links_each_artifact_to_the_last(self, store, tmp_path):
        first = tmp_path / "one.log"
        first.write_text("first")
        second = tmp_path / "two.log"
        second.write_text("second")

        a = store.register(first, "log")
        b = store.register(second, "log")

        assert a.previous_sha256 == "0" * 64
        assert b.previous_sha256 == a.chain_hash

    def test_verification_passes_on_untouched_evidence(self, store, pcap):
        store.register(pcap, "pcap")
        assert store.verify()["intact"]

    def test_modified_artifact_is_detected(self, store, pcap):
        artifact = store.register(pcap, "pcap")
        from pathlib import Path

        Path(artifact.stored_path).write_bytes(b"tampered")

        report = store.verify()
        assert not report["intact"]
        assert "capture.pcap" in report["modified"]

    def test_deleted_artifact_is_detected(self, store, pcap):
        artifact = store.register(pcap, "pcap")
        from pathlib import Path

        Path(artifact.stored_path).unlink()

        report = store.verify()
        assert "capture.pcap" in report["missing"]

    def test_reordering_the_manifest_breaks_the_chain(self, store, tmp_path):
        """Removing the capture that contradicts a finding must be visible."""
        for name in ("a.log", "b.log", "c.log"):
            path = tmp_path / name
            path.write_text(name)
            store.register(path, "log")

        del store._artifacts[1]          # excise the middle exhibit
        assert store.verify()["chain_broken"]

    def test_identical_recapture_is_idempotent(self, store, pcap):
        first = store.register(pcap, "pcap")
        second = store.register(pcap, "pcap")
        assert first.artifact_id == second.artifact_id
        assert len(store.artifacts()) == 1

    def test_conflicting_recapture_is_refused(self, store, tmp_path):
        """Losing the original is the one failure that cannot be undone."""
        path = tmp_path / "shot.png"
        path.write_bytes(b"first image")
        store.register(path, "screenshot")

        path.write_bytes(b"different image entirely")
        with pytest.raises(ArtifactError, match="refusing to overwrite"):
            store.register(path, "screenshot")

    def test_missing_source_raises(self, store, tmp_path):
        with pytest.raises(ArtifactError, match="not found"):
            store.register(tmp_path / "absent.pcap", "pcap")

    def test_in_memory_content_can_be_captured(self, store):
        artifact = store.register_bytes(b"\x89PNG\r\n\x1a\n" + b"x" * 100,
                                        "screenshot", "stage3.png")
        assert artifact.size_bytes == 108
        assert store.artifacts("screenshot")

    def test_totals_are_reported(self, store, tmp_path):
        for index in range(3):
            path = tmp_path / f"f{index}.log"
            path.write_bytes(b"x" * 1000)
            store.register(path, "log")

        assert len(store.artifacts()) == 3
        assert store.total_bytes() == 3000


# ============================================================================
# Memory analysis
# ============================================================================

class TestMemoryAnalysis:

    def _dump(self, tmp_path, contents: bytes, name="memory.raw"):
        path = tmp_path / name
        # Zero padding around the payload, as a real image is mostly empty.
        path.write_bytes(b"\x00" * 4096 + contents + b"\x00" * 4096)
        return path

    def test_missing_dump_fails_without_raising(self, tmp_path):
        result = MemoryDumpAnalyzer().analyze(tmp_path / "absent.raw")
        assert result.status in ("failed", "engine_unavailable")

    @pytest.mark.skipif(not STATIC_ENGINE_AVAILABLE,
                        reason="static analysis engine not importable")
    def test_indicators_are_recovered_from_the_image(self, tmp_path):
        dump = self._dump(tmp_path, (
            b"https://c2.badactor.in/gate.php\x00"
            b"payee scamcollect@okhdfcbank\x00"
        ))
        result = MemoryDumpAnalyzer().analyze(dump)

        assert result.status == "completed"
        values = {item["value"] for item in result.indicators}
        assert "c2.badactor.in" in values
        assert "scamcollect@okhdfcbank" in values

    @pytest.mark.skipif(not STATIC_ENGINE_AVAILABLE,
                        reason="static analysis engine not importable")
    def test_the_finding_is_what_the_disk_file_did_not_show(self, tmp_path):
        """
        A packer decrypts itself to run, so the C2 appears in memory and not in
        the file. That difference is the entire reason to capture memory.
        """
        dump = self._dump(tmp_path, (
            b"https://known.example.in/api\x00"
            b"https://hidden-c2.badactor.in/gate\x00"
        ))
        result = MemoryDumpAnalyzer().analyze(
            dump, disk_indicators=["known.example.in", "https://known.example.in/api"]
        )

        hidden = {item["value"] for item in result.indicators_absent_from_disk}
        assert "hidden-c2.badactor.in" in hidden
        assert "known.example.in" not in hidden
        assert result.revealed_hidden_payload

    @pytest.mark.skipif(not STATIC_ENGINE_AVAILABLE,
                        reason="static analysis engine not importable")
    def test_signatures_match_against_the_image(self, tmp_path):
        dump = self._dump(tmp_path, (
            b"api.telegram.org\x00sendMessage\x00chat_id\x00sendDocument\x00"
        ))
        result = MemoryDumpAnalyzer().analyze(dump)
        assert any(match["rule_name"] == "C2_Telegram_Bot_Channel"
                   for match in result.signature_matches)

    @pytest.mark.skipif(not STATIC_ENGINE_AVAILABLE,
                        reason="static analysis engine not importable")
    def test_empty_image_reveals_nothing(self, tmp_path):
        dump = self._dump(tmp_path, b"\x00" * 1000)
        result = MemoryDumpAnalyzer().analyze(dump)
        assert result.status == "completed"
        assert not result.revealed_hidden_payload

    def test_absent_engine_is_reported_not_hidden(self, tmp_path):
        """
        "Nothing found" and "nothing looked" must never be the same output.
        """
        analyzer = MemoryDumpAnalyzer.__new__(MemoryDumpAnalyzer)
        analyzer._scanner = None
        analyzer._extractor = None

        result = analyzer.analyze(self._dump(tmp_path, b"payload"))
        assert result.status == "engine_unavailable"
        assert "not examined" in result.error
