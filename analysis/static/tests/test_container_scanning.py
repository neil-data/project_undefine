"""
tests/test_container_scanning.py — Decompressed container analysis.

THE BUG THIS SUITE EXISTS FOR
-----------------------------
A real APK deflate-compresses its members. Scanning the file on disk therefore
reads compressed bytes: the DEX is invisible, the manifest is invisible, and
every Android signature matches nothing at all.

It was invisible in testing because `ZipFile.writestr` defaults to
ZIP_STORED — every fixture in this repository was uncompressed, so the rules
matched in tests and would have detected nothing on a real sample. Every test
here that builds an APK uses ZIP_DEFLATED for exactly that reason.
"""

from __future__ import annotations

import secrets
import zipfile

import pytest

from static_analysis.container import ContainerMember, is_container, iter_members
from static_analysis.core.engine import StaticAnalysisEngine
from static_analysis.yara_scan import YARA_AVAILABLE


SCAM_DEX = (
    b"dex\n035\x00"
    b"echallan parivahan challan rto pay now fine amount upi://pay "
    b"HDFCBK one time password do not share abortBroadcast "
    b"android.provider.Telephony.SMS_RECEIVED sendTextMessage "
    b"https://challan-pay.example-scam.in/collect scamcollect@okhdfcbank\x00"
)
SCAM_MANIFEST = (
    "android.permission.RECEIVE_SMS android.permission.READ_SMS"
).encode("utf-16-le")


def build_apk(path, compression=zipfile.ZIP_DEFLATED, extra: dict | None = None):
    with zipfile.ZipFile(path, "w", compression=compression) as archive:
        archive.writestr("AndroidManifest.xml", SCAM_MANIFEST)
        archive.writestr("classes.dex", SCAM_DEX)
        for name, payload in (extra or {}).items():
            archive.writestr(name, payload)
    return path


@pytest.fixture(scope="module")
def engine():
    return StaticAnalysisEngine()


# ============================================================================
# Member iteration
# ============================================================================

class TestMemberIteration:

    def test_detects_containers(self, tmp_path):
        apk = build_apk(tmp_path / "a.apk")
        plain = tmp_path / "b.bin"
        plain.write_bytes(b"MZ not a zip")

        assert is_container(apk)
        assert not is_container(plain)

    def test_members_are_returned_decompressed(self, tmp_path):
        apk = build_apk(tmp_path / "a.apk")
        members = {member.name: member.data for member in iter_members(apk)}
        assert b"echallan" in members["classes.dex"]

    def test_manifest_and_dex_come_first(self, tmp_path):
        """
        The limits are real, so the members that carry the behaviour must be
        read before four hundred drawable resources are.
        """
        extra = {f"res/raw/file{i}.dat": b"padding" * 100 for i in range(50)}
        apk = build_apk(tmp_path / "padded.apk", extra=extra)
        names = [member.name for member in iter_members(apk)]
        assert names[:2] == ["AndroidManifest.xml", "classes.dex"]

    def test_media_members_are_skipped(self, tmp_path):
        apk = build_apk(tmp_path / "a.apk",
                        extra={"res/drawable/icon.png": b"\x89PNG" + b"x" * 5000})
        assert not any(m.name.endswith(".png") for m in iter_members(apk))

    def test_member_count_is_bounded(self, tmp_path):
        extra = {f"res/raw/f{i}.dat": b"x" * 10 for i in range(60)}
        apk = build_apk(tmp_path / "many.apk", extra=extra)
        assert len(list(iter_members(apk, max_members=10))) == 10

    def test_total_size_is_bounded(self, tmp_path):
        extra = {f"res/raw/f{i}.dat": b"x" * 20000 for i in range(20)}
        apk = build_apk(tmp_path / "big.apk", extra=extra)
        total = sum(len(m.data) for m in iter_members(apk, max_total_bytes=50000))
        assert total <= 50000

    def test_oversized_member_is_skipped_not_read(self, tmp_path):
        """A decompression bomb must not be materialized to find out it is one."""
        apk = build_apk(tmp_path / "bomb.apk", extra={"payload.bin": b"\x00" * 200000})
        names = [m.name for m in iter_members(apk, max_member_bytes=1000)]
        assert "payload.bin" not in names

    def test_compression_ratio_is_exposed(self, tmp_path):
        apk = build_apk(tmp_path / "a.apk", extra={"flat.txt": b"A" * 100000})
        member = next(m for m in iter_members(apk) if m.name == "flat.txt")
        assert member.compression_ratio > 10

    def test_corrupt_container_yields_nothing_without_raising(self, tmp_path):
        broken = tmp_path / "broken.apk"
        broken.write_bytes(b"PK\x03\x04" + secrets.token_bytes(500))
        assert list(iter_members(broken)) == []


# ============================================================================
# End-to-end: the compressed sample must analyze like an uncompressed one
# ============================================================================

@pytest.mark.skipif(not YARA_AVAILABLE, reason="yara-python not installed")
class TestCompressedSampleAnalysis:

    def test_deflated_apk_matches_signatures(self, engine, tmp_path):
        report = engine.analyze(build_apk(tmp_path / "deflated.apk"))
        assert report["signatures"]["match_count"] > 0
        assert report["signatures"]["india_scam_matches"]

    def test_compression_does_not_change_the_verdict(self, engine, tmp_path):
        deflated = engine.analyze(build_apk(tmp_path / "d.apk", zipfile.ZIP_DEFLATED))
        stored = engine.analyze(build_apk(tmp_path / "s.apk", zipfile.ZIP_STORED))

        assert deflated["classification"]["verdict"] == stored["classification"]["verdict"]
        assert deflated["classification"]["scam_type"] == stored["classification"]["scam_type"]
        assert (set(deflated["signatures"]["india_scam_matches"])
                == set(stored["signatures"]["india_scam_matches"]))

    def test_cross_member_rules_still_match(self, engine, tmp_path):
        """
        Permissions live in the manifest and behaviour lives in the DEX, so a
        rule needing both matches neither member alone — the combined view is
        what makes it fire.
        """
        report = engine.analyze(build_apk(tmp_path / "cross.apk"))
        assert "IN_EChallan_OTP_Interceptor" in report["signatures"]["india_scam_matches"]

    def test_indicators_are_recovered_from_compressed_members(self, engine, tmp_path):
        report = engine.analyze(build_apk(tmp_path / "iocs.apk"))
        actionable = {item["value"] for item in report["iocs"]["actionable"]}
        assert "challan-pay.example-scam.in" in actionable
        assert "scamcollect@okhdfcbank" in actionable

    def test_match_reports_which_member_carried_it(self, engine, tmp_path):
        report = engine.analyze(build_apk(tmp_path / "located.apk"))
        match = next(m for m in report["yara_matches"] if m.get("rule_name", "").startswith("IN_"))
        assert match["located_in"]

    def test_encrypted_asset_is_still_found_when_compressed(self, engine, tmp_path):
        apk = build_apk(tmp_path / "dropper.apk",
                        extra={"assets/config.json": secrets.token_bytes(40000)})
        report = engine.analyze(apk)
        assert report["entropy"]["is_likely_packed"]
        assert any(blob["name"] == "assets/config.json"
                   for blob in report["entropy"]["embedded_blobs"])
