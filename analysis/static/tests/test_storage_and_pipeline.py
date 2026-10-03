"""
tests/test_storage_and_pipeline.py — Result storage and the complete pipeline.

The pipeline tests build samples that exercise every stage together, because
the stages only earn their keep in combination: signatures name the fraud,
indicators name the destination, entropy explains what could not be read, and
classification turns all of it into the one line an investigating officer
acts on.

The storage tests cover the properties that matter in a chain-of-custody
system: the hash is the identity, re-analysis replaces rather than duplicates,
and a failed write must not destroy the previous report.
"""

from __future__ import annotations

import json
import zipfile

import pytest

from static_analysis.bootstrap import create_engine
from static_analysis.core.engine import StaticAnalysisEngine
from static_analysis.storage import create_result_repository


def build_apk(path, manifest_terms: str, dex_terms: str, extra: dict | None = None):
    """
    Build a structurally plausible APK.

    The DEX payload is NUL-terminated because real DEX string data items are:
    without it the last string runs straight into the zip central directory's
    `PK` signature, and `scamcollect@okhdfcbank` arrives at the extractor as
    `scamcollect@okhdfcbankPK` — which correctly fails handle validation, but
    for a reason that exists only in the fixture.
    """
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr("AndroidManifest.xml", manifest_terms.encode("utf-16-le"))
        archive.writestr("classes.dex", b"dex\n035\x00" + dex_terms.encode("utf-8") + b"\x00")
        for name, payload in (extra or {}).items():
            archive.writestr(name, payload)
    return path


@pytest.fixture
def engine():
    return StaticAnalysisEngine()


@pytest.fixture
def repository(tmp_path):
    return create_result_repository(tmp_path / "results")


# ============================================================================
# Storage
# ============================================================================

class TestRepository:

    def test_report_round_trips(self, repository):
        report = {"sha256": "a" * 64, "file_name": "sample.apk",
                  "classification": {"verdict": "malicious", "risk_score": 88}}
        path = repository.save(report)

        assert path.is_file()
        loaded = repository.load("a" * 64)
        assert loaded["file_name"] == "sample.apk"
        assert loaded["stored_at"]

    def test_hash_is_the_identity(self, repository):
        """Three submissions of one file are one sample, not three."""
        for name in ("first.apk", "second.apk", "third.apk"):
            repository.save({"sha256": "b" * 64, "file_name": name,
                             "classification": {"verdict": "suspicious"}})

        assert len(repository.list_samples()) == 1
        assert repository.load("b" * 64)["file_name"] == "third.apk"

    def test_lookup_is_case_insensitive(self, repository):
        repository.save({"sha256": "C" * 64, "classification": {}})
        assert repository.exists("c" * 64)

    def test_report_without_a_hash_is_rejected(self, repository):
        """A report that cannot be identified cannot be retrieved."""
        with pytest.raises(ValueError, match="sha256"):
            repository.save({"file_name": "orphan.apk"})

    def test_missing_sample_returns_none(self, repository):
        assert repository.load("f" * 64) is None

    def test_index_summarizes_the_verdict(self, repository):
        repository.save({
            "sha256": "d" * 64, "file_name": "loan.apk", "file_type": "apk",
            "classification": {"verdict": "malicious", "risk_score": 91,
                               "primary_family": "sms_stealer",
                               "scam_type": "loan_app_scam"},
        })
        entry = repository.list_samples()[0]
        assert entry["verdict"] == "malicious"
        assert entry["scam_type"] == "loan_app_scam"

    def test_find_by_verdict(self, repository):
        repository.save({"sha256": "1" * 64, "classification": {"verdict": "malicious"}})
        repository.save({"sha256": "2" * 64, "classification": {"verdict": "benign"}})
        assert len(repository.find_by_verdict("malicious")) == 1

    def test_corrupt_index_does_not_block_new_writes(self, repository):
        """The reports are the record; the index is derived and rebuildable."""
        repository.save({"sha256": "3" * 64, "classification": {}})
        repository.index_path.write_text("{ this is not json", encoding="utf-8")

        repository.save({"sha256": "4" * 64, "classification": {"verdict": "benign"}})
        assert repository.exists("3" * 64)
        assert json.loads(repository.index_path.read_text(encoding="utf-8"))

    def test_ioc_feed_aggregates_across_samples(self, repository):
        shared = {"value": "c2.badactor.in", "type": "domain", "defanged": "c2[.]badactor[.]in"}
        for sha in ("5" * 64, "6" * 64):
            repository.save({"sha256": sha, "classification": {},
                             "iocs": {"actionable": [shared]}})
        repository.save({"sha256": "7" * 64, "classification": {},
                         "iocs": {"actionable": [
                             {"value": "lone.example.in", "type": "domain",
                              "defanged": "lone[.]example[.]in"}]}})

        feed = repository.export_iocs()
        # Shared infrastructure first — that is what ties separate cases together.
        assert feed[0]["value"] == "c2.badactor.in"
        assert len(feed[0]["samples"]) == 2


# ============================================================================
# Full pipeline
# ============================================================================

class TestPipeline:

    def test_scam_apk_produces_a_complete_report(self, engine, tmp_path):
        sample = build_apk(
            tmp_path / "challan.apk",
            "android.permission.RECEIVE_SMS android.permission.READ_SMS "
            "android.permission.READ_CONTACTS android.permission.SYSTEM_ALERT_WINDOW",
            "echallan parivahan challan rto pay now fine amount upi://pay "
            "HDFCBK one time password do not share abortBroadcast "
            "android.provider.Telephony.SMS_RECEIVED sendTextMessage "
            "https://challan-pay.example-scam.in/collect payee scamcollect@okhdfcbank",
        )
        report = engine.analyze(sample)

        assert report["sha256"]
        assert report["file_type"] == "apk"
        assert report["platform"] == "android"
        assert report["signatures"]["status"] == "completed"
        assert report["signatures"]["india_scam_matches"]
        assert report["classification"]["verdict"] == "malicious"
        assert report["classification"]["scam_type"] == "echallan_scam"
        assert report["classification"]["summary"]
        assert report["entropy"]["status"] == "completed"

    def test_indicators_reach_the_report_with_scope(self, engine, tmp_path):
        sample = build_apk(
            tmp_path / "c2.apk", "android.permission.INTERNET",
            "https://c2.badactor.in/gate https://schemas.android.com/apk/res "
            "192.168.1.1 45.13.223.9 payee scamcollect@okhdfcbank",
        )
        report = engine.analyze(sample)

        actionable = {item["value"] for item in report["iocs"]["actionable"]}
        assert "c2.badactor.in" in actionable
        assert "scamcollect@okhdfcbank" in actionable
        # Platform hosts and private addresses are collected but never lead.
        assert "schemas.android.com" not in actionable
        assert "192.168.1.1" not in actionable

    def test_encrypted_payload_becomes_a_stated_limitation(self, engine, tmp_path):
        import secrets

        sample = build_apk(
            tmp_path / "dropper.apk", "android.permission.INTERNET",
            "dalvik.system.DexClassLoader javax.crypto.Cipher getAssets",
            {"assets/settings.json": secrets.token_bytes(40000)},
        )
        report = engine.analyze(sample)

        assert report["entropy"]["is_likely_packed"]
        assert report["entropy"]["embedded_blobs"]
        assert any("sandbox" in note for note in report["classification"]["limitations"])

    def test_benign_file_is_not_flagged(self, engine, tmp_path):
        sample = tmp_path / "notes.txt"
        sample.write_text("quarterly meeting notes, nothing of interest here\n" * 200)
        report = engine.analyze(sample)

        assert report["classification"]["verdict"] in ("benign", "undetermined")
        assert report["classification"]["risk_score"] < 30
        assert report["iocs"]["actionable"] == []

    def test_report_is_json_serializable(self, engine, tmp_path):
        """It is written to disk and shipped to the dashboard; it must serialize."""
        sample = build_apk(tmp_path / "s.apk", "android.permission.INTERNET",
                           "echallan parivahan challan pay now upi://pay")
        report = engine.analyze(sample)
        assert json.loads(json.dumps(report, default=str))

    def test_engine_stores_when_given_a_repository(self, tmp_path, repository):
        engine = StaticAnalysisEngine(repository=repository)
        sample = build_apk(tmp_path / "s.apk", "android.permission.INTERNET",
                           "echallan parivahan challan rto pay now fine amount upi://pay")
        report = engine.analyze(sample)

        assert repository.exists(report["sha256"])
        stored = repository.load(report["sha256"])
        assert stored["classification"]["verdict"] == report["classification"]["verdict"]

    def test_create_engine_wires_storage(self, tmp_path):
        engine = create_engine(results_directory=tmp_path / "out")
        sample = build_apk(tmp_path / "s.apk", "android.permission.INTERNET", "hello world")
        report = engine.analyze(sample)
        assert (tmp_path / "out" / "reports" / f"{report['sha256']}.json").is_file()

    def test_missing_file_raises(self, engine, tmp_path):
        with pytest.raises(FileNotFoundError):
            engine.analyze(tmp_path / "absent.apk")

    def test_empty_file_raises(self, engine, tmp_path):
        empty = tmp_path / "empty.bin"
        empty.write_bytes(b"")
        with pytest.raises(ValueError):
            engine.analyze(empty)
