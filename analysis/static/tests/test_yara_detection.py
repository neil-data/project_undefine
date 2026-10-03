"""
tests/test_yara_detection.py — Signature scanning and the India scam rule set.

Two things are being protected here.

**The rules compile and mean what they say.** A rule file with a syntax error,
or a `meta` block missing its severity, degrades silently into "no matches" —
which is indistinguishable from a clean sample. Every rule is checked for the
metadata the risk score and MITRE mapping consume.

**The India-specific rules discriminate.** They are the project's stated
differentiator, so each is tested against a sample that should fire it *and* a
plausible legitimate app that must not. A rule that flags every banking app is
worse than no rule.
"""

from __future__ import annotations

import zipfile

import pytest

from static_analysis.domain.enums import Severity
from static_analysis.yara_scan import (
    YARA_AVAILABLE,
    YaraStatus,
    create_yara_scanner,
    default_rules_directory,
)

pytestmark = pytest.mark.skipif(not YARA_AVAILABLE, reason="yara-python not installed")


@pytest.fixture(scope="module")
def scanner():
    return create_yara_scanner()


def build_apk(path, manifest_terms: str, dex_terms: str):
    """
    Build a structurally plausible APK.

    Manifest strings are written UTF-16 because that is how they sit in a real
    binary XML string pool — which is exactly why the rules declare `wide`.
    """
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr("AndroidManifest.xml", manifest_terms.encode("utf-16-le"))
        archive.writestr("classes.dex", b"dex\n035\x00" + dex_terms.encode("utf-8"))
    return path


def rule_names(result) -> set[str]:
    return {match.rule_name for match in result.matches}


# ============================================================================
# Rule tree health
# ============================================================================

class TestRuleTree:

    def test_rules_compile(self, scanner):
        assert scanner.available
        assert scanner.status is YaraStatus.COMPLETED
        assert scanner.rule_count >= 20

    def test_both_namespaces_present(self, scanner):
        namespaces = {path.split("\\")[0].split("/")[0] for path in scanner._rule_files}
        assert "india_scam_rules" in namespaces
        assert "generic" in namespaces

    def test_every_rule_declares_the_metadata_the_engine_consumes(self):
        """
        Severity, confidence, family and category drive the risk score, the
        classification and the MITRE mapping. A rule missing them still fires
        but contributes nothing, which is a silent failure.
        """
        required = ("description", "severity", "confidence", "family", "category")
        for rule_file in sorted(default_rules_directory().rglob("*.yar")):
            text = rule_file.read_text(encoding="utf-8")
            blocks = text.split("\nrule ")[1:]
            assert blocks, f"{rule_file.name} declares no rules"
            for block in blocks:
                name = block.split("\n", 1)[0].strip()
                meta = block.split("strings:")[0]
                for key in required:
                    assert f"{key} =" in meta, f"{rule_file.name}:{name} is missing meta.{key}"

    def test_missing_rule_directory_is_reported_not_silent(self, tmp_path):
        empty = create_yara_scanner(tmp_path / "no_such_dir")
        assert empty.status is YaraStatus.NO_RULES
        result = empty.scan(__file__)
        assert result.status is YaraStatus.NO_RULES
        assert result.matches == ()
        assert result.error


# ============================================================================
# India-specific scam rules — the differentiator
# ============================================================================

class TestIndiaScamRules:

    def test_fake_echallan_app_detected(self, scanner, tmp_path):
        sample = build_apk(
            tmp_path / "challan.apk",
            "android.permission.INTERNET",
            "echallan parivahan challan rto office pay now fine amount upi://pay",
        )
        assert "IN_Fake_EChallan_App" in rule_names(scanner.scan(sample))

    def test_genuine_government_origin_suppresses_the_challan_rule(self, scanner, tmp_path):
        """The real mParivahan app must not be flagged as an imitation of itself."""
        sample = build_apk(
            tmp_path / "real.apk",
            "android.permission.INTERNET",
            "echallan parivahan challan pay now fine amount "
            "https://echallan.parivahan.gov.in/index/accused-challan",
        )
        assert "IN_Fake_EChallan_App" not in rule_names(scanner.scan(sample))

    def test_otp_interception_detected(self, scanner, tmp_path):
        sample = build_apk(
            tmp_path / "otp.apk",
            "android.permission.RECEIVE_SMS",
            "HDFCBK one time password do not share abortBroadcast "
            "android.provider.Telephony.SMS_RECEIVED",
        )
        assert "IN_Bank_OTP_Interception" in rule_names(scanner.scan(sample))

    def test_bank_app_without_interception_is_not_flagged(self, scanner, tmp_path):
        """A real bank app mentions OTP constantly and intercepts nothing."""
        sample = build_apk(
            tmp_path / "bank.apk",
            "android.permission.INTERNET",
            "HDFCBK one time password do not share your otp with anyone",
        )
        assert "IN_Bank_OTP_Interception" not in rule_names(scanner.scan(sample))

    def test_loan_app_contact_harvesting_detected(self, scanner, tmp_path):
        sample = build_apk(
            tmp_path / "loan.apk",
            "android.permission.READ_CONTACTS",
            "instant loan quick cash disbursal repayment "
            "content://com.android.contacts uploadContacts /api/contacts",
        )
        assert "IN_LoanApp_Contact_Harvesting" in rule_names(scanner.scan(sample))

    def test_lender_without_contact_upload_is_not_flagged(self, scanner, tmp_path):
        sample = build_apk(
            tmp_path / "nbfc.apk",
            "android.permission.INTERNET",
            "instant loan disbursal repayment emi schedule interest rate",
        )
        assert "IN_LoanApp_Contact_Harvesting" not in rule_names(scanner.scan(sample))

    def test_electricity_scam_detected(self, scanner, tmp_path):
        sample = build_apk(
            tmp_path / "bijli.apk",
            "android.permission.INTERNET",
            "MSEDCL your electricity will be disconnected consumer number "
            "light bill pay bill upi://pay",
        )
        assert "IN_Electricity_Bill_Scam_App" in rule_names(scanner.scan(sample))

    def test_upi_collect_abuse_detected(self, scanner, tmp_path):
        sample = build_apk(
            tmp_path / "upi.apk",
            "android.permission.INTERNET",
            "upi://pay?pa=collect@okhdfcbank&am=4999&tn=refund processing",
        )
        assert "IN_UPI_Collect_Request_Abuse" in rule_names(scanner.scan(sample))

    def test_india_matches_are_reported_as_their_own_group(self, scanner, tmp_path):
        sample = build_apk(
            tmp_path / "mixed.apk",
            "android.permission.RECEIVE_SMS android.permission.SYSTEM_ALERT_WINDOW",
            "echallan parivahan challan rto pay now fine amount upi://pay "
            "HDFCBK otp abortBroadcast android.provider.Telephony.SMS_RECEIVED",
        )
        result = scanner.scan(sample)
        assert result.india_scam_matches
        assert all(match.is_india_scam_rule for match in result.india_scam_matches)


# ============================================================================
# Generic capability rules
# ============================================================================

class TestGenericRules:

    def test_accessibility_abuse_detected(self, scanner, tmp_path):
        sample = build_apk(
            tmp_path / "a11y.apk",
            "android.permission.BIND_ACCESSIBILITY_SERVICE",
            "performGlobalAction findAccessibilityNodeInfosByText getRootInActiveWindow",
        )
        assert "Android_Accessibility_Service_Abuse" in rule_names(scanner.scan(sample))

    def test_overlay_attack_requires_foreground_awareness(self, scanner, tmp_path):
        """Drawing a window is universal; watching which app is in front is not."""
        harmless = build_apk(
            tmp_path / "widget.apk",
            "android.permission.SYSTEM_ALERT_WINDOW",
            "addView WindowManager$LayoutParams",
        )
        assert "Android_Overlay_Attack" not in rule_names(scanner.scan(harmless))

        targeted = build_apk(
            tmp_path / "trojan.apk",
            "android.permission.SYSTEM_ALERT_WINDOW",
            "addView WindowManager$LayoutParams TYPE_APPLICATION_OVERLAY "
            "UsageStatsManager TYPE_WINDOW_STATE_CHANGED",
        )
        assert "Android_Overlay_Attack" in rule_names(scanner.scan(targeted))

    def test_runtime_dex_loading_detected(self, scanner, tmp_path):
        sample = build_apk(
            tmp_path / "dropper.apk", "",
            "dalvik.system.DexClassLoader javax.crypto.Cipher getAssets",
        )
        assert "Android_Runtime_Dex_Loading" in rule_names(scanner.scan(sample))

    def test_telegram_c2_detected(self, scanner, tmp_path):
        sample = build_apk(
            tmp_path / "c2.apk", "",
            "api.telegram.org sendMessage chat_id sendDocument",
        )
        assert "C2_Telegram_Bot_Channel" in rule_names(scanner.scan(sample))

    def test_windows_rules_require_a_pe_header(self, scanner, tmp_path):
        """`uint16(0) == 0x5A4D` keeps the Windows set off Android samples."""
        sample = build_apk(
            tmp_path / "notpe.apk", "",
            "VirtualAllocEx WriteProcessMemory CreateRemoteThread OpenProcess",
        )
        assert "Windows_Process_Injection_Capability" not in rule_names(scanner.scan(sample))

    def test_windows_injection_detected_in_a_pe(self, scanner, tmp_path):
        sample = tmp_path / "inject.exe"
        sample.write_bytes(
            b"MZ" + b"\x00" * 64 + b"PE\x00\x00"
            + b"VirtualAllocEx\x00WriteProcessMemory\x00CreateRemoteThread\x00OpenProcess\x00"
        )
        assert "Windows_Process_Injection_Capability" in rule_names(scanner.scan(sample))

    def test_upx_packing_detected(self, scanner, tmp_path):
        sample = tmp_path / "packed.exe"
        sample.write_bytes(b"MZ" + b"\x00" * 60 + b"UPX0\x00UPX1\x00UPX!")
        assert "Windows_UPX_Packed" in rule_names(scanner.scan(sample))


# ============================================================================
# Result contract
# ============================================================================

class TestScanResult:

    def test_clean_file_produces_no_matches(self, scanner, tmp_path):
        sample = tmp_path / "notes.txt"
        sample.write_text("meeting notes for tuesday, nothing here at all")
        result = scanner.scan(sample)
        assert result.status is YaraStatus.COMPLETED
        assert result.matches == ()
        assert result.highest_severity is None

    def test_matches_carry_severity_family_and_mitre(self, scanner, tmp_path):
        sample = build_apk(
            tmp_path / "otp.apk", "android.permission.RECEIVE_SMS",
            "HDFCBK one time password abortBroadcast "
            "android.provider.Telephony.SMS_RECEIVED",
        )
        match = next(m for m in scanner.scan(sample).matches
                     if m.rule_name == "IN_Bank_OTP_Interception")
        assert match.severity is Severity.CRITICAL
        assert match.family == "otp_theft"
        assert "T1636.004" in match.mitre

    def test_matches_are_ordered_most_severe_first(self, scanner, tmp_path):
        sample = build_apk(
            tmp_path / "mixed.apk",
            "android.permission.RECEIVE_SMS",
            "echallan parivahan challan rto HDFCBK otp abortBroadcast "
            "android.provider.Telephony.SMS_RECEIVED sendTextMessage "
            "api.telegram.org sendMessage chat_id",
        )
        severities = [m.severity for m in scanner.scan(sample).matches]
        order = {Severity.CRITICAL: 0, Severity.HIGH: 1, Severity.MEDIUM: 2,
                 Severity.LOW: 3, Severity.INFO: 4}
        assert severities == sorted(severities, key=lambda s: order[s])

    def test_string_hits_are_bounded(self, scanner, tmp_path):
        """A rule firing ten thousand times must not put ten thousand rows in a report."""
        sample = build_apk(
            tmp_path / "spam.apk", "",
            "api.telegram.org sendMessage " * 5000 + "chat_id",
        )
        for match in scanner.scan(sample).matches:
            assert len(match.string_hits) <= 20
