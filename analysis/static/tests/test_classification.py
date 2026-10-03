"""
tests/test_classification.py — The verdict stage.

The rule this suite enforces: **capability alone is not a malicious verdict.**
An app that *can* read SMS is a capability; an app that reads SMS, matches an
interception signature and ships a hardcoded payee is intent. Getting that
boundary wrong in either direction is what makes a tool either ignored or
dangerous, so both directions are tested.

`UNDETERMINED` is tested too. A packed sample whose payload never appears
statically has not been assessed, and reporting it as benign would be the
single worst answer this engine could give.
"""

from __future__ import annotations

import pytest

from static_analysis.classification import (
    MalwareFamily,
    ScamType,
    ThreatClassifier,
    Verdict,
)
from static_analysis.detection.models import ConfidenceLevel
from static_analysis.domain.enums import Severity
from static_analysis.entropy.models import (
    EmbeddedBlob,
    EntropyClass,
    EntropyResult,
    EntropyStatus,
)
from static_analysis.ioc.models import (
    Indicator,
    IocExtractionResult,
    IocExtractionStatus,
    IocScope,
    IocType,
)
from static_analysis.yara_scan.models import YaraMatch, YaraScanResult, YaraStatus


@pytest.fixture
def classifier():
    return ThreatClassifier()


def yara_result(*matches, status: YaraStatus = YaraStatus.COMPLETED) -> YaraScanResult:
    return YaraScanResult(source="s", status=status, matches=tuple(matches), rules_loaded=25)


def match(name: str, severity: Severity, family: str = "", mitre: tuple = (),
          description: str = "") -> YaraMatch:
    return YaraMatch(
        rule_name=name,
        namespace="india_scam_rules" if name.startswith("IN_") else "generic",
        description=description or f"{name} fired",
        severity=severity,
        confidence=ConfidenceLevel.HIGH,
        family=family,
        category="india_scam" if name.startswith("IN_") else "capability",
        mitre=mitre,
    )


def iocs(*indicators) -> IocExtractionResult:
    return IocExtractionResult(
        source="s", status=IocExtractionStatus.COMPLETED, indicators=tuple(indicators)
    )


def indicator(value: str, ioc_type: IocType,
              scope: IocScope = IocScope.EXTERNAL) -> Indicator:
    return Indicator(
        value=value, ioc_type=ioc_type, scope=scope,
        confidence=ConfidenceLevel.HIGH, defanged=value,
    )


def packed_entropy() -> EntropyResult:
    return EntropyResult(
        source="s",
        status=EntropyStatus.COMPLETED,
        overall_entropy=7.9,
        classification=EntropyClass.PACKED_OR_ENCRYPTED,
        is_container=True,
        embedded_blobs=(EmbeddedBlob(
            name="assets/config.json", size=30000, entropy=7.99,
            declared_kind="json", reason="encrypted contents under a json name",
        ),),
    )


# ============================================================================
# Verdicts
# ============================================================================

class TestVerdicts:

    def test_no_evidence_is_benign(self, classifier):
        result = classifier.classify(yara=yara_result())
        assert result.verdict is Verdict.BENIGN
        assert result.risk_score == 0

    def test_critical_signature_is_malicious(self, classifier):
        result = classifier.classify(
            yara=yara_result(match("IN_Bank_OTP_Interception", Severity.CRITICAL,
                                   family="otp_theft", mitre=("T1636.004",))),
        )
        assert result.verdict is Verdict.MALICIOUS

    def test_single_capability_signature_is_only_suspicious(self, classifier):
        """
        An accessibility service is how a screen reader works. Static analysis
        establishes the capability; the sandbox settles what it is used for.
        """
        result = classifier.classify(
            yara=yara_result(match("Android_Accessibility_Service_Abuse", Severity.HIGH,
                                   family="banking_trojan")),
        )
        assert result.verdict is Verdict.SUSPICIOUS

    def test_several_agreeing_signals_reach_malicious(self, classifier):
        result = classifier.classify(
            yara=yara_result(
                match("Android_SMS_Interception", Severity.HIGH, family="sms_stealer"),
                match("Android_Overlay_Attack", Severity.HIGH, family="banking_trojan"),
                match("C2_Telegram_Bot_Channel", Severity.HIGH, family="c2"),
            ),
            iocs=iocs(indicator("scam@okhdfcbank", IocType.UPI_ID)),
        )
        assert result.verdict is Verdict.MALICIOUS
        assert result.risk_score >= 70

    def test_packed_sample_with_nothing_else_is_undetermined(self, classifier):
        """Not benign: the part that matters was unreadable."""
        result = classifier.classify(yara=yara_result(), entropy=packed_entropy())
        assert result.verdict in (Verdict.SUSPICIOUS, Verdict.UNDETERMINED)
        assert result.limitations

    def test_unreadable_sample_with_no_signals_is_undetermined_not_benign(self, classifier):
        result = classifier.classify(
            yara=yara_result(status=YaraStatus.ENGINE_UNAVAILABLE),
        )
        assert result.verdict is Verdict.UNDETERMINED
        assert any("did not run" in note for note in result.limitations)

    def test_confidence_rises_with_independent_evidence(self, classifier):
        single = classifier.classify(
            yara=yara_result(match("IN_EChallan_OTP_Interceptor", Severity.CRITICAL,
                                   family="echallan_scam")),
        )
        corroborated = classifier.classify(
            yara=yara_result(match("IN_EChallan_OTP_Interceptor", Severity.CRITICAL,
                                   family="echallan_scam")),
            iocs=iocs(indicator("scam@okhdfcbank", IocType.UPI_ID)),
            dangerous_permissions=("READ_SMS", "SEND_SMS", "READ_CONTACTS", "CAMERA"),
        )
        assert corroborated.confidence is ConfidenceLevel.HIGH
        assert single.confidence is ConfidenceLevel.MEDIUM


# ============================================================================
# Family and scam typing
# ============================================================================

class TestFamilyAndScamType:

    def test_primary_family_follows_the_strongest_evidence(self, classifier):
        result = classifier.classify(
            yara=yara_result(
                match("IN_Bank_OTP_Interception", Severity.CRITICAL, family="sms_stealer"),
                match("Exfil_Dynamic_DNS_Endpoint", Severity.MEDIUM, family="c2"),
            ),
        )
        assert result.primary_family is MalwareFamily.SMS_STEALER
        assert MalwareFamily.C2_TOOLING in result.families

    @pytest.mark.parametrize("family,expected", [
        ("loan_app_scam", ScamType.LOAN_APP_SCAM),
        ("echallan_scam", ScamType.ECHALLAN_SCAM),
        ("light_bill_scam", ScamType.LIGHT_BILL_SCAM),
        ("upi_fraud", ScamType.UPI_FRAUD),
        ("kyc_fraud", ScamType.KYC_FRAUD),
    ])
    def test_india_scam_type_is_named(self, classifier, family, expected):
        result = classifier.classify(
            yara=yara_result(match(f"IN_{family}", Severity.HIGH, family=family)),
        )
        assert result.scam_type is expected

    def test_no_scam_type_for_generic_malware(self, classifier):
        result = classifier.classify(
            yara=yara_result(match("Windows_Ransomware_Capability", Severity.CRITICAL,
                                   family="ransomware")),
        )
        assert result.scam_type is ScamType.NONE
        assert result.primary_family is MalwareFamily.RANSOMWARE

    def test_capabilities_are_stated_in_plain_language(self, classifier):
        result = classifier.classify(
            yara=yara_result(match("Android_SMS_Interception", Severity.HIGH,
                                   family="sms_stealer")),
        )
        assert any("text messages" in capability for capability in result.capabilities)


# ============================================================================
# Explanation quality — what an investigating officer actually reads
# ============================================================================

class TestExplanation:

    def test_summary_names_the_scam_in_ordinary_words(self, classifier):
        result = classifier.classify(
            yara=yara_result(match("IN_LoanApp_Extortion_Payload", Severity.CRITICAL,
                                   family="loan_app_scam")),
        )
        assert "contact list" in result.summary
        assert "loan" in result.summary.lower()

    def test_benign_summary_does_not_claim_safety(self, classifier):
        """Static analysis cannot see runtime behaviour, and must say so."""
        summary = classifier.classify(yara=yara_result()).summary
        assert "not a guarantee" in summary

    def test_reasons_are_ordered_most_severe_first(self, classifier):
        result = classifier.classify(
            yara=yara_result(
                match("Exfil_Paste_And_Shortener_Staging", Severity.MEDIUM, family="loader"),
                match("IN_Bank_OTP_Interception", Severity.CRITICAL, family="otp_theft"),
                match("Android_SMS_Interception", Severity.HIGH, family="sms_stealer"),
            ),
        )
        order = {Severity.CRITICAL: 0, Severity.HIGH: 1, Severity.MEDIUM: 2}
        severities = [order[reason.severity] for reason in result.reasons
                      if reason.severity in order]
        assert severities == sorted(severities)

    def test_every_reason_names_its_source(self, classifier):
        result = classifier.classify(
            yara=yara_result(match("IN_UPI_Collect_Request_Abuse", Severity.HIGH,
                                   family="upi_fraud")),
            entropy=packed_entropy(),
            iocs=iocs(indicator("scam@okhdfcbank", IocType.UPI_ID)),
            dangerous_permissions=("READ_SMS", "CAMERA", "READ_CONTACTS"),
        )
        assert {r.source for r in result.reasons} >= {"yara", "entropy", "ioc", "permissions"}

    def test_payment_destination_is_called_out(self, classifier):
        result = classifier.classify(
            iocs=iocs(indicator("scamcollect@okhdfcbank", IocType.UPI_ID)),
        )
        payment_reason = next(r for r in result.reasons if r.source == "ioc")
        assert "payment destination" in payment_reason.summary
        assert "scamcollect@okhdfcbank" in payment_reason.evidence

    def test_mitre_techniques_are_collected_from_signatures(self, classifier):
        result = classifier.classify(
            yara=yara_result(
                match("IN_Bank_OTP_Interception", Severity.CRITICAL,
                      family="otp_theft", mitre=("T1636.004", "T1582")),
                match("C2_Telegram_Bot_Channel", Severity.HIGH,
                      family="c2", mitre=("T1102",)),
            ),
        )
        assert result.mitre_techniques == ("T1102", "T1582", "T1636.004")


# ============================================================================
# False positives
# ============================================================================

class TestFalsePositives:

    def test_platform_endpoints_alone_do_not_raise_a_verdict(self, classifier):
        result = classifier.classify(
            yara=yara_result(),
            iocs=iocs(indicator("schemas.android.com", IocType.DOMAIN,
                                scope=IocScope.KNOWN_INFRASTRUCTURE)),
        )
        assert result.verdict is Verdict.BENIGN

    def test_private_addresses_alone_do_not_raise_a_verdict(self, classifier):
        result = classifier.classify(
            yara=yara_result(),
            iocs=iocs(indicator("192.168.1.1", IocType.IPV4, scope=IocScope.INTERNAL)),
        )
        assert result.verdict is Verdict.BENIGN

    def test_two_permissions_are_not_worth_reporting(self, classifier):
        result = classifier.classify(
            yara=yara_result(), dangerous_permissions=("CAMERA", "RECORD_AUDIO"),
        )
        assert not any(r.source == "permissions" for r in result.reasons)

    def test_score_is_bounded(self, classifier):
        result = classifier.classify(
            yara=yara_result(*[
                match(f"IN_Rule{i}", Severity.CRITICAL, family="otp_theft")
                for i in range(20)
            ]),
            rule_score=100,
        )
        assert result.risk_score == 100
