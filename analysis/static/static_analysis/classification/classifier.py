"""
Threat classification — turning accumulated evidence into one defensible verdict.

WHY A SEPARATE STAGE
--------------------
Everything upstream produces facts: signatures matched, entropy measured,
indicators extracted, permissions read. A risk number alone does not tell an
investigating officer what to do — "risk 62" is not a finding, and nobody can
act on it or put it in a case file.

This stage answers three questions in the order an investigator asks them:

    Is it malicious?        → verdict, with the confidence stated
    What kind of thing?     → family and, for this problem statement, scam type
    How do we know?         → the reasons, each traceable to its evidence

THE RULE THIS FOLLOWS
---------------------
A verdict of MALICIOUS requires evidence of *intent*, not just capability. An
app that can read SMS is a capability; an app that reads SMS, matches the OTP
interception signature and ships a hardcoded UPI payee is intent. Capability
alone lands at SUSPICIOUS, where it belongs, because the dynamic sandbox is
what settles it.

`UNDETERMINED` exists for the case that matters most in practice: a packed
sample with an encrypted payload that never appears statically. Calling that
benign because nothing matched would be the worst possible answer.
"""

from __future__ import annotations

from collections import Counter

from static_analysis.classification.models import (
    ClassificationReason,
    MalwareFamily,
    ScamType,
    ThreatClassification,
    Verdict,
)
from static_analysis.detection.models import ConfidenceLevel
from static_analysis.domain.enums import Severity
from static_analysis.entropy.models import EntropyResult
from static_analysis.ioc.models import IocExtractionResult, IocType
from static_analysis.rules.models import RuleCategory, RuleMatch
from static_analysis.yara_scan.models import YaraScanResult, YaraStatus

# Score thresholds. Chosen so that a single capability signature cannot on its
# own produce a malicious verdict — that requires either a critical signature
# or several independent lines of evidence agreeing.
MALICIOUS_SCORE = 70
SUSPICIOUS_SCORE = 30

_SEVERITY_ORDER = {
    Severity.CRITICAL: 4, Severity.HIGH: 3, Severity.MEDIUM: 2,
    Severity.LOW: 1, Severity.INFO: 0,
}

_SCAM_BY_FAMILY = {
    "loan_app_scam": ScamType.LOAN_APP_SCAM,
    "echallan_scam": ScamType.ECHALLAN_SCAM,
    "light_bill_scam": ScamType.LIGHT_BILL_SCAM,
    "upi_fraud": ScamType.UPI_FRAUD,
    "otp_theft": ScamType.OTP_THEFT,
    "kyc_fraud": ScamType.KYC_FRAUD,
}

_SCAM_DESCRIPTIONS = {
    ScamType.LOAN_APP_SCAM: (
        "a predatory instant-loan application: it collects the victim's contact "
        "list and photos so that the borrower can be threatened through their "
        "own family and colleagues if they do not pay"
    ),
    ScamType.ECHALLAN_SCAM: (
        "a counterfeit traffic-challan or RTO application: it imitates the "
        "government service, takes a 'fine' payment, and intercepts the bank "
        "one-time password so the victim never sees the transaction"
    ),
    ScamType.LIGHT_BILL_SCAM: (
        "an electricity-disconnection scam application: the victim is warned "
        "their power will be cut off tonight and walked into installing this, "
        "which then exposes their banking credentials"
    ),
    ScamType.UPI_FRAUD: (
        "a UPI payment fraud application: it presents what looks like a refund "
        "but issues a collect request, so approving it debits the victim"
    ),
    ScamType.OTP_THEFT: (
        "an one-time-password interceptor: it reads the victim's bank messages "
        "and forwards them, which defeats the second factor entirely"
    ),
    ScamType.KYC_FRAUD: (
        "a fake KYC-update application: it threatens account suspension to "
        "collect identity documents and card details"
    ),
}

# Capability labels, derived from evidence, that the report lists plainly.
_CAPABILITY_BY_FAMILY = {
    "sms_stealer": "Reads and sends text messages without the user",
    "banking_trojan": "Can see and act on the screen of other applications",
    "dropper": "Loads additional code at runtime that is not in this file",
    "ransomware": "Encrypts files and destroys recovery options",
    "stealer": "Reads stored browser and system credentials",
    "injector": "Injects code into other running programs",
    "c2": "Contacts an operator-controlled command channel",
    "spyware": "Captures location, camera, microphone or screen content",
    "persistence": "Resists removal and survives reboot",
    "evasion": "Detects analysis environments and changes behaviour",
    "packer": "Conceals its real contents until it runs",
    "loader": "Fetches its instructions or payload from a remote source",
}


class ThreatClassifier:
    """Combines every upstream signal into one verdict with stated reasons."""

    def classify(
        self,
        *,
        yara: YaraScanResult | None = None,
        rule_matches: tuple[RuleMatch, ...] = (),
        rule_score: int = 0,
        entropy: EntropyResult | None = None,
        iocs: IocExtractionResult | None = None,
        dangerous_permissions: tuple[str, ...] = (),
        file_type: str = "",
    ) -> ThreatClassification:
        reasons: list[ClassificationReason] = []
        families: Counter[str] = Counter()
        capabilities: set[str] = set()
        mitre: set[str] = set()
        limitations: list[str] = []

        score = min(100, max(0, rule_score))

        score = self._score_yara(yara, reasons, families, capabilities, mitre, score)
        score = self._score_rules(rule_matches, reasons, families, score)
        score = self._score_entropy(entropy, reasons, families, capabilities, limitations, score)
        score = self._score_iocs(iocs, reasons, capabilities, score)
        self._note_permissions(dangerous_permissions, reasons)

        if yara is not None and yara.status is not YaraStatus.COMPLETED:
            limitations.append(
                f"Signature scanning did not run ({yara.status.value}), so the "
                f"result reflects structural analysis only."
            )

        score = min(100, score)
        verdict, confidence = self._decide(score, yara, reasons, limitations)
        primary, ranked = self._rank_families(families)
        scam_type = self._scam_type(families)

        return ThreatClassification(
            verdict=verdict,
            confidence=confidence,
            risk_score=score,
            risk_band=self._band(score),
            primary_family=primary,
            families=ranked,
            scam_type=scam_type,
            capabilities=tuple(sorted(capabilities)),
            reasons=tuple(sorted(reasons, key=lambda r: -_SEVERITY_ORDER.get(r.severity, 0))),
            mitre_techniques=tuple(sorted(mitre)),
            summary=self._summary(verdict, primary, scam_type, reasons, file_type, limitations),
            limitations=tuple(limitations),
        )

    # -- evidence scoring --------------------------------------------------

    def _score_yara(self, yara, reasons, families, capabilities, mitre, score: int) -> int:
        if yara is None or yara.status is not YaraStatus.COMPLETED:
            return score

        weights = {Severity.CRITICAL: 45, Severity.HIGH: 25,
                   Severity.MEDIUM: 12, Severity.LOW: 5, Severity.INFO: 0}

        for match in yara.matches:
            score += weights.get(match.severity, 0)
            mitre.update(match.mitre)
            if match.family:
                families[match.family] += _SEVERITY_ORDER.get(match.severity, 1)
                capability = _CAPABILITY_BY_FAMILY.get(match.family)
                if capability:
                    capabilities.add(capability)
            reasons.append(ClassificationReason(
                summary=match.description or f"Matched signature {match.rule_name}",
                severity=match.severity,
                source="yara",
                evidence=tuple(f"{hit.identifier} @ 0x{hit.offset:x}: {hit.matched}"
                               for hit in match.string_hits[:5]),
            ))
        return score

    def _score_rules(self, matches, reasons, families, score: int) -> int:
        for match in matches:
            if match.category is RuleCategory.PACKED_BINARY:
                families["packer"] += 1
            elif match.category is RuleCategory.SUSPICIOUS_IMPORT:
                families["injector"] += 1
            reasons.append(ClassificationReason(
                summary=match.description or match.title,
                severity=match.severity,
                source="rules",
                evidence=tuple(match.evidence[:5]),
            ))
        return score

    def _score_entropy(self, entropy, reasons, families, capabilities,
                       limitations, score: int) -> int:
        if entropy is None or not entropy.is_likely_packed:
            return score

        families["packer"] += 2
        capabilities.add(_CAPABILITY_BY_FAMILY["packer"])
        score += 15
        reasons.append(ClassificationReason(
            summary=(
                "The file carries a block of encrypted or packed data that its own "
                "structure does not account for — its real contents are not visible "
                "to inspection of the file alone."
            ),
            severity=Severity.HIGH,
            source="entropy",
            evidence=entropy.packing_evidence[:5],
        ))
        limitations.append(
            "Part of this sample is encrypted and was not readable statically; "
            "detonation in the sandbox is required to see what it does."
        )
        return score

    def _score_iocs(self, iocs, reasons, capabilities, score: int) -> int:
        if iocs is None:
            return score

        actionable = iocs.actionable
        if not actionable:
            return score

        payment = [i for i in actionable if i.ioc_type in
                   (IocType.UPI_ID, IocType.BITCOIN_ADDRESS, IocType.ETHEREUM_ADDRESS)]
        if payment:
            score += 15
            capabilities.add("Carries a hardcoded payment destination")
            reasons.append(ClassificationReason(
                summary=(
                    "A payment destination is hardcoded into the file. Money taken "
                    "from victims is directed here, and it is traceable."
                ),
                severity=Severity.HIGH,
                source="ioc",
                evidence=tuple(i.value for i in payment[:5]),
            ))

        network = [i for i in actionable if i.ioc_type not in
                   (IocType.UPI_ID, IocType.BITCOIN_ADDRESS, IocType.ETHEREUM_ADDRESS)]
        if network:
            score += 5
            reasons.append(ClassificationReason(
                summary=(
                    f"{len(network)} external destination(s) are built into the file, "
                    f"beyond the platform and SDK endpoints every app contains."
                ),
                severity=Severity.MEDIUM,
                source="ioc",
                evidence=tuple(i.defanged for i in network[:5]),
            ))
        return score

    def _note_permissions(self, permissions, reasons) -> None:
        if len(permissions) < 3:
            return
        reasons.append(ClassificationReason(
            summary=(
                f"The application requests {len(permissions)} sensitive permissions. "
                f"Each one is a category of the owner's data it can reach."
            ),
            severity=Severity.MEDIUM if len(permissions) < 6 else Severity.HIGH,
            source="permissions",
            evidence=tuple(sorted(permissions)[:8]),
        ))

    # -- decisions ---------------------------------------------------------

    def _decide(self, score, yara, reasons, limitations) -> tuple[Verdict, ConfidenceLevel]:
        has_critical = any(r.severity is Severity.CRITICAL for r in reasons)
        high_count = sum(1 for r in reasons if r.severity is Severity.HIGH)
        independent_sources = len({r.source for r in reasons})

        if has_critical or score >= MALICIOUS_SCORE:
            # Two independent evidence sources agreeing is what separates a
            # confident verdict from one resting on a single signature.
            confidence = (ConfidenceLevel.HIGH if has_critical and independent_sources >= 2
                          else ConfidenceLevel.MEDIUM)
            return Verdict.MALICIOUS, confidence

        if score >= SUSPICIOUS_SCORE or high_count >= 1:
            return Verdict.SUSPICIOUS, (
                ConfidenceLevel.MEDIUM if independent_sources >= 2 else ConfidenceLevel.LOW
            )

        if limitations:
            # Nothing matched, but something was unreadable. That is not clean.
            return Verdict.UNDETERMINED, ConfidenceLevel.LOW

        return Verdict.BENIGN, (
            ConfidenceLevel.MEDIUM if yara is not None
            and yara.status is YaraStatus.COMPLETED else ConfidenceLevel.LOW
        )

    @staticmethod
    def _band(score: int) -> Severity:
        if score >= 80:
            return Severity.CRITICAL
        if score >= 55:
            return Severity.HIGH
        if score >= 30:
            return Severity.MEDIUM
        if score >= 10:
            return Severity.LOW
        return Severity.INFO

    @staticmethod
    def _rank_families(families: Counter[str]) -> tuple[MalwareFamily, tuple[MalwareFamily, ...]]:
        ranked: list[MalwareFamily] = []
        # Weight descending, then name — Counter.most_common leaves ties in
        # insertion order, which here is scan order, so an identical sample
        # could be typed differently depending on how the container was
        # compressed. A verdict must not depend on that.
        for name, _weight in sorted(families.items(), key=lambda item: (-item[1], item[0])):
            try:
                ranked.append(MalwareFamily(name))
            except ValueError:
                continue
        primary = ranked[0] if ranked else MalwareFamily.UNKNOWN
        return primary, tuple(ranked)

    @staticmethod
    def _scam_type(families: Counter[str]) -> ScamType:
        for name, _weight in sorted(families.items(), key=lambda item: (-item[1], item[0])):
            scam = _SCAM_BY_FAMILY.get(name)
            if scam is not None:
                return scam
        return ScamType.NONE

    @staticmethod
    def _summary(verdict, primary, scam_type, reasons, file_type, limitations) -> str:
        subject = "This application" if file_type == "apk" else "This file"

        if verdict is Verdict.BENIGN:
            return (
                f"{subject} shows no indication of malicious behaviour in static "
                f"analysis. That is not a guarantee of safety — behaviour that only "
                f"appears when the file runs is outside what static inspection can see."
            )

        if verdict is Verdict.UNDETERMINED:
            return (
                f"{subject} could not be assessed from its contents alone. "
                f"{limitations[0] if limitations else ''} Until it is run in the "
                f"sandbox, treat it as unknown rather than safe."
            ).strip()

        if scam_type is not ScamType.NONE:
            lead = (
                f"{subject} matches the pattern of {_SCAM_DESCRIPTIONS.get(scam_type, scam_type.value)}."
            )
        elif primary is not MalwareFamily.UNKNOWN:
            lead = f"{subject} is consistent with {primary.value.replace('_', ' ')}."
        else:
            lead = f"{subject} shows behaviour that does not fit ordinary software."

        ranked = sorted(reasons, key=lambda r: -_SEVERITY_ORDER.get(r.severity, 0))[:2]
        # Rule and signature descriptions are written as fragments, so they are
        # terminated here rather than run together into one unreadable line.
        detail = " ".join(
            summary if summary.endswith((".", "!", "?")) else f"{summary}."
            for summary in (r.summary.strip() for r in ranked)
            if summary
        )

        confidence_note = (
            "The evidence is strong enough to act on."
            if verdict is Verdict.MALICIOUS
            else "The evidence warrants running it in the sandbox before drawing a conclusion."
        )
        return f"{lead} {detail} {confidence_note}".strip()
