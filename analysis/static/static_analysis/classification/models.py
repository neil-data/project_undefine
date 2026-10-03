"""Data contracts for the final static verdict."""

from dataclasses import dataclass, field
from enum import Enum

from static_analysis.detection.models import ConfidenceLevel
from static_analysis.domain.enums import Severity


class Verdict(str, Enum):
    """
    The one line an investigating officer reads first.

    `UNDETERMINED` is a real outcome and not a failure: a heavily packed sample
    whose payload never appears statically has genuinely not been assessed, and
    saying so is more useful than calling it clean.
    """

    MALICIOUS = "malicious"
    SUSPICIOUS = "suspicious"
    UNDETERMINED = "undetermined"
    BENIGN = "benign"


class MalwareFamily(str, Enum):
    """Behavioural families this engine can name from static evidence alone."""

    BANKING_TROJAN = "banking_trojan"
    SMS_STEALER = "sms_stealer"
    SPYWARE = "spyware"
    RANSOMWARE = "ransomware"
    DROPPER = "dropper"
    LOADER = "loader"
    STEALER = "stealer"
    INJECTOR = "injector"
    BACKDOOR = "backdoor"
    ADWARE = "adware"
    PACKER = "packer"
    EVASION = "evasion"
    C2_TOOLING = "c2"
    PERSISTENCE = "persistence"
    UNKNOWN = "unknown"


class ScamType(str, Enum):
    """India-specific fraud patterns named in the problem statement."""

    LOAN_APP_SCAM = "loan_app_scam"
    ECHALLAN_SCAM = "echallan_scam"
    LIGHT_BILL_SCAM = "light_bill_scam"
    UPI_FRAUD = "upi_fraud"
    OTP_THEFT = "otp_theft"
    KYC_FRAUD = "kyc_fraud"
    NONE = "none"


@dataclass(frozen=True, slots=True)
class ClassificationReason:
    """One piece of evidence behind the verdict, in language a non-analyst reads."""

    summary: str
    severity: Severity
    source: str                 # 'yara' | 'rules' | 'entropy' | 'ioc' | 'permissions'
    evidence: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class ThreatClassification:
    """The engine's final static assessment of one sample."""

    verdict: Verdict
    confidence: ConfidenceLevel
    risk_score: int
    risk_band: Severity

    primary_family: MalwareFamily = MalwareFamily.UNKNOWN
    families: tuple[MalwareFamily, ...] = ()
    scam_type: ScamType = ScamType.NONE

    capabilities: tuple[str, ...] = ()
    reasons: tuple[ClassificationReason, ...] = ()
    mitre_techniques: tuple[str, ...] = ()

    # One paragraph, no jargon — this is what goes at the top of the report.
    summary: str = ""

    # What the sample could not tell us, stated explicitly.
    limitations: tuple[str, ...] = field(default_factory=tuple)

    @property
    def is_actionable_threat(self) -> bool:
        return self.verdict in (Verdict.MALICIOUS, Verdict.SUSPICIOUS)
