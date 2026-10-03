"""Final static verdict: is it malicious, what kind, and how do we know."""

from static_analysis.classification.bootstrap import create_threat_classifier
from static_analysis.classification.classifier import (
    MALICIOUS_SCORE,
    SUSPICIOUS_SCORE,
    ThreatClassifier,
)
from static_analysis.classification.models import (
    ClassificationReason,
    MalwareFamily,
    ScamType,
    ThreatClassification,
    Verdict,
)

__all__ = (
    "ClassificationReason",
    "MALICIOUS_SCORE",
    "MalwareFamily",
    "SUSPICIOUS_SCORE",
    "ScamType",
    "ThreatClassification",
    "ThreatClassifier",
    "Verdict",
    "create_threat_classifier",
)
