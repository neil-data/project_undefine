"""Explicit assembly for the threat classifier."""

from static_analysis.classification.classifier import ThreatClassifier


def create_threat_classifier() -> ThreatClassifier:
    """Create the default evidence-combining classifier."""
    return ThreatClassifier()
