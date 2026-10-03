"""Offline contracts supplying the forensic PDF report."""

from __future__ import annotations

import os
import sys

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)


def test_threat_level_covers_all_levels():
    from backend.app.models.api_models import threat_level_from_score
    assert [threat_level_from_score(score) for score in (0, 20, 40, 70, 90)] == ["LOW", "MEDIUM", "HIGH", "CRITICAL", "CRITICAL"]


def test_verdict_and_confidence_contracts():
    from backend.app.models.api_models import confidence_from_signals, verdict_from_score
    assert [verdict_from_score(score) for score in (0, 20, 60)] == ["CLEAN", "SUSPICIOUS", "MALICIOUS"]
    assert 0 <= confidence_from_signals(0, 0, False) <= 100
    assert confidence_from_signals(999, 999, True) == 100


def test_network_indicators_include_every_report_key():
    from backend.app.analysis import _extract_network_indicators
    result = _extract_network_indicators({"extracted_strings": {"ips": ["8.8.8.8"], "urls": ["https://example.test/a"]}}, {"dns_queries": ["example.test"], "network_connections": []})
    assert {"ips", "domains", "urls", "dns_queries", "connections"} <= result.keys()


def test_geoip_empty_fallback_is_safe():
    from backend.app.geoip import lookup_many
    assert lookup_many([]) == []


def test_ai_analysis_and_assessment_have_pdf_sections():
    from backend.app.analysis import _build_ai_analysis, _build_threat_assessment
    assessment = _build_threat_assessment(50, [], [], [], False)
    ai = _build_ai_analysis({"narrative_summary": "Evidence summary", "mitre_techniques": [], "dynamic_output": None}, {}, {"ips": [], "domains": [], "urls": [], "dns_queries": [], "connections": []}, [], assessment)
    assert {"risk_score", "threat_level", "verdict", "confidence", "key_findings"} <= assessment.keys()
    assert {"executive_summary", "malware_behavior", "network_interpretation", "recommendations", "confidence"} <= ai.keys()
