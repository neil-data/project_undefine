"""
test_risk_scoring.py — Unit tests for the risk scoring formula,
including boundary conditions (score clamping at 0 and 100).
"""

from agents.orchestrator.risk_scoring import compute_risk_score
from agents.orchestrator.schema import MitreTechnique, CapabilityTag


class TestBasicScoring:
    def test_benign_sample_scores_zero(self, benign_static):
        score = compute_risk_score(benign_static, None, [], [])
        assert score == 0

    def test_yara_match_increases_score(self, android_malicious_static):
        score = compute_risk_score(android_malicious_static, None, [], [])
        assert score > 0  # 1 YARA match should contribute

    def test_more_signals_means_higher_score(self, android_malicious_static, android_malicious_dynamic):
        techniques = [MitreTechnique(technique_id="T1517", technique_name="x", confidence=0.9)]
        caps = [CapabilityTag(capability="sms_otp_theft", confidence=0.9, evidence=["x"])]

        static_only_score = compute_risk_score(android_malicious_static, None, [], [])
        full_signal_score = compute_risk_score(android_malicious_static, android_malicious_dynamic, techniques, caps)

        assert full_signal_score > static_only_score


class TestScoreClamping:
    def test_score_never_exceeds_100(self, android_malicious_static, android_malicious_dynamic):
        """Stack an unrealistic number of techniques/capabilities to force
        the raw score past 100, confirm it clamps correctly."""
        many_techniques = [
            MitreTechnique(technique_id=f"T{i}", technique_name="x", confidence=1.0)
            for i in range(20)
        ]
        many_caps = [
            CapabilityTag(capability=f"cap{i}", confidence=1.0, evidence=["x"])
            for i in range(20)
        ]
        score = compute_risk_score(android_malicious_static, android_malicious_dynamic, many_techniques, many_caps)
        assert score == 100

    def test_score_never_goes_below_zero(self, benign_static):
        score = compute_risk_score(benign_static, None, [], [])
        assert score >= 0

    def test_score_is_always_an_integer(self, android_malicious_static, android_malicious_dynamic):
        score = compute_risk_score(android_malicious_static, android_malicious_dynamic, [], [])
        assert isinstance(score, int)


class TestDynamicSignalContribution:
    def test_flagged_c2_connection_adds_bonus(self, android_malicious_static, android_malicious_dynamic, empty_dynamic):
        score_with_c2 = compute_risk_score(android_malicious_static, android_malicious_dynamic, [], [])
        score_without_c2 = compute_risk_score(android_malicious_static, empty_dynamic, [], [])
        assert score_with_c2 > score_without_c2

    def test_no_dynamic_data_does_not_crash(self, android_malicious_static):
        score = compute_risk_score(android_malicious_static, None, [], [])
        assert isinstance(score, int)