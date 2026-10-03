"""
test_capability_rules.py — Unit tests for each capability classification rule.
"""

from agents.capability_classifier.capability_rules import classify_capabilities


class TestSmsOtpTheft:
    def test_fires_with_full_evidence(self, android_malicious_static, android_malicious_dynamic):
        tags = classify_capabilities(android_malicious_static, android_malicious_dynamic)
        caps = [t.capability for t in tags]
        assert "sms_otp_theft" in caps
        tag = next(t for t in tags if t.capability == "sms_otp_theft")
        assert len(tag.evidence) == 3  # permission + YARA + dynamic API call

    def test_does_not_fire_on_benign(self, benign_static):
        tags = classify_capabilities(benign_static, None)
        caps = [t.capability for t in tags]
        assert "sms_otp_theft" not in caps


class TestGpsTracking:
    def test_fires_on_location_permission_and_api(self, android_malicious_static, android_malicious_dynamic):
        tags = classify_capabilities(android_malicious_static, android_malicious_dynamic)
        caps = [t.capability for t in tags]
        assert "gps_tracking" in caps


class TestOverlayPhishing:
    def test_fires_on_system_alert_window(self, android_malicious_static):
        tags = classify_capabilities(android_malicious_static, None)
        caps = [t.capability for t in tags]
        assert "overlay_phishing" in caps


class TestDeviceAdminPersistence:
    def test_requires_dynamic_confirmation(self, android_malicious_static, android_malicious_dynamic):
        tags = classify_capabilities(android_malicious_static, android_malicious_dynamic)
        caps = [t.capability for t in tags]
        assert "uninstall_resistance" in caps

    def test_does_not_fire_static_only(self, android_malicious_static):
        tags = classify_capabilities(android_malicious_static, None)
        caps = [t.capability for t in tags]
        assert "uninstall_resistance" not in caps


class TestDataExfiltration:
    def test_fires_on_confirmed_c2_traffic(self, android_malicious_static, android_malicious_dynamic):
        tags = classify_capabilities(android_malicious_static, android_malicious_dynamic)
        caps = [t.capability for t in tags]
        assert "data_exfiltration" in caps

    def test_beaconing_interval_adds_evidence(self, android_malicious_static, android_malicious_dynamic):
        tags = classify_capabilities(android_malicious_static, android_malicious_dynamic)
        tag = next(t for t in tags if t.capability == "data_exfiltration")
        assert any("beaconing" in e for e in tag.evidence)


class TestKeylogging:
    def test_fires_on_windows_sample(self, windows_malicious_static, windows_malicious_dynamic):
        tags = classify_capabilities(windows_malicious_static, windows_malicious_dynamic)
        caps = [t.capability for t in tags]
        assert "keylogging" in caps

    def test_does_not_fire_on_android_sample(self, android_malicious_static, android_malicious_dynamic):
        tags = classify_capabilities(android_malicious_static, android_malicious_dynamic)
        caps = [t.capability for t in tags]
        assert "keylogging" not in caps


class TestPersistenceRegistry:
    def test_fires_on_run_key(self, windows_malicious_static, windows_malicious_dynamic):
        tags = classify_capabilities(windows_malicious_static, windows_malicious_dynamic)
        caps = [t.capability for t in tags]
        assert "persistence_registry" in caps

    def test_does_not_fire_without_dynamic(self, windows_malicious_static):
        tags = classify_capabilities(windows_malicious_static, None)
        caps = [t.capability for t in tags]
        assert "persistence_registry" not in caps


class TestEdgeCases:
    def test_sparse_data_returns_empty_not_crash(self, sparse_static):
        tags = classify_capabilities(sparse_static, None)
        assert tags == []

    def test_empty_dynamic_object_does_not_crash(self, android_malicious_static, empty_dynamic):
        """Dynamic ran but found nothing — must not crash, must not false-positive on dynamic-only capabilities."""
        tags = classify_capabilities(android_malicious_static, empty_dynamic)
        caps = [t.capability for t in tags]
        assert "uninstall_resistance" not in caps
        assert "persistence_registry" not in caps

    def test_no_duplicate_capabilities(self, android_malicious_static, android_malicious_dynamic):
        tags = classify_capabilities(android_malicious_static, android_malicious_dynamic)
        caps = [t.capability for t in tags]
        assert len(caps) == len(set(caps)), "Duplicate capability tags returned"

    def test_all_confidences_within_valid_range(self, android_malicious_static, android_malicious_dynamic):
        tags = classify_capabilities(android_malicious_static, android_malicious_dynamic)
        for t in tags:
            assert 0.0 <= t.confidence <= 1.0, f"{t.capability} confidence out of range: {t.confidence}"

    def test_every_tag_has_evidence(self, android_malicious_static, android_malicious_dynamic):
        """A capability claim with zero evidence is not useful/defensible in a report."""
        tags = classify_capabilities(android_malicious_static, android_malicious_dynamic)
        for t in tags:
            assert len(t.evidence) > 0, f"{t.capability} has no supporting evidence"