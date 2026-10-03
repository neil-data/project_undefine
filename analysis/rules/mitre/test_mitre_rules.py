"""
test_mitre_rules.py — Unit tests for each MITRE ATT&CK rule in isolation.

Each test checks ONE rule's behavior specifically, not the whole
pipeline — if this fails, you know exactly which rule broke.
"""

from agents.mitre_mapper.mitre_rules import map_to_mitre


class TestSmsAccessRule:
    def test_fires_on_android_malicious_sample(self, android_malicious_static, android_malicious_dynamic):
        techniques = map_to_mitre(android_malicious_static, android_malicious_dynamic)
        ids = [t.technique_id for t in techniques]
        assert "T1517" in ids

    def test_does_not_fire_on_benign_sample(self, benign_static):
        techniques = map_to_mitre(benign_static, None)
        ids = [t.technique_id for t in techniques]
        assert "T1517" not in ids

    def test_confidence_is_exactly_09_when_both_signals_present(self, android_malicious_static, android_malicious_dynamic):
        techniques = map_to_mitre(android_malicious_static, android_malicious_dynamic)
        t1517 = next(t for t in techniques if t.technique_id == "T1517")
        assert t1517.confidence == 0.9

    def test_confidence_is_exactly_07_when_only_static_signal(self, android_malicious_static):
        techniques = map_to_mitre(android_malicious_static, None)
        t1517 = next(t for t in techniques if t.technique_id == "T1517")
        assert t1517.confidence == 0.7


class TestC2CommsRule:
    def test_fires_on_flagged_c2_connection(self, android_malicious_static, android_malicious_dynamic):
        techniques = map_to_mitre(android_malicious_static, android_malicious_dynamic)
        ids = [t.technique_id for t in techniques]
        assert "T1071" in ids

    def test_fires_on_static_hardcoded_ip_alone(self, android_malicious_static):
        techniques = map_to_mitre(android_malicious_static, None)
        ids = [t.technique_id for t in techniques]
        assert "T1071" in ids

    def test_does_not_fire_without_any_c2_signal(self, benign_static, empty_dynamic):
        techniques = map_to_mitre(benign_static, empty_dynamic)
        ids = [t.technique_id for t in techniques]
        assert "T1071" not in ids


class TestOverlayRule:
    def test_fires_on_system_alert_window_permission(self, android_malicious_static):
        techniques = map_to_mitre(android_malicious_static, None)
        ids = [t.technique_id for t in techniques]
        assert "T1417" in ids

    def test_does_not_fire_without_permission(self, benign_static):
        techniques = map_to_mitre(benign_static, None)
        ids = [t.technique_id for t in techniques]
        assert "T1417" not in ids


class TestDeviceAdminRule:
    def test_fires_on_device_policy_manager_call(self, android_malicious_static, android_malicious_dynamic):
        techniques = map_to_mitre(android_malicious_static, android_malicious_dynamic)
        ids = [t.technique_id for t in techniques]
        assert "T1626" in ids

    def test_does_not_fire_without_dynamic_data(self, android_malicious_static):
        """Static alone can't confirm device admin abuse — needs dynamic proof."""
        techniques = map_to_mitre(android_malicious_static, None)
        ids = [t.technique_id for t in techniques]
        assert "T1626" not in ids


class TestLocationTrackingRule:
    def test_fires_on_location_permission(self, android_malicious_static):
        techniques = map_to_mitre(android_malicious_static, None)
        ids = [t.technique_id for t in techniques]
        assert "T1430" in ids


class TestRegistryPersistenceRule:
    def test_fires_on_run_key_write(self, windows_malicious_static, windows_malicious_dynamic):
        techniques = map_to_mitre(windows_malicious_static, windows_malicious_dynamic)
        ids = [t.technique_id for t in techniques]
        assert "T1547.001" in ids

    def test_does_not_fire_on_android_sample(self, android_malicious_static, android_malicious_dynamic):
        """Android sample has no registry_changes — must not false-positive."""
        techniques = map_to_mitre(android_malicious_static, android_malicious_dynamic)
        ids = [t.technique_id for t in techniques]
        assert "T1547.001" not in ids

    def test_does_not_fire_without_dynamic_data(self, windows_malicious_static):
        techniques = map_to_mitre(windows_malicious_static, None)
        ids = [t.technique_id for t in techniques]
        assert "T1547.001" not in ids


class TestKeyloggingRule:
    def test_fires_on_keyboard_hook_api(self, windows_malicious_static, windows_malicious_dynamic):
        techniques = map_to_mitre(windows_malicious_static, windows_malicious_dynamic)
        ids = [t.technique_id for t in techniques]
        assert "T1056.001" in ids

    def test_fires_on_static_keyword_alone_lower_confidence(self, windows_malicious_static):
        techniques = map_to_mitre(windows_malicious_static, None)
        t1056 = next((t for t in techniques if t.technique_id == "T1056.001"), None)
        assert t1056 is not None
        assert t1056.confidence == 0.6  # static-only path

    def test_does_not_fire_without_any_signal(self, benign_static):
        techniques = map_to_mitre(benign_static, None)
        ids = [t.technique_id for t in techniques]
        assert "T1056.001" not in ids


class TestEdgeCases:
    def test_sparse_data_returns_empty_list_not_crash(self, sparse_static):
        techniques = map_to_mitre(sparse_static, None)
        assert techniques == []

    def test_no_duplicate_technique_ids(self, android_malicious_static, android_malicious_dynamic):
        techniques = map_to_mitre(android_malicious_static, android_malicious_dynamic)
        ids = [t.technique_id for t in techniques]
        assert len(ids) == len(set(ids)), "Duplicate MITRE technique IDs returned"

    def test_all_confidences_within_valid_range(self, android_malicious_static, android_malicious_dynamic):
        techniques = map_to_mitre(android_malicious_static, android_malicious_dynamic)
        for t in techniques:
            assert 0.0 <= t.confidence <= 1.0, f"{t.technique_id} confidence out of range: {t.confidence}"