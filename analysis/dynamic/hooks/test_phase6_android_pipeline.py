"""
test_phase6_android_pipeline.py — Host-side Android event pipeline.

The Android Frida agent already emitted SMS, location, clipboard, camera,
microphone, accessibility and overlay events. Before this phase the host
engine had no catalog entry for any of them, so resolve_api() returned None
and ingest() dropped every one — the guest collected the evidence and the
control plane threw it away.

These tests hold that path open end to end: the event resolves, normalizes,
decodes, correlates into a named behavior, and scores.

The negative cases carry as much weight as the detections. A messaging app
reads SMS. A maps app polls location. A keyboard adds views and inflates
layouts. If any of those produce a finding, the Android monitor is noise and
an investigator learns to ignore it.

Run:
    pytest dynamic-sandbox/hooks/test_phase6_android_pipeline.py -v
"""

from __future__ import annotations

from uuid import uuid4

import pytest

from hooks.api_catalog import (
    ANDROID_MONITORED_APIS,
    ANDROID_REQUIRED_APIS,
    API_CATALOG,
    ApiCategory,
    classify_content_uri,
    dangerous_permissions,
    has_credential_search_term,
    is_covert_audio_source,
    is_dangerous_permission,
    is_overlay_window,
    resolve_api,
)
from hooks.hook_engine import CHAIN_RULES, CONDITIONS, ChainSeverity, HookEngine
from hooks.hook_installer import (
    generate_cape_config,
    generate_frida_android_agent,
    installation_manifest,
)
from hooks.stage_integration import MockHookSource, StageHookMonitor


@pytest.fixture
def engine():
    return HookEngine(uuid4())


@pytest.fixture
def source():
    return MockHookSource()


def feed(engine, calls):
    for call in calls:
        engine.ingest(call)
    return set(engine.chain_counts)


def findings(engine):
    return {f["rule_id"] for f in engine.volume_findings()}


# ============================================================================
# Catalog coverage — the gap this phase closed
# ============================================================================

class TestAndroidCatalog:

    def test_every_agent_event_resolves(self):
        """
        The guest emits these names; each must map to a catalog entry.

        This is the regression test for the original defect: an unresolved
        name is silently discarded, so a missing entry costs an entire
        capability with no error anywhere.
        """
        for name in ANDROID_REQUIRED_APIS:
            hook = resolve_api(name)
            assert hook is not None, f"{name} does not resolve — events will be dropped"
            assert hook.platform == "android"

    def test_agent_source_and_catalog_agree(self):
        """Names emitted by the generated agent must all exist in the catalog."""
        agent = generate_frida_android_agent()
        for name in ANDROID_REQUIRED_APIS:
            assert f"rec('{name}'" in agent, f"{name} is catalogued but never emitted"

    def test_android_entries_carry_mitre_mapping(self):
        # LayoutInflate is deliberately unmapped: on its own it is ordinary UI
        # work and only has meaning as a link inside the overlay chain.
        unmapped = {
            name for name in ANDROID_REQUIRED_APIS
            if not API_CATALOG[name].mitre and name != "LayoutInflate"
        }
        assert not unmapped

    def test_android_categories_are_distinct_from_windows(self):
        android_categories = {API_CATALOG[n].category for n in ANDROID_MONITORED_APIS}
        assert ApiCategory.SMS in android_categories
        assert ApiCategory.ACCESSIBILITY in android_categories
        assert ApiCategory.OVERLAY in android_categories

    def test_sms_body_is_never_captured_verbatim(self):
        """Message content must stay in the guest — only the digest travels."""
        body = next(a for a in API_CATALOG["SendSMS"].args if a.name == "messageBodyHash")
        assert body.hash_only

    def test_cape_config_excludes_android(self):
        """CAPE hooks native exports; Java class names would break its monitor."""
        names = {h["name"] for h in generate_cape_config()["api_hooks"]}
        assert not (names & ANDROID_REQUIRED_APIS)

    def test_manifest_reports_both_guests_separately(self):
        manifest = installation_manifest()
        # Check that manifest covers at least the required Android APIs
        assert manifest["android_api_count"] >= len(ANDROID_REQUIRED_APIS)
        assert ANDROID_REQUIRED_APIS <= set(manifest["android_apis"])
        assert not (set(manifest["windows_apis"]) & ANDROID_REQUIRED_APIS)

    def test_android_names_get_no_ansi_aliases(self):
        """SendSMSW is not a thing — alias generation is Windows-only."""
        assert resolve_api("SendSMSW") is None

    def test_every_android_rule_condition_is_registered(self):
        for rule in CHAIN_RULES:
            for predicate in rule.conditions.values():
                assert predicate in CONDITIONS, f"{rule.rule_id} names unknown {predicate}"


# ============================================================================
# Ingest and normalization
# ============================================================================

class TestAndroidIngest:

    def test_android_event_is_no_longer_dropped(self, engine, source):
        call, _ = engine.ingest(source.android_sms_interception()[0])
        assert call is not None
        assert call.api_name == "ReadSMS"
        assert call.category is ApiCategory.SMS
        assert engine.total_calls == 1

    def test_content_uri_is_classified(self, engine, source):
        call, _ = engine.ingest(source.android_sms_interception()[0])
        assert call.decoded_args["content_family"] == "sms"

    def test_permissions_are_filtered_to_the_sensitive_subset(self, engine, source):
        call, _ = engine.ingest(source.android_permission_escalation()[0])
        assert "android.permission.RECORD_AUDIO" in call.decoded_args["dangerous_permissions"]
        assert call.decoded_args["permission_count"] == 6

    def test_overlay_window_type_is_named(self, engine, source):
        overlay = next(c for c in source.android_banking_overlay()
                       if c["api"] == "OverlayWindowAdded")
        call, _ = engine.ingest(overlay)
        assert call.decoded_args["window_type_name"] == "TYPE_APPLICATION_OVERLAY"
        assert call.decoded_args["is_overlay"] is True

    def test_call_recording_is_distinguished_from_room_audio(self, engine):
        call, _ = engine.ingest({
            "api": "MediaRecorderAudioSource", "pid": 1, "tid": 1,
            "args": {"source": 4, "isMic": False},          # VOICE_CALL
        })
        assert call.decoded_args["audio_source_name"] == "VOICE_CALL"
        assert call.decoded_args["records_call"] is True

        call, _ = engine.ingest({
            "api": "MediaRecorderAudioSource", "pid": 1, "tid": 1,
            "args": {"source": 1, "isMic": True},           # MIC
        })
        assert call.decoded_args["records_call"] is False
        assert call.decoded_args["covert_audio"] is True

    def test_guest_string_numbers_are_coerced(self, engine):
        """Frida reports longs as strings; the interval check must survive that."""
        call, _ = engine.ingest({
            "api": "RequestLocationUpdates", "pid": 1, "tid": 1,
            "args": {"provider": "gps", "minTimeMs": "3000", "minDistanceM": 0},
        })
        assert call.decoded_args["high_frequency"] is True
        assert call.decoded_args["interval_ms"] == 3000

    def test_dex_load_is_flagged_under_the_loadlibrary_identity(self, engine, source):
        call, _ = engine.ingest(source.android_dynamic_dex()[0])
        assert call.decoded_args["dynamic_dex"] is True


# ============================================================================
# Behavior chains
# ============================================================================

class TestAndroidChains:

    def test_sms_interception(self, engine, source):
        assert "android_sms_interception" in feed(engine, source.android_sms_interception())

    def test_sms_exfiltration(self, engine, source):
        assert "android_sms_exfiltration" in feed(engine, source.android_sms_exfiltration())

    def test_contact_harvest_then_smishing(self, engine, source):
        assert "android_contact_smishing" in feed(
            engine, source.android_contact_harvest(smish=True)
        )

    def test_contact_harvest_then_upload(self, engine, source):
        assert "android_contact_exfiltration" in feed(
            engine, source.android_contact_harvest(smish=False)
        )

    def test_location_tracking(self, engine, source):
        detected = feed(engine, source.android_location_tracking())
        assert "android_location_exfiltration" in detected
        assert "android_cached_location_exfiltration" in detected

    def test_crypto_clipper(self, engine, source):
        detected = feed(engine, source.android_crypto_clipper())
        assert "android_crypto_clipper" in detected

    def test_generic_clipboard_hijack_stays_silent_under_the_clipper(self, engine, source):
        """
        The narrower rule must not double-report the same substitution.

        Counting and emission are separate by design, so the match is still
        tallied — what must not happen is a second *finding* describing the
        same clipboard swap at a lower level of detail.
        """
        feed(engine, source.android_crypto_clipper())
        emitted = {c.rule_id for c in engine.chains}
        assert "android_crypto_clipper" in emitted
        assert "android_clipboard_hijack" not in emitted

    def test_clipboard_hijack_fires_without_the_crypto_heuristic(self, engine):
        calls = [
            {"api": "ClipboardRead", "pid": 1, "tid": 1,
             "args": {"hasContent": True, "possibleCryptoAddress": False}},
            {"api": "ClipboardWrite", "pid": 1, "tid": 1, "args": {"textLength": 12}},
        ]
        assert "android_clipboard_hijack" in feed(engine, calls)

    def test_audio_surveillance(self, engine, source):
        detected = feed(engine, source.android_audio_surveillance())
        assert "android_audio_surveillance" in detected
        assert "android_covert_audio_recording" in detected

    def test_camera_surveillance(self, engine, source):
        detected = feed(engine, source.android_camera_surveillance())
        assert "android_camera_surveillance" in detected
        assert "android_video_recording" in detected

    def test_accessibility_credential_theft(self, engine, source):
        detected = feed(engine, source.android_accessibility_credential_theft())
        assert "android_accessibility_credential_theft" in detected

    def test_banking_overlay(self, engine, source):
        detected = feed(engine, source.android_banking_overlay())
        assert "android_targeted_overlay" in detected
        assert "android_overlay_credential_theft" in detected

    def test_dynamic_dex_then_network(self, engine, source):
        assert "android_dynamic_dex_then_network" in feed(engine, source.android_dynamic_dex())

    def test_chain_carries_severity_and_mitre(self, engine, source):
        feed(engine, source.android_sms_interception())
        chain = engine.chains[0]
        assert chain.severity is ChainSeverity.CRITICAL
        assert "T1636.004" in chain.mitre

    def test_chain_evidence_names_the_recipient(self, engine, source):
        feed(engine, source.android_sms_interception())
        evidence = engine.chains[0].evidence
        assert "+919876500011" in evidence["sms_destinations"]
        assert "content://sms/inbox" in evidence["content_uris"]


# ============================================================================
# False positives — the tests that decide whether this is usable
# ============================================================================

class TestAndroidFalsePositives:

    def test_ordinary_app_activity_is_silent(self, engine, source):
        assert feed(engine, source.android_benign_activity()) == set()

    def test_ordinary_app_activity_produces_no_volume_findings(self, engine, source):
        feed(engine, source.android_benign_activity())
        assert findings(engine) == set()

    def test_apps_own_windows_are_not_overlays(self, engine):
        """
        addView is how every app draws itself. Only overlay window types can
        cover another app, and without that check this rule fires on all UI.
        """
        calls = [
            {"api": "AccessibilityEvent", "pid": 1, "tid": 1,
             "args": {"packageName": "com.example", "eventType": 32,
                      "isWindowChange": True}},
            {"api": "OverlayWindowAdded", "pid": 1, "tid": 1,
             "args": {"windowType": 1, "flags": 0}},     # TYPE_APPLICATION
        ]
        assert "android_targeted_overlay" not in feed(engine, calls)

    def test_accessibility_without_text_capture_does_not_exfiltrate(self, engine):
        """A service that only sees window changes is not reading credentials."""
        calls = [
            {"api": "AccessibilityEvent", "pid": 1, "tid": 1,
             "args": {"packageName": "com.example", "eventType": 32,
                      "isTextChange": False, "isWindowChange": True}},
            {"api": "InternetConnect", "pid": 1, "tid": 1,
             "args": {"lpszServerName": "api.example.test", "nServerPort": 443}},
        ]
        assert "android_accessibility_exfiltration" not in feed(engine, calls)

    def test_non_credential_node_search_is_silent(self, engine):
        calls = [
            {"api": "AccessibilityEvent", "pid": 1, "tid": 1,
             "args": {"packageName": "com.example", "eventType": 16,
                      "isTextChange": True}},
            {"api": "AccessibilityFindByText", "pid": 1, "tid": 1,
             "args": {"searchText": "Continue", "sensitiveSearch": False}},
        ]
        assert "android_accessibility_credential_theft" not in feed(engine, calls)

    def test_deliberate_voice_recognition_is_not_covert_capture(self, engine):
        """VOICE_RECOGNITION is a user-initiated dictation source."""
        calls = [
            {"api": "MediaRecorderAudioSource", "pid": 1, "tid": 1,
             "args": {"source": 6, "isMic": False}},
            {"api": "MediaRecorderStart", "pid": 1, "tid": 1, "args": {}},
        ]
        assert "android_covert_audio_recording" not in feed(engine, calls)

    def test_screen_recording_is_not_camera_capture(self, engine):
        calls = [
            {"api": "MediaRecorderVideoSource", "pid": 1, "tid": 1,
             "args": {"source": 2}},        # SURFACE, not CAMERA
            {"api": "MediaRecorderStart", "pid": 1, "tid": 1, "args": {}},
        ]
        assert "android_video_recording" not in feed(engine, calls)

    def test_ordinary_dex_free_library_load_is_silent(self, engine):
        calls = [
            {"api": "LoadLibrary", "pid": 1, "tid": 1,
             "args": {"lpLibFileName": "sqlite"}},
            {"api": "InternetConnect", "pid": 1, "tid": 1,
             "args": {"lpszServerName": "api.example.test", "nServerPort": 443}},
        ]
        assert "android_dynamic_dex_then_network" not in feed(engine, calls)

    def test_a_few_texts_are_not_a_burst(self, engine, source):
        feed(engine, source.android_sms_burst(count=3))
        assert "android_sms_burst" not in findings(engine)

    def test_two_sensitive_permissions_are_not_escalation(self, engine):
        engine.ingest({
            "api": "RequestPermissions", "pid": 1, "tid": 1,
            "args": {"permissions": ["android.permission.CAMERA",
                                     "android.permission.RECORD_AUDIO"]},
        })
        assert "android_permission_escalation" not in findings(engine)


# ============================================================================
# Volume findings
# ============================================================================

class TestAndroidVolumeFindings:

    def test_sms_burst(self, engine, source):
        feed(engine, source.android_sms_burst(count=15))
        finding = next(f for f in engine.volume_findings()
                       if f["rule_id"] == "android_sms_burst")
        assert finding["count"] == 15
        assert len(finding["recipients"]) > 1

    def test_continuous_location_tracking(self, engine, source):
        feed(engine, source.android_location_tracking(polls=25))
        assert "android_continuous_tracking" in findings(engine)

    def test_sustained_audio_capture_reports_volume(self, engine, source):
        feed(engine, source.android_audio_surveillance(reads=60))
        finding = next(f for f in engine.volume_findings()
                       if f["rule_id"] == "android_sustained_audio_capture")
        assert finding["bytes_captured"] == 60 * 4096
        assert "android_call_recording" in findings(engine)

    def test_clipboard_monitoring(self, engine, source):
        feed(engine, source.android_clipboard_monitoring(polls=35))
        assert "android_clipboard_monitoring" in findings(engine)

    def test_keylogging_names_the_apps_observed(self, engine, source):
        feed(engine, source.android_accessibility_credential_theft(text_events=60))
        finding = next(f for f in engine.volume_findings()
                       if f["rule_id"] == "android_accessibility_keylogging")
        assert "com.bank.example" in finding["packages"]

    def test_single_invisible_overlay_is_enough(self, engine, source):
        """
        No threshold here on purpose. A transparent, untouchable window over
        the screen has no benign explanation — one is the finding.
        """
        feed(engine, source.android_tapjacking())
        assert "android_tapjacking" in findings(engine)

    def test_permission_escalation(self, engine, source):
        feed(engine, source.android_permission_escalation())
        finding = next(f for f in engine.volume_findings()
                       if f["rule_id"] == "android_permission_escalation")
        assert finding["count"] == 6

    def test_volume_counts_survive_rate_limiting(self, engine, source):
        """
        Suppressed calls still count. A sample that floods a hook past its
        limit must be measured on what it did, not on what got logged.
        """
        feed(engine, source.android_sms_burst(count=15))
        assert engine.call_counts["SendSMS"] == 15


# ============================================================================
# Scoring, reporting and stage attribution
# ============================================================================

class TestAndroidReporting:

    def test_android_behavior_contributes_risk(self, engine, source):
        feed(engine, source.android_banking_overlay())
        assert engine.risk_contribution() > 0

    def test_benign_android_activity_scores_zero(self, engine, source):
        feed(engine, source.android_benign_activity())
        assert engine.risk_contribution() == 0

    def test_summary_exposes_android_signals(self, engine, source):
        feed(engine, source.android_accessibility_credential_theft(text_events=60))
        summary = engine.summary()
        assert summary["android_signals"]["accessibility_text_events"] == 60
        assert "T1417.001" in summary["mitre_techniques"]

    def test_summary_lists_requested_permissions(self, engine, source):
        feed(engine, source.android_permission_escalation())
        assert "android.permission.CAMERA" in engine.summary()["android_permissions_requested"]

    def test_stage_attribution_works_for_android(self, source):
        monitor = StageHookMonitor(uuid4())
        monitor.enter_stage("interaction")
        monitor.ingest_batch(source.android_banking_overlay())
        monitor.exit_stage("interaction")

        breakdown = monitor.engine.stage_breakdown()
        assert "interaction" in breakdown
        assert breakdown["interaction"]["critical_chains"] >= 1


# ============================================================================
# Helper predicates
# ============================================================================

class TestAndroidHelpers:

    @pytest.mark.parametrize("permission,expected", [
        ("android.permission.READ_SMS", True),
        ("READ_SMS", True),
        ("android.permission.INTERNET", False),
        (None, False),
    ])
    def test_dangerous_permission(self, permission, expected):
        assert is_dangerous_permission(permission) is expected

    def test_dangerous_permissions_deduplicates_and_sorts(self):
        result = dangerous_permissions([
            "android.permission.CAMERA",
            "android.permission.CAMERA",
            "android.permission.INTERNET",
        ])
        assert result == ["android.permission.CAMERA"]

    def test_dangerous_permissions_tolerates_a_bare_string(self):
        assert dangerous_permissions("android.permission.CAMERA")

    @pytest.mark.parametrize("uri,expected", [
        ("content://sms/inbox", "sms"),
        ("content://mms-sms/conversations", "sms"),
        ("content://com.android.contacts/data", "contacts"),
        ("content://media/external/images", None),
        (None, None),
    ])
    def test_classify_content_uri(self, uri, expected):
        assert classify_content_uri(uri) == expected

    @pytest.mark.parametrize("window_type,expected", [
        (2038, True), (2003, True), (1, False), ("2038", True), (None, False),
    ])
    def test_is_overlay_window(self, window_type, expected):
        assert is_overlay_window(window_type) is expected

    @pytest.mark.parametrize("source_id,expected", [
        (1, True), (4, True), (6, False), (0, False), (None, False),
    ])
    def test_is_covert_audio_source(self, source_id, expected):
        assert is_covert_audio_source(source_id) is expected

    @pytest.mark.parametrize("text,expected", [
        ("Enter OTP", True), ("UPI PIN", True), ("Continue", False), (None, False),
    ])
    def test_credential_search_terms(self, text, expected):
        assert has_credential_search_term(text) is expected


if __name__ == "__main__":
    import sys
    sys.exit(pytest.main([__file__, "-v"]))
