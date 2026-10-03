"""
test_phase4_android_engine.py — Android behavior engine tests for Phase 4.

Tests the enhanced Android behavior detection capabilities including:
- Enhanced permission monitoring
- Advanced SMS analysis
- Location monitoring with geofencing
- Contact monitoring with abuse patterns
- Enhanced clipboard monitoring
- Camera monitoring with surveillance detection
- Microphone monitoring
- Enhanced accessibility detection
- Enhanced overlay detection
- Android-specific behavior correlation rules
"""

import pytest
from datetime import datetime, timedelta
from uuid import uuid4

from hooks.hook_engine import (
    HookEngine,
    ApiCallEvent,
    ChainSeverity,
    CHAIN_RULES,
)
from hooks.api_catalog import (
    API_CATALOG,
    resolve_api,
)


class TestAndroidPermissionMonitoring:
    """Test enhanced Android permission detection."""
    
    def test_grant_runtime_permission_detection(self):
        """Test privileged permission granting detection."""
        api = resolve_api("GrantRuntimePermission")
        assert api is not None
        assert api.name == "GrantRuntimePermission"
        assert api.category.value == "permissions"
        assert api.baseline_risk.value == "high"
        assert "T1068" in api.mitre
    
    def test_set_package_permission_detection(self):
        """Test permission state modification detection."""
        api = resolve_api("SetPackagePermission")
        assert api is not None
        assert api.name == "SetPackagePermission"
        assert "T1068" in api.mitre
    
    def test_permission_escalation_chain(self):
        """Test permission escalation detection."""
        engine = HookEngine(uuid4())
        
        calls = [
            self._create_call("GrantRuntimePermission", {"permissionName": "android.permission.SEND_SMS", "packageName": "com.malware"}),
        ]
        
        chains = engine.ingest_batch(calls)
        assert "android_permission_escalation" in [c.rule_id for c in chains]
    
    def test_permission_state_manipulation_chain(self):
        """Test permission state manipulation detection."""
        engine = HookEngine(uuid4())
        
        calls = [
            self._create_call("SetPackagePermission", {"permissionName": "android.permission.CAMERA", "permissionState": 1}),
        ]
        
        chains = engine.ingest_batch(calls)
        assert "android_permission_state_manipulation" in [c.rule_id for c in chains]
    
    def _create_call(self, api_name, args, pid=1234):
        """Helper to create an API call event."""
        api = resolve_api(api_name)
        return ApiCallEvent(
            call_id=uuid4(),
            analysis_id=uuid4(),
            api_name=api_name,
            raw_name=api_name,
            module=api.module if api else "unknown",
            timestamp=datetime.now(),
            pid=pid,
            tid=1,
            args=args,
        )


class TestAndroidSMSMonitoring:
    """Test enhanced SMS detection."""
    
    def test_delete_sms_detection(self):
        """Test SMS deletion detection."""
        api = resolve_api("DeleteSMS")
        assert api is not None
        assert api.name == "DeleteSMS"
        assert "T1070.004" in api.mitre
    
    def test_send_multipart_text_message_detection(self):
        """Test alternative multipart SMS detection."""
        api = resolve_api("SendMultipartTextMessage")
        assert api is not None
        assert api.name == "SendMultipartTextMessage"
    
    def test_download_mms_detection(self):
        """Test MMS download detection."""
        api = resolve_api("DownloadMMS")
        assert api is not None
        assert api.name == "DownloadMMS"
        assert "T1105" in api.mitre
    
    def test_sms_evidence_destruction_chain(self):
        """Test SMS evidence destruction detection."""
        engine = HookEngine(uuid4())
        
        calls = [
            self._create_call("ReadSMS", {"uri": "content://sms"}),
            self._create_call("DeleteSMS", {"uri": "content://sms/1"}),
        ]
        
        chains = engine.ingest_batch(calls)
        assert "android_sms_evidence_destruction" in [c.rule_id for c in chains]
    
    def test_mms_payload_delivery_chain(self):
        """Test MMS payload delivery detection."""
        engine = HookEngine(uuid4())
        
        calls = [
            self._create_call("DownloadMMS", {"contentUrl": "http://attacker.com/payload.bin"}),
        ]
        
        chains = engine.ingest_batch(calls)
        assert "android_mms_payload_delivery" in [c.rule_id for c in chains]
    
    def _create_call(self, api_name, args, pid=1234):
        """Helper to create an API call event."""
        api = resolve_api(api_name)
        return ApiCallEvent(
            call_id=uuid4(),
            analysis_id=uuid4(),
            api_name=api_name,
            raw_name=api_name,
            module=api.module if api else "unknown",
            timestamp=datetime.now(),
            pid=pid,
            tid=1,
            args=args,
        )


class TestAndroidLocationMonitoring:
    """Test enhanced location detection."""
    
    def test_geofencing_detection(self):
        """Test geofencing detection."""
        api = resolve_api("GeofencingAdd")
        assert api is not None
        assert api.name == "GeofencingAdd"
        assert api.category.value == "location"
    
    def test_high_accuracy_detection(self):
        """Test high-accuracy location request detection."""
        api = resolve_api("LocationRequestHighAccuracy")
        assert api is not None
        assert api.name == "LocationRequestHighAccuracy"
    
    def test_geofencing_surveillance_chain(self):
        """Test geofencing surveillance detection."""
        engine = HookEngine(uuid4())
        
        calls = [
            self._create_call("GeofencingAdd", {"latitude": 40.7128, "longitude": -74.0060, "radius": 100.0, "transitionType": 1}),
        ]
        
        chains = engine.ingest_batch(calls)
        assert "android_geofencing_surveillance" in [c.rule_id for c in chains]
    
    def test_high_accuracy_tracking_chain(self):
        """Test high-accuracy tracking detection."""
        engine = HookEngine(uuid4())
        
        calls = [
            self._create_call("LocationRequestHighAccuracy", {"quality": 100, "intervalMs": 5000}),
        ]
        
        chains = engine.ingest_batch(calls)
        assert "android_high_accuracy_tracking" in [c.rule_id for c in chains]
    
    def test_location_geofence_exfiltration_chain(self):
        """Test geofencing exfiltration detection."""
        engine = HookEngine(uuid4())
        
        calls = [
            self._create_call("GeofencingAdd", {"latitude": 40.7128, "longitude": -74.0060, "radius": 100.0, "transitionType": 1}),
            self._create_call("InternetConnect", {"lpszServerName": "attacker.com"}),
        ]
        
        chains = engine.ingest_batch(calls)
        assert "android_location_geofence_exfiltration" in [c.rule_id for c in chains]  # Fixed rule_id
    
    def _create_call(self, api_name, args, pid=1234):
        """Helper to create an API call event."""
        api = resolve_api(api_name)
        return ApiCallEvent(
            call_id=uuid4(),
            analysis_id=uuid4(),
            api_name=api_name,
            raw_name=api_name,
            module=api.module if api else "unknown",
            timestamp=datetime.now(),
            pid=pid,
            tid=1,
            args=args,
        )


class TestAndroidContactMonitoring:
    """Test enhanced contact detection."""
    
    def test_write_contacts_detection(self):
        """Test contact writing detection."""
        api = resolve_api("WriteContacts")
        assert api is not None
        assert api.name == "WriteContacts"
        assert "T1582" in api.mitre
    
    def test_delete_contacts_detection(self):
        """Test contact deletion detection."""
        api = resolve_api("DeleteContacts")
        assert api is not None
        assert api.name == "DeleteContacts"
        assert "T1070.004" in api.mitre
    
    def test_contact_manipulation_chain(self):
        """Test contact manipulation detection."""
        engine = HookEngine(uuid4())
        
        calls = [
            self._create_call("WriteContacts", {"uri": "content://com.android.contacts", "values": "contact_data"}),
        ]
        
        chains = engine.ingest_batch(calls)
        assert "android_contact_manipulation" in [c.rule_id for c in chains]
    
    def test_contact_replacement_chain(self):
        """Test contact replacement detection."""
        engine = HookEngine(uuid4())
        
        calls = [
            self._create_call("DeleteContacts", {"uri": "content://com.android.contacts/1"}),
            self._create_call("WriteContacts", {"uri": "content://com.android.contacts", "values": "fake_contact"}),
        ]
        
        chains = engine.ingest_batch(calls)
        assert "android_contact_replacement" in [c.rule_id for c in chains]
    
    def _create_call(self, api_name, args, pid=1234):
        """Helper to create an API call event."""
        api = resolve_api(api_name)
        return ApiCallEvent(
            call_id=uuid4(),
            analysis_id=uuid4(),
            api_name=api_name,
            raw_name=api_name,
            module=api.module if api else "unknown",
            timestamp=datetime.now(),
            pid=pid,
            tid=1,
            args=args,
        )


class TestAndroidCameraMonitoring:
    """Test enhanced camera detection."""
    
    def test_camera_take_picture_detection(self):
        """Test covert photo capture detection."""
        api = resolve_api("CameraTakePicture")
        assert api is not None
        assert api.name == "CameraTakePicture"
        assert api.baseline_risk.value == "high"
    
    def test_camera_set_parameters_detection(self):
        """Test camera parameter modification detection."""
        api = resolve_api("CameraSetParameters")
        assert api is not None
        assert api.name == "CameraSetParameters"
    
    def test_covert_photo_capture_chain(self):
        """Test covert photo capture detection."""
        engine = HookEngine(uuid4())
        
        calls = [
            self._create_call("CameraTakePicture", {"cameraId": "0", "facing": "1"}),
        ]
        
        chains = engine.ingest_batch(calls)
        assert "android_covert_photo_capture" in [c.rule_id for c in chains]
    
    def test_camera_without_permission_flow_chain(self):
        """Test camera access without permission flow."""
        engine = HookEngine(uuid4())
        
        calls = [
            self._create_call("CameraOpen", {"cameraId": "0", "facing": "1", "api": "camera2"}),
            self._create_call("CameraSetParameters", {"parameters": "no_shutter_sound"}),
        ]
        
        chains = engine.ingest_batch(calls)
        assert "android_camera_without_permission_flow" in [c.rule_id for c in chains]
    
    def _create_call(self, api_name, args, pid=1234):
        """Helper to create an API call event."""
        api = resolve_api(api_name)
        return ApiCallEvent(
            call_id=uuid4(),
            analysis_id=uuid4(),
            api_name=api_name,
            raw_name=api_name,
            module=api.module if api else "unknown",
            timestamp=datetime.now(),
            pid=pid,
            tid=1,
            args=args,
        )


class TestAndroidAccessibilityDetection:
    """Test enhanced accessibility detection."""
    
    def test_accessibility_perform_action_detection(self):
        """Test accessibility action automation detection."""
        api = resolve_api("AccessibilityPerformAction")
        assert api is not None
        assert api.name == "AccessibilityPerformAction"
        assert "T1516" in api.mitre
    
    def test_accessibility_find_node_detection(self):
        """Test accessibility node finding detection."""
        api = resolve_api("AccessibilityFindAccessibilityNodeInfo")
        assert api is not None
        assert api.name == "AccessibilityFindAccessibilityNodeInfo"
    
    def test_accessibility_automation_chain(self):
        """Test accessibility automation detection."""
        engine = HookEngine(uuid4())
        
        calls = [
            self._create_call("AccessibilityEvent", {"packageName": "com.bankapp", "eventType": 32}),
            self._create_call("AccessibilityPerformAction", {"action": 16, "packageName": "com.bankapp"}),
        ]
        
        chains = engine.ingest_batch(calls)
        assert "android_accessibility_automation" in [c.rule_id for c in chains]
    
    def test_accessibility_credential_automation_chain(self):
        """Test accessibility credential automation detection."""
        engine = HookEngine(uuid4())
        
        calls = [
            self._create_call("AccessibilityFindByText", {"searchText": "OTP", "sensitiveSearch": 1}),
            self._create_call("AccessibilityPerformAction", {"action": 16, "packageName": "com.bankapp"}),
        ]
        
        chains = engine.ingest_batch(calls)
        assert "android_accessibility_credential_automation" in [c.rule_id for c in chains]
    
    def _create_call(self, api_name, args, pid=1234):
        """Helper to create an API call event."""
        api = resolve_api(api_name)
        return ApiCallEvent(
            call_id=uuid4(),
            analysis_id=uuid4(),
            api_name=api_name,
            raw_name=api_name,
            module=api.module if api else "unknown",
            timestamp=datetime.now(),
            pid=pid,
            tid=1,
            args=args,
        )


class TestAndroidOverlayDetection:
    """Test enhanced overlay detection."""
    
    def test_window_manager_add_view_detection(self):
        """Test alternative overlay creation detection."""
        api = resolve_api("WindowManagerAddView")
        assert api is not None
        assert api.name == "WindowManagerAddView"
        assert "T1516" in api.mitre
    
    def test_system_alert_window_request_detection(self):
        """Test overlay permission request detection."""
        api = resolve_api("SystemAlertWindowRequest")
        assert api is not None
        assert api.name == "SystemAlertWindowRequest"
        assert "T1626" in api.mitre
    
    def test_overlay_without_permission_chain(self):
        """Test overlay creation without permission."""
        engine = HookEngine(uuid4())
        
        calls = [
            self._create_call("WindowManagerAddView", {"view": "ptr", "params": "ptr"}),
        ]
        
        chains = engine.ingest_batch(calls)
        assert "android_overlay_without_permission" in [c.rule_id for c in chains]
    
    def test_overlay_with_permission_escalation_chain(self):
        """Test overlay permission escalation detection."""
        engine = HookEngine(uuid4())
        
        calls = [
            self._create_call("SystemAlertWindowRequest", {"requested": 1, "granted": 1}),
            self._create_call("OverlayWindowAdded", {"windowType": 2038, "flags": 0, "isOverlay": 1}),
        ]
        
        chains = engine.ingest_batch(calls)
        assert "android_overlay_with_permission_escalation" in [c.rule_id for c in chains]
    
    def test_automated_overlay_attack_chain(self):
        """Test automated overlay attack detection."""
        engine = HookEngine(uuid4())
        
        calls = [
            self._create_call("AccessibilityEvent", {"packageName": "com.bankapp", "eventType": 32, "isWindowChange": 1}),
            self._create_call("OverlayWindowAdded", {"windowType": 2038, "flags": 0, "isOverlay": 1}),
        ]
        
        chains = engine.ingest_batch(calls)
        assert "android_automated_overlay_attack" in [c.rule_id for c in chains]
    
    def _create_call(self, api_name, args, pid=1234):
        """Helper to create an API call event."""
        api = resolve_api(api_name)
        return ApiCallEvent(
            call_id=uuid4(),
            analysis_id=uuid4(),
            api_name=api_name,
            raw_name=api_name,
            module=api.module if api else "unknown",
            timestamp=datetime.now(),
            pid=pid,
            tid=1,
            args=args,
        )


class TestAndroidBehaviorCorrelation:
    """Test Android behavior correlation rules."""
    
    def test_permission_escalation_correlation(self):
        """Test permission escalation behavior correlation."""
        engine = HookEngine(uuid4())
        
        calls = [
            self._create_call("GrantRuntimePermission", {"permissionName": "android.permission.ACCESS_FINE_LOCATION", "packageName": "com.malware"}),
        ]
        
        chains = engine.ingest_batch(calls)
        assert any(c.rule_id == "android_permission_escalation" for c in chains)
        assert any(c.severity == ChainSeverity.CRITICAL for c in chains)
    
    def test_evidence_destruction_correlation(self):
        """Test evidence destruction behavior correlation."""
        engine = HookEngine(uuid4())
        
        calls = [
            self._create_call("ReadSMS", {"uri": "content://sms"}),
            self._create_call("DeleteSMS", {"uri": "content://sms/1"}),
        ]
        
        chains = engine.ingest_batch(calls)
        assert "android_sms_evidence_destruction" in [c.rule_id for c in chains]
    
    def test_contact_manipulation_correlation(self):
        """Test contact manipulation behavior correlation."""
        engine = HookEngine(uuid4())
        
        calls = [
            self._create_call("DeleteContacts", {"uri": "content://com.android.contacts/1"}),
            self._create_call("WriteContacts", {"uri": "content://com.android.contacts", "values": "attacker_contact"}),
        ]
        
        chains = engine.ingest_batch(calls)
        assert "android_contact_replacement" in [c.rule_id for c in chains]
    
    def _create_call(self, api_name, args, pid=1234):
        """Helper to create an API call event."""
        api = resolve_api(api_name)
        return ApiCallEvent(
            call_id=uuid4(),
            analysis_id=uuid4(),
            api_name=api_name,
            raw_name=api_name,
            module=api.module if api else "unknown",
            timestamp=datetime.now(),
            pid=pid,
            tid=1,
            args=args,
        )


class TestAndroidRiskScoring:
    """Test Android-specific risk scoring integration."""
    
    def test_android_behavior_chain_scoring(self):
        """Test Android behavior chain risk scoring."""
        from agents.orchestrator.risk_scoring import (
            _compute_behavior_chain_score,
            compute_android_risk_profile,
        )
        from agents.orchestrator.schema import DynamicAnalysisOutput
        
        # Create mock dynamic output with Android behavior chains
        dynamic = DynamicAnalysisOutput(
            sample_id="test_android_sample_123",
            behavior_chains=[
                {
                    'rule_id': 'android_sms_interception',
                    'severity': 'critical',
                    'risk_points': 55,
                    'mitre': ['T1636.004', 'T1582'],
                },
                {
                    'rule_id': 'android_location_exfiltration',
                    'severity': 'high',
                    'risk_points': 40,
                    'mitre': ['T1430', 'T1639'],
                },
            ]
        )
        
        score = _compute_behavior_chain_score(dynamic)
        assert score > 0
        assert score >= 55 + 40  # Sum of risk points
    
    def test_android_special_detection_bonuses(self):
        """Test Android special detection bonuses."""
        from agents.orchestrator.risk_scoring import (
            _compute_special_detection_bonuses,
        )
        from agents.orchestrator.schema import DynamicAnalysisOutput
        
        # Create mock dynamic output with Android detections
        dynamic = DynamicAnalysisOutput(
            sample_id="test_android_sample_456",
            behavior_chains=[
                {'rule_id': 'android_sms_interception', 'severity': 'critical'},
                {'rule_id': 'android_accessibility_automation', 'severity': 'critical'},
                {'rule_id': 'android_permission_escalation', 'severity': 'critical'},
            ]
        )
        
        bonus = _compute_special_detection_bonuses(dynamic)
        assert bonus > 0
        # Should have bonuses for SMS, accessibility, and permission escalation
        assert bonus >= 30 + 35 + 30
    
    def test_android_risk_profile(self):
        """Test Android risk profile generation."""
        from agents.orchestrator.risk_scoring import compute_android_risk_profile
        from agents.orchestrator.schema import DynamicAnalysisOutput
        
        dynamic = DynamicAnalysisOutput(
            sample_id="test_android_sample_789",
            behavior_chains=[
                {
                    'rule_id': 'android_sms_interception',
                    'name': 'SMS interception',
                    'severity': 'critical',
                    'risk_points': 55,
                    'mitre': ['T1636.004', 'T1582'],
                },
                {
                    'rule_id': 'android_location_exfiltration',
                    'name': 'Location tracking',
                    'severity': 'high',
                    'risk_points': 40,
                    'mitre': ['T1430', 'T1639'],
                },
            ]
        )
        
        profile = compute_android_risk_profile(dynamic)
        
        assert profile['total_chains'] == 2
        assert len(profile['critical_chains']) == 1
        assert len(profile['high_chains']) == 1
        assert profile['android_risk_categories']['sms_interception'] == True
        assert profile['android_risk_categories']['sms_exfiltration'] == True
        assert profile['android_risk_categories']['location_tracking'] == True
        assert profile['total_risk_points'] == 95
        assert 'T1636.004' in profile['mitre_coverage']
        assert 'T1430' in profile['mitre_coverage']


if __name__ == "__main__":
    pytest.main([__file__, "-v"])