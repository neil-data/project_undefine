# Phase 4 — Android Malware Analysis Implementation

## Overview

Phase 4 completes the Android behavior engine for the E-Rakshak malware analysis system. This implementation enhances the existing Android monitoring capabilities with comprehensive detection of advanced Android malware techniques, including permission escalation, SMS abuse, location tracking, contact manipulation, surveillance, accessibility abuse, and overlay attacks.

## Implementation Goals

The Android behavior engine aims to:

1. **Enhance Permission Monitoring**: Detect runtime permission escalation and privilege abuse
2. **Enhance SMS Monitoring**: Advanced SMS analysis including evidence destruction and MMS abuse
3. **Enhance Location Monitoring**: Geofencing, high-accuracy tracking, and surveillance detection
4. **Enhance Contact Monitoring**: Contact manipulation and abuse pattern detection
5. **Enhance Clipboard Monitoring**: Crypto address detection and credential theft
6. **Enhance Camera Monitoring**: Covert photo capture and surveillance detection
7. **Enhance Microphone Monitoring**: Covert recording and call surveillance
8. **Enhance Accessibility Detection**: Keystroke logging and UI automation
9. **Enhance Overlay Detection**: Tapjacking, injection, and automated overlay attacks
10. **Add Android-specific Behavior Correlation Rules**: Advanced chain detection
11. **Integrate with Risk Scoring**: Android-specific risk scoring and profiling
12. **Testing**: Comprehensive test coverage for all new capabilities
13. **Documentation**: Complete implementation documentation

## Architecture

### Component Structure

```
dynamic-sandbox/hooks/
├── api_catalog.py          # Enhanced with 10+ new Android APIs
├── hook_engine.py          # Enhanced with 15+ new Android behavior rules
├── test_phase4_android_engine.py  # Comprehensive Android test suite
└── README.md              # Updated documentation

agents/orchestrator/
├── risk_scoring.py        # Enhanced with Android-specific scoring
└── schema.py              # Updated with Android behavior chain support
```

## API Catalog Enhancements

### New Android APIs Added

#### Permission Monitoring (2 new APIs)
- **GrantRuntimePermission**: Privileged permission granting (root/vulnerability exploitation)
- **SetPackagePermission**: Direct permission state modification (privileged access)

#### SMS Monitoring (3 new APIs)
- **DeleteSMS**: SMS/MMS deletion (evidence destruction)
- **SendMultipartTextMessage**: Alternative multipart SMS sending
- **DownloadMMS**: MMS content download (payload delivery, C2 channel)

#### Location Monitoring (2 new APIs)
- **GeofencingAdd**: Geofence registration (location-based triggers)
- **LocationRequestHighAccuracy**: High-accuracy GPS requests (surveillance)

#### Contact Monitoring (2 new APIs)
- **WriteContacts**: Contact writing (smishing campaign preparation)
- **DeleteContacts**: Contact deletion (evidence destruction, disruption)

#### Camera Monitoring (2 new APIs)
- **CameraTakePicture**: Covert photo capture (surveillance)
- **CameraSetParameters**: Camera parameter modification (covert operation)

#### Accessibility Detection (2 new APIs)
- **AccessibilityPerformAction**: Automated UI actions (form filling, auto-fraud)
- **AccessibilityFindAccessibilityNodeInfo**: Systematic UI navigation

#### Overlay Detection (2 new APIs)
- **WindowManagerAddView**: Alternative overlay creation (bypass detection)
- **SystemAlertWindowRequest**: Overlay permission request (attack preparation)

## Behavior Chain Rules

### Permission Escalation Rules (3 new rules)

1. **android_permission_escalation**: Runtime permission escalation without user consent
   - Sequence: GrantRuntimePermission
   - Severity: CRITICAL
   - MITRE: T1626, T1068
   - Risk Points: 60

2. **android_permission_state_manipulation**: Direct permission state modification
   - Sequence: SetPackagePermission
   - Severity: CRITICAL
   - MITRE: T1626, T1068
   - Risk Points: 55

3. **android_overlay_permission_request**: Overlay permission requested for malicious purposes
   - Sequence: SystemAlertWindowRequest
   - Severity: HIGH
   - MITRE: T1417.002, T1626
   - Risk Points: 35

### SMS Evidence Destruction Rules (2 new rules)

4. **android_sms_evidence_destruction**: SMS messages deleted after reading
   - Sequence: ReadSMS → DeleteSMS
   - Severity: CRITICAL
   - MITRE: T1636.004, T1070.004
   - Risk Points: 50

5. **android_sms_mass_deletion**: Mass SMS deletion (systematic evidence destruction)
   - Sequence: DeleteSMS (repeated)
   - Severity: HIGH
   - MITRE: T1636.004, T1070.004
   - Risk Points: 40

6. **android_mms_payload_delivery**: MMS used for payload delivery
   - Sequence: DownloadMMS
   - Severity: HIGH
   - MITRE: T1105, T1582
   - Risk Points: 35

### Contact Manipulation Rules (3 new rules)

7. **android_contact_manipulation**: Contact list modified for smishing campaign
   - Sequence: WriteContacts
   - Severity: HIGH
   - MITRE: T1636.003, T1582
   - Risk Points: 40

8. **android_contact_destruction**: Contact list destruction
   - Sequence: DeleteContacts
   - Severity: HIGH
   - MITRE: T1636.003, T1070.004
   - Risk Points: 35

9. **android_contact_replacement**: Legitimate contacts replaced with fraudulent ones
   - Sequence: DeleteContacts → WriteContacts
   - Severity: CRITICAL
   - MITRE: T1636.003, T1582
   - Risk Points: 50

### Location Tracking Enhancement Rules (3 new rules)

10. **android_geofencing_surveillance**: Geofencing configured for tracking
    - Sequence: GeofencingAdd
    - Severity: HIGH
    - MITRE: T1430
    - Risk Points: 40

11. **android_high_accuracy_tracking**: High-accuracy location tracking in background
    - Sequence: LocationRequestHighAccuracy
    - Severity: HIGH
    - MITRE: T1430
    - Risk Points: 35

12. **android_location_geofence_exfiltration**: Geofencing triggers reported to remote server
    - Sequence: GeofencingAdd → InternetConnect
    - Severity: HIGH
    - MITRE: T1430, T1639
    - Risk Points: 45

### Camera Enhancement Rules (2 new rules)

13. **android_covert_photo_capture**: Covert photo capture without UI
    - Sequence: CameraTakePicture
    - Severity: CRITICAL
    - MITRE: T1512
    - Risk Points: 55

14. **android_camera_without_permission_flow**: Camera accessed without user permission flow
    - Sequence: CameraOpen → CameraSetParameters
    - Severity: HIGH
    - MITRE: T1512, T1068
    - Risk Points: 40

### Accessibility Automation Rules (3 new rules)

15. **android_accessibility_automation**: Accessibility service performing automated actions
    - Sequence: AccessibilityEvent → AccessibilityPerformAction
    - Severity: CRITICAL
    - MITRE: T1417.001, T1516
    - Risk Points: 50

16. **android_accessibility_credential_automation**: Accessibility service automating credential input
    - Sequence: AccessibilityFindByText → AccessibilityPerformAction
    - Severity: CRITICAL
    - MITRE: T1417.001, T1516
    - Risk Points: 55

17. **android_accessibility_navigate_and_act**: Accessibility service systematically navigating UI
    - Sequence: AccessibilityFindAccessibilityNodeInfo → AccessibilityPerformAction
    - Severity: HIGH
    - MITRE: T1417.001
    - Risk Points: 40

### Overlay Enhancement Rules (3 new rules)

18. **android_overlay_without_permission**: Overlay created without proper permission flow
    - Sequence: WindowManagerAddView
    - Severity: HIGH
    - MITRE: T1417.002, T1068
    - Risk Points: 40

19. **android_overlay_with_permission_escalation**: Overlay permission escalated then used
    - Sequence: SystemAlertWindowRequest → OverlayWindowAdded
    - Severity: CRITICAL
    - MITRE: T1417.002, T1626
    - Risk Points: 55

20. **android_automated_overlay_attack**: Accessibility combined with overlay for automated attack
    - Sequence: AccessibilityEvent → OverlayWindowAdded
    - Severity: CRITICAL
    - MITRE: T1417.001, T1417.002
    - Risk Points: 60

## Condition Functions

### Android Conditions (Phase 4)
- `_cond_permission_granted`: Detects when permissions were granted
- `_cond_high_accuracy_requested`: Detects high-accuracy location requests
- `_cond_window_change_event`: Detects accessibility window state changes

## Risk Scoring Integration

### Enhanced Risk Calculation

The risk scoring system has been enhanced with Android-specific behavior analysis:

```python
def compute_risk_score(static, dynamic, mitre, capabilities):
    # Original scoring + Windows/Android behavior scoring
    score += _compute_behavior_chain_score(dynamic)
    score += _compute_special_detection_bonuses(dynamic)
    return min(score, MAX_SCORE)
```

### Android-Specific Detection Bonuses

- **SMS Interception**: +30 points
- **Location Tracking**: +25 points
- **Clipboard Attack**: +25 points
- **Surveillance**: +35 points
- **Permission Escalation**: +30 points
- **Accessibility Abuse**: +35 points
- **Overlay Attack**: +30 points

### Android Risk Profile

New function `compute_android_risk_profile()` generates detailed Android risk analysis:

```python
{
    'total_chains': 15,
    'critical_chains': [...],
    'high_chains': [...],
    'android_risk_categories': {
        'sms_interception': True,
        'sms_exfiltration': True,
        'contact_abuse': True,
        'location_tracking': True,
        'geofencing': True,
        'clipboard_attack': False,
        'camera_surveillance': True,
        'audio_surveillance': False,
        'accessibility_abuse': True,
        'overlay_attack': True,
        'permission_escalation': True,
        'contact_manipulation': False,
    },
    'mitre_coverage': ['T1636.004', 'T1512', ...],
    'total_risk_points': 450
}
```

## Testing

### Test Coverage

The test suite `test_phase4_android_engine.py` provides comprehensive coverage:

#### Test Classes
1. **TestAndroidPermissionMonitoring**: Permission escalation detection
2. **TestAndroidSMSMonitoring**: Advanced SMS analysis
3. **TestAndroidLocationMonitoring**: Geofencing and tracking detection
4. **TestAndroidContactMonitoring**: Contact manipulation detection
5. **TestAndroidCameraMonitoring**: Surveillance detection
6. **TestAndroidAccessibilityDetection**: UI automation detection
7. **TestAndroidOverlayDetection**: Overlay attack detection
8. **TestAndroidBehaviorCorrelation**: Behavior correlation rules
9. **TestAndroidRiskScoring**: Risk scoring integration

#### Test Examples

```python
def test_permission_escalation_chain(self):
    """Test permission escalation detection."""
    engine = HookEngine(uuid4())
    
    calls = [
        self._create_call("GrantRuntimePermission", {"permissionName": "android.permission.SEND_SMS", "packageName": "com.malware"}),
    ]
    
    chains = engine.ingest_batch(calls)
    assert "android_permission_escalation" in [c.rule_id for c in chains]
```

### Running Tests

```bash
cd dynamic-sandbox/hooks
pytest test_phase4_android_engine.py -v
```

## Integration Points

### Dynamic Sandbox Integration

The Android behavior engine integrates with the existing dynamic sandbox pipeline:

1. **Hook Installation**: New Android APIs are automatically included in Frida agent generation
2. **Event Collection**: API calls are collected and normalized through existing pipeline
3. **Behavior Correlation**: New rules are applied in the hook engine
4. **Risk Scoring**: Android behavior chains are scored and integrated with overall risk assessment
5. **Reporting**: Android-specific findings are included in analysis reports

### Agent Orchestrator Integration

The enhanced risk scoring integrates with the LangGraph agent orchestrator:

1. **Risk Assessment**: Android behavior chains contribute to overall risk score
2. **Capability Classification**: Behavior chains inform capability detection
3. **MITRE Mapping**: Automatic MITRE ATT&CK technique mapping
4. **Narrative Generation**: Android findings contribute to investigation narrative

## Detection Capabilities

### Malware Families Detected

The enhanced Android behavior engine can detect:

#### Banking Trojans
- SMS OTP interception (existing)
- Accessibility credential theft (enhanced)
- Overlay fake login screens (enhanced)
- Camera surveillance for "selfie verification" (enhanced)
- Contact list smishing (enhanced)

#### Stalkerware
- Location tracking with geofencing (new)
- High-accuracy GPS surveillance (new)
- Camera surveillance (enhanced)
- Microphone recording (existing)
- Accessibility window monitoring (existing)

#### Ransomware
- SMS exfiltration for leverage (existing)
- Contact list harassment (enhanced)
- Evidence destruction (new)

#### Spyware
- Permission escalation (new)
- SMS mass deletion (new)
- Contact manipulation (new)
- Camera covert capture (new)
- Accessibility UI automation (new)

#### Loan App Scams
- Contact list abuse (enhanced)
- SMS harassment campaigns (existing)
- Camera for "verification" (enhanced)
- Location tracking for harassment (enhanced)
- Permission escalation at runtime (new)

### MITRE ATT&CK Coverage

The implementation covers 20+ MITRE ATT&CK techniques:

#### Credential Access (T1114)
- T1414: Input Capture (clipboard monitoring)

#### Collection (T1113)
- T1005: Data from Local System (SMS, contacts)
- T1119: Automated Collection
- T1123: Audio Capture
- T1125: Video Capture

#### Command and Control (T1102)
- T1102: Web Service
- T1071: Application Layer Protocol (HTTP, custom protocols)

#### Defense Evasion (T1626)
- T1626: Virtualization/Sandbox Evasion
- T1068: Exploitation for Privilege Escalation

#### Discovery (T1430)
- T1430: Remote System Software Discovery (location services)

#### Exfiltration (T1639)
- T1639: Exfiltration Over Web Service

#### Impact (T1582, T1643)
- T1582: Service Hijacking (SMS abuse)
- T1643: Remote Service Software Hijacking

#### Initial Access (T1636)
- T1636.003: Spearphishing via SMS
- T1636.004: Spearphishing via Voice

## Performance Considerations

### Rate Limiting

New Android APIs include appropriate rate limiting to prevent performance impact:

- High-frequency APIs (AccessibilityEvent, ClipboardCheck): 300-500 calls/sec
- Medium-frequency APIs (ReadSMS, ReadContacts): 50-100 calls/sec
- Low-frequency APIs (GrantRuntimePermission, GeofencingAdd): 10-20 calls/sec

### Memory Management

- Bounded sliding windows for call history (existing)
- Efficient condition function evaluation
- Minimal event data retention

### Processing Overhead

- Condition functions are optimized for performance
- Early termination in condition evaluation
- Efficient string matching for permission and content analysis

## India-Specific Detection Patterns

### Loan App Scams
- Contact list harassment detection
- SMS smishing campaign detection
- Camera "verification" abuse detection
- Location tracking for harassment
- Permission escalation at runtime

### e-Challan Fraud
- SMS OTP interception (existing)
- Camera for document verification abuse
- Location tracking for victim monitoring
- Accessibility automation for form filling

### UPI Fraud
- Clipboard crypto address clipping (existing)
- Accessibility credential theft (enhanced)
- Overlay fake payment screens (existing)
- SMS verification bypass

## Future Enhancements

### Potential Improvements

1. **App Signing Detection**: Certificate validation and signing abuse
2. **Root Detection**: Root privilege usage and detection bypass
3. **Background Service Detection**: Long-running background services
4. **Broadcast Receiver Monitoring**: System event abuse
5. **Content Provider Monitoring**: Cross-app data access
6. **Intent Fuzzing**: Intent-based attack detection

### Advanced Features

1. **Machine Learning**: Behavior-based anomaly detection
2. **Graph Analysis**: App interaction graph analysis
3. **Timeline Correlation**: Cross-app behavior correlation
4. **User Activity Detection**: Human vs. automated behavior differentiation

## Documentation

### API Documentation

Each Android API in the catalog includes:
- Purpose and functionality
- Why it's monitored (malicious use cases)
- Argument capture specification
- MITRE ATT&CK mapping
- Risk classification

### Rule Documentation

Each Android behavior rule includes:
- Detection description
- API sequence and timing
- Severity and risk scoring
- MITRE ATT&CK techniques
- Condition requirements

### Configuration

Configuration options in `api_catalog.py`:
- Rate limiting thresholds
- Flag decoding maps
- Permission classification
- Risk level assignments

## Comparison with Windows Engine

### Platform-Specific Differences

| Feature | Windows | Android |
|---------|---------|---------|
| API Surface | Win32 APIs | Java/Kotlin APIs |
| Privilege Model | Token-based | Permission-based |
| Persistence | Registry, Services | Services, Receivers |
| IPC | Named pipes, COM | Intents, Content Providers |
| UI Automation | Accessibility (limited) | Accessibility (extensive) |
| File System | NTFS | Ext4, FAT32 |
| Package Format | PE | APK |

### Shared Detection Patterns

- **Data Exfiltration**: Both platforms monitor data leaving the device
- **C2 Communication**: Both platforms detect network-based command and control
- **Persistence**: Both monitor mechanisms to survive restart
- **Credential Theft**: Both platforms target credentials
- **Evasion**: Both platforms detect anti-analysis techniques

## Conclusion

The Phase 4 Android behavior engine implementation significantly enhances the E-Rakshak system's malware detection capabilities for Android platforms. By adding 10+ new Android APIs, 15+ behavior correlation rules, and comprehensive risk scoring integration, the system can now detect sophisticated Android malware techniques including permission escalation, SMS abuse, geofencing surveillance, contact manipulation, accessibility automation, and overlay attacks.

The implementation maintains compatibility with the existing dynamic sandbox pipeline while providing investigators with detailed, actionable intelligence about Android malware behavior. The comprehensive test suite ensures reliability and maintainability of the new capabilities.

This implementation, combined with the Phase 3 Windows behavior engine, positions E-Rakshak as a comprehensive, cross-platform malware analysis platform capable of handling the most sophisticated malware threats encountered by cyber-crime units across both Windows and Android ecosystems.