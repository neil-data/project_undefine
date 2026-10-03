# Phase 3 — Windows Behavior Engine Implementation

## Overview

Phase 3 completes the Windows behavior engine for the E-Rakshak malware analysis system. This implementation enhances the existing dynamic sandbox with comprehensive Windows-specific malware detection capabilities, adding advanced process monitoring, registry detection, service analysis, driver detection, privilege escalation detection, and enhanced persistence mechanisms.

## Implementation Goals

The Windows behavior engine aims to:

1. **Enhance Process Monitoring**: Add advanced Windows process tracking for injection, hollowing, and reconnaissance
2. **Registry Monitoring**: Comprehensive Windows registry detection for persistence and security bypass
3. **Service Detection**: Windows service analysis for persistence and defense evasion
4. **Driver Detection**: Kernel driver detection for rootkits and BYOVD attacks
5. **Privilege Escalation**: Token manipulation and privilege escalation detection
6. **Persistence Detection**: Enhanced Windows-specific persistence mechanisms
7. **Network Activity**: Advanced Windows protocol monitoring for C2 communication
8. **Behavior Correlation**: Windows-specific behavior correlation rules
9. **Risk Scoring**: Integration with the existing risk scoring system
10. **Testing**: Comprehensive test coverage for all new capabilities

## Architecture

### Component Structure

```
dynamic-sandbox/hooks/
├── api_catalog.py          # Enhanced with 20+ new Windows APIs
├── hook_engine.py          # Enhanced with 15+ new behavior rules
├── test_phase3_windows_engine.py  # Comprehensive test suite
└── README.md              # Updated documentation

agents/orchestrator/
├── risk_scoring.py        # Enhanced with Windows-specific scoring
└── schema.py              # Updated with behavior chain support
```

## API Catalog Enhancements

### New Windows APIs Added

#### Process Monitoring (6 new APIs)
- **OpenProcess**: Opens processes with specific access rights (injection/credential dumping)
- **TerminateProcess**: Terminates processes (defense evasion)
- **EnumProcesses**: Enumerates running processes (reconnaissance)
- **EnumProcessModules**: Enumerates loaded modules (API resolution detection)
- **GetModuleFileName**: Retrieves module file paths (sandbox detection)

#### Registry Monitoring (4 new APIs)
- **RegDeleteKey**: Deletes registry keys (security tool removal)
- **RegDeleteValue**: Deletes registry values (configuration cleanup)
- **RegEnumKey**: Enumerates registry subkeys (persistence discovery)
- **RegOpenKey**: Opens registry keys (reconnaissance)

#### Service Detection (2 new APIs)
- **ControlService**: Controls service state (disabling security services)
- **DeleteService**: Deletes service entries (evidence removal)

#### Network Monitoring (4 new APIs)
- **InternetOpenUrl**: High-level URL operations (simple C2)
- **send/recv**: Raw socket operations (custom protocols)
- **connect**: Socket connection establishment (C2 beaconing)

#### File System (4 new APIs)
- **MoveFile**: Moves files (persistence via system directories)
- **CopyFile**: Copies files (DLL hijacking, startup folders)
- **FindFirstFile/FindNextFile**: Directory enumeration (ransomware reconnaissance)

#### Privilege Escalation (2 new APIs)
- **SetThreadToken**: Thread-level token manipulation
- **GetTokenInformation**: Token enumeration (privilege discovery)

### API Alias System

Enhanced to support 30+ new Windows API variants:
- Process APIs: OpenProcessA/W, TerminateProcessA/W
- Registry APIs: RegDeleteKeyA/W, RegDeleteValueA/W, RegEnumKeyA/W
- Service APIs: ControlServiceA/W, DeleteServiceA/W
- Network APIs: InternetOpenUrlA/W, sendA/W, recvA/W
- File APIs: MoveFileA/W, CopyFileA/W, FindFirstFileA/W

## Behavior Chain Rules

### Defense Evasion Rules (4 new rules)

1. **security_process_termination**: Terminating security software processes
   - Sequence: OpenProcess → TerminateProcess
   - Severity: CRITICAL
   - MITRE: T1562.001, T1489
   - Risk Points: 55

2. **security_service_disabled**: Stopping security services
   - Sequence: OpenSCManager → ControlService
   - Severity: CRITICAL
   - MITRE: T1562.001, T1543.003
   - Risk Points: 50

3. **security_service_deleted**: Deleting security service entries
   - Sequence: OpenSCManager → DeleteService
   - Severity: CRITICAL
   - MITRE: T1562.001, T1070.006
   - Risk Points: 50

4. **registry_security_disabled**: Modifying security registry keys
   - Sequence: RegOpenKey → RegDeleteValue
   - Severity: HIGH
   - MITRE: T1112, T1562.001
   - Risk Points: 40

### Process Reconnaissance Rules (2 new rules)

5. **process_enumeration_high_frequency**: High-frequency process monitoring
   - Sequence: EnumProcesses (repeated)
   - Severity: MEDIUM
   - MITRE: T1057
   - Risk Points: 25

6. **module_enumeration_suspicious_target**: Enumerating system process modules
   - Sequence: OpenProcess → EnumProcessModules
   - Severity: HIGH
   - MITRE: T1057, T1014
   - Risk Points: 35

### File System Reconnaissance Rules (3 new rules)

7. **document_directory_enumeration**: Searching user document directories
   - Sequence: FindFirstFile → FindNextFile
   - Severity: HIGH
   - MITRE: T1083, T1005
   - Risk Points: 35

8. **system_directory_enumeration**: Searching Windows system directories
   - Sequence: FindFirstFile → FindNextFile
   - Severity: MEDIUM
   - MITRE: T1083, T1014
   - Risk Points: 25

9. **file_replacement_attack**: Replacing system binaries
   - Sequence: CopyFile (to system directory)
   - Severity: HIGH
   - MITRE: T1574.001, T1547.001
   - Risk Points: 40

### Network C2 Patterns (3 new rules)

10. **socket_based_c2**: Custom TCP-based C2 communication
    - Sequence: connect → send
    - Severity: HIGH
    - MITRE: T1071.004, T1041
    - Risk Points: 40

11. **high_frequency_beaconing**: Regular C2 beaconing
    - Sequence: WinHttpSendRequest (repeated)
    - Severity: HIGH
    - MITRE: T1071.001, T1102
    - Risk Points: 35

12. **direct_url_c2**: Simple URL-based C2
    - Sequence: InternetOpenUrl
    - Severity: HIGH
    - MITRE: T1071.001, T1105
    - Risk Points: 35

### Advanced Persistence Rules (3 new rules)

13. **file_based_persistence**: Startup folder persistence
    - Sequence: CopyFile (to startup directory)
    - Severity: HIGH
    - MITRE: T1547.001
    - Risk Points: 40

14. **file_moved_to_system_location**: System directory persistence
    - Sequence: MoveFile (to system directory)
    - Severity: HIGH
    - MITRE: T1547.001, T1074.001
    - Risk Points: 40

15. **registry_run_key_persistence**: Run key persistence
    - Sequence: RegCreateKey → RegSetValue (Run keys)
    - Severity: HIGH
    - MITRE: T1547.001
    - Risk Points: 35

### Lateral Movement Preparation (2 new rules)

16. **credential_dumping_preparation**: LSASS access for credential theft
    - Sequence: OpenProcess (lsass with VM_READ)
    - Severity: CRITICAL
    - MITRE: T1003.001, T1055
    - Risk Points: 55

17. **network_discovery**: Network reconnaissance
    - Sequence: InternetConnect (multiple targets)
    - Severity: MEDIUM
    - MITRE: T1010, T1016
    - Risk Points: 25

## Condition Functions

### Defense Evasion Conditions
- `_cond_suspicious_target_process`: Identifies security/system process targeting
- `_cond_service_stop`: Detects SERVICE_CONTROL_STOP operations
- `_cond_security_registry_key`: Identifies security-related registry paths

### File System Conditions
- `_cond_document_pattern`: Detects document file search patterns
- `_cond_system_pattern`: Detects system directory searches
- `_cond_system_directory_destination`: Identifies system directory targets
- `_cond_startup_directory`: Identifies startup folder operations
- `_cond_run_key`: Detects Run registry key operations

### Lateral Movement Conditions
- `_cond_lsass_target`: Identifies LSASS process access with memory rights

## Risk Scoring Integration

### Enhanced Risk Calculation

The risk scoring system has been enhanced with Windows-specific behavior analysis:

```python
def compute_risk_score(static, dynamic, mitre, capabilities):
    # Original scoring + Windows behavior scoring
    score += _compute_behavior_chain_score(dynamic)
    score += _compute_special_detection_bonuses(dynamic)
    return min(score, MAX_SCORE)
```

### Behavior Chain Scoring

- **Critical chains**: 30 points each (injection, privilege escalation, drivers)
- **High chains**: 20 points each (persistence, defense evasion)
- **Medium chains**: 10 points each (reconnaissance)
- **Low chains**: 5 points each (informational)

### Special Detection Bonuses

- **Process injection**: +25 points
- **Privilege escalation**: +25 points
- **Kernel driver loading**: +30 points
- **Defense evasion**: +20 points
- **Advanced persistence**: +15 points

### Windows Risk Profile

New function `compute_windows_risk_profile()` generates detailed risk analysis:

```python
{
    'total_chains': 15,
    'critical_chains': [...],
    'high_chains': [...],
    'risk_categories': {
        'process_injection': True,
        'privilege_escalation': True,
        'kernel_driver': False,
        'defense_evasion': True,
        'persistence': True,
        'ransomware': False,
        'data_exfiltration': False,
        'credential_theft': True,
    },
    'mitre_coverage': ['T1055.002', 'T1134.001', ...],
    'total_risk_points': 450
}
```

## Testing

### Test Coverage

The test suite `test_phase3_windows_engine.py` provides comprehensive coverage:

#### Test Classes
1. **TestWindowsProcessMonitoring**: Advanced process detection
2. **TestWindowsRegistryMonitoring**: Registry modification detection
3. **TestWindowsServiceDetection**: Service manipulation detection
4. **TestWindowsDriverDetection**: Driver loading detection
5. **TestWindowsPrivilegeEscalation**: Token manipulation detection
6. **TestWindowsPersistenceDetection**: Enhanced persistence detection
7. **TestWindowsNetworkMonitoring**: Advanced network detection
8. **TestWindowsBehaviorCorrelation**: Behavior correlation rules
9. **TestWindowsAPIAliases**: API alias resolution
10. **TestWindowsRiskScoring**: Risk scoring integration

#### Test Examples

```python
def test_security_process_termination(self):
    """Test security process termination detection."""
    engine = HookEngine(uuid4())
    
    calls = [
        self._create_call("OpenProcess", {"dwDesiredAccess": 0x1F0FFF, "dwProcessId": 1234}),
        self._create_call("TerminateProcess", {"hProcess": 0x1234, "uExitCode": 0}),
    ]
    
    chains = engine.ingest_batch(calls)
    assert "security_process_termination" in [c.rule_id for c in chains]
```

### Running Tests

```bash
cd dynamic-sandbox/hooks
pytest test_phase3_windows_engine.py -v
```

## Integration Points

### Dynamic Sandbox Integration

The Windows behavior engine integrates with the existing dynamic sandbox pipeline:

1. **Hook Installation**: New APIs are automatically included in Frida agent generation
2. **Event Collection**: API calls are collected and normalized through existing pipeline
3. **Behavior Correlation**: New rules are applied in the hook engine
4. **Risk Scoring**: Behavior chains are scored and integrated with overall risk assessment
5. **Reporting**: Windows-specific findings are included in analysis reports

### Agent Orchestrator Integration

The enhanced risk scoring integrates with the LangGraph agent orchestrator:

1. **Risk Assessment**: Windows behavior chains contribute to overall risk score
2. **Capability Classification**: Behavior chains inform capability detection
3. **MITRE Mapping**: Automatic MITRE ATT&CK technique mapping
4. **Narrative Generation**: Behavior findings contribute to investigation narrative

## Detection Capabilities

### Malware Families Detected

The enhanced Windows behavior engine can detect:

#### Ransomware
- File encryption cycles (existing)
- Document directory enumeration (new)
- System directory enumeration (new)
- Security service termination (new)

#### Banking Trojans
- Credential dumping preparation (new)
- LSASS process access (new)
- Registry Run key persistence (new)
- Browser process injection (existing)

#### Rootkits
- Kernel driver loading (existing)
- BYOVD attacks (existing)
- System file replacement (new)
- Registry security bypass (new)

#### Spyware
- Process enumeration (new)
- Module enumeration (new)
- Token impersonation (existing)
- Network C2 communication (enhanced)

#### Botnets
- Custom socket C2 (new)
- High-frequency beaconing (new)
- Service-based persistence (existing)
- Registry persistence (enhanced)

### MITRE ATT&CK Coverage

The implementation covers 25+ MITRE ATT&CK techniques:

#### Defense Evasion (T1562)
- T1562.001: Disable or Modify Tools
- T1070.006: Indicator Blocking

#### Credential Access (T1003)
- T1003.001: OS Credential Dumping

#### Privilege Escalation (T1134)
- T1134.001: Token Manipulation
- T1134.002: Create Process with Token
- T1134.003: Make and Impersonate Token

#### Persistence (T1547)
- T1547.001: Boot or Logon Autostart Execution
- T1543.003: Create or Modify System Service

#### Discovery (T1057, T1083)
- T1057: Process Discovery
- T1083: File and Directory Discovery

#### Lateral Movement (T1010, T1016)
- T1010: Application Window Discovery
- T1016: System Network Configuration Discovery

## Performance Considerations

### Rate Limiting

New APIs include appropriate rate limiting to prevent performance impact:

- High-frequency APIs (EnumProcesses, FindNextFile): 100-200 calls/sec
- Medium-frequency APIs (RegEnumKey, GetModuleFileName): 50-100 calls/sec
- Low-frequency APIs (TerminateProcess, ControlService): 20-50 calls/sec

### Memory Management

- Bounded sliding windows for call history (existing)
- Efficient condition function evaluation
- Minimal event data retention

### Processing Overhead

- Condition functions are optimized for performance
- Early termination in condition evaluation
- Efficient string matching for path analysis

## Future Enhancements

### Potential Improvements

1. **ETW Integration**: Event Tracing for Windows for deeper system visibility
2. **PowerShell Monitoring**: PowerShell script block logging
3. **WMI Monitoring**: Windows Management Instrumentation event monitoring
4. **Macro Detection**: Office macro behavior analysis
5. **COM Object Monitoring**: COM object instantiation and usage
6. **Threat Intelligence Integration**: API-level IOC matching

### Advanced Features

1. **Machine Learning**: Behavior-based anomaly detection
2. **Graph Analysis**: Process tree and dependency graph analysis
3. **Timeline Correlation**: Cross-stage behavior correlation
4. **User Activity Detection**: Human vs. automated behavior differentiation

## Documentation

### API Documentation

Each API in the catalog includes:
- Purpose and functionality
- Why it's monitored (malicious use cases)
- Argument capture specification
- MITRE ATT&CK mapping
- Risk classification

### Rule Documentation

Each behavior rule includes:
- Detection description
- API sequence and timing
- Severity and risk scoring
- MITRE ATT&CK techniques
- Condition requirements

### Configuration

Configuration options in `api_catalog.py`:
- Rate limiting thresholds
- Flag decoding maps
- Path classification
- Risk level assignments

## Conclusion

The Phase 3 Windows behavior engine implementation significantly enhances the E-Rakshak system's malware detection capabilities. By adding 20+ new Windows APIs, 15+ behavior correlation rules, and comprehensive risk scoring integration, the system can now detect sophisticated Windows malware techniques including defense evasion, privilege escalation, advanced persistence, and lateral movement preparation.

The implementation maintains compatibility with the existing dynamic sandbox pipeline while providing investigators with detailed, actionable intelligence about Windows malware behavior. The comprehensive test suite ensures reliability and maintainability of the new capabilities.

This implementation positions E-Rakshak as a comprehensive malware analysis platform capable of handling the most sophisticated Windows malware threats encountered by cyber-crime units.