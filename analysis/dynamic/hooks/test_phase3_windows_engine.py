"""
test_phase3_windows_engine.py — Windows behavior engine tests for Phase 3.

Tests the enhanced Windows behavior detection capabilities including:
- Advanced process monitoring
- Registry monitoring  
- Service detection
- Driver detection
- Privilege escalation detection
- Enhanced persistence detection
- Network activity monitoring
- Behavior correlation rules
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


class TestWindowsProcessMonitoring:
    """Test advanced Windows process detection capabilities."""
    
    def test_open_process_detection(self):
        """Test that OpenProcess is properly catalogued and detected."""
        api = resolve_api("OpenProcess")
        assert api is not None
        assert api.name == "OpenProcess"
        assert api.category.value == "process"
        assert api.baseline_risk.value == "medium"
    
    def test_terminate_process_chain(self):
        """Test security process termination detection."""
        engine = HookEngine(uuid4())
        
        calls = [
            self._create_call("OpenProcess", {"dwDesiredAccess": 0x1F0FFF, "dwProcessId": 666}),  # Use system PID (<1000)
            self._create_call("TerminateProcess", {"hProcess": 0x1234, "uExitCode": 0}),
        ]
        
        chains = engine.ingest_batch(calls)
        assert "security_process_termination" in [c.rule_id for c in chains]
    
    def test_process_enumeration(self):
        """Test high-frequency process enumeration detection."""
        engine = HookEngine(uuid4())
        
        # Simulate multiple process enumeration calls
        calls = [self._create_call("EnumProcesses", {"lpidProcess": "ptr", "cb": 1024}) for _ in range(10)]
        
        chains = engine.ingest_batch(calls)
        # Should detect high-frequency enumeration
        assert len(chains) > 0
    
    def test_lsass_access_detection(self):
        """Test LSASS process access for credential dumping."""
        engine = HookEngine(uuid4())
        
        # LSASS access with VM_READ rights
        calls = [
            self._create_call("OpenProcess", {"dwDesiredAccess": 0x10, "dwProcessId": 666}),
        ]
        
        chains = engine.ingest_batch(calls)
        assert "credential_dumping_preparation" in [c.rule_id for c in chains]
    
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


class TestWindowsRegistryMonitoring:
    """Test enhanced Windows registry detection."""
    
    def test_registry_key_deletion(self):
        """Test registry key deletion detection."""
        api = resolve_api("RegDeleteKey")
        assert api is not None
        assert api.name == "RegDeleteKey"
        assert "T1562.001" in api.mitre
    
    def test_registry_value_deletion(self):
        """Test registry value deletion detection."""
        api = resolve_api("RegDeleteValue")
        assert api is not None
        assert api.name == "RegDeleteValue"
    
    def test_registry_enumeration(self):
        """Test registry enumeration detection."""
        api = resolve_api("RegEnumKey")
        assert api is not None
        assert api.name == "RegEnumKey"
    
    def test_security_registry_modification(self):
        """Test security registry key modification detection."""
        engine = HookEngine(uuid4())
        
        calls = [
            self._create_call("RegOpenKey", {"hKey": 0x80000002, "lpSubKey": "software\\microsoft\\windows defender"}),
            self._create_call("RegDeleteValue", {"hKey": 0x1234, "lpValueName": "DisableAntiSpyware"}),
        ]
        
        chains = engine.ingest_batch(calls)
        assert "registry_security_disabled" in [c.rule_id for c in chains]
    
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


class TestWindowsServiceDetection:
    """Test Windows service detection capabilities."""
    
    def test_service_control_detection(self):
        """Test service control detection."""
        api = resolve_api("ControlService")
        assert api is not None
        assert api.name == "ControlService"
        assert "T1562.001" in api.mitre
    
    def test_service_deletion_detection(self):
        """Test service deletion detection."""
        api = resolve_api("DeleteService")
        assert api is not None
        assert api.name == "DeleteService"
        assert "T1070.006" in api.mitre
    
    def test_security_service_stop_chain(self):
        """Test security service stop detection."""
        engine = HookEngine(uuid4())
        
        calls = [
            self._create_call("OpenSCManager", {"lpMachineName": None, "dwDesiredAccess": 0x0002}),
            self._create_call("ControlService", {"hService": 0x1234, "dwControl": 0x1}),
        ]
        
        chains = engine.ingest_batch(calls)
        assert "security_service_disabled" in [c.rule_id for c in chains]
    
    def test_service_deletion_chain(self):
        """Test service deletion detection."""
        engine = HookEngine(uuid4())
        
        calls = [
            self._create_call("OpenSCManager", {"lpMachineName": None, "dwDesiredAccess": 0x0002}),
            self._create_call("DeleteService", {"hService": 0x1234}),
        ]
        
        chains = engine.ingest_batch(calls)
        assert "security_service_deleted" in [c.rule_id for c in chains]
    
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


class TestWindowsDriverDetection:
    """Test Windows driver detection capabilities."""
    
    def test_system_information_detection(self):
        """Test NtSetSystemInformation detection."""
        api = resolve_api("NtSetSystemInformation")
        assert api is not None
        assert api.name == "NtSetSystemInformation"
        assert "T1014" in api.mitre
    
    def test_driver_load_detection(self):
        """Test NtLoadDriver detection."""
        api = resolve_api("NtLoadDriver")
        assert api is not None
        assert api.name == "NtLoadDriver"
        assert api.baseline_risk.value == "high"


class TestWindowsPrivilegeEscalation:
    """Test privilege escalation detection."""
    
    def test_set_thread_token_detection(self):
        """Test SetThreadToken detection."""
        api = resolve_api("SetThreadToken")
        assert api is not None
        assert api.name == "SetThreadToken"
        assert "T1134.003" in api.mitre
    
    def test_get_token_information_detection(self):
        """Test GetTokenInformation detection."""
        api = resolve_api("GetTokenInformation")
        assert api is not None
        assert api.name == "GetTokenInformation"
    
    def test_token_manipulation_chain(self):
        """Test token manipulation chain detection."""
        engine = HookEngine(uuid4())
        
        calls = [
            self._create_call("OpenProcessToken", {"ProcessHandle": 0x1234, "DesiredAccess": 0x2}),
            self._create_call("DuplicateTokenEx", {"hExistingToken": 0x5678, "TokenType": 1}),
            self._create_call("CreateProcessWithToken", {"hToken": 0x9ABC, "lpCommandLine": "cmd.exe"}),
        ]
        
        chains = engine.ingest_batch(calls)
        assert "token_impersonation_full" in [c.rule_id for c in chains]
    
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


class TestWindowsPersistenceDetection:
    """Test enhanced persistence detection."""
    
    def test_file_copy_detection(self):
        """Test file copy detection."""
        api = resolve_api("CopyFile")
        assert api is not None
        assert api.name == "CopyFile"
        assert "T1547.001" in api.mitre  # Updated to match actual MITRE tags
    
    def test_file_move_detection(self):
        """Test file move detection."""
        api = resolve_api("MoveFile")
        assert api is not None
        assert api.name == "MoveFile"
        assert "T1574.001" in api.mitre  # Updated to match actual MITRE tags
    
    def test_file_search_detection(self):
        """Test file search detection."""
        api = resolve_api("FindFirstFile")
        assert api is not None
        assert api.name == "FindFirstFile"
        
        api = resolve_api("FindNextFile")
        assert api is not None
        assert api.name == "FindNextFile"
    
    def test_document_enumeration_chain(self):
        """Test document directory enumeration detection."""
        engine = HookEngine(uuid4())
        
        calls = [
            self._create_call("FindFirstFile", {"lpFileName": "C:\\Users\\*.doc"}),
            self._create_call("FindNextFile", {"hFindFile": 0x1234}),
        ]
        
        chains = engine.ingest_batch(calls)
        assert "document_directory_enumeration" in [c.rule_id for c in chains]
    
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


class TestWindowsNetworkMonitoring:
    """Test enhanced network monitoring."""
    
    def test_internet_open_url_detection(self):
        """Test InternetOpenUrl detection."""
        api = resolve_api("InternetOpenUrl")
        assert api is not None
        assert api.name == "InternetOpenUrl"
        assert "T1071.001" in api.mitre
    
    def test_socket_operations_detection(self):
        """Test socket operations detection."""
        api = resolve_api("connect")
        assert api is not None
        assert api.name == "connect"
        
        api = resolve_api("send")
        assert api is not None
        assert api.name == "send"
        
        api = resolve_api("recv")
        assert api is not None
        assert api.name == "recv"
    
    def test_socket_c2_chain(self):
        """Test socket-based C2 detection."""
        engine = HookEngine(uuid4())
        
        calls = [
            self._create_call("connect", {"s": 123, "name": "ptr"}),
            self._create_call("send", {"s": 123, "buf": "ptr", "len": 1024}),
        ]
        
        chains = engine.ingest_batch(calls)
        assert "socket_based_c2" in [c.rule_id for c in chains]
    
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


class TestWindowsBehaviorCorrelation:
    """Test Windows behavior correlation rules."""
    
    def test_defense_evasion_correlation(self):
        """Test defense evasion behavior correlation."""
        engine = HookEngine(uuid4())
        
        # Test security process termination
        calls = [
            self._create_call("OpenProcess", {"dwDesiredAccess": 0x1F0FFF, "dwProcessId": 888}),
            self._create_call("TerminateProcess", {"hProcess": 0x1234, "uExitCode": 0}),
        ]
        
        chains = engine.ingest_batch(calls)
        assert any(c.rule_id == "security_process_termination" for c in chains)
        assert any(c.severity == ChainSeverity.CRITICAL for c in chains)
    
    def test_lateral_movement_preparation(self):
        """Test lateral movement preparation detection."""
        engine = HookEngine(uuid4())
        
        # Test credential dumping preparation
        calls = [
            self._create_call("OpenProcess", {"dwDesiredAccess": 0x10, "dwProcessId": 666}),
        ]
        
        chains = engine.ingest_batch(calls)
        assert "credential_dumping_preparation" in [c.rule_id for c in chains]
    
    def test_advanced_persistence_correlation(self):
        """Test advanced persistence behavior correlation."""
        engine = HookEngine(uuid4())
        
        # Test file-based persistence
        calls = [
            self._create_call("CopyFile", {"lpExistingFileName": "malware.exe", "lpNewFileName": "C:\\Users\\Admin\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\malware.exe"}),
        ]
        
        chains = engine.ingest_batch(calls)
        assert "file_based_persistence" in [c.rule_id for c in chains]
    
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


class TestWindowsAPIAliases:
    """Test Windows API alias resolution."""
    
    def test_process_api_aliases(self):
        """Test process API alias resolution."""
        assert resolve_api("OpenProcessA").name == "OpenProcess"
        assert resolve_api("OpenProcessW").name == "OpenProcess"
        assert resolve_api("TerminateProcessA").name == "TerminateProcess"
        assert resolve_api("TerminateProcessW").name == "TerminateProcess"
    
    def test_registry_api_aliases(self):
        """Test registry API alias resolution."""
        assert resolve_api("RegDeleteKeyA").name == "RegDeleteKey"
        assert resolve_api("RegDeleteKeyW").name == "RegDeleteKey"
        assert resolve_api("RegDeleteValueA").name == "RegDeleteValue"
        assert resolve_api("RegDeleteValueW").name == "RegDeleteValue"
    
    def test_service_api_aliases(self):
        """Test service API alias resolution."""
        assert resolve_api("ControlServiceA").name == "ControlService"
        assert resolve_api("ControlServiceW").name == "ControlService"
        assert resolve_api("DeleteServiceA").name == "DeleteService"
        assert resolve_api("DeleteServiceW").name == "DeleteService"
    
    def test_network_api_aliases(self):
        """Test network API alias resolution."""
        assert resolve_api("InternetOpenUrlA").name == "InternetOpenUrl"
        assert resolve_api("InternetOpenUrlW").name == "InternetOpenUrl"
    
    def test_filesystem_api_aliases(self):
        """Test filesystem API alias resolution."""
        assert resolve_api("MoveFileA").name == "MoveFile"
        assert resolve_api("MoveFileW").name == "MoveFile"
        assert resolve_api("CopyFileA").name == "CopyFile"
        assert resolve_api("CopyFileW").name == "CopyFile"


class TestWindowsRiskScoring:
    """Test Windows-specific risk scoring integration."""
    
    def test_behavior_chain_scoring(self):
        """Test behavior chain risk scoring."""
        from agents.orchestrator.risk_scoring import (
            _compute_behavior_chain_score,
            compute_windows_risk_profile,
        )
        from agents.orchestrator.schema import DynamicAnalysisOutput
        
        # Create mock dynamic output with behavior chains
        dynamic = DynamicAnalysisOutput(
            sample_id="test_sample_123",
            behavior_chains=[
                {
                    'rule_id': 'classic_injection',
                    'severity': 'critical',
                    'risk_points': 55,
                    'mitre': ['T1055.002'],
                },
                {
                    'rule_id': 'token_impersonation_full',
                    'severity': 'critical',
                    'risk_points': 60,
                    'mitre': ['T1134.001'],
                },
            ]
        )
        
        score = _compute_behavior_chain_score(dynamic)
        assert score > 0
        assert score >= 55 + 60  # Sum of risk points
    
    def test_special_detection_bonuses(self):
        """Test special detection bonuses."""
        from agents.orchestrator.risk_scoring import (
            _compute_special_detection_bonuses,
        )
        from agents.orchestrator.schema import DynamicAnalysisOutput
        
        # Create mock dynamic output with various detections
        dynamic = DynamicAnalysisOutput(
            sample_id="test_sample_456",
            behavior_chains=[
                {'rule_id': 'classic_injection', 'severity': 'critical'},
                {'rule_id': 'token_impersonation_full', 'severity': 'critical'},
                {'rule_id': 'driver_load_from_nonstandard_path', 'severity': 'critical'},
                {'rule_id': 'security_process_termination', 'severity': 'critical'},
            ]
        )
        
        bonus = _compute_special_detection_bonuses(dynamic)
        assert bonus > 0
        # Should have bonuses for injection, privilege escalation, driver, and evasion
        assert bonus >= 25 + 25 + 30 + 20
    
    def test_windows_risk_profile(self):
        """Test Windows risk profile generation."""
        from agents.orchestrator.risk_scoring import compute_windows_risk_profile
        from agents.orchestrator.schema import DynamicAnalysisOutput
        
        dynamic = DynamicAnalysisOutput(
            sample_id="test_sample_789",
            behavior_chains=[
                {
                    'rule_id': 'classic_injection',
                    'name': 'Process injection',
                    'severity': 'critical',
                    'risk_points': 55,
                    'mitre': ['T1055.002'],
                },
                {
                    'rule_id': 'token_impersonation_full',
                    'name': 'Privilege escalation',
                    'severity': 'critical',
                    'risk_points': 60,
                    'mitre': ['T1134.001'],
                },
            ]
        )
        
        profile = compute_windows_risk_profile(dynamic)
        
        assert profile['total_chains'] == 2
        assert len(profile['critical_chains']) == 2
        assert profile['risk_categories']['process_injection'] == True
        assert profile['risk_categories']['privilege_escalation'] == True
        assert profile['total_risk_points'] == 115
        assert 'T1055.002' in profile['mitre_coverage']
        assert 'T1134.001' in profile['mitre_coverage']


if __name__ == "__main__":
    pytest.main([__file__, "-v"])