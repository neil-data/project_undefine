"""
test_phase5_6_hooks.py
======================
Tests for Phase 5 (Windows: Services, Drivers, Privilege Escalation) and
Phase 6 (Android: Permission, SMS, Location, Contact, Clipboard, Camera,
Microphone, Accessibility, Overlay) implementations.

Run with:
    python -m pytest dynamic-sandbox/hooks/test_phase5_6_hooks.py -v
"""

from __future__ import annotations

import sys
import unittest
from datetime import datetime, timezone
from uuid import uuid4

from hooks.api_catalog import (
    API_CATALOG, resolve_api, REQUIRED_APIS, ApiCategory, BaselineRisk,
    MONITORED_APIS,
)
from hooks.hook_engine import (
    HookEngine, CHAIN_RULES, CONDITIONS, ApiCallEvent,
    _cond_service_auto_start, _cond_suspicious_binary_path,
    _cond_nonstandard_driver_path,
    _cond_debug_privilege_enabled, _cond_any_privilege_enabled,
    _cond_token_primary_type,
)
from hooks.hook_installer import installation_manifest, generate_frida_android_agent


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _event(api: str, args: dict, pid: int = 1234) -> ApiCallEvent:
    return ApiCallEvent(
        call_id=uuid4(),
        analysis_id=uuid4(),
        api_name=api,
        raw_name=api,
        module="advapi32.dll",
        pid=pid,
        tid=1,
        timestamp=datetime.now(timezone.utc),
        args=args,
        decoded_args={},
        return_value=None,
    )


def _raw(api: str, args: dict, pid: int = 1234) -> dict:
    return {
        "api": api,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "pid": pid,
        "tid": 1,
        "args": args,
        "return_value": 0,
    }


def _ingest_seq(engine: HookEngine, events: list) -> list:
    chains = []
    for raw in events:
        _, new_chains = engine.ingest(raw)
        chains.extend(new_chains)
    return chains


# ============================================================================
# Phase 5.1 - Service Monitor: API Catalog
# ============================================================================

class TestServiceAPICatalog(unittest.TestCase):

    def test_open_sc_manager_registered(self):
        hook = resolve_api("OpenSCManager")
        self.assertIsNotNone(hook, "OpenSCManager must be in API catalog")
        self.assertIn("T1543.003", hook.mitre)

    def test_open_sc_manager_aliases(self):
        self.assertEqual(resolve_api("OpenSCManagerA").name, "OpenSCManager")
        self.assertEqual(resolve_api("OpenSCManagerW").name, "OpenSCManager")

    def test_create_service_registered(self):
        hook = resolve_api("CreateService")
        self.assertIsNotNone(hook)
        self.assertEqual(hook.baseline_risk, BaselineRisk.HIGH)
        self.assertIn("T1543.003", hook.mitre)

    def test_create_service_aliases(self):
        self.assertEqual(resolve_api("CreateServiceA").name, "CreateService")
        self.assertEqual(resolve_api("CreateServiceW").name, "CreateService")

    def test_change_service_config_registered(self):
        hook = resolve_api("ChangeServiceConfig")
        self.assertIsNotNone(hook)
        self.assertIn("T1574", hook.mitre)

    def test_start_service_registered(self):
        hook = resolve_api("StartService")
        self.assertIsNotNone(hook)
        self.assertIn("T1543.003", hook.mitre)

    def test_all_service_apis_in_required_set(self):
        for api in ("OpenSCManager", "CreateService", "ChangeServiceConfig", "StartService"):
            self.assertIn(api, REQUIRED_APIS, f"{api} missing from REQUIRED_APIS")


# ============================================================================
# Phase 5.1 - Service Monitor: Chain Rules
# ============================================================================

class TestServiceChainRules(unittest.TestCase):

    def _engine(self):
        return HookEngine(uuid4())

    def test_service_persistence_install_chain_fires(self):
        eng = self._engine()
        chains = _ingest_seq(eng, [
            _raw("OpenSCManagerW", {"dwDesiredAccess": 0x0002}),
            _raw("CreateServiceW", {
                "lpServiceName": "EvilSvc",
                "lpBinaryPathName": r"C:\Windows\Temp\evil.exe",
                "dwStartType": 0x2,
                "dwServiceType": 0x10,
            }),
            _raw("StartServiceW", {"hService": 1}),
        ])
        rule_ids = {c.rule_id for c in chains}
        self.assertIn("service_persistence_install", rule_ids)

    def test_service_hijack_chain_fires(self):
        eng = self._engine()
        chains = _ingest_seq(eng, [
            _raw("OpenSCManagerW", {"dwDesiredAccess": 0x0002}),
            _raw("ChangeServiceConfigW", {
                "hService": 5,
                "dwStartType": 0x2,
                # AppData path triggers suspicious_binary_path condition
                "lpBinaryPathName": r"C:\Users\bob\AppData\Roaming\malware.exe",
            }),
        ])
        rule_ids = {c.rule_id for c in chains}
        self.assertIn("service_hijack", rule_ids)

    def test_drop_and_install_service_chain_fires(self):
        eng = self._engine()
        chains = _ingest_seq(eng, [
            _raw("WriteFile", {"lpFileName": r"C:\Temp\payload.exe", "nNumberOfBytesToWrite": 4096}),
            _raw("OpenSCManagerW", {"dwDesiredAccess": 0x0002}),
            _raw("CreateServiceW", {
                "lpServiceName": "BadSvc",
                "lpBinaryPathName": r"C:\Temp\payload.exe",
                "dwStartType": 0x2,
                "dwServiceType": 0x10,
            }),
        ])
        rule_ids = {c.rule_id for c in chains}
        self.assertIn("drop_and_install_service", rule_ids)


# ============================================================================
# Phase 5.1 - Service Condition Predicates
# ============================================================================

class TestServiceConditions(unittest.TestCase):

    def test_auto_start_flag_detected(self):
        e = _event("CreateService", {"dwStartType": 0x2})
        self.assertTrue(_cond_service_auto_start(e))

    def test_boot_start_flag_detected(self):
        e = _event("CreateService", {"dwStartType": 0x0})
        self.assertTrue(_cond_service_auto_start(e))

    def test_demand_start_not_flagged(self):
        e = _event("CreateService", {"dwStartType": 0x3})
        self.assertFalse(_cond_service_auto_start(e))

    def test_suspicious_path_appdata(self):
        e = _event("ChangeServiceConfig", {"lpBinaryPathName": r"C:\Users\bob\AppData\Roaming\svc.exe"})
        self.assertTrue(_cond_suspicious_binary_path(e))

    def test_suspicious_path_temp(self):
        e = _event("ChangeServiceConfig", {"lpBinaryPathName": r"C:\Windows\Temp\payload.exe"})
        self.assertTrue(_cond_suspicious_binary_path(e))

    def test_legitimate_path_not_flagged(self):
        e = _event("CreateService", {"lpBinaryPathName": r"C:\Program Files\MyApp\service.exe"})
        self.assertFalse(_cond_suspicious_binary_path(e))


# ============================================================================
# Phase 5.2 - Driver Monitor: API Catalog
# ============================================================================

class TestDriverAPICatalog(unittest.TestCase):

    def test_nt_load_driver_registered(self):
        hook = resolve_api("NtLoadDriver")
        self.assertIsNotNone(hook)
        self.assertEqual(hook.baseline_risk, BaselineRisk.HIGH)
        self.assertIn("T1014", hook.mitre)
        self.assertIn("T1068", hook.mitre)

    def test_nt_load_driver_alias_zw(self):
        self.assertEqual(resolve_api("ZwLoadDriver").name, "NtLoadDriver")

    def test_nt_set_system_information_registered(self):
        hook = resolve_api("NtSetSystemInformation")
        self.assertIsNotNone(hook)
        self.assertIn("T1068", hook.mitre)

    def test_driver_apis_in_required_set(self):
        for api in ("NtLoadDriver", "NtSetSystemInformation"):
            self.assertIn(api, REQUIRED_APIS)


# ============================================================================
# Phase 5.2 - Driver Monitor: Chain Rules + Conditions
# ============================================================================

class TestDriverChainRules(unittest.TestCase):

    def _engine(self):
        return HookEngine(uuid4())

    def test_byovd_chain_fires(self):
        eng = self._engine()
        chains = _ingest_seq(eng, [
            _raw("NtLoadDriver", {"DriverServiceName": r"\Registry\Machine\System\CurrentControlSet\Services\Vuln"}),
            _raw("DeviceIoControl", {"hDevice": 1, "dwIoControlCode": 0x222004, "lpInBuffer": ""}),
        ])
        rule_ids = {c.rule_id for c in chains}
        self.assertIn("byovd_attack", rule_ids)

    def test_nonstandard_driver_path_condition(self):
        e = _event("NtLoadDriver", {"DriverServiceName": r"C:\Users\Public\rootkit.sys"})
        self.assertTrue(_cond_nonstandard_driver_path(e))

    def test_standard_driver_path_not_flagged(self):
        # Standard registry path — these contain 'currentcontrolset\services'
        e = _event("NtLoadDriver", {
            "DriverServiceName": r"\Registry\Machine\System\CurrentControlSet\Services\legit"
        })
        self.assertFalse(_cond_nonstandard_driver_path(e))


# ============================================================================
# Phase 5.3 - Privilege Escalation: API Catalog
# ============================================================================

class TestPrivEscAPICatalog(unittest.TestCase):

    def test_open_process_token_registered(self):
        hook = resolve_api("OpenProcessToken")
        self.assertIsNotNone(hook)
        self.assertIn("T1134", hook.mitre)

    def test_adjust_token_privileges_registered(self):
        hook = resolve_api("AdjustTokenPrivileges")
        self.assertIsNotNone(hook)
        self.assertIn("T1134.001", hook.mitre)

    def test_duplicate_token_ex_registered(self):
        hook = resolve_api("DuplicateTokenEx")
        self.assertIsNotNone(hook)
        self.assertEqual(hook.baseline_risk, BaselineRisk.HIGH)
        self.assertIn("T1134.001", hook.mitre)

    def test_impersonate_logged_on_user_registered(self):
        hook = resolve_api("ImpersonateLoggedOnUser")
        self.assertIsNotNone(hook)
        self.assertIn("T1134.003", hook.mitre)

    def test_create_process_with_token_registered(self):
        hook = resolve_api("CreateProcessWithToken")
        self.assertIsNotNone(hook)
        self.assertIn("T1134.002", hook.mitre)

    def test_priv_esc_apis_in_required_set(self):
        for api in ("OpenProcessToken", "AdjustTokenPrivileges", "DuplicateTokenEx",
                    "ImpersonateLoggedOnUser", "CreateProcessWithToken"):
            self.assertIn(api, REQUIRED_APIS)


# ============================================================================
# Phase 5.3 - Privilege Escalation: Chain Rules + Conditions
# ============================================================================

class TestPrivEscChainRules(unittest.TestCase):

    def _engine(self):
        return HookEngine(uuid4())

    def test_token_impersonation_full_fires(self):
        eng = self._engine()
        chains = _ingest_seq(eng, [
            _raw("OpenProcessToken", {"ProcessHandle": 4, "DesiredAccess": 0x2}),
            _raw("DuplicateTokenEx", {
                "hExistingToken": 100,
                "dwDesiredAccess": 0xF01FF,
                "ImpersonationLevel": 2,
                "TokenType": 1,
            }),
            _raw("CreateProcessWithTokenW", {
                "hToken": 101,
                "lpApplicationName": r"C:\Windows\System32\cmd.exe",
                "lpCommandLine": "cmd.exe /c whoami",
            }),
        ])
        rule_ids = {c.rule_id for c in chains}
        self.assertIn("token_impersonation_full", rule_ids)

    def test_privilege_enable_debug_fires(self):
        eng = self._engine()
        chains = _ingest_seq(eng, [
            _raw("OpenProcessToken", {"ProcessHandle": 4, "DesiredAccess": 0x20}),
            _raw("AdjustTokenPrivileges", {
                "TokenHandle": 100,
                "DisableAllPrivileges": False,
                "PrivilegeCount": 1,
                "FirstLuid": "20",
            }),
        ])
        rule_ids = {c.rule_id for c in chains}
        self.assertIn("privilege_enable_debug", rule_ids)

    def test_escalate_and_exec_fires(self):
        eng = self._engine()
        chains = _ingest_seq(eng, [
            _raw("AdjustTokenPrivileges", {
                "TokenHandle": 100,
                "DisableAllPrivileges": False,
                "PrivilegeCount": 1,
                "FirstLuid": "22",
            }),
            _raw("CreateProcessW", {
                "lpApplicationName": r"C:\Windows\System32\cmd.exe",
                "dwCreationFlags": 0,
            }),
        ])
        rule_ids = {c.rule_id for c in chains}
        self.assertIn("escalate_and_exec", rule_ids)

    def test_debug_privilege_detected(self):
        e = _event("AdjustTokenPrivileges", {
            "DisableAllPrivileges": False,
            "PrivilegeCount": 1,
            "FirstLuid": "20",
        })
        self.assertTrue(_cond_debug_privilege_enabled(e))

    def test_non_debug_privilege_not_flagged(self):
        e = _event("AdjustTokenPrivileges", {
            "DisableAllPrivileges": False,
            "PrivilegeCount": 1,
            "FirstLuid": "7",
        })
        self.assertFalse(_cond_debug_privilege_enabled(e))

    def test_disable_all_skips_debug_check(self):
        e = _event("AdjustTokenPrivileges", {
            "DisableAllPrivileges": True,
            "PrivilegeCount": 0,
        })
        self.assertFalse(_cond_debug_privilege_enabled(e))

    def test_any_privilege_enabled(self):
        e = _event("AdjustTokenPrivileges", {
            "DisableAllPrivileges": False,
            "PrivilegeCount": 2,
        })
        self.assertTrue(_cond_any_privilege_enabled(e))

    def test_token_primary_type(self):
        e = _event("DuplicateTokenEx", {"TokenType": 1})
        self.assertTrue(_cond_token_primary_type(e))

    def test_impersonation_token_type_not_flagged(self):
        e = _event("DuplicateTokenEx", {"TokenType": 2})
        self.assertFalse(_cond_token_primary_type(e))


# ============================================================================
# Phase 6 - Android Monitor Coverage
# ============================================================================

class TestAndroidAgentCoverage(unittest.TestCase):

    def setUp(self):
        self.agent = generate_frida_android_agent()
        self.manifest = installation_manifest()

    def test_permission_monitor_in_agent(self):
        self.assertIn("requestPermissions", self.agent)
        self.assertIn("checkSelfPermission", self.agent)
        self.assertIn("READ_SMS", self.agent)

    def test_sms_monitor_in_agent(self):
        self.assertIn("SmsManager", self.agent)
        self.assertIn("sendTextMessage", self.agent)
        self.assertIn("ReadSMS", self.agent)

    def test_location_monitor_in_agent(self):
        self.assertIn("LocationManager", self.agent)
        self.assertIn("requestLocationUpdates", self.agent)
        self.assertIn("FusedLocationProviderClient", self.agent)
        self.assertIn("highFrequency", self.agent)

    def test_contact_monitor_in_agent(self):
        self.assertIn("ReadContacts", self.agent)
        self.assertIn("contacts", self.agent)

    def test_clipboard_monitor_in_agent(self):
        self.assertIn("ClipboardManager", self.agent)
        self.assertIn("getPrimaryClip", self.agent)
        self.assertIn("setPrimaryClip", self.agent)
        self.assertIn("possibleCryptoAddress", self.agent)

    def test_camera_monitor_in_agent(self):
        self.assertIn("CameraManager", self.agent)
        self.assertIn("openCamera", self.agent)
        self.assertIn("setVideoSource", self.agent)

    def test_microphone_monitor_in_agent(self):
        self.assertIn("AudioRecord", self.agent)
        self.assertIn("startRecording", self.agent)
        self.assertIn("isMic", self.agent)

    def test_accessibility_monitor_in_agent(self):
        self.assertIn("AccessibilityService", self.agent)
        self.assertIn("onAccessibilityEvent", self.agent)
        self.assertIn("sensitiveSearch", self.agent)

    def test_overlay_monitor_in_agent(self):
        self.assertIn("WindowManagerImpl", self.agent)
        self.assertIn("isOverlay", self.agent)
        self.assertIn("invisibleTapLogger", self.agent)

    def test_extended_hooks_marker_present(self):
        self.assertIn("extended: true", self.agent)

    def test_all_9_android_monitors_in_manifest(self):
        phase6 = self.manifest.get("android_phase6", {})
        expected = [
            "permission_monitor", "sms_monitor", "location_monitor",
            "contact_monitor", "clipboard_monitor", "camera_monitor",
            "microphone_monitor", "accessibility_monitor", "overlay_monitor",
        ]
        for monitor in expected:
            self.assertIn(monitor, phase6, f"{monitor} missing from android_phase6 manifest")


# ============================================================================
# Integration - Catalog Integrity
# ============================================================================

class TestCatalogIntegrity(unittest.TestCase):

    def test_required_apis_all_present(self):
        for api in REQUIRED_APIS:
            self.assertIsNotNone(resolve_api(api), f"{api} missing from catalog")

    def test_new_windows_apis_count(self):
        # 20 original + 11 new (Services x4, Drivers x2, PrivEsc x5) = 31 possible
        # actual count may vary slightly — ensure at least 30
        self.assertGreaterEqual(len(API_CATALOG), 30)

    def test_chain_rules_count(self):
        self.assertGreaterEqual(len(CHAIN_RULES), 20)

    def test_conditions_dict_covers_new_predicates(self):
        new_conditions = [
            "service_auto_start", "suspicious_binary_path",
            "nonstandard_driver_path",
            "debug_privilege_enabled", "any_privilege_enabled", "token_primary_type",
        ]
        for cond in new_conditions:
            self.assertIn(cond, CONDITIONS, f"Condition '{cond}' missing from CONDITIONS dict")

    def test_installation_manifest_includes_phase5_6(self):
        manifest = installation_manifest()
        self.assertIn("windows_phase5", manifest)
        self.assertIn("android_phase6", manifest)
        p6 = manifest["android_phase6"]
        self.assertEqual(len(p6), 9)


class TestSupersededRules(unittest.TestCase):

    def test_token_basic_superseded_by_full(self):
        basic = next(r for r in CHAIN_RULES if r.rule_id == "token_impersonation_basic")
        self.assertIn("token_impersonation_full", basic.superseded_by)


# ============================================================================
# Entry point
# ============================================================================

if __name__ == "__main__":
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()
    for cls in [
        TestServiceAPICatalog, TestServiceChainRules, TestServiceConditions,
        TestDriverAPICatalog, TestDriverChainRules,
        TestPrivEscAPICatalog, TestPrivEscChainRules,
        TestAndroidAgentCoverage, TestCatalogIntegrity, TestSupersededRules,
    ]:
        suite.addTests(loader.loadTestsFromTestCase(cls))
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    sys.exit(0 if result.wasSuccessful() else 1)
