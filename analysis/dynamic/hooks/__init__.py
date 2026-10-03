"""
Live API hook monitoring.

Monitors 30 Win32 APIs and 24 Android Java APIs, and correlates them into
named behaviors. The correlation is the point: individual calls are
near-worthless as evidence (VirtualAlloc fires constantly in benign software,
and a messaging app reads SMS), while ordered sequences are decisive:

    VirtualAlloc(RWX) → NtWriteVirtualMemory(foreign) → CreateRemoteThread
        = process injection

    ReadFile → CryptEncrypt → WriteFile, repeated across user documents
        = ransomware

    ReadSMS → SendSMS
        = OTP interception

    AccessibilityEvent(window change) → OverlayWindowAdded(overlay type)
        = banking overlay attack

Usage
-----
    from hooks import StageHookMonitor, generate_frida_agent

    monitor = StageHookMonitor(analysis_id)
    monitor.enter_stage("long_execution")
    chains = monitor.ingest_batch(calls_from_guest)
    rollup = monitor.exit_stage("long_execution")
"""

from .api_catalog import (
    ANDROID_DANGEROUS_PERMISSIONS,
    ANDROID_MONITORED_APIS,
    ANDROID_REQUIRED_APIS,
    API_ALIASES,
    API_CATALOG,
    MONITORED_APIS,
    PAGE_PROTECTION,
    REQUIRED_APIS,
    WINDOWS_MONITORED_APIS,
    ApiArg,
    ApiCategory,
    ApiHook,
    BaselineRisk,
    apis_by_category,
    apis_by_platform,
    classify_content_uri,
    dangerous_permissions,
    decode_flags,
    has_credential_search_term,
    is_covert_audio_source,
    is_dangerous_permission,
    is_executable,
    is_overlay_window,
    is_rwx,
    resolve_api,
)
from .hook_engine import (
    CHAIN_RULES,
    ApiCallEvent,
    BehaviorChain,
    ChainRule,
    ChainSeverity,
    HookEngine,
)
from .hook_installer import (
    generate_cape_config,
    generate_frida_agent,
    generate_frida_android_agent,
    installation_manifest,
)
from .stage_integration import MockHookSource, StageHookMonitor

__all__ = [
    # Catalog
    "API_CATALOG", "API_ALIASES", "MONITORED_APIS", "REQUIRED_APIS",
    "ApiHook", "ApiArg", "ApiCategory", "BaselineRisk",
    "resolve_api", "apis_by_category", "apis_by_platform", "decode_flags",
    "is_rwx", "is_executable", "PAGE_PROTECTION",
    # Catalog — Android
    "ANDROID_MONITORED_APIS", "ANDROID_REQUIRED_APIS",
    "WINDOWS_MONITORED_APIS", "ANDROID_DANGEROUS_PERMISSIONS",
    "is_dangerous_permission", "dangerous_permissions", "classify_content_uri",
    "is_overlay_window", "is_covert_audio_source", "has_credential_search_term",
    # Engine
    "HookEngine", "ApiCallEvent", "BehaviorChain",
    "ChainRule", "ChainSeverity", "CHAIN_RULES",
    # Installer
    "generate_frida_agent", "generate_frida_android_agent",
    "generate_cape_config", "installation_manifest",
    # Stage integration
    "StageHookMonitor", "MockHookSource",
]
