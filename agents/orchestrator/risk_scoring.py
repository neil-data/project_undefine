"""
risk_scoring.py — Weighted risk score calculation, extracted into its
own module so it's unit-testable in isolation from the graph.

Weighting is intentionally simple and documented here — tune weights
in ONE place if scores don't feel right during demo prep.

PHASE 3 ENHANCEMENTS:
- Added Windows-specific behavior chain scoring
- Added critical severity detection bonuses
- Added advanced persistence and privilege escalation detection
- Added defense evasion activity penalties
"""

from __future__ import annotations
from typing import Optional, Dict, Any

from agents.orchestrator.schema import (
    StaticAnalysisOutput,
    DynamicAnalysisOutput,
    MitreTechnique,
    CapabilityTag,
)

# Weight constants — documented and centralized so they're easy to tune
YARA_MATCH_WEIGHT = 15
MITRE_TECHNIQUE_WEIGHT = 8
CAPABILITY_CONFIDENCE_MULTIPLIER = 15
ML_LIKELY_MALICIOUS_BONUS = 20
DYNAMIC_C2_CONFIRMED_BONUS = 20
DYNAMIC_DEVICE_ADMIN_BONUS = 10

# Configurable ELF / Linux scoring constants
SCORE_OBSERVED_DOWNLOAD_AND_EXEC = 20
SCORE_OBSERVED_PERSISTENCE = 15
SCORE_OBSERVED_MINING = 15
SCORE_OBSERVED_SCANNING = 10
SCORE_OBSERVED_HIDDEN_FILE = 10
SCORE_OBSERVED_PTRACE = 5

SCORE_OBSERVED_CAP = 50
SCORE_STATIC_CAP = 20

YARA_FAMILY_WEIGHT = 15
YARA_GENERIC_WEIGHT = 0
YARA_CAP = 40

INTEL_FLOOR_SCORE = 85
MAX_SCORE = 100
MIN_SCORE = 0

GENERIC_YARA_RULES = {
    "md5_constants", "sha1_constants", "ripemd160_constants",
    "enterpriseapps2", "detectencryptedvariants"
}

# Windows behavior chain weights (Phase 3)
BEHAVIOR_CHAIN_CRITICAL_WEIGHT = 30
BEHAVIOR_CHAIN_HIGH_WEIGHT = 20
BEHAVIOR_CHAIN_MEDIUM_WEIGHT = 10
BEHAVIOR_CHAIN_LOW_WEIGHT = 5

# Special detection bonuses (Phase 3)
PROCESS_INJECTION_BONUS = 25
PRIVILEGE_ESCALATION_BONUS = 25
KERNEL_DRIVER_BONUS = 30
DEFENSE_EVASION_BONUS = 20
PERSISTENCE_BONUS = 15

# Android-specific bonuses (Phase 4)
ANDROID_SMS_INTERCEPTION_BONUS = 30
ANDROID_LOCATION_TRACKING_BONUS = 25
ANDROID_CLIPBOARD_ATTACK_BONUS = 25
ANDROID_SURVEILLANCE_BONUS = 35
ANDROID_PERMISSION_ESCALATION_BONUS = 30
ANDROID_ACCESSIBILITY_ABUSE_BONUS = 35
ANDROID_OVERLAY_ATTACK_BONUS = 30

# Severity thresholds
CRITICAL_CHAIN_THRESHOLD = 3
HIGH_CHAIN_THRESHOLD = 5


def _is_generic_yara_rule(rule_name: str, category: str = "") -> bool:
    name_low = rule_name.lower()
    if name_low in GENERIC_YARA_RULES:
        return True
    if name_low.endswith("_constants") or "_constants" in name_low:
        return True
    if category.lower() in ("crypto", "mass_hunt", "generic"):
        return True
    return False


def compute_risk_score(
    static: StaticAnalysisOutput,
    dynamic: Optional[DynamicAnalysisOutput],
    mitre: list[MitreTechnique],
    capabilities: list[CapabilityTag],
) -> int:
    is_elf = (
        getattr(static, "platform", None) == "linux"
        or getattr(static, "file_type", None) == "elf"
    )

    # 1. YARA scoring with family vs generic distinction
    yara_score = 0
    seen_families: set[str] = set()
    for ym in getattr(static, "yara_matches", []):
        r_name = getattr(ym, "rule_name", "")
        cat = getattr(ym, "category", "")
        if _is_generic_yara_rule(r_name, cat):
            yara_score += YARA_GENERIC_WEIGHT
        else:
            # Count at most once per family if family in rule name
            fam_key = r_name.split("_")[0].lower() if "_" in r_name else r_name.lower()
            if fam_key not in seen_families:
                seen_families.add(fam_key)
                yara_score += YARA_FAMILY_WEIGHT
            else:
                yara_score += 5  # additional rule in same family contributes slightly
    yara_score = min(yara_score, YARA_CAP)

    if is_elf:
        # Static cap
        static_contrib = yara_score
        if getattr(static, "static_risk_flags", []):
            static_contrib += 10
        static_contrib = min(static_contrib, SCORE_STATIC_CAP)

        # Observed dynamic behaviors
        dyn_contrib = 0
        if dynamic:
            dyn_status = getattr(dynamic, "dynamic_status", "completed")
            procs_str = str(getattr(dynamic, "process_tree", [])).lower()
            apis_str = str(getattr(dynamic, "api_calls", [])).lower()
            files_str = str(getattr(dynamic, "files_written", [])).lower()
            pers_str = str(getattr(dynamic, "persistence_artifacts", [])).lower()
            conns = getattr(dynamic, "network_connections", [])

            # download-and-exec
            has_download = any(tool in procs_str or tool in apis_str for tool in ("curl", "wget", "ftpget", "tftp"))
            has_exec = any(tool in procs_str or tool in apis_str for tool in ("/bin/sh", "/bin/bash", "execve"))
            if has_download and has_exec:
                dyn_contrib += SCORE_OBSERVED_DOWNLOAD_AND_EXEC
            elif has_download or has_exec:
                dyn_contrib += 10

            # persistence write
            if pers_str or any(p in files_str for p in ("cron", "rc.local", "systemd", "init.d")):
                dyn_contrib += SCORE_OBSERVED_PERSISTENCE

            # mining
            if any("stratum" in c or c.get("dest_port") in (3333, 8888, 9999, 14444) for c in conns if isinstance(c, dict)):
                dyn_contrib += SCORE_OBSERVED_MINING

            # scanning
            if any(c.get("type") == "scanning" or "scan" in str(c) for c in conns if isinstance(c, dict)) or len(conns) >= 10:
                dyn_contrib += SCORE_OBSERVED_SCANNING

            # hidden file
            if any("/." in str(f) or "/dev/shm" in str(f) for f in getattr(dynamic, "files_written", [])):
                dyn_contrib += SCORE_OBSERVED_HIDDEN_FILE

            # ptrace
            if "ptrace" in apis_str:
                dyn_contrib += SCORE_OBSERVED_PTRACE

            dyn_contrib = min(dyn_contrib, SCORE_OBSERVED_CAP)

        # MITRE & Capabilities
        mitre_contrib = len(mitre) * MITRE_TECHNIQUE_WEIGHT
        cap_contrib = sum(int(c.confidence * CAPABILITY_CONFIDENCE_MULTIPLIER) for c in capabilities)

        total_score = static_contrib + dyn_contrib + mitre_contrib + cap_contrib
        return max(MIN_SCORE, min(total_score, MAX_SCORE))

    # Standard non-ELF scoring logic
    score = yara_score
    score += len(mitre) * MITRE_TECHNIQUE_WEIGHT
    score += sum(int(c.confidence * CAPABILITY_CONFIDENCE_MULTIPLIER) for c in capabilities)

    if static.ml_classifier and static.ml_classifier.classification == "likely_malicious":
        score += ML_LIKELY_MALICIOUS_BONUS

    if dynamic:
        if any(conn.get("flagged_c2") for conn in dynamic.network_connections):
            score += DYNAMIC_C2_CONFIRMED_BONUS
        if any("DevicePolicyManager" in c for c in dynamic.api_calls):
            score += DYNAMIC_DEVICE_ADMIN_BONUS
        
        # Phase 3: Windows behavior chain scoring
        score += _compute_behavior_chain_score(dynamic)
        
        # Phase 3: Special detection bonuses
        score += _compute_special_detection_bonuses(dynamic)

    return max(MIN_SCORE, min(score, MAX_SCORE))


def _compute_behavior_chain_score(dynamic: DynamicAnalysisOutput) -> int:
    """
    Compute risk score from Windows behavior chains.
    
    Behavior chains are sequences of API calls that together constitute
    malicious behavior. Each chain has an associated risk_point value
    and severity level.
    """
    score = 0
    behavior_chains = dynamic.behavior_chains if hasattr(dynamic, 'behavior_chains') else []
    
    critical_count = 0
    high_count = 0
    medium_count = 0
    low_count = 0
    
    for chain in behavior_chains:
        severity = chain.get('severity', 'low').lower()
        risk_points = chain.get('risk_points', 0)
        
        if severity == 'critical':
            critical_count += 1
            score += risk_points
        elif severity == 'high':
            high_count += 1
            score += risk_points
        elif severity == 'medium':
            medium_count += 1
            score += risk_points
        elif severity == 'low':
            low_count += 1
            score += risk_points
    
    # Bonus for multiple critical chains
    if critical_count >= CRITICAL_CHAIN_THRESHOLD:
        score += CRITICAL_CHAIN_THRESHOLD * BEHAVIOR_CHAIN_CRITICAL_WEIGHT
    
    # Bonus for multiple high chains
    if high_count >= HIGH_CHAIN_THRESHOLD:
        score += HIGH_CHAIN_THRESHOLD * BEHAVIOR_CHAIN_HIGH_WEIGHT
    
    return score


def _compute_special_detection_bonuses(dynamic: DynamicAnalysisOutput) -> int:
    """
    Compute bonus scores for special high-value detections.
    
    These are specific behaviors that are particularly concerning
    and warrant additional risk scoring.
    """
    bonus = 0
    behavior_chains = dynamic.behavior_chains if hasattr(dynamic, 'behavior_chains') else []
    
    # Check for process injection
    injection_chains = [
        'classic_injection', 'injection_no_alloc', 'process_hollowing'
    ]
    if any(chain.get('rule_id') in injection_chains for chain in behavior_chains):
        bonus += PROCESS_INJECTION_BONUS
    
    # Check for privilege escalation
    privilege_chains = [
        'token_impersonation_full', 'token_impersonation_basic',
        'privilege_enable_debug', 'escalate_and_exec'
    ]
    if any(chain.get('rule_id') in privilege_chains for chain in behavior_chains):
        bonus += PRIVILEGE_ESCALATION_BONUS
    
    # Check for kernel driver loading
    driver_chains = [
        'driver_load_from_nonstandard_path', 'drop_and_load_driver', 'byovd_attack'
    ]
    if any(chain.get('rule_id') in driver_chains for chain in behavior_chains):
        bonus += KERNEL_DRIVER_BONUS
    
    # Check for defense evasion
    evasion_chains = [
        'security_process_termination', 'security_service_disabled',
        'security_service_deleted', 'registry_security_disabled'
    ]
    if any(chain.get('rule_id') in evasion_chains for chain in behavior_chains):
        bonus += DEFENSE_EVASION_BONUS
    
    # Check for advanced persistence
    persistence_chains = [
        'service_persistence_install', 'service_hijack', 'drop_and_install_service',
        'file_based_persistence', 'file_moved_to_system_location'
    ]
    if any(chain.get('rule_id') in persistence_chains for chain in behavior_chains):
        bonus += PERSISTENCE_BONUS
    
    # Phase 4: Android-specific bonuses
    # Check for SMS interception
    sms_chains = [
        'android_sms_interception', 'android_sms_exfiltration', 'android_sms_evidence_destruction'
    ]
    if any(chain.get('rule_id') in sms_chains for chain in behavior_chains):
        bonus += ANDROID_SMS_INTERCEPTION_BONUS
    
    # Check for location tracking
    location_chains = [
        'android_location_exfiltration', 'android_cached_location_exfiltration',
        'android_geofencing_surveillance', 'android_high_accuracy_tracking'
    ]
    if any(chain.get('rule_id') in location_chains for chain in behavior_chains):
        bonus += ANDROID_LOCATION_TRACKING_BONUS
    
    # Check for clipboard attacks
    clipboard_chains = [
        'android_crypto_clipper', 'android_clipboard_hijack', 'android_clipboard_exfiltration'
    ]
    if any(chain.get('rule_id') in clipboard_chains for chain in behavior_chains):
        bonus += ANDROID_CLIPBOARD_ATTACK_BONUS
    
    # Check for surveillance (camera/microphone)
    surveillance_chains = [
        'android_audio_surveillance', 'android_covert_audio_recording',
        'android_camera_surveillance', 'android_covert_photo_capture'
    ]
    if any(chain.get('rule_id') in surveillance_chains for chain in behavior_chains):
        bonus += ANDROID_SURVEILLANCE_BONUS
    
    # Check for permission escalation
    permission_chains = [
        'android_permission_escalation', 'android_permission_state_manipulation',
        'android_overlay_permission_request'
    ]
    if any(chain.get('rule_id') in permission_chains for chain in behavior_chains):
        bonus += ANDROID_PERMISSION_ESCALATION_BONUS
    
    # Check for accessibility abuse
    accessibility_chains = [
        'android_accessibility_automation', 'android_accessibility_credential_automation',
        'android_accessibility_navigate_and_act'
    ]
    if any(chain.get('rule_id') in accessibility_chains for chain in behavior_chains):
        bonus += ANDROID_ACCESSIBILITY_ABUSE_BONUS
    
    # Check for overlay attacks
    overlay_chains = [
        'android_overlay_without_permission', 'android_overlay_with_permission_escalation',
        'android_automated_overlay_attack'
    ]
    if any(chain.get('rule_id') in overlay_chains for chain in behavior_chains):
        bonus += ANDROID_OVERLAY_ATTACK_BONUS
    
    return bonus


def compute_windows_risk_profile(
    dynamic: DynamicAnalysisOutput
) -> Dict[str, Any]:
    """
    Generate a detailed Windows risk profile from behavior chains.
    
    This provides detailed breakdown of risk factors for the dashboard
    and reporting, beyond the single numerical score.
    """
    behavior_chains = dynamic.behavior_chains if hasattr(dynamic, 'behavior_chains') else []
    
    profile = {
        'total_chains': len(behavior_chains),
        'critical_chains': [],
        'high_chains': [],
        'medium_chains': [],
        'low_chains': [],
        'risk_categories': {
            'process_injection': False,
            'privilege_escalation': False,
            'kernel_driver': False,
            'defense_evasion': False,
            'persistence': False,
            'ransomware': False,
            'data_exfiltration': False,
            'credential_theft': False,
        },
        'mitre_coverage': set(),
        'total_risk_points': 0,
    }
    
    for chain in behavior_chains:
        severity = chain.get('severity', 'low').lower()
        rule_id = chain.get('rule_id', '')
        risk_points = chain.get('risk_points', 0)
        mitre = chain.get('mitre', [])
        
        profile['total_risk_points'] += risk_points
        profile['mitre_coverage'].update(mitre)
        
        chain_summary = {
            'rule_id': rule_id,
            'name': chain.get('name', ''),
            'risk_points': risk_points,
            'mitre': mitre,
        }
        
        if severity == 'critical':
            profile['critical_chains'].append(chain_summary)
        elif severity == 'high':
            profile['high_chains'].append(chain_summary)
        elif severity == 'medium':
            profile['medium_chains'].append(chain_summary)
        else:
            profile['low_chains'].append(chain_summary)
        
        # Categorize by risk type
        if 'injection' in rule_id or 'hollowing' in rule_id:
            profile['risk_categories']['process_injection'] = True
        if 'token' in rule_id or 'privilege' in rule_id or 'escalate' in rule_id:
            profile['risk_categories']['privilege_escalation'] = True
        if 'driver' in rule_id:
            profile['risk_categories']['kernel_driver'] = True
        if 'security' in rule_id or 'evasion' in rule_id or 'termination' in rule_id:
            profile['risk_categories']['defense_evasion'] = True
        if 'persist' in rule_id or 'service' in rule_id or 'run_key' in rule_id:
            profile['risk_categories']['persistence'] = True
        if 'ransomware' in rule_id or 'encrypt' in rule_id:
            profile['risk_categories']['ransomware'] = True
        if 'exfiltrate' in rule_id or 'collect_and' in rule_id:
            profile['risk_categories']['data_exfiltration'] = True
        if 'credential' in rule_id or 'lsass' in rule_id or 'debug' in rule_id:
            profile['risk_categories']['credential_theft'] = True
    
    profile['mitre_coverage'] = list(profile['mitre_coverage'])
    
    return profile


def compute_android_risk_profile(
    dynamic: DynamicAnalysisOutput
) -> Dict[str, Any]:
    """
    Generate a detailed Android risk profile from behavior chains.
    
    This provides detailed breakdown of Android-specific risk factors
    for the dashboard and reporting.
    """
    behavior_chains = dynamic.behavior_chains if hasattr(dynamic, 'behavior_chains') else []
    
    profile = {
        'total_chains': len(behavior_chains),
        'critical_chains': [],
        'high_chains': [],
        'medium_chains': [],
        'low_chains': [],
        'android_risk_categories': {
            'sms_interception': False,
            'sms_exfiltration': False,
            'contact_abuse': False,
            'location_tracking': False,
            'geofencing': False,
            'clipboard_attack': False,
            'camera_surveillance': False,
            'audio_surveillance': False,
            'accessibility_abuse': False,
            'overlay_attack': False,
            'permission_escalation': False,
            'contact_manipulation': False,
        },
        'mitre_coverage': set(),
        'total_risk_points': 0,
    }
    
    for chain in behavior_chains:
        severity = chain.get('severity', 'low').lower()
        rule_id = chain.get('rule_id', '')
        risk_points = chain.get('risk_points', 0)
        mitre = chain.get('mitre', [])
        
        # Only consider Android-specific chains
        if not rule_id.startswith('android_'):
            continue
            
        profile['total_risk_points'] += risk_points
        profile['mitre_coverage'].update(mitre)
        
        chain_summary = {
            'rule_id': rule_id,
            'name': chain.get('name', ''),
            'risk_points': risk_points,
            'mitre': mitre,
        }
        
        if severity == 'critical':
            profile['critical_chains'].append(chain_summary)
        elif severity == 'high':
            profile['high_chains'].append(chain_summary)
        elif severity == 'medium':
            profile['medium_chains'].append(chain_summary)
        else:
            profile['low_chains'].append(chain_summary)
        
        # Categorize by Android risk type
        if 'sms' in rule_id:
            if 'interception' in rule_id or 'exfiltration' in rule_id:
                profile['android_risk_categories']['sms_interception'] = True
                profile['android_risk_categories']['sms_exfiltration'] = True
        if 'contact' in rule_id:
            if 'smishing' in rule_id or 'exfiltration' in rule_id:
                profile['android_risk_categories']['contact_abuse'] = True
            if 'manipulation' in rule_id or 'replacement' in rule_id:
                profile['android_risk_categories']['contact_manipulation'] = True
        if 'location' in rule_id:
            profile['android_risk_categories']['location_tracking'] = True
        if 'geofencing' in rule_id:
            profile['android_risk_categories']['geofencing'] = True
        if 'clipboard' in rule_id:
            profile['android_risk_categories']['clipboard_attack'] = True
        if 'camera' in rule_id:
            profile['android_risk_categories']['camera_surveillance'] = True
        if 'audio' in rule_id or 'recording' in rule_id:
            profile['android_risk_categories']['audio_surveillance'] = True
        if 'accessibility' in rule_id:
            profile['android_risk_categories']['accessibility_abuse'] = True
        if 'overlay' in rule_id:
            profile['android_risk_categories']['overlay_attack'] = True
        if 'permission' in rule_id:
            profile['android_risk_categories']['permission_escalation'] = True
    
    profile['mitre_coverage'] = list(profile['mitre_coverage'])
    
    return profile