"""
demo_investigation.py — Standalone demo of the Phase 10 AI Investigation Engine.

This script demonstrates the investigation workflow without requiring the full
orchestrator to run. It uses mock data to show how each component works.
"""

import sys
from pathlib import Path

# Add repo root to path
_repo_root = str(Path(__file__).resolve().parents[2])
if _repo_root not in sys.path:
    sys.path.insert(0, _repo_root)

from agents.investigation_engine.investigation_engine import InvestigationEngine


def create_sample_state():
    """Create a sample investigation state with mock data."""
    return {
        "sample_id": "demo_sample_001",
        "static_output": {
            "sha256": "a" * 64,
            "platform": "android",
            "file_type": "apk",
            "file_size_bytes": 2048576,
            "submitted_at": "2026-08-06T00:00:00Z",
            "yara_matches": [
                {
                    "rule_name": "android_spyware",
                    "category": "spyware",
                    "severity": "high",
                    "description": "Known Android spyware signature targeting banking apps"
                },
                {
                    "rule_name": "sms_stealer",
                    "category": "theft",
                    "severity": "critical",
                    "description": "SMS interception and OTP theft capability"
                }
            ],
            "android_manifest": {
                "package_name": "com.fake.security.update",
                "permissions": [
                    "android.permission.READ_SMS",
                    "android.permission.SEND_SMS",
                    "android.permission.ACCESS_FINE_LOCATION",
                    "android.permission.CAMERA",
                    "android.permission.RECORD_AUDIO"
                ],
                "requested_sdk": 30,
                "exported_components": [".MainActivity", ".SmsService"]
            },
            "extracted_strings": {
                "urls": [
                    "http://c2-server.evil-domain.com/api/submit",
                    "https://cdn.malicious-net.com/payload"
                ],
                "ips": ["192.168.1.100", "10.0.0.50"],
                "suspicious_keywords": [
                    "password",
                    "login",
                    "steal",
                    "otp",
                    "banking",
                    "credential"
                ]
            },
            "ml_classifier": {
                "model": "android_malware_detector_v2",
                "anomaly_score": 0.92,
                "classification": "likely_malicious"
            },
            "static_risk_flags": [
                "suspicious_permissions",
                "obfuscated_code",
                "known_bad_domain"
            ]
        },
        "dynamic_output": {
            "process_tree": [
                {"name": "malware.exe", "pid": 1234, "parent_pid": 1000},
                {"name": "payload.dll", "pid": 1235, "parent_pid": 1234},
                {"name": "injector.exe", "pid": 1236, "parent_pid": 1234}
            ],
            "api_calls": [
                "ReadProcessMemory",
                "WriteProcessMemory",
                "InternetConnect",
                "HttpSendRequest",
                "CryptEncrypt",
                "GetClipboardData",
                "GetAsyncKeyState"
            ],
            "network_connections": [
                {
                    "dest_ip": "192.168.1.100",
                    "dest_port": 443,
                    "protocol": "https",
                    "flagged_c2": True,
                    "interval_seconds": 60,
                    "bytes_sent": 15000,
                    "bytes_received": 5000
                },
                {
                    "dest_ip": "10.0.0.50",
                    "dest_port": 8080,
                    "protocol": "http",
                    "flagged_c2": False,
                    "interval_seconds": 300,
                    "bytes_sent": 2000,
                    "bytes_received": 1000
                }
            ],
            "files_written": [
                "/data/data/com.fake.security.update/cache.dat",
                "/sdcard/Android/data/.hidden/payload.exe",
                "/system/bin/.backdoor/service"
            ],
            "registry_changes": [
                "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
                "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"
            ],
            "persistence_artifacts": [
                "systemd service installed",
                "cron job added",
                "launchd plist created"
            ],
            "c2_endpoints_detected": [
                "192.168.1.100:443",
                "c2-server.evil-domain.com"
            ]
        },
        "mitre_techniques": [
            {"technique_id": "T1112", "technique_name": "Modify Registry", "confidence": 0.85},
            {"technique_id": "T1055", "technique_name": "Process Injection", "confidence": 0.92},
            {"technique_id": "T1056", "technique_name": "Input Capture", "confidence": 0.88},
            {"technique_id": "T1113", "technique_name": "Screen Capture", "confidence": 0.75},
            {"technique_id": "T1412", "technique_name": "SMS Intercept", "confidence": 0.95},
            {"technique_id": "T1418", "technique_name": "Location Tracking", "confidence": 0.80}
        ],
        "capability_tags": [
            {"capability": "sms_theft", "confidence": 0.95, "evidence": ["READ_SMS permission", "SMS API calls"]},
            {"capability": "gps_tracking", "confidence": 0.80, "evidence": ["ACCESS_FINE_LOCATION permission"]},
            {"capability": "keylogging", "confidence": 0.88, "evidence": ["keyboard hook API", "GetAsyncKeyState"]},
            {"capability": "screen_capture", "confidence": 0.75, "evidence": ["Camera permission", "screen capture APIs"]},
            {"capability": "persistence", "confidence": 0.85, "evidence": ["Registry changes", "systemd service"]},
            {"capability": "c2_communication", "confidence": 0.92, "evidence": ["Known C2 endpoints", "periodic connections"]}
        ],
        "risk_score": 85,
        "narrative_summary": "This Android APK sample exhibits multiple malicious capabilities including SMS theft, GPS tracking, and keylogging. The malware maintains persistence through system services and communicates with known command-and-control servers. Risk score: 85/100.",
        "investigation_output": {
            "timeline_events": [],
            "malware_explanation": None,
            "victim_impact": None,
            "exfiltration_analysis": None,
            "recommendations": [],
            "investigation_summary": None,
        },
    }


def print_section(title: str):
    """Print a formatted section header."""
    print(f"\n{'=' * 80}")
    print(f"  {title}")
    print(f"{'=' * 80}\n")


def main():
    """Run the investigation engine demo."""
    print_section("Phase 10 — AI Investigation Engine Demo")
    
    # Create investigation state
    state = create_sample_state()
    print(f"Sample ID: {state['sample_id']}")
    print(f"Platform: {state['static_output']['platform']}")
    print(f"File Type: {state['static_output']['file_type']}")
    print(f"Risk Score: {state['risk_score']}/100")
    
    # Run investigation with chain verification
    engine = InvestigationEngine(secret_key="demo_secret_key")
    final_state = engine.run_investigation_with_verification(state, verify_chain=True)
    
    # Display results
    print_section("Investigation Results")
    
    # Timeline
    print_section("Timeline Events")
    timeline = final_state.get("timeline_events", [])
    print(f"Total events: {len(timeline)}")
    for i, event in enumerate(timeline[:10], 1):  # Show first 10
        print(f"{i}. [{event.severity.upper()}] {event.event_type}: {event.description}")
    if len(timeline) > 10:
        print(f"... and {len(timeline) - 10} more events")
    
    # Malware Explanation
    print_section("Malware Explanation")
    malware_exp = final_state.get("malware_explanation")
    if malware_exp:
        print(f"Summary: {malware_exp.summary}")
        print(f"\nTechnical Details: {malware_exp.technical_details}")
        print(f"\nCapabilities: {', '.join(malware_exp.capabilities_identified)}")
        print(f"Confidence: {malware_exp.confidence_level:.0%}")
    
    # Victim Impact
    print_section("Victim Impact Analysis")
    victim_impact = final_state.get("victim_impact")
    if victim_impact:
        print(f"Overall Impact: {victim_impact.overall_impact.upper()}")
        print(f"\nData Accessed: {', '.join(victim_impact.data_accessed) or 'None'}")
        print(f"Privacy Risks: {', '.join(victim_impact.privacy_risks) or 'None'}")
        print(f"Financial Risks: {', '.join(victim_impact.financial_risks) or 'None'}")
        print(f"Device Integrity: {', '.join(victim_impact.device_integrity) or 'None'}")
        print(f"\nExplanation: {victim_impact.explanation}")
    
    # Exfiltration Analysis
    print_section("Exfiltration Analysis")
    exfil = final_state.get("exfiltration_analysis")
    if exfil:
        print(f"Data Types: {', '.join(exfil.data_types) or 'None'}")
        print(f"Destinations: {', '.join(exfil.destinations) or 'None'}")
        print(f"Timing Patterns: {exfil.timing_patterns}")
        print(f"Encryption Status: {exfil.encryption_status}")
        print(f"Estimated Volume: {exfil.estimated_volume}")
        print(f"Risk Assessment: {exfil.risk_assessment}")
    
    # Recommendations
    print_section("Recommendations")
    recommendations = final_state.get("recommendations", [])
    print(f"Total recommendations: {len(recommendations)}")
    for i, rec in enumerate(recommendations, 1):
        print(f"{i}. [{rec.priority.upper()}] {rec.category}: {rec.action}")
        print(f"   Rationale: {rec.rationale}\n")
    
    # Final Summary
    print_section("Investigation Summary")
    summary = final_state.get("investigation_summary")
    if summary:
        print(f"Executive Summary: {summary.executive_summary}")
        print(f"\nKey Findings:")
        for finding in summary.key_findings:
            print(f"  - {finding}")
        print(f"\nTimeline Summary: {summary.timeline_summary}")
        print(f"Risk Assessment: {summary.risk_assessment}")
        print(f"\nNext Steps:")
        for step in summary.next_steps:
            print(f"  - {step}")
        print(f"\nGenerated at: {summary.generated_at}")
    
    # Chain Verification
    print_section("Chain Verification")
    chain_verification = final_state.get("chain_verification")
    if chain_verification:
        print(f"Status: {chain_verification.get('status', 'unknown').upper()}")
        print(f"Valid: {chain_verification.get('is_valid', False)}")
        print(f"Verified Links: {chain_verification.get('verified_links', 0)}/{chain_verification.get('total_links', 0)}")
        
        if chain_verification.get('tampered_links'):
            print(f"Tampered Links: {', '.join(chain_verification['tampered_links'])}")
        
        if chain_verification.get('missing_links'):
            print(f"Missing Links: {', '.join(chain_verification['missing_links'])}")
        
        if chain_verification.get('errors'):
            print(f"Errors:")
            for error in chain_verification['errors']:
                print(f"  - {error}")
        
        print(f"Verified At: {chain_verification.get('verified_at', 'unknown')}")
        
        # Show chain export
        chain_export = chain_verification.get('chain_export')
        if chain_export:
            print(f"\nChain Export (first 500 chars):")
            print(chain_export[:500] + "..." if len(chain_export) > 500 else chain_export)
    else:
        print("No chain verification data available")
    
    print_section("Demo Complete")


if __name__ == "__main__":
    main()
