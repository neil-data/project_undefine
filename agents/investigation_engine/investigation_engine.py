"""
investigation_engine.py — Phase 10 AI Investigation Engine.

This module implements the investigation workflow that processes all collected
evidence and generates a comprehensive investigation report.

Workflow:
    Load All Evidence
           ↓
    Generate Timeline
           ↓
    Explain Malware
           ↓
    Explain Victim Impact
           ↓
    Explain Exfiltration
           ↓
    Generate Recommendations
           ↓
    Generate Summary
"""

import os
import json
from typing import Optional, List, Dict, Any, Tuple
from datetime import datetime, timedelta

try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

from .investigation_schema import (
    InvestigationState,
    TimelineEvent,
    MalwareExplanation,
    VictimImpact,
    ExfiltrationAnalysis,
    Recommendation,
    InvestigationSummary,
)
from .chain_verification import (
    ChainVerifier,
    ChainLink,
    VerificationResult,
    verify_chain,
    verify_integrity,
)


class InvestigationEngine:
    """Main investigation engine that orchestrates the investigation workflow."""
    
    def __init__(self, groq_api_key: Optional[str] = None, secret_key: Optional[str] = None):
        self.groq_api_key = groq_api_key or os.environ.get("GROQ_API_KEY")
        self.secret_key = secret_key or os.environ.get("CHAIN_VERIFICATION_SECRET")
        self.chain_verifier = ChainVerifier(secret_key=self.secret_key)
        
    def run_investigation(self, state: InvestigationState) -> InvestigationState:
        """Run the complete investigation workflow."""
        print(f"[InvestigationEngine] Starting investigation for sample {state.get('sample_id', 'unknown')}")
        
        # Step 1: Load All Evidence (already in state)
        state = self._load_all_evidence(state)
        
        # Step 2: Generate Timeline
        state = self._generate_timeline(state)
        
        # Step 3: Explain Malware
        state = self._explain_malware(state)
        
        # Step 4: Explain Victim Impact
        state = self._explain_victim_impact(state)
        
        # Step 5: Explain Exfiltration
        state = self._explain_exfiltration(state)
        
        # Step 6: Generate Recommendations
        state = self._generate_recommendations(state)
        
        # Step 7: Generate Summary
        state = self._generate_summary(state)
        
        print(f"[InvestigationEngine] Investigation completed for sample {state.get('sample_id', 'unknown')}")
        return state
    
    def _load_all_evidence(self, state: InvestigationState) -> InvestigationState:
        """Load and validate all evidence from the state."""
        print("[InvestigationEngine] Loading all evidence...")
        
        # Ensure all evidence is present in state
        static = state.get("static_output")
        dynamic = state.get("dynamic_output")
        mitre = state.get("mitre_techniques", [])
        capabilities = state.get("capability_tags", [])
        risk_score = state.get("risk_score", 0)
        
        evidence_count = sum([
            1 if static else 0,
            1 if dynamic else 0,
            len(mitre),
            len(capabilities),
            1 if risk_score > 0 else 0
        ])
        
        print(f"[InvestigationEngine] Loaded {evidence_count} evidence sources")
        return state
    
    def _generate_timeline(self, state: InvestigationState) -> InvestigationState:
        """Generate a chronological timeline of malware behavior."""
        print("[InvestigationEngine] Generating timeline...")
        
        timeline_events: List[TimelineEvent] = []
        static = state.get("static_output", {})
        dynamic = state.get("dynamic_output", {})
        
        # Static analysis events
        if static:
            timeline_events.append(TimelineEvent(
                timestamp=datetime.utcnow().isoformat(),
                event_type="static",
                description=f"File submitted for analysis: {static.get('sha256', 'unknown')[:16]}",
                severity="info",
                evidence=["SHA256 hash computed", "File type identified"]
            ))
            
            # YARA matches
            yara_matches = static.get("yara_matches", [])
            for match in yara_matches:
                # Map severity to allowed values
                severity_map = {
                    "low": "info",
                    "medium": "warning", 
                    "high": "critical",
                    "critical": "critical"
                }
                severity = severity_map.get(match.get("severity", "medium").lower(), "warning")
                
                timeline_events.append(TimelineEvent(
                    timestamp=datetime.utcnow().isoformat(),
                    event_type="static",
                    description=f"YARA rule matched: {match.get('rule_name', 'unknown')}",
                    severity=severity,
                    evidence=[match.get("description", "")]
                ))
        
        # Dynamic analysis events
        if dynamic:
            # Process tree
            process_tree = dynamic.get("process_tree", [])
            for process in process_tree:
                timeline_events.append(TimelineEvent(
                    timestamp=datetime.utcnow().isoformat(),
                    event_type="process",
                    description=f"Process spawned: {process.get('name', 'unknown')}",
                    severity="warning",
                    evidence=[f"PID: {process.get('pid', 'unknown')}"]
                ))
            
            # Network connections
            network_connections = dynamic.get("network_connections", [])
            for conn in network_connections:
                severity = "critical" if conn.get("flagged_c2") else "warning"
                timeline_events.append(TimelineEvent(
                    timestamp=datetime.utcnow().isoformat(),
                    event_type="network",
                    description=f"Network connection to {conn.get('dest_ip', 'unknown')}:{conn.get('dest_port', 'unknown')}",
                    severity=severity,
                    evidence=[f"Protocol: {conn.get('protocol', 'unknown')}"]
                ))
            
            # File operations
            files_written = dynamic.get("files_written", [])
            for file_path in files_written:
                timeline_events.append(TimelineEvent(
                    timestamp=datetime.utcnow().isoformat(),
                    event_type="file",
                    description=f"File written: {file_path}",
                    severity="warning",
                    evidence=["File system modification detected"]
                ))
            
            # Registry changes
            registry_changes = dynamic.get("registry_changes", [])
            for reg_key in registry_changes:
                timeline_events.append(TimelineEvent(
                    timestamp=datetime.utcnow().isoformat(),
                    event_type="registry",
                    description=f"Registry modified: {reg_key}",
                    severity="warning",
                    evidence=["Persistence mechanism detected"]
                ))
        
        # Sort by timestamp (for now, they're all current, but this structure allows future timestamps)
        timeline_events.sort(key=lambda x: x.timestamp)
        
        print(f"[InvestigationEngine] Generated {len(timeline_events)} timeline events")
        return {**state, "timeline_events": timeline_events}
    
    def _explain_malware(self, state: InvestigationState) -> InvestigationState:
        """Generate AI-powered explanation of what the malware does."""
        print("[InvestigationEngine] Explaining malware behavior...")
        
        static = state.get("static_output", {})
        dynamic = state.get("dynamic_output", {})
        capabilities = state.get("capability_tags", [])
        mitre = state.get("mitre_techniques", [])
        
        # Extract capabilities
        capability_list = [cap.get("capability", "unknown") for cap in capabilities]
        
        # Build context for AI
        context = {
            "platform": static.get("platform", "unknown"),
            "file_type": static.get("file_type", "unknown"),
            "capabilities": capability_list,
            "mitre_techniques": [t.get("technique_id", "unknown") for t in mitre],
            "yara_matches": len(static.get("yara_matches", [])),
            "network_connections": len(dynamic.get("network_connections", [])) if dynamic else 0,
        }
        
        # Try to use AI if available
        if self.groq_api_key:
            try:
                from groq import Groq
                client = Groq(api_key=self.groq_api_key)
                
                prompt = f"""
                Analyze this malware and explain what it does in plain language:
                
                Platform: {context['platform']}
                File Type: {context['file_type']}
                Capabilities: {', '.join(context['capabilities'])}
                MITRE Techniques: {', '.join(context['mitre_techniques'])}
                YARA Matches: {context['yara_matches']}
                Network Connections: {context['network_connections']}
                
                Provide:
                1. A 2-3 sentence summary
                2. Technical details (how it works)
                3. List of capabilities identified
                """
                
                preferred_model = os.environ.get("GROQ_MODEL", "openai/gpt-oss-120b")
                candidate_models = [preferred_model, "qwen/qwen3.8-27b", "llama-3.3-70b-versatile", "openai/gpt-oss-20b"]
                response = None
                for model_name in candidate_models:
                    if not model_name:
                        continue
                    try:
                        response = client.chat.completions.create(
                            model=model_name,
                            messages=[
                                {"role": "system", "content": "You are a malware analyst explaining findings to investigators."},
                                {"role": "user", "content": prompt}
                            ],
                            temperature=0.3,
                            max_tokens=500,
                            timeout=15,
                        )
                        break
                    except Exception as model_err:
                        if "model_not_found" in str(model_err) or "does not exist" in str(model_err):
                            continue
                        raise model_err

                if not response:
                    raise RuntimeError("No compatible Groq model found")

                ai_response = response.choices[0].message.content.strip()
                
                # Parse AI response (simplified - in production, use structured output)
                malware_explanation = MalwareExplanation(
                    summary=ai_response[:200] + "..." if len(ai_response) > 200 else ai_response,
                    technical_details=ai_response,
                    capabilities_identified=capability_list,
                    confidence_level=0.8
                )
                
            except Exception as e:
                print(f"[InvestigationEngine] AI explanation failed: {e}, using fallback")
                malware_explanation = self._fallback_malware_explanation(context, capability_list)
        else:
            malware_explanation = self._fallback_malware_explanation(context, capability_list)
        
        print(f"[InvestigationEngine] Malware explanation generated with {len(malware_explanation.capabilities_identified)} capabilities")
        return {**state, "malware_explanation": malware_explanation}
    
    def _fallback_malware_explanation(self, context: Dict, capabilities: List[str]) -> MalwareExplanation:
        """Fallback malware explanation when AI is not available."""
        cap_text = ", ".join(capabilities) if capabilities else "no specific capabilities"
        
        return MalwareExplanation(
            summary=f"This {context['platform']} {context['file_type']} sample exhibits {cap_text}.",
            technical_details=f"Static analysis identified {context['yara_matches']} YARA rule matches. Dynamic analysis captured {context['network_connections']} network connections. MITRE ATT&CK techniques: {', '.join(context['mitre_techniques'])}.",
            capabilities_identified=capabilities,
            confidence_level=0.7
        )
    
    def _explain_victim_impact(self, state: InvestigationState) -> InvestigationState:
        """Analyze and explain the impact on the victim."""
        print("[InvestigationEngine] Analyzing victim impact...")
        
        static = state.get("static_output", {})
        dynamic = state.get("dynamic_output", {})
        capabilities = state.get("capability_tags", [])
        
        data_accessed = []
        privacy_risks = []
        financial_risks = []
        device_integrity = []
        
        # Analyze capabilities
        for cap in capabilities:
            cap_name = cap.get("capability", "")
            
            if "sms" in cap_name.lower() or "otp" in cap_name.lower():
                data_accessed.append("SMS messages and OTP codes")
                privacy_risks.append("Two-factor authentication bypass")
                financial_risks.append("Unauthorized bank transactions")
            
            if "gps" in cap_name.lower() or "location" in cap_name.lower():
                data_accessed.append("GPS location data")
                privacy_risks.append("Physical location tracking")
            
            if "contact" in cap_name.lower():
                data_accessed.append("Contact list")
                privacy_risks.append("Contact information exposure")
            
            if "camera" in cap_name.lower() or "microphone" in cap_name.lower():
                data_accessed.append("Camera and/or microphone access")
                privacy_risks.append("Audio/video surveillance")
            
            if "keylog" in cap_name.lower():
                data_accessed.append("Keystrokes and passwords")
                financial_risks.append("Credential theft")
                privacy_risks.append("Account compromise")
            
            if "persistence" in cap_name.lower():
                device_integrity.append("Malware maintains persistence")
                device_integrity.append("System compromise")
        
        # Analyze network connections
        if dynamic:
            network_connections = dynamic.get("network_connections", [])
            for conn in network_connections:
                if conn.get("flagged_c2"):
                    device_integrity.append("Command & control communication detected")
                    privacy_risks.append("Remote control capability")
        
        # Determine overall impact aligned with risk score and actual compromise
        high_risk_count = sum([
            len(financial_risks),
            len([r for r in privacy_risks if "surveillance" in r.lower() or "tracking" in r.lower()])
        ])
        
        risk_score = state.get("risk_score") or (static.get("risk_score", 0) if isinstance(static, dict) else 0)
        has_c2 = any("command & control" in d.lower() or "c2" in d.lower() for d in device_integrity)
        has_compromise = any("system compromise" in d.lower() or "persistence" in d.lower() for d in device_integrity)

        if risk_score >= 80 or (has_c2 and has_compromise) or high_risk_count >= 3:
            overall_impact = "critical"
        elif risk_score >= 60 or has_c2 or high_risk_count >= 2:
            overall_impact = "high"
        elif risk_score >= 30 or high_risk_count >= 1 or has_compromise:
            overall_impact = "medium"
        else:
            overall_impact = "low"
        
        explanation = f"The malware poses a {overall_impact} risk to the victim. "
        if financial_risks:
            explanation += f"Financial risks include: {', '.join(financial_risks)}. "
        if privacy_risks:
            explanation += f"Privacy risks include: {', '.join(privacy_risks)}. "
        if device_integrity:
            explanation += f"Device integrity concerns: {', '.join(device_integrity)}."
        
        victim_impact = VictimImpact(
            data_accessed=data_accessed,
            privacy_risks=privacy_risks,
            financial_risks=financial_risks,
            device_integrity=device_integrity,
            overall_impact=overall_impact,
            explanation=explanation
        )
        
        print(f"[InvestigationEngine] Victim impact assessed as {overall_impact}")
        return {**state, "victim_impact": victim_impact}
    
    def _explain_exfiltration(self, state: InvestigationState) -> InvestigationState:
        """Analyze data exfiltration patterns."""
        print("[InvestigationEngine] Analyzing exfiltration patterns...")
        
        static = state.get("static_output", {})
        dynamic = state.get("dynamic_output", {})
        
        data_types = []
        destinations = []
        timing_patterns = "Unknown"
        encryption_status = "Unknown"
        estimated_volume = "Unknown"
        risk_assessment = "Low"
        
        # Analyze extracted strings for data types
        extracted_strings = static.get("extracted_strings", {})
        if extracted_strings.get("urls"):
            data_types.append("URLs and links")
        if extracted_strings.get("ips"):
            data_types.append("IP addresses")
        
        # Analyze capabilities
        capabilities = state.get("capability_tags", [])
        for cap in capabilities:
            cap_name = cap.get("capability", "")
            if "sms" in cap_name.lower():
                data_types.append("SMS messages")
            if "contact" in cap_name.lower():
                data_types.append("Contact information")
            if "gps" in cap_name.lower():
                data_types.append("Location data")
            if "keylog" in cap_name.lower():
                data_types.append("Keystrokes/credentials")
        
        # Analyze network connections
        if dynamic:
            network_connections = dynamic.get("network_connections", [])
            for conn in network_connections:
                dest_ip = conn.get("dest_ip", "")
                if dest_ip:
                    destinations.append(f"{dest_ip}:{conn.get('dest_port', 'unknown')}")
                
                if conn.get("flagged_c2"):
                    risk_assessment = "Critical"
                elif risk_assessment == "Low":
                    risk_assessment = "Medium"
                
                # Check for timing patterns
                interval = conn.get("interval_seconds")
                if interval:
                    timing_patterns = f"Periodic every {interval} seconds"
        
        # Estimate volume based on data types
        if len(data_types) > 3:
            estimated_volume = "High (multiple data types)"
        elif len(data_types) > 1:
            estimated_volume = "Medium"
        elif data_types:
            estimated_volume = "Low"
        
        # Check encryption indicators
        if dynamic:
            api_calls = dynamic.get("api_calls", [])
            crypto_apis = [api for api in api_calls if "crypt" in api.lower() or "encrypt" in api.lower()]
            if crypto_apis:
                encryption_status = "Likely encrypted"
        
        exfiltration_analysis = ExfiltrationAnalysis(
            data_types=data_types,
            destinations=destinations,
            timing_patterns=timing_patterns,
            encryption_status=encryption_status,
            estimated_volume=estimated_volume,
            risk_assessment=risk_assessment
        )
        
        print(f"[InvestigationEngine] Exfiltration analysis complete: {risk_assessment} risk")
        return {**state, "exfiltration_analysis": exfiltration_analysis}
    
    def _generate_recommendations(self, state: InvestigationState) -> InvestigationState:
        """Generate actionable recommendations for investigators."""
        print("[InvestigationEngine] Generating recommendations...")
        
        static = state.get("static_output", {})
        dynamic = state.get("dynamic_output", {})
        capabilities = state.get("capability_tags", [])
        victim_impact = state.get("victim_impact")
        exfiltration = state.get("exfiltration_analysis")
        
        recommendations: List[Recommendation] = []
        
        # Immediate containment recommendations
        if victim_impact and victim_impact.overall_impact in ["high", "critical"]:
            recommendations.append(Recommendation(
                priority="immediate",
                category="containment",
                action="Isolate the affected device from the network",
                rationale="High-risk malware detected with potential for data exfiltration"
            ))
            
            recommendations.append(Recommendation(
                priority="immediate",
                category="victim",
                action="Advise victim to change all passwords from a clean device",
                rationale="Credential theft capability detected"
            ))
        
        # Evidence collection recommendations
        if dynamic and dynamic.get("network_connections"):
            recommendations.append(Recommendation(
                priority="high",
                category="evidence",
                action="Capture network traffic logs for forensic analysis",
                rationale="Network connections detected - traffic may contain exfiltrated data"
            ))
        
        if static and static.get("file_type") == "apk":
            recommendations.append(Recommendation(
                priority="high",
                category="evidence",
                action="Extract and analyze APK manifest and DEX files",
                rationale="Android package requires deep static analysis for full understanding"
            ))
        
        # Investigation recommendations
        for cap in capabilities:
            cap_name = cap.get("capability", "")
            
            if "sms" in cap_name.lower() or "otp" in cap_name.lower():
                recommendations.append(Recommendation(
                    priority="high",
                    category="investigation",
                    action="Review victim's SMS logs for unauthorized messages",
                    rationale="SMS theft capability detected"
                ))
            
            if "gps" in cap_name.lower() or "location" in cap_name.lower():
                recommendations.append(Recommendation(
                    priority="medium",
                    category="investigation",
                    action="Obtain location history from service providers",
                    rationale="GPS tracking capability detected"
                ))
        
        # Financial recommendations
        if victim_impact and victim_impact.financial_risks:
            recommendations.append(Recommendation(
                priority="high",
                category="victim",
                action="Advise victim to contact banks and enable transaction monitoring",
                rationale="Financial risks identified: " + ", ".join(victim_impact.financial_risks)
            ))
        
        # Exfiltration-specific recommendations
        if exfiltration and exfiltration.destinations:
            recommendations.append(Recommendation(
                priority="high",
                category="investigation",
                action="Investigate identified exfiltration destinations",
                rationale=f"Data being sent to {len(exfiltration.destinations)} destination(s)"
            ))
        
        # Device integrity recommendations
        if victim_impact and victim_impact.device_integrity:
            recommendations.append(Recommendation(
                priority="medium",
                category="containment",
                action="Perform full device factory reset after evidence collection",
                rationale="System compromise detected - full cleanup required"
            ))
        
        # Sort by priority
        priority_order = {"immediate": 0, "high": 1, "medium": 2, "low": 3}
        recommendations.sort(key=lambda r: priority_order.get(r.priority, 99))
        
        print(f"[InvestigationEngine] Generated {len(recommendations)} recommendations")
        return {**state, "recommendations": recommendations}
    
    def _generate_summary(self, state: InvestigationState) -> InvestigationState:
        """Generate final investigation summary."""
        print("[InvestigationEngine] Generating final summary...")
        
        sample_id = state.get("sample_id", "unknown")
        static = state.get("static_output", {})
        capabilities = state.get("capability_tags", [])
        risk_score = state.get("risk_score", 0)
        victim_impact = state.get("victim_impact")
        exfiltration = state.get("exfiltration_analysis")
        recommendations = state.get("recommendations", [])
        timeline_events = state.get("timeline_events", [])
        
        # Build executive summary
        platform = static.get("platform", "unknown")
        file_type = static.get("file_type", "unknown")
        capability_list = [c.get("capability", "unknown") for c in capabilities]
        
        executive_summary = (
            f"This investigation analyzed a {platform} {file_type} sample (ID: {sample_id}). "
            f"The sample exhibits {len(capability_list)} malicious capabilities: {', '.join(capability_list)}. "
        )
        
        if victim_impact:
            executive_summary += f"Victim impact is assessed as {victim_impact.overall_impact}. "
        
        if risk_score:
            executive_summary += f"Overall risk score: {risk_score}/100."
        
        # Build key findings
        key_findings = []
        
        if len(capability_list) > 0:
            key_findings.append(f"Malware capabilities: {', '.join(capability_list)}")
        
        if victim_impact and victim_impact.data_accessed:
            key_findings.append(f"Data accessed: {', '.join(victim_impact.data_accessed)}")
        
        if exfiltration and exfiltration.destinations:
            key_findings.append(f"Exfiltration destinations: {', '.join(exfiltration.destinations)}")
        
        if timeline_events:
            critical_events = [e for e in timeline_events if e.severity == "critical"]
            if critical_events:
                key_findings.append(f"{len(critical_events)} critical events detected")
        
        # Build timeline summary
        timeline_summary = f"Analysis captured {len(timeline_events)} events across "
        event_types = list(set(e.event_type for e in timeline_events))
        timeline_summary += ", ".join(event_types)
        
        # Build risk assessment
        if risk_score >= 70:
            risk_assessment = "Critical - immediate action required"
        elif risk_score >= 50:
            risk_assessment = "High - urgent investigation recommended"
        elif risk_score >= 30:
            risk_assessment = "Medium - further investigation needed"
        else:
            risk_assessment = "Low - monitor and investigate"
        
        # Build next steps
        next_steps = []
        high_priority_recs = [r for r in recommendations if r.priority in ["immediate", "high"]]
        for rec in high_priority_recs[:5]:  # Top 5 high-priority recommendations
            next_steps.append(rec.action)
        
        if not next_steps:
            next_steps.append("Continue monitoring and analysis")
        
        investigation_summary = InvestigationSummary(
            executive_summary=executive_summary,
            key_findings=key_findings,
            timeline_summary=timeline_summary,
            risk_assessment=risk_assessment,
            next_steps=next_steps
        )
        
        print(f"[InvestigationEngine] Investigation summary generated")
        return {**state, "investigation_summary": investigation_summary}
    
    def verify_chain_integrity(
        self,
        investigation_state: InvestigationState,
        chain: Optional[List[ChainLink]] = None
    ) -> Tuple[VerificationResult, Optional[List[ChainLink]]]:
        """
        Verify the integrity of the investigation chain.
        
        This method ensures that:
        1. All analysis steps are cryptographically linked
        2. No data has been tampered with
        3. The chain of custody is unbroken
        4. All required analysis steps are present
        
        Args:
            investigation_state: Complete investigation state
            chain: Optional existing chain to verify. If None, creates new chain.
            
        Returns:
            Tuple of (VerificationResult, chain)
        """
        print("[InvestigationEngine] Verifying chain integrity...")
        
        result, verified_chain = self.chain_verifier.verify_integrity(
            investigation_state=investigation_state,
            chain=chain
        )
        
        print(f"[InvestigationEngine] Chain verification: {result.status.value}")
        print(f"[InvestigationEngine] Verified {result.verified_links}/{result.total_links} links")
        
        if result.is_valid:
            print("[InvestigationEngine] [OK] Chain integrity verified")
        else:
            print(f"[InvestigationEngine] [FAIL] Chain integrity check failed")
            for error in result.errors:
                print(f"[InvestigationEngine]   - {error}")
        
        return result, verified_chain
    
    def run_investigation_with_verification(
        self,
        state: InvestigationState,
        verify_chain: bool = True
    ) -> InvestigationState:
        """
        Run investigation with optional chain verification.
        
        Args:
            state: Investigation state
            verify_chain: Whether to verify chain integrity after investigation
            
        Returns:
            Investigation state with verification results
        """
        # Run investigation
        final_state = self.run_investigation(state)
        
        # Verify chain if requested
        if verify_chain:
            verification_result, chain = self.verify_chain_integrity(final_state)
            
            # Add verification results to state
            final_state["chain_verification"] = {
                "status": verification_result.status.value,
                "is_valid": verification_result.is_valid,
                "verified_links": verification_result.verified_links,
                "total_links": verification_result.total_links,
                "tampered_links": verification_result.tampered_links,
                "missing_links": verification_result.missing_links,
                "errors": verification_result.errors,
                "verified_at": verification_result.verified_at,
                "chain_export": self.chain_verifier.export_chain(chain) if chain else None
            }
        
        return final_state


def run_investigation_workflow(
    state: InvestigationState,
    verify_chain: bool = True,
    secret_key: Optional[str] = None
) -> InvestigationState:
    """
    Convenience function to run the investigation workflow with optional verification.
    
    Args:
        state: Investigation state
        verify_chain: Whether to verify chain integrity (default: True)
        secret_key: Optional secret key for chain verification
        
    Returns:
        Investigation state with optional verification results
    """
    engine = InvestigationEngine(secret_key=secret_key)
    if verify_chain:
        return engine.run_investigation_with_verification(state, verify_chain=True)
    return engine.run_investigation(state)
