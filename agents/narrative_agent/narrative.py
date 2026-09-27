"""
narrative.py — Real narrative agent, calling Groq for the
plain-language officer report.

Falls back to a template summary if GROQ_API_KEY isn't set, so the
graph never crashes just because a key is missing (useful during dev,
demos on a machine without the key, or if Groq is briefly down).
"""

from __future__ import annotations
import os
from typing import Optional

from agents.orchestrator.schema import (
    StaticAnalysisOutput,
    DynamicAnalysisOutput,
    MitreTechnique,
    CapabilityTag,
)

try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass  # python-dotenv not installed — fine, env vars can be set another way


SYSTEM_PROMPT = """You are a forensic analyst writing a summary for a police \
cyber-crime investigator who is NOT a technical expert. Given structured \
malware analysis findings, write a 3-5 sentence plain-language summary.

Rules:
- No jargon. Explain what the malware DOES to the victim, not how it does it technically.
- Mention the specific risk (e.g. "steals your OTP codes and can access your bank accounts")
- Mention where data is being sent, in plain terms (e.g. "sends this to a server abroad")
- End with one clear, actionable line for the investigator (e.g. what to check next)
- Do NOT use MITRE technique IDs or technical API names in the summary
- Keep it to 3-5 sentences, no bullet points, plain prose
"""


def _build_findings_text(
    static: StaticAnalysisOutput,
    dynamic: Optional[DynamicAnalysisOutput],
    mitre: list[MitreTechnique],
    capabilities: list[CapabilityTag],
    risk_score: int,
) -> str:
    lines = [
        f"Platform: {static.platform}",
        f"Package/file: {static.android_manifest.package_name if static.android_manifest else static.sha256[:16]}",
        f"Risk score: {risk_score}/100",
        f"Detected capabilities: {', '.join(c.capability for c in capabilities) or 'none confirmed'}",
    ]
    for cap in capabilities:
        lines.append(f"  - {cap.capability} (confidence {cap.confidence:.0%}): {'; '.join(cap.evidence)}")

    if dynamic and dynamic.network_connections:
        for conn in dynamic.network_connections:
            if conn.get("flagged_c2"):
                lines.append(
                    f"Network: contacts {conn['dest_ip']}:{conn['dest_port']} "
                    f"every ~{conn.get('interval_seconds', '?')}s (flagged as C2)"
                )

    lines.append(f"MITRE techniques matched: {', '.join(t.technique_id for t in mitre) or 'none'}")
    return "\n".join(lines)


def _fallback_summary(
    static: StaticAnalysisOutput,
    capabilities: list[CapabilityTag],
    risk_score: int,
) -> str:
    caps = [c.capability.replace("_", " ") for c in capabilities]
    cap_text = " and ".join(caps) if caps else "no confirmed malicious capability"
    return (
        f"[FALLBACK — GROQ_API_KEY not set] This sample shows signs of {cap_text}. "
        f"Risk score: {risk_score}/100. Set GROQ_API_KEY in .env for a real "
        f"plain-language narrative."
    )


def generate_narrative(
    static: StaticAnalysisOutput,
    dynamic: Optional[DynamicAnalysisOutput],
    mitre: list[MitreTechnique],
    capabilities: list[CapabilityTag],
    risk_score: int,
) -> str:
    api_key = os.environ.get("GROQ_API_KEY")

    if not api_key:
        return _fallback_summary(static, capabilities, risk_score)

    try:
        from groq import Groq
    except ImportError:
        return _fallback_summary(static, capabilities, risk_score) + " (groq package not installed)"

    findings = _build_findings_text(static, dynamic, mitre, capabilities, risk_score)

    try:
        client = Groq(api_key=api_key)
        preferred_model = os.environ.get("GROQ_MODEL", "openai/gpt-oss-120b")
        candidate_models = [preferred_model, "qwen/qwen3.8-27b", "llama-3.3-70b-versatile", "openai/gpt-oss-20b"]
        
        last_err = None
        for model_name in candidate_models:
            if not model_name:
                continue
            try:
                response = client.chat.completions.create(
                    model=model_name,
                    messages=[
                        {"role": "system", "content": SYSTEM_PROMPT},
                        {"role": "user", "content": f"Findings:\n{findings}\n\nWrite the summary now."},
                    ],
                    temperature=0.3,
                    max_tokens=300,
                    timeout=15,
                )
                return response.choices[0].message.content.strip()
            except Exception as ex:
                last_err = ex
                if "model_not_found" in str(ex) or "does not exist" in str(ex):
                    continue
                raise ex

        if last_err:
            raise last_err
        return _fallback_summary(static, capabilities, risk_score)
    except Exception as e:
        # Never let an LLM/network failure crash the whole pipeline —
        # degrade to the template summary and keep going.
        return _fallback_summary(static, capabilities, risk_score) + f" (Groq call failed: {e})"