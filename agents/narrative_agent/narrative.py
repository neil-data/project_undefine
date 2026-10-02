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


FORBIDDEN_UNGROUNDED_TERMS = (
    "systemd", "rc.local", "pkexec", "xor", "named pipe",
    "strace", "ltrace", "gdb", "cve-2022-0847", "cve-",
    "/usr/lib/.x11-auth", "@reboot", "/etc/shadow",
)


def _is_grounded(text: str, static: StaticAnalysisOutput, dynamic: Optional[DynamicAnalysisOutput]) -> bool:
    """Check if any forbidden specific technical term is mentioned without raw evidence."""
    import re
    lowered = text.lower()
    raw_evidence_corpus = []

    # Gather static evidence strings
    if static.extracted_strings:
        raw_evidence_corpus.extend(static.extracted_strings.suspicious_keywords)
        raw_evidence_corpus.extend(static.extracted_strings.urls)
        raw_evidence_corpus.extend(static.extracted_strings.ips)
    for ym in static.yara_matches:
        raw_evidence_corpus.append(ym.rule_name)
        if ym.description:
            raw_evidence_corpus.append(ym.description)

    # Gather dynamic evidence strings
    if dynamic:
        raw_evidence_corpus.extend(dynamic.api_calls)
        raw_evidence_corpus.extend(dynamic.persistence_artifacts)
        raw_evidence_corpus.extend(dynamic.registry_changes)
        raw_evidence_corpus.extend(dynamic.files_written)
        raw_evidence_corpus.append(str(dynamic.process_tree))

    raw_text = " ".join(raw_evidence_corpus).lower()

    for term in FORBIDDEN_UNGROUNDED_TERMS:
        if term in lowered and term not in raw_text:
            return False

    # Check for direct contradiction on outbound network connections
    has_dynamic_conns = dynamic and len(dynamic.network_connections) > 0
    if has_dynamic_conns:
        if any(phrase in lowered for phrase in ("no outbound network", "does not make outbound", "no network connections")):
            return False

    return True


def _clean_or_render_text(raw_text: str) -> str:
    """Clean model output, parsing JSON if present and ensuring clean table markdown."""
    import json
    text = raw_text.strip()
    if text.startswith("```json"):
        text = text[7:]
    if text.startswith("```"):
        text = text[3:]
    if text.endswith("```"):
        text = text[:-3]
    text = text.strip()

    try:
        parsed = json.loads(text)
        if isinstance(parsed, dict) and "executive_summary" in parsed:
            summary = parsed["executive_summary"].strip()
            steps = parsed.get("technical_steps") or []
            if steps and isinstance(steps, list):
                table_lines = ["\n\n| Step | Action | Evidence |", "|:---|:---|:---|"]
                for s in steps:
                    if isinstance(s, dict):
                        st = str(s.get("step", "")).replace("|", "/").strip()
                        act = str(s.get("action", "")).replace("|", "/").replace("\n", " ").strip()
                        ev = str(s.get("evidence", "")).replace("|", "/").replace("\n", " ").strip()
                        table_lines.append(f"| {st} | {act} | {ev} |")
                summary += "\n" + "\n".join(table_lines)
            return summary
    except Exception:
        pass

    # Ensure no raw literal <br> or broken table artifacts
    cleaned = raw_text.replace("<br>", " ").replace("<br/>", " ")
    return cleaned


def _fallback_summary(
    static: StaticAnalysisOutput,
    capabilities: list[CapabilityTag],
    risk_score: int,
    dynamic: Optional[DynamicAnalysisOutput] = None,
    victim_impact: Optional[str] = "medium",
) -> str:
    caps = [c.capability.replace("_", " ") for c in capabilities]
    cap_text = ", ".join(caps) if caps else "no confirmed malicious capability tags"
    v_imp = victim_impact or "medium"
    return (
        f"[FALLBACK] This {static.platform} {static.file_type} binary exhibits {cap_text}. "
        f"Verified risk score is {risk_score}/100 with {v_imp} victim impact based on verified forensic indicators. "
        f"Immediate containment and perimeter network monitoring are advised."
    )


def generate_narrative(
    static: StaticAnalysisOutput,
    dynamic: Optional[DynamicAnalysisOutput],
    mitre: list[MitreTechnique],
    capabilities: list[CapabilityTag],
    risk_score: int,
    victim_impact: Optional[str] = None,
    malware_bazaar: Optional[dict] = None,
) -> str:
    api_key = os.environ.get("GROQ_API_KEY")

    if not api_key:
        return _fallback_summary(static, capabilities, risk_score, dynamic, victim_impact)

    try:
        from groq import Groq
    except ImportError:
        return _fallback_summary(static, capabilities, risk_score, dynamic, victim_impact) + " (groq package not installed)"

    findings = _build_findings_text(static, dynamic, mitre, capabilities, risk_score)
    if victim_impact:
        findings += f"\nAssessed victim impact: {victim_impact}"
    if malware_bazaar and malware_bazaar.get("signature"):
        findings += f"\nMalwareBazaar intelligence: Confirmed {malware_bazaar.get('signature')} family"

    try:
        client = Groq(api_key=api_key)
        preferred_model = os.environ.get("GROQ_MODEL", "openai/gpt-oss-120b")
        candidate_models = [preferred_model, "qwen/qwen3.8-27b", "llama-3.3-70b-versatile", "openai/gpt-oss-20b"]

        system_instruction = (
            SYSTEM_PROMPT +
            f"\nStrict Constraints:\n"
            f"- The verified risk score is {risk_score}/100. Do NOT contradict or alter this score.\n"
            f"- The determined victim impact is '{victim_impact or 'medium'}'. State this impact accurately and do NOT state a different impact level.\n"
            f"- If network connections or C2 are listed in findings, state them accurately; do NOT claim the file makes no outbound connections.\n"
            f"- If no network connections are observed, do NOT invent any.\n"
            f"- ONLY state technical mechanisms (cron, shell, files) if explicitly listed in the findings.\n"
            f"- Forbidden ungrounded terms: do NOT mention systemd, rc.local, pkexec, xor, named pipe, strace, ltrace, gdb, CVE-2022-0847, /usr/lib/.X11-auth, @reboot, /etc/shadow unless in findings.\n"
            f"- Optional JSON output format: {{\"executive_summary\": \"...\", \"technical_steps\": [{{\"step\": \"1\", \"action\": \"...\", \"evidence\": \"...\"}}]}}\n"
        )

        last_err = None
        for model_name in candidate_models:
            if not model_name:
                continue
            try:
                # Attempt 1
                response = client.chat.completions.create(
                    model=model_name,
                    messages=[
                        {"role": "system", "content": system_instruction},
                        {"role": "user", "content": f"Findings:\n{findings}\n\nWrite the summary now."},
                    ],
                    temperature=0.2,
                    max_tokens=400,
                    timeout=15,
                )
                text = response.choices[0].message.content.strip()

                # Validate against hallucinated ungrounded terms
                if _is_grounded(text, static, dynamic):
                    return _clean_or_render_text(text)

                # Attempt 2: Retry with explicit grounding correction
                correction_prompt = (
                    f"Findings:\n{findings}\n\n"
                    f"Correction: Your previous summary contained technical mechanisms or contradictions not present in the findings. "
                    f"You must strictly ground your summary ONLY in the evidence provided above. "
                    f"Risk score is {risk_score}/100, victim impact is {victim_impact or 'medium'}. "
                    f"Do not mention systemd, rc.local, pkexec, xor, named pipes, strace, ltrace, gdb, CVE-2022-0847, or /usr/lib/.X11-auth. "
                    f"Write the corrected summary now."
                )
                retry_resp = client.chat.completions.create(
                    model=model_name,
                    messages=[
                        {"role": "system", "content": system_instruction},
                        {"role": "user", "content": correction_prompt},
                    ],
                    temperature=0.1,
                    max_tokens=400,
                    timeout=15,
                )
                retry_text = retry_resp.choices[0].message.content.strip()
                if _is_grounded(retry_text, static, dynamic):
                    return _clean_or_render_text(retry_text)

                # Ungrounded after retry -> use deterministic template fallback
                return _fallback_summary(static, capabilities, risk_score, dynamic, victim_impact)

            except Exception as ex:
                last_err = ex
                if "model_not_found" in str(ex) or "does not exist" in str(ex):
                    continue
                raise ex

        if last_err:
            raise last_err
        return _fallback_summary(static, capabilities, risk_score, dynamic, victim_impact)
    except Exception as e:
        return _fallback_summary(static, capabilities, risk_score, dynamic, victim_impact) + f" (Groq call failed: {e})"
