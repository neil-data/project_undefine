"""
stage_report.py — Turns a PipelineResult into an investigator-readable report.

WHY A DEDICATED REPORT LAYER
----------------------------
The eight-stage pipeline produces something a single-shot sandbox cannot: a
*timeline of dormancy*. Knowing that a sample sat completely silent through
boot, idle, user interaction and network simulation — and only woke 22 minutes
into the extended run, after a reboot — is the finding. It is also the part a
non-technical officer can actually act on, because it explains why the device
looked clean when they first checked it.

This module writes for that reader. It leads with the activation timeline and
the evasion profile in plain language, then supplies the technical detail
underneath for the analyst who needs it.

Outputs:
    build_report()      -> structured dict (API / DB / narrative-agent input)
    render_markdown()   -> human-readable report body
    to_narrative_input()-> compact payload for the LLM narrative agent
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, List, Optional

from .stage_definitions import (
    STAGE_CONFIGS,
    STAGE_ORDER,
    EvasionClass,
    PipelineResult,
    StageId,
    StageResult,
    StageStatus,
)


# ============================================================================
# Plain-language vocabulary
# ============================================================================

# Written for an investigating officer, not an analyst. Each line has to
# survive being read aloud in a briefing.
EVASION_PLAIN_LANGUAGE: Dict[EvasionClass, Dict[str, str]] = {
    EvasionClass.TIME_DELAY: {
        "label": "Waits before acting",
        "explain": (
            "The program deliberately does nothing for a long period after it "
            "runs. This is designed to outlast automated security checks, which "
            "usually only watch for a few minutes. On a real device it would "
            "appear harmless at first and begin acting later."
        ),
    },
    EvasionClass.REBOOT_GATE: {
        "label": "Activates after restart",
        "explain": (
            "The program stays mostly inactive until the device is restarted, "
            "then begins its real activity. Anyone checking the device before a "
            "restart would likely see nothing wrong."
        ),
    },
    EvasionClass.INTERACTION_GATE: {
        "label": "Waits for the user",
        "explain": (
            "The program only becomes active once someone actually uses the "
            "device — moving the mouse, typing, or opening files. It stays "
            "hidden on an unattended machine, which is how it avoids automated "
            "scanning."
        ),
    },
    EvasionClass.NETWORK_GATE: {
        "label": "Waits for internet access",
        "explain": (
            "The program stays dormant until it can reach its controller over "
            "the internet. Disconnected from the network it looks inert; once "
            "connected it begins communicating."
        ),
    },
    EvasionClass.ENVIRONMENT_CHECK: {
        "label": "Checks if it is being watched",
        "explain": (
            "The program inspects its surroundings to work out whether it is "
            "running on a real person's device or inside a security testing "
            "environment, and changes its behavior accordingly."
        ),
    },
    EvasionClass.IN_MEMORY_ONLY: {
        "label": "Hides in memory",
        "explain": (
            "The harmful code is never written to the device's storage in a "
            "readable form — it is only assembled in memory while running. "
            "Ordinary file scans would not find it."
        ),
    },
}


SEVERITY_RANK = {"critical": 3, "warning": 2, "info": 1}


# ============================================================================
# Report construction
# ============================================================================

def build_report(result: PipelineResult) -> Dict[str, Any]:
    """Assemble the full structured report from a completed pipeline run."""
    return {
        "analysis_id": str(result.analysis_id),
        "platform": result.platform,
        "generated_at": datetime.utcnow().isoformat(),
        "execution": _execution_summary(result),
        "activation": _activation_summary(result),
        "evasion": _evasion_summary(result),
        "timeline": _stage_timeline(result),
        "findings": _findings_summary(result),
        "artifacts": _artifact_summary(result),
        "coverage": _coverage_summary(result),
        "plain_language_summary": _plain_language_summary(result),
    }


def _execution_summary(result: PipelineResult) -> Dict[str, Any]:
    ran = [r for r in result.stage_results if r.status == StageStatus.COMPLETED]
    skipped = [r for r in result.stage_results if r.status == StageStatus.SKIPPED]
    failed = [
        r for r in result.stage_results
        if r.status in (StageStatus.FAILED, StageStatus.TIMED_OUT)
    ]

    return {
        "started_at": result.started_at.isoformat(),
        "ended_at": result.ended_at.isoformat() if result.ended_at else None,
        "total_duration_sec": round(result.total_duration_sec, 1),
        "total_duration_human": _humanize(result.total_duration_sec),
        "completed": result.completed,
        "aborted": result.aborted,
        "abort_reason": result.abort_reason,
        "final_risk_score": result.final_risk_score,
        "stages_completed": len(ran),
        "stages_skipped": len(skipped),
        "stages_failed": len(failed),
        "total_events": sum(r.event_count for r in result.stage_results),
    }


def _activation_summary(result: PipelineResult) -> Dict[str, Any]:
    """
    The headline. When did this sample actually start doing something, and
    how long would it have stayed hidden from a shorter analysis?
    """
    activation = result.activation_stage

    if activation is None:
        return {
            "activated": False,
            "activation_stage": None,
            "headline": "No activity observed at any stage",
            "detail": (
                "The sample produced no meaningful behavior across the entire "
                "pipeline. This does not by itself establish that the file is "
                "safe — it may require conditions not reproduced here, such as "
                "specific regional settings, a particular target application, "
                "or a live controller that is currently offline."
            ),
            "time_to_activation_sec": None,
            "would_be_missed_by_short_analysis": False,
        }

    index = STAGE_ORDER.index(activation)
    cfg = STAGE_CONFIGS[activation]

    # Cumulative time before this stage began — how long a shorter run would
    # have had to survive to see anything.
    elapsed = 0.0
    for r in result.stage_results:
        if r.stage_id == activation:
            break
        elapsed += r.duration_sec

    # Anything that first stirs at or after the reboot stage would be invisible
    # to a conventional single-shot detonation.
    missed_by_short = index >= STAGE_ORDER.index(StageId.INTERNET_SIMULATION)

    dormant = result.dormant_stages
    dormant_before = [
        s for s in dormant if STAGE_ORDER.index(s) < index
    ]

    return {
        "activated": True,
        "activation_stage": activation.value,
        "activation_stage_name": cfg.display_name,
        "activation_stage_index": index + 1,
        "headline": f"First activity at Stage {index + 1} — {cfg.display_name}",
        "detail": (
            f"The sample remained silent through "
            f"{len(dormant_before)} earlier stage(s) and first showed "
            f"meaningful behavior during {cfg.display_name}, approximately "
            f"{_humanize(elapsed)} into the analysis."
        ),
        "time_to_activation_sec": round(elapsed, 1),
        "time_to_activation_human": _humanize(elapsed),
        "dormant_stages_before_activation": [s.value for s in dormant_before],
        "would_be_missed_by_short_analysis": missed_by_short,
        "short_analysis_note": (
            "A conventional sandbox run of 2-5 minutes would have terminated "
            "before this point and reported no malicious behavior."
            if missed_by_short
            else None
        ),
    }


def _evasion_summary(result: PipelineResult) -> Dict[str, Any]:
    profile = result.evasion_profile

    techniques = []
    for ev in profile:
        vocab = EVASION_PLAIN_LANGUAGE.get(ev, {})
        stage = next(
            (r.stage_id.value for r in result.stage_results if ev in r.evasion_defeated),
            None,
        )
        techniques.append(
            {
                "evasion_class": ev.value,
                "label": vocab.get("label", ev.value),
                "plain_language": vocab.get("explain", ""),
                "detected_at_stage": stage,
            }
        )

    return {
        "evasion_detected": bool(profile),
        "evasion_count": len(profile),
        "techniques": techniques,
        "sophistication": _sophistication(profile),
    }


def _sophistication(profile: List[EvasionClass]) -> str:
    """
    Rough sophistication banding. Stacking multiple independent gates is a
    deliberate engineering choice, not an accident — it signals a developer
    who expected to be analyzed.
    """
    n = len(profile)
    if n == 0:
        return "none"
    if n == 1:
        return "basic"
    if n <= 3:
        return "moderate"
    return "advanced"


def _stage_timeline(result: PipelineResult) -> List[Dict[str, Any]]:
    """Per-stage rows for the dashboard timeline widget and the report table."""
    rows = []
    cumulative = 0.0

    for r in result.stage_results:
        cfg = STAGE_CONFIGS[r.stage_id]
        rows.append(
            {
                "stage_index": STAGE_ORDER.index(r.stage_id) + 1,
                "stage_id": r.stage_id.value,
                "display_name": cfg.display_name,
                "status": r.status.value,
                "start_offset_sec": round(cumulative, 1),
                "duration_sec": round(r.duration_sec, 1),
                "duration_human": _humanize(r.duration_sec),
                "event_count": r.event_count,
                "event_counts_by_type": r.event_counts_by_type,
                "activity_detected": r.activity_detected,
                "risk_score_at_start": r.risk_score_at_start,
                "risk_score_at_end": r.risk_score_at_end,
                "risk_delta": r.risk_delta,
                "finding_count": len(r.findings),
                "critical_findings": len(
                    [f for f in r.findings if f.severity == "critical"]
                ),
                "evasion_defeated": [e.value for e in r.evasion_defeated],
                "skip_reason": r.skip_reason,
                "error": r.error,
            }
        )
        cumulative += r.duration_sec

    return rows


def _findings_summary(result: PipelineResult) -> Dict[str, Any]:
    findings = result.all_findings
    findings_sorted = sorted(
        findings,
        key=lambda f: (-SEVERITY_RANK.get(f.severity, 0), f.observed_at),
    )

    by_severity: Dict[str, int] = {}
    for f in findings:
        by_severity[f.severity] = by_severity.get(f.severity, 0) + 1

    mitre: List[str] = []
    for f in findings:
        for t in f.mitre_techniques:
            if t not in mitre:
                mitre.append(t)

    return {
        "total": len(findings),
        "by_severity": by_severity,
        "mitre_techniques": sorted(mitre),
        "items": [
            {
                "finding_id": str(f.finding_id),
                "stage_id": f.stage_id.value,
                "stage_name": STAGE_CONFIGS[f.stage_id].display_name,
                "title": f.title,
                "detail": f.detail,
                "severity": f.severity,
                "mitre_techniques": f.mitre_techniques,
                "observed_at": f.observed_at.isoformat(),
            }
            for f in findings_sorted
        ],
    }


def _artifact_summary(result: PipelineResult) -> Dict[str, Any]:
    artifacts = [a for r in result.stage_results for a in r.artifacts]
    by_type: Dict[str, int] = {}
    for a in artifacts:
        by_type[a.artifact_type] = by_type.get(a.artifact_type, 0) + 1

    return {
        "total": len(artifacts),
        "by_type": by_type,
        "items": [
            {
                "artifact_type": a.artifact_type,
                "path": a.path,
                "size_bytes": a.size_bytes,
                "sha256": a.sha256,
                "captured_at": a.captured_at.isoformat(),
            }
            for a in artifacts
        ],
    }


def _coverage_summary(result: PipelineResult) -> Dict[str, Any]:
    """
    State plainly which evasion classes this run did *not* test.

    A skipped stage is a blind spot, and a report that quietly omits it invites
    a false "clean" reading. If Stage 6 never ran, the report has to say that
    reboot-gated behavior was not tested.
    """
    tested: List[str] = []
    untested: List[Dict[str, str]] = []

    for stage_id in STAGE_ORDER:
        r = result.stage(stage_id)
        cfg = STAGE_CONFIGS[stage_id]
        classes = [e.value for e in cfg.defeats if e != EvasionClass.NONE]
        if not classes:
            continue

        if r and r.status == StageStatus.COMPLETED:
            tested.extend(c for c in classes if c not in tested)
        else:
            reason = (
                r.skip_reason or r.error if r else "Stage did not run"
            ) or "Stage did not run"
            for c in classes:
                untested.append(
                    {
                        "evasion_class": c,
                        "stage": stage_id.value,
                        "stage_name": cfg.display_name,
                        "reason": reason,
                    }
                )

    return {
        "tested_evasion_classes": tested,
        "untested_evasion_classes": untested,
        "complete_coverage": not untested,
        "caveat": (
            None
            if not untested
            else (
                "This analysis did not test every evasion class. Behavior gated "
                "on the untested conditions listed here would not have been "
                "observed, so an absence of findings in those areas is not "
                "evidence of absence."
            )
        ),
    }


def _plain_language_summary(result: PipelineResult) -> str:
    """
    The paragraph a non-technical investigator reads first.

    Deliberately avoids jargon, MITRE IDs and tool names. States what the
    program did, when it started, and what that means for the device.
    """
    activation = result.activation_stage

    if activation is None:
        return (
            "During extended testing across eight stages — including a restart "
            "and a prolonged run — this file did not show any harmful activity. "
            "That is not the same as confirming it is safe: some programs stay "
            "inactive unless very specific conditions are met. If there is other "
            "evidence pointing to this file, it should be examined further."
        )

    cfg = STAGE_CONFIGS[activation]
    index = STAGE_ORDER.index(activation)
    profile = result.evasion_profile

    parts: List[str] = []

    elapsed = sum(
        r.duration_sec
        for r in result.stage_results
        if STAGE_ORDER.index(r.stage_id) < index
    )

    if index == 0:
        parts.append(
            "This file began acting immediately when it was run. Its behavior "
            "was visible from the very start of testing."
        )
    else:
        parts.append(
            f"This file stayed completely quiet for roughly "
            f"{_humanize(elapsed)} after it was run, and only began acting "
            f"during the '{cfg.display_name.lower()}' stage of testing. "
            f"A device checked during that quiet period would have appeared "
            f"normal."
        )

    if profile:
        labels = [
            EVASION_PLAIN_LANGUAGE.get(e, {}).get("label", e.value) for e in profile
        ]
        if len(labels) == 1:
            parts.append(f"It uses one hiding technique: {labels[0].lower()}.")
        else:
            parts.append(
                "It uses several hiding techniques: "
                + ", ".join(l.lower() for l in labels[:-1])
                + f", and {labels[-1].lower()}."
            )
        parts.append(
            "Combining techniques like these is a deliberate choice by whoever "
            "built the program, intended to make it harder to detect."
        )

    criticals = [f for f in result.all_findings if f.severity == "critical"]
    if criticals:
        parts.append(
            f"Testing recorded {len(criticals)} serious finding"
            f"{'s' if len(criticals) != 1 else ''}, the most significant being: "
            f"{criticals[0].title.lower()}."
        )

    score = result.final_risk_score
    if score >= 86:
        parts.append(
            "Overall assessment: this file is confirmed harmful and should be "
            "treated as a live threat to any device it was found on."
        )
    elif score >= 61:
        parts.append(
            "Overall assessment: this file shows strongly suspicious behavior "
            "and warrants treating the affected device as compromised until "
            "reviewed."
        )
    elif score >= 31:
        parts.append(
            "Overall assessment: this file shows some suspicious behavior that "
            "needs review by an analyst before a conclusion is reached."
        )
    else:
        parts.append(
            "Overall assessment: limited suspicious behavior was recorded, "
            "though the hiding techniques noted above mean this should not be "
            "read as a clean result on its own."
        )

    return " ".join(parts)


# ============================================================================
# Rendering
# ============================================================================

def render_markdown(result: PipelineResult) -> str:
    """Render the report as Markdown for the dashboard and PDF export."""
    report = build_report(result)
    ex = report["execution"]
    act = report["activation"]
    ev = report["evasion"]
    cov = report["coverage"]

    lines: List[str] = []
    add = lines.append

    add("# Multi-Stage Dynamic Analysis Report")
    add("")
    add(f"**Analysis ID:** `{report['analysis_id']}`  ")
    add(f"**Platform:** {report['platform']}  ")
    add(f"**Duration:** {ex['total_duration_human']}  ")
    add(f"**Final risk score:** {ex['final_risk_score']}/100")
    add("")

    add("## Summary for Investigators")
    add("")
    add(report["plain_language_summary"])
    add("")

    add("## Activation")
    add("")
    add(f"**{act['headline']}**")
    add("")
    add(act["detail"])
    if act.get("short_analysis_note"):
        add("")
        add(f"> {act['short_analysis_note']}")
    add("")

    if ev["evasion_detected"]:
        add("## Evasion Techniques Observed")
        add("")
        add(f"Sophistication: **{ev['sophistication']}** "
            f"({ev['evasion_count']} technique(s))")
        add("")
        for t in ev["techniques"]:
            add(f"### {t['label']}")
            add("")
            add(t["plain_language"])
            if t["detected_at_stage"]:
                add("")
                add(f"*Detected during: {t['detected_at_stage']}*")
            add("")

    add("## Stage Timeline")
    add("")
    add("| # | Stage | Status | Duration | Events | Risk Δ | Findings |")
    add("|---|-------|--------|----------|--------|--------|----------|")
    for row in report["timeline"]:
        marker = " 🔺" if row["activity_detected"] else ""
        delta = f"{row['risk_delta']:+d}" if row["risk_delta"] else "—"
        add(
            f"| {row['stage_index']} | {row['display_name']}{marker} "
            f"| {row['status']} | {row['duration_human']} "
            f"| {row['event_count']} | {delta} | {row['finding_count']} |"
        )
    add("")
    add("🔺 = sample showed activity during this stage")
    add("")

    findings = report["findings"]
    if findings["total"]:
        add("## Findings")
        add("")
        by_sev = findings["by_severity"]
        add(
            "  ·  ".join(
                f"**{sev}:** {by_sev[sev]}"
                for sev in ("critical", "warning", "info")
                if sev in by_sev
            )
        )
        add("")
        for item in findings["items"]:
            icon = {"critical": "🔴", "warning": "🟠", "info": "🔵"}.get(
                item["severity"], "•"
            )
            add(f"### {icon} {item['title']}")
            add("")
            add(f"*Stage: {item['stage_name']}*")
            add("")
            add(item["detail"])
            if item["mitre_techniques"]:
                add("")
                add(f"**MITRE ATT&CK:** {', '.join(item['mitre_techniques'])}")
            add("")

    if findings["mitre_techniques"]:
        add("## MITRE ATT&CK Coverage")
        add("")
        add(", ".join(f"`{t}`" for t in findings["mitre_techniques"]))
        add("")

    arts = report["artifacts"]
    if arts["total"]:
        add("## Artifacts Collected")
        add("")
        for atype, count in sorted(arts["by_type"].items()):
            add(f"- **{atype}**: {count}")
        add("")

    if not cov["complete_coverage"]:
        add("## Coverage Limitations")
        add("")
        add(cov["caveat"])
        add("")
        for u in cov["untested_evasion_classes"]:
            add(f"- **{u['evasion_class']}** — not tested "
                f"({u['stage_name']}: {u['reason']})")
        add("")

    return "\n".join(lines)


def to_narrative_input(result: PipelineResult) -> Dict[str, Any]:
    """
    Compact payload for the LLM narrative agent.

    Deliberately trimmed: the narrative agent writes better prose from a small
    set of high-signal facts than from the full event dump.
    """
    report = build_report(result)
    return {
        "platform": result.platform,
        "duration_human": report["execution"]["total_duration_human"],
        "risk_score": result.final_risk_score,
        "activation_stage": report["activation"].get("activation_stage_name"),
        "time_to_activation": report["activation"].get("time_to_activation_human"),
        "dormant_stages": [s.value for s in result.dormant_stages],
        "evasion_techniques": [
            {"label": t["label"], "explanation": t["plain_language"]}
            for t in report["evasion"]["techniques"]
        ],
        "critical_findings": [
            {"title": f["title"], "detail": f["detail"]}
            for f in report["findings"]["items"]
            if f["severity"] == "critical"
        ][:10],
        "mitre_techniques": report["findings"]["mitre_techniques"],
        "coverage_caveat": report["coverage"]["caveat"],
    }


# ============================================================================
# Helpers
# ============================================================================

def _humanize(seconds: float) -> str:
    """Format a duration the way a person would say it."""
    seconds = int(seconds)
    if seconds < 60:
        return f"{seconds}s"
    if seconds < 3600:
        m, s = divmod(seconds, 60)
        return f"{m}m {s}s" if s else f"{m}m"
    h, rem = divmod(seconds, 3600)
    m = rem // 60
    return f"{h}h {m}m" if m else f"{h}h"
