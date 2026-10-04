"""
orchestrator.py — LangGraph agent orchestrator (Week 2 — completed).

Graph flow:

    load_static_analysis
            |
            v
    load_dynamic_analysis   (mock for now — real Week 3 swap point)
            |
            v
    mitre_mapper             (real rule engine — mitre_rules.py)
            |
            v
    capability_classifier    (real rule engine — capability_rules.py)
            |
            v
    compute_risk_score       (weighted, uses static + dynamic signals)
            |
            v
    narrative_agent          (real Groq call, graceful fallback — narrative.py)
            |
            v
          END

SWAP POINTS FOR WEEK 3 (clearly marked below with "WEEK 3 SWAP"):
  1. load_static_analysis  -> replace mock file read with Member 1's real service/DB call
  2. load_dynamic_analysis -> replace mock file read with Member 2's real CAPE/sandbox output

Everything downstream of those two loaders (mapping, classification,
scoring, narrative) already runs on real logic and does NOT need to
change when the swap happens — that was the whole point of building
against a locked mock schema in Week 2.

Run directly:
    python orchestrator.py
"""

import json
import sys
from pathlib import Path

# Ensure repo root is on sys.path when script is executed directly
_repo_root = str(Path(__file__).resolve().parents[2])
if _repo_root not in sys.path:
    sys.path.insert(0, _repo_root)

from langgraph.graph import StateGraph, END

from agents.orchestrator.schema import (
    OrchestratorState,
    StaticAnalysisOutput,
    DynamicAnalysisOutput,
)
from agents.mitre_mapper.mitre_rules import map_to_mitre
from agents.capability_classifier.capability_rules import classify_capabilities
from agents.narrative_agent.narrative import generate_narrative
from agents.orchestrator.risk_scoring import compute_risk_score as _compute_risk_score, _is_generic_yara_rule
from agents.investigation_engine.investigation_engine import run_investigation_workflow


MOCK_DATA_DIR = Path(__file__).parent / "mock_data"


# ---------------------------------------------------------------------
# Node implementations
# ---------------------------------------------------------------------

def load_static_analysis(state: OrchestratorState) -> OrchestratorState:
    """
    WEEK 3 SWAP: replace this mock file read with a real fetch from
    Member 1's static-analysis service/DB, keyed by sample_id. Nothing
    else in the graph needs to change as long as the returned shape
    still validates against schema.StaticAnalysisOutput.

    If static_output is already present in the incoming state (e.g.
    injected by the backend API from a real request), skip the mock
    file read entirely and use that instead — this is what lets
    backend/app/routers/cases.py drive the graph with real submitted
    data instead of only the hardcoded demo sample.
    """
    if state.get("static_output") is not None:
        static_output = state["static_output"]
        print(f"[load_static_analysis] Using injected static data for {static_output.sample_id} "
              f"({static_output.platform})")
        return {**state, "sample_id": static_output.sample_id}

    with open(MOCK_DATA_DIR / "static_analysis_sample.json") as f:
        raw = json.load(f)
    raw.pop("_comment", None)

    static_output = StaticAnalysisOutput.model_validate(raw)

    print(f"[load_static_analysis] Loaded sample {static_output.sample_id} "
          f"({static_output.platform})")

    return {
        **state,
        "sample_id": static_output.sample_id,
        "static_output": static_output,
    }


def load_dynamic_analysis(state: OrchestratorState) -> OrchestratorState:
    """
    WEEK 3 SWAP: replace this mock file read with a real fetch from
    Member 2's CAPE/sandbox output once the GCP detonation plane is
    live. Until then, the graph runs fully against this mock so every
    downstream node (MITRE mapping, capability classification, risk
    score, narrative) can be built and tested now.

    Same injection pattern as load_static_analysis above — if
    dynamic_output key already exists in state (even if None, meaning
    "explicitly no dynamic data yet"), that's respected instead of
    falling back to the mock file.
    """
    if "dynamic_output" in state:
        dynamic_output = state["dynamic_output"]
        if dynamic_output is not None:
            print(f"[load_dynamic_analysis] Using injected dynamic data for {dynamic_output.sample_id}")
        else:
            print("[load_dynamic_analysis] Explicitly no dynamic data provided — continuing static-only")
        return state

    dynamic_path = MOCK_DATA_DIR / "dynamic_analysis_sample.json"

    if not dynamic_path.exists():
        print("[load_dynamic_analysis] No dynamic data available — continuing static-only")
        return {**state, "dynamic_output": None}

    with open(dynamic_path) as f:
        raw = json.load(f)
    raw.pop("_comment", None)

    dynamic_output = DynamicAnalysisOutput.model_validate(raw)

    print(f"[load_dynamic_analysis] Loaded dynamic data for {dynamic_output.sample_id} "
          f"({len(dynamic_output.api_calls)} API calls, "
          f"{len(dynamic_output.network_connections)} network connection(s))")

    return {**state, "dynamic_output": dynamic_output}


def mitre_mapper(state: OrchestratorState) -> OrchestratorState:
    """Real rule-based MITRE ATT&CK mapping — see mitre_rules.py."""
    techniques = map_to_mitre(state["static_output"], state.get("dynamic_output"))
    print(f"[mitre_mapper] Mapped {len(techniques)} technique(s): "
          f"{[t.technique_id for t in techniques]}")
    return {**state, "mitre_techniques": techniques}


def capability_classifier(state: OrchestratorState) -> OrchestratorState:
    """Real rule-based capability classification — see capability_rules.py."""
    tags = classify_capabilities(state["static_output"], state.get("dynamic_output"))
    print(f"[capability_classifier] Tagged {len(tags)} capability/ies: "
          f"{[t.capability for t in tags]}")
    return {**state, "capability_tags": tags}


def compute_risk_score(state: OrchestratorState) -> OrchestratorState:
    """Delegates to risk_scoring.py — see that module for the weighting logic."""
    score = _compute_risk_score(
        static=state["static_output"],
        dynamic=state.get("dynamic_output"),
        mitre=state.get("mitre_techniques", []),
        capabilities=state.get("capability_tags", []),
    )
    # Apply intel floor if provided or from MalwareBazaar
    intel_floor = state.get("intel_floor")
    mb = state.get("malware_bazaar")
    if intel_floor:
        score = max(score, intel_floor)
    elif mb and mb.get("signature"):
        score = max(score, 85)

    # CRITICAL is reserved for corroborated intelligence, observed malicious
    # behavior, or an explicit malware-family YARA match.
    static = state["static_output"]
    dynamic = state.get("dynamic_output")
    family_names = ("mirai", "gafgyt", "mozi", "tsunami", "qbot", "hajime", "bashlite", "dofloo", "xorddos", "chamelgang")
    family_hit = any(
        any(family in (getattr(hit, "rule_name", "") or "").lower() for family in family_names)
        and not _is_generic_yara_rule(getattr(hit, "rule_name", "") or "", getattr(hit, "category", "") or "")
        for hit in getattr(static, "yara_matches", [])
    )
    intel_hit = bool(intel_floor or (mb and mb.get("found") and mb.get("signature")))
    observed_hit = bool(dynamic and any((
        getattr(dynamic, "network_connections", []), getattr(dynamic, "files_written", []),
        getattr(dynamic, "persistence_artifacts", []), getattr(dynamic, "process_tree", []),
        getattr(dynamic, "api_calls", []),
    )))
    if score >= 85 and not (intel_hit or observed_hit or family_hit):
        score = 84

    # Compute victim impact deterministically: 'critical' only with OBSERVED malicious behavior or intel floor; else max 'high'.
    is_real = getattr(dynamic, "execution_mode", "real") == "real" if dynamic else False
    has_intel_floor = bool(intel_floor or (mb and mb.get("signature")))
    has_observed_malicious = False

    if dynamic and is_real:
        has_c2_observed = any(bool(c.get("flagged_c2")) for c in getattr(dynamic, "network_connections", []))
        has_compromise_observed = any(
            "system compromise" in str(p).lower() or "persistence" in str(p).lower()
            for p in getattr(dynamic, "persistence_artifacts", [])
        )
        has_download_exec = any(
            any(t in str(c).lower() for t in ("curl", "wget", "/bin/sh", "exec"))
            for c in getattr(dynamic, "api_calls", []) + [str(p) for p in getattr(dynamic, "process_tree", [])]
        )
        has_files_written = any(
            str(f).startswith("/etc/") or str(f).startswith("/dev/shm/") or "/." in str(f)
            for f in getattr(dynamic, "files_written", [])
        )
        if has_c2_observed or has_compromise_observed or has_download_exec or has_files_written:
            has_observed_malicious = True

    if not is_real:
        if score >= 70:
            victim_impact = "high"
        elif score >= 40:
            victim_impact = "medium"
        else:
            victim_impact = "low"
    else:
        if score >= 85 and (has_observed_malicious or has_intel_floor):
            victim_impact = "critical"
        elif score >= 70:
            victim_impact = "high"
        elif score >= 40:
            victim_impact = "medium"
        else:
            victim_impact = "low"

    print(f"[compute_risk_score] Unified risk score: {score}/100, victim_impact: {victim_impact}")
    return {**state, "risk_score": score, "victim_impact": victim_impact}


def narrative_agent(state: OrchestratorState) -> OrchestratorState:
    """Real narrative generation via Groq, with graceful template fallback."""
    summary = generate_narrative(
        static=state["static_output"],
        dynamic=state.get("dynamic_output"),
        mitre=state.get("mitre_techniques", []),
        capabilities=state.get("capability_tags", []),
        risk_score=state.get("risk_score", 0),
        victim_impact=state.get("victim_impact"),
        malware_bazaar=state.get("malware_bazaar"),
    )
    safe_summary = summary.encode("ascii", errors="replace").decode("ascii")
    print(f"[narrative_agent] {safe_summary}")
    return {**state, "narrative_summary": summary}


def investigation_engine(state: OrchestratorState) -> OrchestratorState:
    """
    Phase 10: AI Investigation Engine.
    
    Runs the complete investigation workflow that processes all collected
    evidence and generates a comprehensive investigation report with chain verification.
    """
    print("[investigation_engine] Starting Phase 10 AI Investigation Engine...")
    
    # Convert orchestrator state to investigation state
    investigation_state = {
        "sample_id": state.get("sample_id", "unknown"),
        "task_id": state.get("task_id"),
        "static_output": state.get("static_output").model_dump() if state.get("static_output") else None,
        "dynamic_output": state.get("dynamic_output").model_dump() if state.get("dynamic_output") else None,
        "mitre_techniques": [t.model_dump() for t in state.get("mitre_techniques", [])],
        "capability_tags": [c.model_dump() for c in state.get("capability_tags", [])],
        "risk_score": state.get("risk_score", 0),
        "intel_floor": state.get("intel_floor"),
        "victim_impact": state.get("victim_impact"),
        "malware_bazaar": state.get("malware_bazaar"),
        "narrative_summary": state.get("narrative_summary"),
    }
    
    # Run investigation workflow with chain verification
    investigation_result = run_investigation_workflow(investigation_state, verify_chain=True)
    
    # Convert investigation results back to dict for storage
    investigation_output = {
        "timeline_events": [e.model_dump() for e in investigation_result.get("timeline_events", [])],
        "malware_explanation": investigation_result.get("malware_explanation").model_dump() if investigation_result.get("malware_explanation") else None,
        "victim_impact": investigation_result.get("victim_impact").model_dump() if investigation_result.get("victim_impact") else None,
        "exfiltration_analysis": investigation_result.get("exfiltration_analysis").model_dump() if investigation_result.get("exfiltration_analysis") else None,
        "recommendations": [r.model_dump() for r in investigation_result.get("recommendations", [])],
        "investigation_summary": investigation_result.get("investigation_summary").model_dump() if investigation_result.get("investigation_summary") else None,
        "chain_verification": investigation_result.get("chain_verification"),
    }
    
    print(f"[investigation_engine] Generated {len(investigation_output['timeline_events'])} timeline events, "
          f"{len(investigation_output['recommendations'])} recommendations")
    
    # Log chain verification status
    chain_verification = investigation_output.get("chain_verification")
    if chain_verification:
        status = chain_verification.get("status", "unknown")
        is_valid = chain_verification.get("is_valid", False)
        print(f"[investigation_engine] Chain verification: {status} (valid: {is_valid})")
    
    return {**state, "investigation_output": investigation_output}


# ---------------------------------------------------------------------
# Graph assembly
# ---------------------------------------------------------------------

def build_graph():
    graph = StateGraph(OrchestratorState)

    graph.add_node("load_static_analysis", load_static_analysis)
    graph.add_node("load_dynamic_analysis", load_dynamic_analysis)
    graph.add_node("mitre_mapper", mitre_mapper)
    graph.add_node("capability_classifier", capability_classifier)
    graph.add_node("compute_risk_score", compute_risk_score)
    graph.add_node("narrative_agent", narrative_agent)
    graph.add_node("investigation_engine", investigation_engine)

    graph.set_entry_point("load_static_analysis")
    graph.add_edge("load_static_analysis", "load_dynamic_analysis")
    graph.add_edge("load_dynamic_analysis", "mitre_mapper")
    graph.add_edge("mitre_mapper", "capability_classifier")
    graph.add_edge("capability_classifier", "compute_risk_score")
    graph.add_edge("compute_risk_score", "narrative_agent")
    graph.add_edge("narrative_agent", "investigation_engine")
    graph.add_edge("investigation_engine", END)

    return graph.compile()


if __name__ == "__main__":
    app = build_graph()
    final_state = app.invoke({})

    print("\n--- FINAL STATE SUMMARY ---")
    print(f"Sample ID: {final_state['sample_id']}")
    print(f"Risk Score: {final_state['risk_score']}")
    print(f"MITRE Techniques: {[t.technique_id for t in final_state['mitre_techniques']]}")
    print(f"Capabilities: {[c.capability for c in final_state['capability_tags']]}")
    print(f"Narrative:\n{final_state['narrative_summary']}")
