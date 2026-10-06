"""Single all-or-nothing path from untrusted provider payload to evidence."""
import json
import os
from typing import Any

from .base import DynamicState, NormalizedProviderResult, ProviderObservation, invalid_response

MAX_BYTES = 256_000
MAX_ITEMS = 100
MAX_TEXT = 512
BEHAVIOR_FIELDS = ("processes", "network", "domains", "dns", "files", "registry", "api_calls", "signatures", "mitre")
_FIELD_MAP = {"processes": "process", "network": "network", "domains": "network", "dns": "dns", "files": "file", "registry": "registry", "api_calls": "api_call", "signatures": "signature", "mitre": "mitre"}


def _bounded_text(value):
    if not isinstance(value, str):
        raise ValueError("text must be a string")
    return value[:MAX_TEXT]


def _safe_rows(value):
    if not isinstance(value, list) or len(value) > MAX_ITEMS:
        raise ValueError("invalid list size")
    rows = []
    for item in value:
        if isinstance(item, str):
            rows.append({"name": _bounded_text(item)})
        elif isinstance(item, dict) and len(item) <= 20:
            row = {}
            for key, val in item.items():
                if not isinstance(key, str) or not isinstance(val, (str, int, float, bool, type(None))):
                    raise ValueError("invalid field type")
                if isinstance(val, float) and not __import__("math").isfinite(val):
                    raise ValueError("invalid numeric value")
                row[_bounded_text(key)] = _bounded_text(val) if isinstance(val, str) else val
            rows.append(row)
        else:
            raise ValueError("invalid row")
    return rows


def normalize_provider_result(provider, raw: Any, task_id, environment, executed_by="provider"):
    try:
        encoded = json.dumps(raw, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        if len(encoded) > MAX_BYTES or not isinstance(raw, dict) or set(raw) - {"behavior", "verdict", "score", "limitations", "state"}:
            return invalid_response()
        if raw.get("state", "COMPLETED") != "COMPLETED":
            state = DynamicState(raw["state"])
            return NormalizedProviderResult(state, reason=state.value.lower().replace("_", " "), narrative=f"Dynamic analysis not performed: {state.value.lower().replace('_', ' ')}")
        behavior = raw.get("behavior", {})
        if not isinstance(behavior, dict) or set(behavior) - set(BEHAVIOR_FIELDS):
            return invalid_response()
        observation = ProviderObservation()
        for key, field in _FIELD_MAP.items():
            rows = _safe_rows(behavior.get(key, []))
            if key == "domains":
                observation.network.extend(rows)
            elif key == "network":
                observation.network = rows + observation.network
            else:
                setattr(observation, field, rows)
        limits = raw.get("limitations", [])
        if not isinstance(limits, list) or len(limits) > 50:
            raise ValueError("invalid limitations")
        observation.limitation = [_bounded_text(item) for item in limits]
        provenance = {"provider": provider.name, "task_id": _bounded_text(task_id) if behavior and any(behavior.values()) else None,
                      "environment": _bounded_text(environment), "executed_by": _bounded_text(executed_by)}
        cap = max(0.0, min(1.0, float(os.environ.get("PROVIDER_DYNAMIC_MAX_CONFIDENCE", "0.85"))))
        findings = []
        from analysis.scoring.orchestrator.schema import EvidenceFinding
        for category in dict.fromkeys(_FIELD_MAP.values()):
            for entry in getattr(observation, category):
                findings.append(EvidenceFinding(source_type="DYNAMIC", evidence_state="OBSERVED", state="OBSERVED", source=f"provider:{provider.name}", confidence=cap, evidence=json.dumps({"category": category, **entry}, ensure_ascii=False), provenance=json.dumps(provenance)))
        verdict = None
        if "verdict" in raw or "score" in raw:
            val = {"verdict": _bounded_text(raw.get("verdict", "")), "score": raw.get("score")}
            if val["score"] is not None and (not isinstance(val["score"], (int, float)) or not 0 <= val["score"] <= 100):
                return invalid_response()
            verdict = EvidenceFinding(source_type="INTEL", evidence_state="INTEL", state="INTEL", source=f"provider:{provider.name}", confidence=cap, evidence=json.dumps(val), provenance=json.dumps(provenance))
        narrative = None if observation.has_behavior() else ("A provider verdict was reported, but no behavior was observed." if verdict else "Dynamic analysis not performed: no result")
        return NormalizedProviderResult(DynamicState.COMPLETED, observation, provenance, findings, verdict, narrative=narrative)
    except (TypeError, ValueError, OverflowError):
        return invalid_response()
