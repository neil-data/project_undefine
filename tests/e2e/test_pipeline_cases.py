"""Layer 2: minimal raw observables enter the production report builders."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from apps.backend.app.analysis import _build_ioc_intelligence, _extract_network_indicators

INPUTS = Path(__file__).parent / "inputs"
CASES = [p.stem for p in sorted(INPUTS.glob("*.json"))]


@pytest.mark.parametrize("case", CASES)
def test_raw_case_report_builder_output_obeys_day2_ioc_contracts(case: str) -> None:
    raw = json.loads((INPUTS / f"{case}.json").read_text(encoding="utf-8"))["raw"]
    strings = raw.get("strings", [])
    raw_static = {
        "sample_id": case,
        "platform": "linux",
        "file_type": "elf",
        "sha256": "a" * 64,
        "extracted_strings": {
            "ips": [],
            "urls": [s for s in strings if s.startswith(("http://", "https://"))],
        },
        "explained_strings": [
            {"value": s, "type": "domain", "category": "network_indicator"}
            for s in strings if not s.startswith(("http://", "https://"))
        ],
        "yara_matches": raw.get("yara_hits", []),
    }
    dynamic = {"dynamic_status": "unavailable", "network_connections": [], "dns_queries": []}
    indicators = _extract_network_indicators(raw_static, dynamic)
    output = _build_ioc_intelligence(raw_static, dynamic, indicators)

    # Layer 2 validators operate on the report-builder output, not the frozen reports.
    assert all(r.get("evidence_state") in {"STATIC", "OBSERVED", "INTEL"} for r in output)
    assert not any(r.get("evidence_state") in {"OBSERVED", "DYNAMIC"} for r in output if r.get("source_type") == "STATIC")
    emitted_domains = {r["indicator"] for r in output if r.get("type") == "DOMAIN"}
    assert not emitted_domains.intersection({"fmt.pp", "go.shape", "io.pipe", "os.file", "jC.bn", "QMrS.lg", "XB.kr"})
