import json
from pathlib import Path

from analysis.scoring.orchestrator.schema import StaticAnalysisOutput
from providers.dynamic.pipeline import DynamicAnalysisPipeline, enrich_orchestrator_state


def test_macho_static_pipeline_has_no_dynamic_rows():
    sample_path = Path(__file__).resolve().parents[2] / "analysis" / "scoring" / "orchestrator" / "mock_data" / "static_analysis_sample.json"
    static = StaticAnalysisOutput.model_validate(json.loads(sample_path.read_text(encoding="utf-8")))
    macho_static = static.model_copy(update={"platform": "macos", "file_type": "mach_o"})

    pipeline = DynamicAnalysisPipeline()
    result = pipeline.run_static_output(macho_static)
    report = enrich_orchestrator_state({"sample_id": macho_static.sample_id, "static_output": macho_static}, result)

    assert result.state.value == "NOT_SUPPORTED_PLATFORM"
    assert result.report_line == "Dynamic analysis: not performed (static-only)"
    assert result.findings == []
    assert pipeline.evidence_store == []
    assert report["dynamic_output"] is None
    assert report["provider_evidence"] == []
    assert report["provider_report_line"] == "Dynamic analysis: not performed (static-only)"
