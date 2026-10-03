"""
test_integration_pipeline.py — Full end-to-end test of the actual
LangGraph graph (not individual functions). This is the closest thing
to "does the real thing work" — it exercises build_graph().invoke()
exactly as orchestrator.py's __main__ block does, using the real mock
data files on disk (catches file-path / schema-validation issues that
unit tests with in-code fixtures can't catch).
"""

import os
from agents.orchestrator.orchestrator import build_graph


class TestFullPipelineIntegration:
    def test_graph_runs_end_to_end_without_error(self, monkeypatch):
        monkeypatch.delenv("GROQ_API_KEY", raising=False)
        app = build_graph()
        final_state = app.invoke({})

        assert final_state["sample_id"] is not None
        assert isinstance(final_state["risk_score"], int)
        assert 0 <= final_state["risk_score"] <= 100
        assert isinstance(final_state["mitre_techniques"], list)
        assert isinstance(final_state["capability_tags"], list)
        assert isinstance(final_state["narrative_summary"], str)
        assert len(final_state["narrative_summary"]) > 0

    def test_graph_produces_expected_findings_for_known_mock_sample(self, monkeypatch):
        """
        Locks in the expected result for the real mock_data files —
        if someone edits the mock JSON and breaks the expected
        detection, this test catches it immediately.
        """
        monkeypatch.delenv("GROQ_API_KEY", raising=False)
        app = build_graph()
        final_state = app.invoke({})

        technique_ids = [t.technique_id for t in final_state["mitre_techniques"]]
        capability_names = [c.capability for c in final_state["capability_tags"]]

        assert "T1517" in technique_ids  # SMS access
        assert "T1071" in technique_ids  # C2 comms
        assert "sms_otp_theft" in capability_names
        assert "data_exfiltration" in capability_names

    def test_graph_state_keys_all_present(self, monkeypatch):
        """Confirms the state dict has every key the dashboard will need to render."""
        monkeypatch.delenv("GROQ_API_KEY", raising=False)
        app = build_graph()
        final_state = app.invoke({})

        required_keys = {
            "sample_id", "static_output", "dynamic_output",
            "mitre_techniques", "capability_tags", "risk_score", "narrative_summary",
        }
        assert required_keys.issubset(final_state.keys())