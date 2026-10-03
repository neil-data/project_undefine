"""
backend/tests/test_no_simulation_guard.py — Guard test ensuring zero simulation strings in production.

Implements Test 12 of the comprehensive test suite:
- Grep codebase for "simulated" across backend/app, agents, static-analysis (excluding tests/fixtures).
- Fails if any production string contains "simulated" (case-insensitive).
- Verifies exact limitation string: "Network is emulated by a fake-service host; remote servers did not respond".
- Verifies DynamicAnalysisOutput schema execution_mode="real".
"""

import re
from pathlib import Path
import pytest
from agents.orchestrator.schema import DynamicAnalysisOutput
from backend.app.strace_parser import parse_strace_artifacts


def test_no_simulation_strings_in_production():
    """Test 12: Production codebase must have ZERO occurrences of 'simulated'."""
    repo_root = Path(__file__).resolve().parent.parent.parent
    production_dirs = [
        repo_root / "backend" / "app",
        repo_root / "agents",
        repo_root / "static-analysis",
    ]

    violations = []
    pattern = re.compile(r"\bsimulated\b", re.IGNORECASE)

    for pdir in production_dirs:
        for py_path in pdir.rglob("*.py"):
            # Exclude tests, fixtures, caches
            if any(x in py_path.parts for x in ("tests", "fixtures", "__pycache__", "venv", ".git")):
                continue
            try:
                content = py_path.read_text(encoding="utf-8", errors="ignore")
                for line_idx, line in enumerate(content.splitlines(), start=1):
                    # Check for forbidden simulation keyword
                    if pattern.search(line):
                        violations.append(f"{py_path.relative_to(repo_root)}:{line_idx}: {line.strip()}")
            except Exception as exc:
                violations.append(f"Failed to read {py_path}: {exc}")

    assert not violations, f"Found {len(violations)} forbidden 'simulated' references in production:\n" + "\n".join(violations)


def test_network_limitation_string_format():
    """Verify the exact wording of the network emulation limitation string."""
    expected_limitation = "Network is emulated by a fake-service host; remote servers did not respond"
    
    # Synthetic log connecting to bridge IP (which triggers the limitation)
    sample_strace = (
        '1000 00:00:00.000100 connect(3, {sa_family=AF_INET, sin_port=htons(80), sin_addr=inet_addr("192.168.100.2")}, 16) = 0\n'
    )
    result = parse_strace_artifacts(
        strace_log=sample_strace,
        sample_id="test_limitation",
        bridge_ip="192.168.100.2",
    )
    assert any(expected_limitation in lim for lim in result.limitations)


def test_dynamic_output_defaults_to_real():
    """DynamicAnalysisOutput must default to real execution mode."""
    out = DynamicAnalysisOutput()
    assert out.execution_mode == "real"