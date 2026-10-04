"""Protect forensic fixture content with a hash manifest and a documented reason."""
from __future__ import annotations

import hashlib
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
FIXTURES = ROOT / "tests" / "e2e" / "fixtures"
MANIFEST = FIXTURES / "MANIFEST.sha256"
CHANGELOG = ROOT / "CHANGELOG.md"


def _manifest() -> dict[str, str]:
    rows = {}
    for line in MANIFEST.read_text(encoding="utf-8").splitlines():
        if line.strip() and not line.lstrip().startswith("#"):
            digest, name = line.split(None, 1)
            rows[name.strip().lstrip("* ")] = digest
    return rows


@pytest.mark.e2e
def test_fixture_integrity() -> None:
    manifest = _manifest()
    changelog = CHANGELOG.read_text(encoding="utf-8")
    fixture_paths = sorted(FIXTURES.glob("*.json"))
    assert set(manifest) == {p.name for p in fixture_paths}, "Manifest fixture list is stale"

    for path in fixture_paths:
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        assert manifest[path.name] == digest, f"{path.name} changed without a manifest update"
        baseline = subprocess.run(
            ["git", "show", f"HEAD:tests/e2e/fixtures/{path.name}"],
            cwd=ROOT, capture_output=True, check=False,
        )
        if baseline.returncode == 0:
            old_digest = hashlib.sha256(baseline.stdout).hexdigest()
            if old_digest != digest:
                documented = any(
                    path.name in line and "fixture" in line.lower() and len(line.strip()) > 24
                    for line in changelog.splitlines()
                )
                assert documented, f"{path.name} changed without a reason line in CHANGELOG.md"
