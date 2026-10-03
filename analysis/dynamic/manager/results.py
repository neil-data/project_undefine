"""
results.py — Where a completed run is written down.

Mirrors the static engine's repository deliberately: same identity rule (the
sample's SHA-256), same atomic write, same derived index. An investigator
should be able to look up a sample once and get both halves of its analysis,
without knowing which engine produced which field.

The one difference is that a dynamic run is keyed by analysis as well as by
sample. The same APK detonated twice — once quick, once deep — produces two
runs with different findings, and both are evidence. The index therefore holds
the newest run per sample, and every run remains retrievable by its own id.
"""

from __future__ import annotations

import json
import logging
import os
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

_LOGGER = logging.getLogger(__name__)

_SCHEMA_VERSION = "1.0"


class RunResultRepository:
    """Stores completed detonation reports and indexes them by sample."""

    def __init__(self, root: str | Path) -> None:
        self._root = Path(root)
        self._runs = self._root / "runs"

    @property
    def root(self) -> Path:
        return self._root

    @property
    def index_path(self) -> Path:
        return self._root / "index.json"

    def save(self, report: Dict[str, Any]) -> Path:
        """Persist one run report and refresh the index."""
        analysis_id = str(report.get("analysis_id") or "").strip()
        if not analysis_id:
            raise ValueError("Run report is missing analysis_id; it could not be retrieved")

        self._runs.mkdir(parents=True, exist_ok=True)
        stored = dict(report)
        stored.setdefault("schema_version", _SCHEMA_VERSION)
        stored["stored_at"] = datetime.now(timezone.utc).isoformat()

        target = self._runs / f"{analysis_id}.json"
        self._atomic_write(target, stored)
        self._update_index(stored)
        return target

    def load(self, analysis_id: str) -> Optional[Dict[str, Any]]:
        path = self._runs / f"{str(analysis_id).strip()}.json"
        if not path.is_file():
            return None
        try:
            return json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as error:
            _LOGGER.warning("Stored run unreadable for %s: %s", analysis_id, error)
            return None

    def exists(self, analysis_id: str) -> bool:
        return (self._runs / f"{str(analysis_id).strip()}.json").is_file()

    def runs_for_sample(self, sha256: str) -> List[Dict[str, Any]]:
        """Every recorded detonation of one sample, newest first."""
        wanted = str(sha256).strip().lower()
        runs = []
        if not self._runs.is_dir():
            return runs
        for path in self._runs.glob("*.json"):
            try:
                report = json.loads(path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                continue
            if str(report.get("sha256", "")).lower() == wanted:
                runs.append(report)
        runs.sort(key=lambda item: str(item.get("stored_at") or ""), reverse=True)
        return runs

    def list_runs(self) -> List[Dict[str, Any]]:
        index = self._read_index()
        entries = [{"sha256": sha, **summary} for sha, summary in index.items()]
        entries.sort(key=lambda item: str(item.get("stored_at") or ""), reverse=True)
        return entries

    # -- internals ---------------------------------------------------------

    def _update_index(self, report: Dict[str, Any]) -> None:
        index = self._read_index()
        sha256 = str(report.get("sha256") or report.get("analysis_id"))

        index[sha256] = {
            "analysis_id": report.get("analysis_id"),
            "job_id": report.get("job_id"),
            "file_name": report.get("file_name"),
            "platform": report.get("platform"),
            "profile": report.get("profile"),
            "state": report.get("state"),
            "risk_score": report.get("final_risk_score"),
            "activation_stage": report.get("activation_stage"),
            "evasion_profile": report.get("evasion_profile", []),
            "artifact_count": report.get("artifact_count", 0),
            "stored_at": report.get("stored_at"),
        }

        self._root.mkdir(parents=True, exist_ok=True)
        self._atomic_write(self.index_path, index)

    def _read_index(self) -> Dict[str, Any]:
        if not self.index_path.is_file():
            return {}
        try:
            data = json.loads(self.index_path.read_text(encoding="utf-8"))
            return data if isinstance(data, dict) else {}
        except (OSError, json.JSONDecodeError) as error:
            # The run documents are the record; the index is derived and can
            # be rebuilt, so a corrupt index must not block storing a result.
            _LOGGER.warning("Run index unreadable, rebuilding on write: %s", error)
            return {}

    @staticmethod
    def _atomic_write(target: Path, payload: Dict[str, Any]) -> None:
        target.parent.mkdir(parents=True, exist_ok=True)
        handle, raw_path = tempfile.mkstemp(dir=str(target.parent), suffix=".tmp")
        temporary = Path(raw_path)
        try:
            with os.fdopen(handle, "w", encoding="utf-8") as stream:
                json.dump(payload, stream, indent=2, ensure_ascii=False, default=str)
            os.replace(temporary, target)
        except Exception:
            temporary.unlink(missing_ok=True)
            raise
