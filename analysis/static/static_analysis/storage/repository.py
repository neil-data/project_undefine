"""
Analysis result storage.

WHY A FILE-BACKED JSON STORE
----------------------------
The detonation plane is network-isolated and the deployment has to work
air-gapped, so the static engine cannot assume Postgres is reachable. It
writes a self-contained JSON document per sample and an index alongside it;
the backend ingests those into Postgres and Elasticsearch when a link exists.

Two properties matter more than the format:

**The sample hash is the identity.** A file named `invoice.pdf.apk` submitted
three times from three districts is one sample with three submissions, and the
SHA-256 is what makes that true. Re-analysis overwrites the document rather
than accumulating duplicates.

**Writes are atomic.** A report is written to a temporary file in the same
directory and then moved into place, so a crash mid-write leaves the previous
report intact rather than a truncated document that fails to parse — which, in
a chain-of-custody system, is the difference between an old record and a
corrupt one.
"""

from __future__ import annotations

import json
import logging
import os
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

_LOGGER = logging.getLogger(__name__)

_INDEX_FILENAME = "index.json"
_SCHEMA_VERSION = "1.0"


class AnalysisResultRepository:
    """Stores and retrieves static analysis reports keyed by sample SHA-256."""

    def __init__(self, root: str | Path) -> None:
        self._root = Path(root)
        self._reports = self._root / "reports"

    @property
    def root(self) -> Path:
        return self._root

    @property
    def index_path(self) -> Path:
        return self._root / _INDEX_FILENAME

    # -- write -------------------------------------------------------------

    def save(self, report: dict[str, Any]) -> Path:
        """
        Persist one analysis report and update the index.

        Returns the path written. Raises ValueError when the report carries no
        SHA-256, because a report that cannot be identified cannot be retrieved
        and silently storing it under a generated name would hide the bug.
        """
        sha256 = str(report.get("sha256") or "").strip().lower()
        if not sha256:
            raise ValueError("Report is missing sha256; cannot be stored or retrieved")

        self._reports.mkdir(parents=True, exist_ok=True)

        stored = dict(report)
        stored.setdefault("schema_version", _SCHEMA_VERSION)
        stored["stored_at"] = datetime.now(timezone.utc).isoformat()

        target = self._reports / f"{sha256}.json"
        self._atomic_write(target, stored)
        self._update_index(stored)
        return target

    def _atomic_write(self, target: Path, payload: dict[str, Any]) -> None:
        # Same directory as the target: os.replace is only atomic within one
        # filesystem, and the temp dir is frequently on another volume.
        handle, raw_path = tempfile.mkstemp(dir=str(target.parent), suffix=".tmp")
        temporary = Path(raw_path)
        try:
            with os.fdopen(handle, "w", encoding="utf-8") as stream:
                json.dump(payload, stream, indent=2, ensure_ascii=False, default=str)
            os.replace(temporary, target)
        except Exception:
            temporary.unlink(missing_ok=True)
            raise

    def _update_index(self, report: dict[str, Any]) -> None:
        index = self._read_index()
        classification = report.get("classification") or {}

        index[str(report["sha256"])] = {
            "sample_id": report.get("sample_id"),
            "file_name": report.get("file_name"),
            "file_type": report.get("file_type"),
            "platform": report.get("platform"),
            "file_size_bytes": report.get("file_size_bytes"),
            "verdict": classification.get("verdict"),
            "risk_score": classification.get("risk_score", report.get("risk_score")),
            "primary_family": classification.get("primary_family"),
            "scam_type": classification.get("scam_type"),
            "stored_at": report.get("stored_at"),
        }

        self._root.mkdir(parents=True, exist_ok=True)
        self._atomic_write(self.index_path, index)

    # -- read --------------------------------------------------------------

    def load(self, sha256: str) -> dict[str, Any] | None:
        """Return a stored report, or None when the sample has not been analyzed."""
        path = self._reports / f"{str(sha256).strip().lower()}.json"
        if not path.is_file():
            return None
        try:
            return json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as error:
            _LOGGER.warning("Stored report unreadable for %s: %s", sha256, error)
            return None

    def exists(self, sha256: str) -> bool:
        return (self._reports / f"{str(sha256).strip().lower()}.json").is_file()

    def _read_index(self) -> dict[str, Any]:
        if not self.index_path.is_file():
            return {}
        try:
            data = json.loads(self.index_path.read_text(encoding="utf-8"))
            return data if isinstance(data, dict) else {}
        except (OSError, json.JSONDecodeError) as error:
            # A corrupt index must not block storing new results — the reports
            # themselves are the record of truth and the index is derived.
            _LOGGER.warning("Index unreadable, rebuilding from this write: %s", error)
            return {}

    def list_samples(self) -> tuple[dict[str, Any], ...]:
        """Return index entries, newest first."""
        index = self._read_index()
        entries = [{"sha256": sha, **summary} for sha, summary in index.items()]
        entries.sort(key=lambda item: str(item.get("stored_at") or ""), reverse=True)
        return tuple(entries)

    def find_by_verdict(self, verdict: str) -> tuple[dict[str, Any], ...]:
        return tuple(entry for entry in self.list_samples() if entry.get("verdict") == verdict)

    def export_iocs(self) -> tuple[dict[str, Any], ...]:
        """
        Flatten every stored sample's actionable indicators into one feed.

        This is what an investigator hands to a network team or submits for
        blocking — deduplicated across cases, with the samples that carried
        each indicator attached.
        """
        aggregated: dict[tuple[str, str], dict[str, Any]] = {}

        for entry in self.list_samples():
            report = self.load(str(entry["sha256"]))
            if not report:
                continue
            for indicator in (report.get("iocs") or {}).get("actionable", []):
                key = (str(indicator.get("value")), str(indicator.get("type")))
                record = aggregated.setdefault(key, {
                    "value": indicator.get("value"),
                    "type": indicator.get("type"),
                    "defanged": indicator.get("defanged"),
                    "samples": [],
                })
                record["samples"].append(entry["sha256"])

        feed = list(aggregated.values())
        # Indicators seen across several samples first: shared infrastructure
        # is what ties separate cases to one operator.
        feed.sort(key=lambda item: (-len(item["samples"]), str(item["value"])))
        return tuple(feed)
