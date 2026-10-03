"""
store.py — Evidence custody for run artifacts.

WHAT AN ARTIFACT IS HERE
------------------------
Anything the run produced that outlives it: packet captures, memory dumps,
screenshots, dropped files, guest logs. These are the exhibits — the parts of
an analysis that get attached to a case file and, eventually, looked at by
someone who was not in the room.

THREE PROPERTIES THAT MAKE THEM EVIDENCE RATHER THAN FILES
----------------------------------------------------------
**Hashed at the moment of capture.** An artifact recorded without a digest
cannot later be shown to be the same bytes. The hash is taken when the file is
registered, not when the report is written.

**Chained.** Each entry carries the digest of the one before it, so the
manifest itself detects reordering or removal — deleting the packet capture
that contradicts a finding breaks the chain visibly rather than silently.

**Immutable once registered.** Re-registering the same logical artifact with
different bytes is refused, not overwritten. Losing the original is the one
failure that cannot be recovered from.

MEMORY DUMPS GET READ, NOT JUST FILED
-------------------------------------
A memory dump nobody looks at is a large file, not evidence. `scan_memory_dump`
runs the static engine's signature and indicator extraction over the captured
image, which is where the unpacked payload lives: a packer that decrypts
itself in memory has, by definition, put its real strings, its C2 domains and
its configuration somewhere the disk file never showed.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import shutil
import tempfile
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional
from uuid import UUID

_LOGGER = logging.getLogger(__name__)

_HASH_CHUNK = 1024 * 1024
GENESIS_LINK = "0" * 64


class ArtifactError(RuntimeError):
    """Raised when custody would be violated — never to signal a missing file."""


@dataclass
class Artifact:
    """One captured exhibit, with the chain link that fixes its position."""

    artifact_id: str
    analysis_id: str
    artifact_type: str          # pcap | memdump | screenshot | dropped_file | log
    name: str
    stored_path: str
    size_bytes: int
    sha256: str
    captured_at: str
    stage_id: Optional[str] = None
    description: str = ""

    previous_sha256: str = GENESIS_LINK
    chain_hash: str = ""

    analysis: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


def sha256_of(path: str | Path) -> str:
    digest = hashlib.sha256()
    with Path(path).open("rb") as stream:
        while chunk := stream.read(_HASH_CHUNK):
            digest.update(chunk)
    return digest.hexdigest()


class ArtifactStore:
    """Per-analysis artifact directory with a hash-chained manifest."""

    def __init__(self, root: str | Path, analysis_id: UUID | str) -> None:
        self._analysis_id = str(analysis_id)
        self._root = Path(root) / self._analysis_id
        self._artifacts: List[Artifact] = []
        self._by_name: Dict[str, Artifact] = {}

    @property
    def root(self) -> Path:
        return self._root

    @property
    def manifest_path(self) -> Path:
        return self._root / "manifest.json"

    # -- capture -----------------------------------------------------------

    def register(
        self,
        source_path: str | Path,
        artifact_type: str,
        *,
        name: Optional[str] = None,
        stage_id: Optional[str] = None,
        description: str = "",
        move: bool = False,
    ) -> Artifact:
        """
        Take custody of a file the run produced.

        `move` is for artifacts already on this host that should not be
        duplicated — a multi-gigabyte memory image, typically. Copying is the
        default because the guest-side path may be reverted out from under us
        by the next snapshot restore.
        """
        source = Path(source_path)
        if not source.is_file():
            raise ArtifactError(f"Artifact not found: {source}")

        artifact_name = name or source.name
        digest = sha256_of(source)

        existing = self._by_name.get(artifact_name)
        if existing is not None:
            if existing.sha256 == digest:
                return existing
            raise ArtifactError(
                f"Artifact '{artifact_name}' already exists with different content "
                f"({existing.sha256[:12]} vs {digest[:12]}); refusing to overwrite "
                f"captured evidence"
            )

        self._root.mkdir(parents=True, exist_ok=True)
        destination = self._root / artifact_name
        destination.parent.mkdir(parents=True, exist_ok=True)

        if move:
            shutil.move(str(source), str(destination))
        else:
            shutil.copy2(str(source), str(destination))

        previous = self._artifacts[-1].chain_hash if self._artifacts else GENESIS_LINK
        artifact = Artifact(
            artifact_id=f"{self._analysis_id}:{len(self._artifacts):04d}",
            analysis_id=self._analysis_id,
            artifact_type=artifact_type,
            name=artifact_name,
            stored_path=str(destination),
            size_bytes=destination.stat().st_size,
            sha256=digest,
            captured_at=datetime.now(timezone.utc).isoformat(),
            stage_id=stage_id,
            description=description,
            previous_sha256=previous,
        )
        artifact.chain_hash = self._link(artifact)

        self._artifacts.append(artifact)
        self._by_name[artifact_name] = artifact
        self._write_manifest()

        _LOGGER.info("Artifact %s captured (%s, %d bytes)",
                     artifact_name, artifact_type, artifact.size_bytes)
        return artifact
    
    def analyze_memory_forensics(
        self,
        artifact: Artifact,
    ) -> Dict[str, Any]:
        """
        Perform comprehensive memory forensics analysis on a memory dump artifact.
        
        This method runs the advanced memory forensics analyzer on the memory dump
        and stores the results in the artifact's analysis field.
        
        Args:
            artifact: The memory dump artifact to analyze
            
        Returns:
            Dictionary containing the memory forensics analysis results
        """
        if artifact.artifact_type != "memdump":
            raise ArtifactError(
                f"Memory forensics analysis requires memdump artifact, got {artifact.artifact_type}"
            )
        
        try:
            from .memory_forensics import MemoryForensicsAnalyzer
            
            analyzer = MemoryForensicsAnalyzer()
            result = analyzer.analyze(artifact.stored_path)
            
            # Store results in artifact
            artifact.analysis["memory_forensics"] = result.to_dict()
            self._write_manifest()
            
            _LOGGER.info(
                "Memory forensics analysis completed for %s: %d suspicious regions, "
                "%d shellcode matches, %d credential matches",
                artifact.name,
                len(result.suspicious_regions),
                len(result.shellcode_matches),
                len(result.credential_matches)
            )
            
            return result.to_dict()
            
        except ImportError:
            _LOGGER.warning("Memory forensics analyzer not available")
            artifact.analysis["memory_forensics"] = {
                "status": "unavailable",
                "error": "Memory forensics analyzer not available"
            }
            self._write_manifest()
            return artifact.analysis["memory_forensics"]
        except Exception as error:
            _LOGGER.error("Memory forensics analysis failed: %s", error)
            artifact.analysis["memory_forensics"] = {
                "status": "failed",
                "error": str(error)
            }
            self._write_manifest()
            return artifact.analysis["memory_forensics"]

    def register_bytes(
        self,
        payload: bytes,
        artifact_type: str,
        name: str,
        *,
        stage_id: Optional[str] = None,
        description: str = "",
    ) -> Artifact:
        """Take custody of in-memory content — a screenshot pulled over the wire."""
        handle, raw_path = tempfile.mkstemp(prefix="artifact_")
        try:
            with os.fdopen(handle, "wb") as stream:
                stream.write(payload)
            return self.register(raw_path, artifact_type, name=name,
                                 stage_id=stage_id, description=description, move=True)
        finally:
            Path(raw_path).unlink(missing_ok=True)

    @staticmethod
    def _link(artifact: Artifact) -> str:
        """Bind an artifact's identity to its predecessor's."""
        material = "|".join([
            artifact.artifact_id,
            artifact.artifact_type,
            artifact.name,
            artifact.sha256,
            artifact.captured_at,
            artifact.previous_sha256,
        ])
        return hashlib.sha256(material.encode("utf-8")).hexdigest()

    # -- verification ------------------------------------------------------

    def verify(self) -> Dict[str, Any]:
        """
        Re-hash every artifact and re-walk the chain.

        Two independent failures are distinguished, because they mean
        different things: `modified` says the bytes on disk changed since
        capture; `chain_broken` says the manifest itself was edited.
        """
        modified: List[str] = []
        missing: List[str] = []
        chain_broken: List[str] = []
        previous = GENESIS_LINK

        for artifact in self._artifacts:
            path = Path(artifact.stored_path)
            if not path.is_file():
                missing.append(artifact.name)
            elif sha256_of(path) != artifact.sha256:
                modified.append(artifact.name)

            if artifact.previous_sha256 != previous or artifact.chain_hash != self._link(artifact):
                chain_broken.append(artifact.name)
            previous = artifact.chain_hash

        return {
            "analysis_id": self._analysis_id,
            "artifact_count": len(self._artifacts),
            "intact": not (modified or missing or chain_broken),
            "modified": modified,
            "missing": missing,
            "chain_broken": chain_broken,
            "verified_at": datetime.now(timezone.utc).isoformat(),
        }

    # -- inspection --------------------------------------------------------

    def artifacts(self, artifact_type: Optional[str] = None) -> List[Artifact]:
        if artifact_type is None:
            return list(self._artifacts)
        return [a for a in self._artifacts if a.artifact_type == artifact_type]

    def total_bytes(self) -> int:
        return sum(a.size_bytes for a in self._artifacts)

    def _write_manifest(self) -> None:
        payload = {
            "analysis_id": self._analysis_id,
            "updated_at": datetime.now(timezone.utc).isoformat(),
            "artifact_count": len(self._artifacts),
            "total_bytes": self.total_bytes(),
            "artifacts": [artifact.to_dict() for artifact in self._artifacts],
        }
        self._root.mkdir(parents=True, exist_ok=True)
        # Written through a temporary file in the same directory so an
        # interrupted write cannot leave an unparseable manifest behind.
        handle, raw_path = tempfile.mkstemp(dir=str(self._root), suffix=".tmp")
        temporary = Path(raw_path)
        try:
            with os.fdopen(handle, "w", encoding="utf-8") as stream:
                json.dump(payload, stream, indent=2, default=str)
            os.replace(temporary, self.manifest_path)
        except Exception:
            temporary.unlink(missing_ok=True)
            raise

    def to_dict(self) -> Dict[str, Any]:
        return {
            "analysis_id": self._analysis_id,
            "root": str(self._root),
            "manifest": str(self.manifest_path),
            "artifact_count": len(self._artifacts),
            "total_bytes": self.total_bytes(),
            "artifacts": [artifact.to_dict() for artifact in self._artifacts],
        }
