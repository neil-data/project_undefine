"""
memory.py — Reading what the memory dump actually contains.

WHY THIS IS WORTH DOING
-----------------------
Capturing memory and filing it is the easy half. The reason to capture it at
all is that a packed sample has to decrypt itself to run: whatever the file on
disk concealed — the real strings, the C2 domain, the configuration, the
second stage — is sitting in the process image in plaintext. Static analysis
of the dropped file sees a wall of ciphertext; the same analysis of the dump
sees the payload.

So the captured image is run back through the static engine's signature and
indicator extraction, and what comes out is compared against what the file
gave up. The interesting number is the *difference*: indicators present in
memory and absent from disk are precisely the ones the sample was hiding.

DEGRADING WITHOUT LYING
-----------------------
The static analysis package may not be installed on the detonation plane — it
is a separate distribution and the plane is deliberately minimal. When it is
absent, this reports `engine_unavailable` and the report says the memory
analysis stage did not run. It never reports "nothing found", which is
indistinguishable from a clean dump.
"""

from __future__ import annotations

import logging
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

_LOGGER = logging.getLogger(__name__)

# Memory images are large and mostly zero pages; a dump is scanned in windows
# rather than read whole.
_SCAN_WINDOW_BYTES = 16 * 1024 * 1024
_MAX_SCAN_BYTES = 512 * 1024 * 1024
_MIN_STRING_LENGTH = 6


def _load_static_engine():
    """
    Import the static analysis engine if this host has it.

    Located by walking up to the repository root rather than assuming an
    installed distribution, because the detonation plane runs from a checkout
    with no package index reachable.
    """
    try:
        import static_analysis  # noqa: F401
        return True
    except ImportError:
        pass

    candidate = Path(__file__).resolve().parents[2] / "static-analysis" / "src"
    if candidate.is_dir():
        if str(candidate) not in sys.path:
            sys.path.insert(0, str(candidate))
        try:
            import static_analysis  # noqa: F401
            return True
        except ImportError:
            return False
    return False


STATIC_ENGINE_AVAILABLE = _load_static_engine()


@dataclass
class MemoryAnalysis:
    """What was recovered from a captured memory image."""

    dump_path: str
    status: str                     # completed | engine_unavailable | failed
    size_bytes: int = 0

    signature_matches: List[Dict[str, Any]] = field(default_factory=list)
    indicators: List[Dict[str, Any]] = field(default_factory=list)

    # Indicators present in memory but absent from the file on disk. This is
    # the payload the sample kept encrypted until it ran.
    indicators_absent_from_disk: List[Dict[str, Any]] = field(default_factory=list)

    strings_recovered: int = 0
    error: Optional[str] = None

    @property
    def revealed_hidden_payload(self) -> bool:
        return bool(self.indicators_absent_from_disk or self.signature_matches)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "dump_path": self.dump_path,
            "status": self.status,
            "size_bytes": self.size_bytes,
            "strings_recovered": self.strings_recovered,
            "signature_matches": self.signature_matches,
            "indicators": self.indicators,
            "indicators_absent_from_disk": self.indicators_absent_from_disk,
            "revealed_hidden_payload": self.revealed_hidden_payload,
            "error": self.error,
        }


class MemoryDumpAnalyzer:
    """Runs signature and indicator extraction over a captured memory image."""

    def __init__(self, yara_scanner=None, ioc_extractor=None) -> None:
        self._scanner = yara_scanner
        self._extractor = ioc_extractor

        if STATIC_ENGINE_AVAILABLE:
            if self._scanner is None:
                from static_analysis.yara_scan import create_yara_scanner

                self._scanner = create_yara_scanner()
            if self._extractor is None:
                from static_analysis.ioc import create_ioc_extractor

                self._extractor = create_ioc_extractor()

    @property
    def available(self) -> bool:
        return self._scanner is not None and self._extractor is not None

    def analyze(
        self,
        dump_path: str | Path,
        disk_indicators: Optional[List[str]] = None,
    ) -> MemoryAnalysis:
        """
        Scan a memory image and diff its indicators against the disk file's.

        `disk_indicators` is the static analysis result for the sample itself.
        Passing it is what turns a list of memory strings into the specific
        finding that matters: these appeared only once the sample was running.
        """
        source = Path(dump_path)

        if not self.available:
            return MemoryAnalysis(
                dump_path=str(source),
                status="engine_unavailable",
                error=(
                    "The static analysis engine is not installed on this host, so "
                    "the captured memory image was stored but not examined."
                ),
            )

        if not source.is_file():
            return MemoryAnalysis(dump_path=str(source), status="failed",
                                  error=f"Memory dump not found: {source}")

        try:
            return self._analyze(source, set(disk_indicators or []))
        except Exception as error:  # noqa: BLE001 - never fail a run over post-processing
            _LOGGER.warning("Memory analysis failed for %s: %s", source, error)
            return MemoryAnalysis(dump_path=str(source), status="failed", error=str(error))

    # -- internals ---------------------------------------------------------

    def _analyze(self, source: Path, disk_indicators: set) -> MemoryAnalysis:
        from static_analysis.ioc.models import IocScope
        from static_analysis.strings.models import ExtractedString, StringType

        size = source.stat().st_size
        matches: Dict[str, Dict[str, Any]] = {}
        recovered: Dict[str, ExtractedString] = {}
        scanned = 0

        with source.open("rb") as stream:
            offset = 0
            while scanned < _MAX_SCAN_BYTES and (window := stream.read(_SCAN_WINDOW_BYTES)):
                scanned += len(window)

                result = self._scanner.scan_bytes(f"{source.name}@{offset}", window)
                for match in result.matches:
                    matches.setdefault(match.rule_name, {
                        "rule_name": match.rule_name,
                        "namespace": match.namespace,
                        "severity": match.severity.value,
                        "family": match.family,
                        "description": match.description,
                        "mitre": list(match.mitre),
                        "window_offset": offset,
                    })

                for value in self._printable_runs(window):
                    if value not in recovered:
                        recovered[value] = ExtractedString(
                            value=value,
                            string_type=StringType.ASCII,
                            offset=offset,
                            length=len(value),
                            encoding="ascii",
                        )
                offset += len(window)

        ioc_result = self._extractor.extract(str(source), tuple(recovered.values()))
        actionable = [
            {
                "value": indicator.value,
                "type": indicator.ioc_type.value,
                "confidence": indicator.confidence.value,
                "defanged": indicator.defanged,
                "note": indicator.note,
            }
            for indicator in ioc_result.actionable
            if indicator.scope is IocScope.EXTERNAL
        ]

        hidden = [item for item in actionable if item["value"] not in disk_indicators]

        return MemoryAnalysis(
            dump_path=str(source),
            status="completed",
            size_bytes=size,
            signature_matches=list(matches.values()),
            indicators=actionable,
            indicators_absent_from_disk=hidden,
            strings_recovered=len(recovered),
        )

    @staticmethod
    def _printable_runs(window: bytes) -> List[str]:
        """
        Pull printable runs out of a memory window.

        Deliberately simple and self-contained: the static engine's extractor
        works on files, and a memory image is scanned in windows so that a
        multi-gigabyte dump never has to be resident.
        """
        runs: List[str] = []
        current = bytearray()
        for byte in window:
            if 0x20 <= byte <= 0x7E:
                current.append(byte)
                continue
            if len(current) >= _MIN_STRING_LENGTH:
                runs.append(current.decode("ascii", errors="ignore"))
            current.clear()
        if len(current) >= _MIN_STRING_LENGTH:
            runs.append(current.decode("ascii", errors="ignore"))
        return runs
