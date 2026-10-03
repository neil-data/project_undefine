"""
YARA signature scanning.

TWO DESIGN POINTS WORTH KNOWING
-------------------------------
**The engine is optional, and its absence is reported, not hidden.** An
air-gapped deployment may not have `yara-python` available. Returning "no
matches" in that situation would be a lie an investigator could act on, so the
result carries an explicit `ENGINE_UNAVAILABLE` status and the report says the
signature stage did not run. A silent empty list is the failure mode that
makes a tool untrustworthy.

**Rule metadata is part of the contract.** Each rule declares severity,
confidence, family, category and MITRE techniques in its `meta` block. Those
values flow into the risk score, the classification and the MITRE mapping
directly, so adding a rule file is enough to extend the engine — no Python
change is needed to teach it a new fraud pattern.

Namespaces follow the directory layout, which is what lets the report separate
"matched an India-specific fraud signature" from "matched a generic packer
signature" — a distinction that matters to an investigating officer.
"""

from __future__ import annotations

import logging
from pathlib import Path

from static_analysis.detection.models import ConfidenceLevel
from static_analysis.domain.enums import Severity
from static_analysis.yara_scan.models import (
    YaraMatch,
    YaraScanResult,
    YaraStatus,
    YaraStringHit,
)

_LOGGER = logging.getLogger(__name__)

try:  # pragma: no cover - import-time environment probe
    import yara as _yara

    YARA_AVAILABLE = True
except ImportError:  # pragma: no cover - exercised on air-gapped installs
    _yara = None
    YARA_AVAILABLE = False


_SEVERITY_BY_NAME = {
    "info": Severity.INFO,
    "low": Severity.LOW,
    "medium": Severity.MEDIUM,
    "high": Severity.HIGH,
    "critical": Severity.CRITICAL,
}

_CONFIDENCE_BY_NAME = {
    "high": ConfidenceLevel.HIGH,
    "medium": ConfidenceLevel.MEDIUM,
    "low": ConfidenceLevel.LOW,
    "none": ConfidenceLevel.NONE,
}

_MAX_STRING_HITS_PER_RULE = 20
_MAX_MATCHED_BYTES = 120
_DEFAULT_TIMEOUT_SECONDS = 60


def default_rules_directory() -> Path:
    """Locate the shipped rule tree relative to this package."""
    # New monorepo layout: analysis/rules/yara
    p = Path(__file__).resolve().parents[3] / "rules" / "yara"
    if p.is_dir():
        return p
    for fallback in [
        Path(__file__).resolve().parents[3] / "yara_rules",
        Path(__file__).resolve().parents[4] / "analysis" / "rules" / "yara",
    ]:
        if fallback.is_dir():
            return fallback
    return p


class YaraScanner:
    """Compiles a rule tree once and scans samples against it."""

    def __init__(
        self,
        rules_directory: str | Path | None = None,
        timeout_seconds: int = _DEFAULT_TIMEOUT_SECONDS,
    ) -> None:
        self._directory = Path(rules_directory) if rules_directory else default_rules_directory()
        self._timeout = timeout_seconds

        self._rules = None
        self._rule_files: tuple[str, ...] = ()
        self._rule_count = 0
        self._status = YaraStatus.COMPLETED
        self._error: str | None = None
        self._warnings: tuple[str, ...] = ()

        self._compile()

    # -- public ------------------------------------------------------------

    @property
    def available(self) -> bool:
        return self._rules is not None

    @property
    def rule_count(self) -> int:
        return self._rule_count

    @property
    def status(self) -> YaraStatus:
        return self._status

    def scan_bytes(self, name: str, data: bytes) -> YaraScanResult:
        """
        Scan an in-memory buffer — a decompressed container member.

        Required for APKs: their members are deflate-compressed, so scanning
        the file on disk sees compressed bytes and matches nothing at all.
        """
        if self._rules is None:
            return YaraScanResult(
                source=name,
                status=self._status,
                rules_loaded=self._rule_count,
                rule_files=self._rule_files,
                error=self._error,
                warnings=self._warnings,
            )

        try:
            raw_matches = self._rules.match(data=data, timeout=self._timeout)
        except Exception as error:  # noqa: BLE001 - yara raises its own error family
            _LOGGER.warning("YARA scan failed for member %s: %s", name, error)
            return YaraScanResult(
                source=name,
                status=YaraStatus.SCAN_FAILED,
                rules_loaded=self._rule_count,
                rule_files=self._rule_files,
                error=str(error),
            )

        return YaraScanResult(
            source=name,
            status=YaraStatus.COMPLETED,
            matches=self._ordered(tuple(self._normalize(m) for m in raw_matches)),
            rules_loaded=self._rule_count,
            rule_files=self._rule_files,
            warnings=self._warnings,
        )

    def scan(self, path: str | Path) -> YaraScanResult:
        """Scan one file, degrading to a described failure rather than raising."""
        source = Path(path)

        if self._rules is None:
            return YaraScanResult(
                source=str(source),
                status=self._status,
                rules_loaded=self._rule_count,
                rule_files=self._rule_files,
                error=self._error,
                warnings=self._warnings,
            )

        try:
            raw_matches = self._rules.match(str(source), timeout=self._timeout)
        except Exception as error:  # noqa: BLE001 - yara raises its own error family
            _LOGGER.warning("YARA scan failed for %s: %s", source, error)
            return YaraScanResult(
                source=str(source),
                status=YaraStatus.SCAN_FAILED,
                rules_loaded=self._rule_count,
                rule_files=self._rule_files,
                error=str(error),
                warnings=self._warnings,
            )

        return YaraScanResult(
            source=str(source),
            status=YaraStatus.COMPLETED,
            matches=self._ordered(tuple(self._normalize(m) for m in raw_matches)),
            rules_loaded=self._rule_count,
            rule_files=self._rule_files,
            warnings=self._warnings,
        )

    # -- internals ---------------------------------------------------------

    @staticmethod
    def _ordered(matches: tuple[YaraMatch, ...]) -> tuple[YaraMatch, ...]:
        """Most severe first — the report leads with the worst finding."""
        order = {Severity.CRITICAL: 0, Severity.HIGH: 1, Severity.MEDIUM: 2,
                 Severity.LOW: 3, Severity.INFO: 4}
        return tuple(sorted(matches, key=lambda m: (order.get(m.severity, 9), m.rule_name)))

    def _compile(self) -> None:
        if not YARA_AVAILABLE:
            self._status = YaraStatus.ENGINE_UNAVAILABLE
            self._error = (
                "yara-python is not installed; signature scanning did not run. "
                "Install it with `pip install yara-python` to enable this stage."
            )
            _LOGGER.warning(self._error)
            return

        if not self._directory.is_dir():
            self._status = YaraStatus.NO_RULES
            self._error = f"Rule directory not found: {self._directory}"
            _LOGGER.warning(self._error)
            return

        # Namespace per subdirectory, so a match reports whether it came from
        # the India-specific set or the generic set.
        sources: dict[str, str] = {}
        files: list[str] = []
        warnings: list[str] = []

        for rule_file in sorted(self._directory.rglob("*.yar")) + sorted(self._directory.rglob("*.yara")):
            try:
                text = rule_file.read_text(encoding="utf-8")
            except OSError as error:
                warnings.append(f"Unreadable rule file {rule_file.name}: {error}")
                continue
            namespace = rule_file.parent.name if rule_file.parent != self._directory else "default"
            sources[namespace] = sources.get(namespace, "") + "\n" + text
            files.append(str(rule_file.relative_to(self._directory)))

        if not sources:
            self._status = YaraStatus.NO_RULES
            self._error = f"No .yar rule files under {self._directory}"
            _LOGGER.warning(self._error)
            return

        try:
            self._rules = _yara.compile(sources=sources)
        except Exception as error:  # noqa: BLE001 - yara.SyntaxError and friends
            self._status = YaraStatus.COMPILE_FAILED
            self._error = f"Rule compilation failed: {error}"
            _LOGGER.error(self._error)
            self._rules = None
            return

        self._rule_files = tuple(files)
        self._rule_count = self._count_rules(sources)
        self._warnings = tuple(warnings)
        self._status = YaraStatus.COMPLETED

    @staticmethod
    def _count_rules(sources: dict[str, str]) -> int:
        total = 0
        for text in sources.values():
            for line in text.splitlines():
                stripped = line.strip()
                if stripped.startswith("rule ") or stripped.startswith("private rule "):
                    total += 1
        return total

    def _normalize(self, match) -> YaraMatch:
        """Turn a yara match object into the engine's own contract."""
        meta = getattr(match, "meta", {}) or {}

        severity = _SEVERITY_BY_NAME.get(str(meta.get("severity", "")).lower(), Severity.MEDIUM)
        confidence = _CONFIDENCE_BY_NAME.get(
            str(meta.get("confidence", "")).lower(), ConfidenceLevel.MEDIUM
        )
        mitre_raw = str(meta.get("mitre", ""))
        mitre = tuple(item.strip() for item in mitre_raw.split(",") if item.strip())

        return YaraMatch(
            rule_name=match.rule,
            namespace=getattr(match, "namespace", "") or "default",
            description=str(meta.get("description", "")),
            severity=severity,
            confidence=confidence,
            family=str(meta.get("family", "")),
            category=str(meta.get("category", "")),
            platform=str(meta.get("platform", "")),
            mitre=mitre,
            tags=tuple(getattr(match, "tags", ()) or ()),
            string_hits=self._string_hits(match),
        )

    @staticmethod
    def _string_hits(match) -> tuple[YaraStringHit, ...]:
        """
        Collect where each string matched, bounded and truncated.

        Matched bytes are evidence an investigator reads, so they are decoded
        leniently and capped — a rule that fires on ten thousand offsets must
        not put ten thousand rows in the report.
        """
        hits: list[YaraStringHit] = []
        for string_match in getattr(match, "strings", ()) or ():
            # yara-python 4.3+ exposes StringMatch objects with .instances;
            # older releases yield (offset, identifier, data) tuples.
            identifier = getattr(string_match, "identifier", None)
            if identifier is None and isinstance(string_match, tuple) and len(string_match) == 3:
                offset, identifier, data = string_match
                hits.append(YaraStringHit(
                    identifier=str(identifier),
                    offset=int(offset),
                    matched=_decode(data),
                ))
                continue

            for instance in getattr(string_match, "instances", ()) or ():
                hits.append(YaraStringHit(
                    identifier=str(identifier),
                    offset=int(getattr(instance, "offset", 0)),
                    matched=_decode(getattr(instance, "matched_data", b"")),
                ))
                if len(hits) >= _MAX_STRING_HITS_PER_RULE:
                    break
            if len(hits) >= _MAX_STRING_HITS_PER_RULE:
                break

        return tuple(hits[:_MAX_STRING_HITS_PER_RULE])


def _decode(data: bytes | str) -> str:
    if isinstance(data, str):
        text = data
    else:
        text = data.decode("utf-8", errors="replace")
    text = text.replace("\x00", "")
    return text[:_MAX_MATCHED_BYTES]
