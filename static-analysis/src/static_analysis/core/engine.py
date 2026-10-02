import dataclasses
import gzip
import logging
import os
import tempfile
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from static_analysis.apk.analyzer import ApkAnalyzer
from static_analysis.classification.bootstrap import create_threat_classifier
from static_analysis.container.members import is_container, iter_members
from static_analysis.classification.classifier import ThreatClassifier
from static_analysis.detection.bootstrap import create_file_type_detector
from static_analysis.entropy.bootstrap import create_entropy_analyzer
from static_analysis.entropy.service import EntropyAnalysisService
from static_analysis.ioc.bootstrap import create_ioc_extractor
from static_analysis.ioc.extractor import StringIocExtractor
from static_analysis.storage.repository import AnalysisResultRepository
from static_analysis.yara_scan.bootstrap import create_yara_scanner
from static_analysis.yara_scan.models import YaraScanResult
from static_analysis.yara_scan.scanner import YaraScanner
from static_analysis.detection.service import FileTypeDetectionService
from static_analysis.domain.enums import AnalysisStatus, TargetFormat
from static_analysis.domain.models import AnalysisContext, AnalysisReport, AnalysisTarget, AnalyzerOutcome
from static_analysis.elf.analyzer import ElfAnalyzer
from static_analysis.hashing.bootstrap import create_hash_engine
from static_analysis.hashing.engine import HashEngine
from static_analysis.mach_o.analyzer import MachOAnalyzer
from static_analysis.metadata.bootstrap import create_metadata_extractor
from static_analysis.metadata.service import MetadataExtractionService
from static_analysis.packing.bootstrap import create_packing_detector, create_unpacker
from static_analysis.packing.detector import PackerDetector
from static_analysis.packing.unpacker import UpxUnpacker
from static_analysis.pe.analyzer import PeAnalyzer
from static_analysis.rules.bootstrap import create_rule_engine
from static_analysis.rules.engine import RuleEngine
from static_analysis.rules.models import RuleContext, RuleMatch
from static_analysis.strings.bootstrap import create_string_extractor
from static_analysis.strings.explain import explain_string
from static_analysis.strings.service import StringExtractionService
from static_analysis.core.registry import AnalyzerRegistry

_MAX_UNPACK_RECURSION_DEPTH = 1

# Cap on the combined decompressed view held in memory for cross-member rule
# matching. Members arrive manifest-and-DEX first, so the bytes that carry the
# behaviour are inside this bound even for a very large APK.
_MAX_COMBINED_SCAN_BYTES = 32 * 1024 * 1024
_MAX_CONTAINER_MEMBER_BYTES = 200 * 1024 * 1024  # 200MB cap on any single extracted archive member

_LOGGER = logging.getLogger(__name__)


class StaticAnalysisEngine:
    """Production static analysis engine executing the complete 9-step orchestration pipeline."""

    def __init__(
        self,
        registry: AnalyzerRegistry | None = None,
        detector: FileTypeDetectionService | None = None,
        metadata_service: MetadataExtractionService | None = None,
        hasher: HashEngine | None = None,
        string_service: StringExtractionService | None = None,
        rule_engine: RuleEngine | None = None,
        packing_detector: PackerDetector | None = None,
        unpacker: UpxUnpacker | None = None,
        yara_scanner: YaraScanner | None = None,
        ioc_extractor: StringIocExtractor | None = None,
        entropy_analyzer: EntropyAnalysisService | None = None,
        classifier: ThreatClassifier | None = None,
        repository: AnalysisResultRepository | None = None,
    ) -> None:
        self._hasher = hasher or create_hash_engine()
        self._detector = detector or create_file_type_detector(analyzers=registry)
        self._metadata = metadata_service or create_metadata_extractor(analyzers=registry)
        self._strings = string_service or create_string_extractor(analyzers=registry)
        self._rules = rule_engine or create_rule_engine()
        self._packing_detector = packing_detector or create_packing_detector()
        self._unpacker = unpacker or create_unpacker()
        self._registry = registry or AnalyzerRegistry()

        # Rule compilation happens once here, not per sample — a batch of two
        # hundred seized samples should pay that cost a single time.
        self._yara = yara_scanner or create_yara_scanner()
        self._iocs = ioc_extractor or create_ioc_extractor()
        self._entropy = entropy_analyzer or create_entropy_analyzer()
        self._classifier = classifier or create_threat_classifier()

        # Optional: when absent, analyze() returns the report without storing
        # it, which is what the unit tests and one-off CLI runs want.
        self._repository = repository

        # Auto-register all core format analyzers
        self._register_default_analyzers()

    def _register_default_analyzers(self) -> None:
        """Automatically register APK, PE, ELF, and Mach-O format analyzers."""
        try:
            self._registry.register(lambda: ApkAnalyzer(self._detector, self._metadata, self._strings))
        except Exception:
            pass
        try:
            self._registry.register(lambda: PeAnalyzer(self._metadata, self._strings, self._rules))
        except Exception:
            pass
        try:
            self._registry.register(lambda: ElfAnalyzer(self._metadata, self._strings, self._rules))
        except Exception:
            pass
        try:
            self._registry.register(lambda: MachOAnalyzer(self._metadata, self._strings, self._rules))
        except Exception:
            pass

    @property
    def registry(self) -> AnalyzerRegistry:
        return self._registry

    def analyze(self, file_path: str | Path, _depth: int = 0) -> dict[str, Any]:
        """
        Executes the unified static analysis pipeline:
         1. Validation
         2. File type detection
         3. Metadata extraction
         4. Hash generation
         5. String extraction
         6. Analyzer selection and format parsing
         7. Rule engine evaluation
         8. Packing detection and best-effort unpacking
         9. YARA signature scanning (file and, for containers, every member)
        10. Indicator extraction
        11. Entropy analysis
        12. Threat classification
        13. Report assembly
        14. Persistence, when a repository is configured

        `_depth` guards the internal recursive re-analysis performed for a
        successfully unpacked binary (and for an extracted archive member, see
        `_maybe_unwrap_container`) — callers should never pass it directly.
        """
        source = Path(file_path)

        # Step 1: Validation
        if not source.exists():
            raise FileNotFoundError(f"File not found: {source}")
        if not source.is_file():
            raise ValueError(f"Path is not a regular file: {source}")
        if source.stat().st_size == 0:
            raise ValueError(f"File is empty (0 bytes): {source}")

        # Step 2: File Type Detection
        detection = self._detector.detect(source)
        declared_format = detection.target_format

        # A bare zip/gzip-wrapped payload (e.g. a sample shared as
        # "sample.exe.zip" to slip past attachment filters) won't match any
        # known format signature directly — APK is already handled above
        # since ApkDetector recognizes the ZIP + AndroidManifest.xml combination.
        # Unwrap one level and re-run the full pipeline on the inner file,
        # merging in a "container" marker, instead of reporting UNKNOWN.
        if declared_format is None and _depth < _MAX_UNPACK_RECURSION_DEPTH:
            unwrapped = self._maybe_unwrap_container(source)
            if unwrapped is not None:
                inner_path, container_info = unwrapped
                try:
                    inner_report = self.analyze(inner_path, _depth=_depth + 1)
                    inner_report["container"] = container_info
                    return inner_report
                finally:
                    inner_path.unlink(missing_ok=True)

        # Step 3: Metadata Extraction
        metadata = self._metadata.extract(source)

        # Step 4: Hash Generation
        hashes = self._hasher.calculate(source)

        # Step 5: String Extraction
        strings_result = self._strings.extract(source, metadata)
        extracted_strings = strings_result.strings

        # Step 6: Analyzer Selection & Execution
        analyzers = list(self._registry.for_format(declared_format)) if declared_format is not None else []
        outcomes: list[AnalyzerOutcome] = []
        target = AnalysisTarget(reference=str(source), declared_format=declared_format)
        context = AnalysisContext(correlation_id=source.name, requested_at=datetime.now(timezone.utc))

        format_details: dict[str, Any] = {}
        format_rule_matches: list[RuleMatch] = []
        if analyzers:
            for analyzer in analyzers:
                if analyzer.supports(target):
                    outcome = analyzer.analyze(target, context)
                    outcomes.append(outcome)
                    # Run format specific extract method
                    if hasattr(analyzer, "extract"):
                        try:
                            res = analyzer.extract(source)
                            if getattr(res, "info", None) is not None:
                                # NOTE: format info models are frozen, slotted dataclasses
                                # (no __dict__), so dataclasses.asdict() is required here —
                                # `res.info.__dict__` silently returns {} for every one of
                                # them and previously dropped all format-specific facts
                                # (permissions, packing/entropy indicators, imports, signature)
                                # before they ever reached the rule engine.
                                format_details = dataclasses.asdict(res.info)
                            format_rule_matches.extend(self._collect_format_matches(res))
                        except Exception as err:
                            _LOGGER.warning("Format extraction failed: %s", err)

        dangerous_permissions = ()
        security_flags = format_details.get("security_flags") if isinstance(format_details, dict) else None
        if isinstance(security_flags, dict):
            dangerous_permissions = tuple(security_flags.get("dangerous_permissions", ()))

        # Step 7: Rule Engine Evaluation (format-agnostic facts: extracted strings,
        # embedded network indicators, and the dangerous-permission cross-check)
        rule_ctx = RuleContext(
            analyzer_id="unified.static",
            strings=extracted_strings,
            dangerous_permissions=dangerous_permissions,
        )
        rule_eval = self._rules.evaluate(rule_ctx)

        # Merge the format-agnostic matches with each analyzer's own format-specific
        # matches (packing, entropy, suspicious imports, signature, APK permissions),
        # de-duplicating by rule_id so a rule firing in both contexts (e.g. suspicious
        # strings, which every analyzer's context also carries) isn't reported twice.
        merged_matches: dict[str, RuleMatch] = {}
        for match in (*format_rule_matches, *rule_eval.matches):
            merged_matches.setdefault(match.rule_id, match)
        combined_matches = tuple(merged_matches.values())
        combined_risk_score = self._rules.score(combined_matches)

        # Packing detection + best-effort unpacking (runs on both packed/compressed
        # samples and plain/uncompressed ones — for the latter this simply reports
        # is_packed=False without attempting to unpack anything).
        packing_report = self._analyze_packing(source, format_details, _depth)

        # Flag stripped/packed binary with low plaintext strings (< 10)
        if len(extracted_strings) < 10:
            evidence = list(packing_report.get("evidence", []))
            if "Binary stripped or packed (low plaintext strings)" not in evidence:
                evidence.append("Binary stripped or packed (low plaintext strings)")
                packing_report["evidence"] = evidence

        # Step 8: Threat Signature Matching
        yara_matches = []
        for match in combined_matches:
            yara_matches.append({
                "rule_name": match.rule_id,
                "category": match.category.value if hasattr(match.category, "value") else str(match.category),
                "severity": match.severity.value if hasattr(match.severity, "value") else str(match.severity),
                "description": match.description,
            })

        # Step 9: Unified Analysis Report Assembly
        urls = [
            s.value for s in extracted_strings
            if hasattr(s, "string_type") and str(s.string_type) in ("StringType.URL", "url")
            and len(s.value) >= 10 and not any(s.value.lower().startswith(b) for b in ("http/1.", "http/2", "httponly", "httpu", "http-equiv"))
        ]
        ips = [s.value for s in extracted_strings if hasattr(s, "string_type") and str(s.string_type) in ("StringType.IPV4", "ipv4")]
        keywords = [s.value for s in extracted_strings if any(kw in s.value.lower() for kw in ("cmd", "powershell", "shell", "c2", "socket", "intercept"))]

        # Detailed, investigator-facing explanation for every string worth flagging —
        # not just the bare matched value (see strings/explain.py).
        explained_strings = []
        for item in extracted_strings:
            explanation = explain_string(item)
            if explanation is not None:
                explained_strings.append({
                    "value": explanation.value,
                    "type": explanation.string_type.value,
                    "category": explanation.category,
                    "explanation": explanation.explanation,
                    "severity": explanation.severity,
                })
            if len(explained_strings) >= 25:
                break

        file_type_str = declared_format.value if declared_format is not None else detection.file_format.value
        if file_type_str == "pe":
            if str(detection.file_type) in ("DetectedFileType.WINDOWS_DYNAMIC_LIBRARY", "windows_dynamic_library"):
                file_type_str = "dll"
            elif str(detection.file_type) in ("DetectedFileType.WINDOWS_EXECUTABLE", "windows_executable"):
                file_type_str = "exe"
        if file_type_str == "unknown":
            file_type_str = source.suffix.lstrip(".").lower() or "bin"

        platform = "android" if file_type_str == "apk" else "windows" if file_type_str in ("exe", "dll", "pe") else "linux" if file_type_str == "elf" else "macos"

        # Step 10: YARA signature scanning (including the India-specific scam set).
        # For a container this must run over decompressed members — see
        # _scan_container_members for why scanning the file alone finds nothing.
        yara_result = self._yara.scan(source)
        member_strings: tuple[Any, ...] = ()
        member_evidence: dict[str, list[str]] = {}

        if is_container(source):
            yara_result, member_strings, member_evidence = self._scan_container_members(
                source, yara_result
            )

        # Step 11: Indicator extraction — validated, scoped, deduplicated
        ioc_result = self._iocs.extract(
            str(source), tuple(extracted_strings) + member_strings
        )

        # Step 12: Entropy analysis — whole file, windowed, and per container
        # member, which is the only way an APK gets a packing verdict at all
        # (a zip has no sections for the format analyzers to measure).
        section_entropies = self._section_entropies(format_details)
        entropy_result = self._entropy.analyze(source, section_entropies)

        # Step 13: Threat classification — one verdict, with its reasons
        classification = self._classifier.classify(
            yara=yara_result,
            rule_matches=combined_matches,
            rule_score=combined_risk_score.value,
            entropy=entropy_result,
            iocs=ioc_result,
            dangerous_permissions=tuple(dangerous_permissions),
            file_type=file_type_str,
        )

        # Signature matches join the rule matches under `yara_matches` so the
        # existing dashboard and report consumers see both without a change.
        for match in yara_result.matches:
            yara_matches.append({
                "rule_name": match.rule_name,
                "namespace": match.namespace,
                # Which file inside the container carried it: "classes.dex" is
                # evidence, "somewhere in the APK" is not.
                "located_in": member_evidence.get(match.rule_name, []),
                "category": match.category or "signature",
                "severity": match.severity.value,
                "description": match.description,
                "family": match.family,
                "mitre": list(match.mitre),
                "matched_strings": [
                    {"identifier": hit.identifier, "offset": hit.offset, "value": hit.matched}
                    for hit in match.string_hits[:5]
                ],
            })

        report = {
            "sample_id": f"ER-{hashes.sha256[:8].upper() if hashes and hashes.sha256 else '00000000'}",
            "sha256": hashes.sha256 if hashes else "",
            "md5": hashes.md5 if hashes else "",
            "sha1": hashes.sha1 if hashes else "",
            "file_name": source.name,
            "platform": platform,
            "file_type": file_type_str,
            "architecture": format_details.get("architecture") if isinstance(format_details, dict) else None,
            "file_size_bytes": metadata.file_size if metadata else source.stat().st_size,
            "submitted_at": datetime.now(timezone.utc).isoformat(),
            "yara_matches": yara_matches,
            "extracted_strings": {
                "urls": urls[:10],
                "ips": ips[:10],
                "suspicious_keywords": keywords[:15],
            },
            "explained_strings": explained_strings,
            "format_details": format_details,
            "risk_score": classification.risk_score,
            "rule_risk_score": combined_risk_score.value,
            "packing": packing_report,
            "container": None,
            "signatures": self._serialize_yara(yara_result),
            "iocs": self._serialize_iocs(ioc_result),
            "entropy": self._serialize_entropy(entropy_result),
            "classification": self._serialize_classification(classification),
        }

        # Step 14: Persist. Only the top-level analysis is stored — an unpacked
        # or unwrapped inner file is evidence about the original sample, not a
        # separate case.
        if self._repository is not None and _depth == 0:
            try:
                self._repository.save(report)
            except Exception as err:  # noqa: BLE001 - storage must not fail an analysis
                _LOGGER.warning("Failed to store analysis report: %s", err)

        return report

    # ------------------------------------------------------------------
    # Container-aware scanning
    # ------------------------------------------------------------------

    def _scan_container_members(self, source: Path, file_result: Any):
        """
        Scan decompressed container members and merge the results.

        This is not an optimization, it is a correctness requirement. An APK
        stores its members deflate-compressed, so scanning the file on disk
        sees compressed bytes: the DEX, the manifest and every string in them
        are invisible, and every Android signature matches nothing at all.
        A ZIP_STORED test fixture hides this completely — which is exactly how
        a rule set passes its tests and detects nothing in the field.

        Matches are deduplicated by rule name, keeping the member that carried
        each one, because "the OTP interceptor is in classes.dex" is evidence
        and "somewhere in the APK" is not.
        """
        merged: dict[str, Any] = {match.rule_name: match for match in file_result.matches}
        member_evidence: dict[str, list[str]] = {
            match.rule_name: [source.name] for match in file_result.matches
        }
        collected: list[Any] = []
        warnings = list(file_result.warnings)

        # A combined view is required as well as the per-member one. An APK
        # declares its permissions in AndroidManifest.xml and implements the
        # behaviour in classes.dex, so a rule that requires both — which is
        # most of the useful ones — matches neither member on its own.
        combined_buffer: list[bytes] = []
        combined_bytes = 0

        for member in iter_members(source):
            member_result = self._yara.scan_bytes(member.name, member.data)
            for match in member_result.matches:
                member_evidence.setdefault(match.rule_name, []).append(member.name)
                merged.setdefault(match.rule_name, match)

            if combined_bytes < _MAX_COMBINED_SCAN_BYTES:
                combined_buffer.append(member.data)
                combined_bytes += len(member.data)

            try:
                collected.extend(self._strings.extract_from_bytes(member.name, member.data))
            except Exception as error:  # noqa: BLE001 - one bad member must not stop the scan
                _LOGGER.warning("String extraction failed for member %s: %s",
                                member.name, error)
                warnings.append(f"Unreadable member {member.name}")

        if combined_buffer:
            # A separator keeps two members' bytes from forming a string that
            # exists in neither of them.
            whole = b"\x00".join(combined_buffer)
            for match in self._yara.scan_bytes(f"{source.name} (all members)", whole).matches:
                member_evidence.setdefault(match.rule_name, []).append("multiple members")
                merged.setdefault(match.rule_name, match)

        combined = YaraScanResult(
            source=str(source),
            status=file_result.status,
            matches=tuple(merged.values()),
            rules_loaded=file_result.rules_loaded,
            rule_files=file_result.rule_files,
            error=file_result.error,
            warnings=tuple(warnings),
        )
        return combined, tuple(collected), member_evidence

    # ------------------------------------------------------------------
    # Serialization for the report contract
    # ------------------------------------------------------------------

    @staticmethod
    def _section_entropies(format_details: dict[str, Any]) -> dict[str, float]:
        """Pull per-section entropy out of the format-specific info, if present."""
        entropies: dict[str, float] = {}
        if not isinstance(format_details, dict):
            return entropies

        for section in format_details.get("sections") or []:
            if isinstance(section, dict) and isinstance(section.get("entropy"), (int, float)):
                entropies[str(section.get("name", "?"))] = float(section["entropy"])

        for architecture in format_details.get("architectures") or []:
            if not isinstance(architecture, dict):
                continue
            arch_name = architecture.get("architecture", "arch")
            for section in architecture.get("sections") or []:
                if isinstance(section, dict) and isinstance(section.get("entropy"), (int, float)):
                    entropies[f"{arch_name}:{section.get('name', '?')}"] = float(section["entropy"])

        return entropies

    @staticmethod
    def _serialize_yara(result: Any) -> dict[str, Any]:
        return {
            "status": result.status.value,
            "rules_loaded": result.rules_loaded,
            "match_count": len(result.matches),
            "india_scam_matches": [m.rule_name for m in result.india_scam_matches],
            "families": list(result.families),
            "mitre_techniques": list(result.mitre_techniques),
            "highest_severity": result.highest_severity.value if result.highest_severity else None,
            "error": result.error,
        }

    @staticmethod
    def _serialize_iocs(result: Any) -> dict[str, Any]:
        def render(indicator: Any) -> dict[str, Any]:
            return {
                "value": indicator.value,
                "type": indicator.ioc_type.value,
                "scope": indicator.scope.value,
                "confidence": indicator.confidence.value,
                "defanged": indicator.defanged,
                "occurrences": indicator.occurrences,
                "note": indicator.note,
            }

        return {
            "status": result.status.value,
            "counts_by_type": result.counts_by_type,
            "total": len(result.indicators),
            # The actionable set is what an investigator works from; the full
            # inventory stays available but is not what leads the report.
            "actionable": [render(indicator) for indicator in result.actionable[:50]],
            "all": [render(indicator) for indicator in result.indicators[:200]],
            "error": result.error,
        }

    @staticmethod
    def _serialize_entropy(result: Any) -> dict[str, Any]:
        return {
            "status": result.status.value,
            "overall_entropy": result.overall_entropy,
            "classification": result.classification.value,
            "is_container": result.is_container,
            "is_likely_packed": result.is_likely_packed,
            "packing_evidence": list(result.packing_evidence),
            "high_entropy_regions": [
                {
                    "start_offset": region.start_offset,
                    "end_offset": region.end_offset,
                    "size": region.size,
                    "mean_entropy": region.mean_entropy,
                    "reaches_end_of_file": region.reaches_end_of_file,
                }
                for region in result.high_entropy_regions[:20]
            ],
            "embedded_blobs": [
                {
                    "name": blob.name,
                    "size": blob.size,
                    "entropy": blob.entropy,
                    "declared_kind": blob.declared_kind,
                    "reason": blob.reason,
                }
                for blob in result.embedded_blobs[:20]
            ],
            "component_entropies": result.component_entropies,
            "error": result.error,
        }

    @staticmethod
    def _serialize_classification(classification: Any) -> dict[str, Any]:
        return {
            "verdict": classification.verdict.value,
            "confidence": classification.confidence.value,
            "risk_score": classification.risk_score,
            "risk_band": classification.risk_band.value,
            "primary_family": classification.primary_family.value,
            "families": [family.value for family in classification.families],
            "scam_type": classification.scam_type.value,
            "capabilities": list(classification.capabilities),
            "mitre_techniques": list(classification.mitre_techniques),
            "summary": classification.summary,
            "limitations": list(classification.limitations),
            "reasons": [
                {
                    "summary": reason.summary,
                    "severity": reason.severity.value,
                    "source": reason.source,
                    "evidence": list(reason.evidence),
                }
                for reason in classification.reasons
            ],
        }

    def _maybe_unwrap_container(self, source: Path) -> tuple[Path, dict[str, Any]] | None:
        """Best-effort, single-level extraction of a bare zip/gzip-wrapped sample.

        Deliberately conservative (one level deep, size-capped, single member)
        to avoid decompression-bomb risk while still covering the common case
        of a sample shared as a plain archive around an executable/APK.
        Returns `None` when the file isn't a recognizable/safe container —
        the caller then falls through to reporting an unknown format as before.
        """
        try:
            header = source.open("rb").read(4)
        except OSError:
            return None

        if header[:4] in (b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08"):
            return self._unwrap_zip(source)
        if header[:2] == b"\x1f\x8b":
            return self._unwrap_gzip(source)
        return None

    def _unwrap_zip(self, source: Path) -> tuple[Path, dict[str, Any]] | None:
        try:
            with zipfile.ZipFile(source) as archive:
                members = [item for item in archive.infolist() if not item.is_dir()]
                if not members:
                    return None
                if any(item.file_size > _MAX_CONTAINER_MEMBER_BYTES for item in members):
                    _LOGGER.warning("Skipping container unwrap: member exceeds size cap in %s", source)
                    return None
                largest = max(members, key=lambda item: item.file_size)
                payload = archive.read(largest.filename)
        except (OSError, zipfile.BadZipFile) as error:
            _LOGGER.warning("Failed to unwrap zip container %s: %s", source, error)
            return None

        suffix = Path(largest.filename).suffix or ".bin"
        output_path = self._write_temp_file(payload, prefix="sentinel_container_", suffix=suffix)
        return output_path, {"type": "zip", "original_entry": largest.filename}

    def _unwrap_gzip(self, source: Path) -> tuple[Path, dict[str, Any]] | None:
        try:
            with gzip.open(source, "rb") as stream:
                payload = stream.read(_MAX_CONTAINER_MEMBER_BYTES + 1)
        except OSError as error:
            _LOGGER.warning("Failed to unwrap gzip container %s: %s", source, error)
            return None

        if len(payload) > _MAX_CONTAINER_MEMBER_BYTES:
            _LOGGER.warning("Skipping container unwrap: decompressed content exceeds size cap in %s", source)
            return None

        inner_name = source.stem if source.suffix.lower() == ".gz" else source.name
        suffix = Path(inner_name).suffix or ".bin"
        output_path = self._write_temp_file(payload, prefix="sentinel_container_", suffix=suffix)
        return output_path, {"type": "gzip", "original_entry": inner_name}

    @staticmethod
    def _write_temp_file(payload: bytes, *, prefix: str, suffix: str) -> Path:
        """Write `payload` to a fresh temp file and return its path.

        Uses `tempfile.mkstemp` for a collision-safe name but immediately closes
        the low-level file descriptor it returns — leaving it open (a bug fixed
        here) holds a lock on Windows that then blocks `Path.unlink()` on the
        very file the caller writes and later cleans up.
        """
        import os

        fd, raw_path = tempfile.mkstemp(prefix=prefix, suffix=suffix)
        os.close(fd)
        output_path = Path(raw_path)
        output_path.write_bytes(payload)
        return output_path

    def _analyze_packing(self, source: Path, format_details: dict[str, Any], depth: int) -> dict[str, Any]:
        """Detect packing and, best-effort, unpack + re-analyze the unpacked binary.

        Always returns a fully-populated dict — an unavailable/failed unpack never
        raises or blocks the surrounding `analyze()` call, matching this module's
        existing "controlled failure" style (see hashing/metadata/string services).
        """
        is_packed, suspicious_section_names, high_entropy_sections = self._packing_indicators(format_details)
        finding = self._packing_detector.detect(
            is_packed=is_packed,
            suspicious_section_names=suspicious_section_names,
            high_entropy_sections=high_entropy_sections,
        )

        report: dict[str, Any] = {
            "is_packed": finding.is_packed,
            "packer_name": finding.packer_name,
            "confidence": finding.confidence,
            "evidence": list(finding.evidence),
            "unpack_attempted": False,
            "unpack_succeeded": False,
            "unpack_method": None,
            "unpack_error": None,
            "unpacked_sha256": None,
            "unpacked_yara_matches": [],
            "unpacked_extracted_strings": {},
        }

        if not finding.is_packed or depth >= _MAX_UNPACK_RECURSION_DEPTH:
            return report

        unpack_result = self._unpacker.unpack(source)
        report["unpack_attempted"] = unpack_result.attempted
        report["unpack_succeeded"] = unpack_result.succeeded
        report["unpack_method"] = unpack_result.method
        report["unpack_error"] = unpack_result.error

        if unpack_result.succeeded and unpack_result.output_path:
            unpacked_path = Path(unpack_result.output_path)
            try:
                unpacked_report = self.analyze(unpacked_path, _depth=depth + 1)
                report["unpacked_sha256"] = unpacked_report.get("sha256")
                report["unpacked_yara_matches"] = unpacked_report.get("yara_matches", [])
                report["unpacked_extracted_strings"] = unpacked_report.get("extracted_strings", {})
            except Exception as err:  # noqa: BLE001 - unpacked re-analysis is best-effort
                _LOGGER.warning("Unpacked-binary re-analysis failed: %s", err)
                report["unpack_error"] = f"reanalysis_failed: {err}"
            finally:
                unpacked_path.unlink(missing_ok=True)

        return report

    def _packing_indicators(self, format_details: dict[str, Any]) -> tuple[bool, tuple[str, ...], tuple[str, ...]]:
        """Pull (is_packed, suspicious_section_names, high_entropy_sections) out of
        the asdict'd format-specific info, tolerant of each format's differing shape
        (PE/ELF carry indicators directly; Mach-O carries them per architecture)."""
        if not isinstance(format_details, dict):
            return False, (), ()

        indicators = format_details.get("indicators")
        if isinstance(indicators, dict):
            is_packed = bool(indicators.get("packed", False))
            high_entropy = tuple(indicators.get("high_entropy_sections") or ())
            suspicious_names = tuple(indicators.get("suspicious_section_names") or ())
            if not suspicious_names:
                # PE indicators don't carry suspicious_section_names directly —
                # derive them from each section's own flat "suspicious" flag instead.
                sections = format_details.get("sections") or []
                suspicious_names = tuple(
                    section.get("name", "")
                    for section in sections
                    if isinstance(section, dict) and section.get("suspicious")
                )
            return is_packed, suspicious_names, high_entropy

        architectures = format_details.get("architectures")
        if isinstance(architectures, list):
            is_packed = False
            suspicious_names: list[str] = []
            high_entropy: list[str] = []
            for architecture in architectures:
                if not isinstance(architecture, dict):
                    continue
                arch_indicators = architecture.get("indicators") or {}
                is_packed = is_packed or bool(arch_indicators.get("packed", False))
                suspicious_names.extend(arch_indicators.get("suspicious_section_names") or ())
                high_entropy.extend(arch_indicators.get("high_entropy_sections") or ())
            return is_packed, tuple(suspicious_names), tuple(high_entropy)

        return False, (), ()

    def _collect_format_matches(self, result: Any) -> list[RuleMatch]:
        """Gather rule matches contributed by one format analyzer's result.

        PE/ELF/Mach-O analyzers already evaluate their own `RuleContext` (packing,
        entropy, suspicious imports, signature status) and attach the outcome as
        `result.rules` — reuse it directly instead of re-deriving those facts here.
        APK doesn't carry its own rule evaluation, so build a small `RuleContext`
        from the already-parsed manifest facts (dangerous permissions, obfuscation
        indicators) and evaluate it now.
        """
        rules_result = getattr(result, "rules", None)
        if rules_result is not None:
            return list(rules_result.matches)

        info = getattr(result, "info", None)
        security_flags = getattr(info, "security_flags", None)
        if info is not None and security_flags is not None:
            structure = getattr(info, "structure", None)
            apk_context = RuleContext(
                analyzer_id="apk.static",
                dangerous_permissions=security_flags.dangerous_permissions,
                suspicious_metadata=structure.obfuscation_indicators if structure is not None else (),
            )
            return list(self._rules.evaluate(apk_context).matches)
        return []
