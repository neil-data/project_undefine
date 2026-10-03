"""Registry-compatible static APK analyzer built on manifest and ZIP inspection."""

import re
import struct
import zipfile
from pathlib import Path

from static_analysis.analyzers.base import Analyzer, AnalyzerDescriptor
from static_analysis.apk.axml import ManifestParseError, XmlNode, parse_manifest
from static_analysis.apk.models import (
    ApkAnalysisResult, ApkCertificate, ApkComponent, ApkInfo, ApkIntentFilter, ApkPermission,
    ApkSecurityFlags, ApkStructureInfo,
)
from static_analysis.detection.models import FileFormat
from static_analysis.detection.service import FileTypeDetectionService
from static_analysis.domain.enums import AnalysisStatus, TargetFormat
from static_analysis.domain.models import AnalysisContext, AnalysisTarget, AnalyzerOutcome
from static_analysis.metadata.contracts import MetadataService
from static_analysis.metadata.models import MetadataStatus
from static_analysis.strings.contracts import StringExtractionServiceContract

_ANDROID = "android:"
_DANGEROUS = frozenset({
    "android.permission.READ_CALENDAR", "android.permission.WRITE_CALENDAR", "android.permission.CAMERA",
    "android.permission.READ_CONTACTS", "android.permission.WRITE_CONTACTS", "android.permission.GET_ACCOUNTS",
    "android.permission.ACCESS_FINE_LOCATION", "android.permission.ACCESS_COARSE_LOCATION", "android.permission.RECORD_AUDIO",
    "android.permission.READ_PHONE_STATE", "android.permission.CALL_PHONE", "android.permission.READ_CALL_LOG",
    "android.permission.WRITE_CALL_LOG", "android.permission.ADD_VOICEMAIL", "android.permission.USE_SIP",
    "android.permission.PROCESS_OUTGOING_CALLS", "android.permission.BODY_SENSORS", "android.permission.SEND_SMS",
    "android.permission.RECEIVE_SMS", "android.permission.READ_SMS", "android.permission.RECEIVE_WAP_PUSH",
    "android.permission.RECEIVE_MMS", "android.permission.READ_EXTERNAL_STORAGE", "android.permission.WRITE_EXTERNAL_STORAGE",
})
_URL = re.compile(r"(?:https?|ftp)://[^\s\"'<>]+", re.IGNORECASE)
_DOMAIN = re.compile(r"(?<![A-Z0-9.-])(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+[A-Z]{2,63}(?![A-Z0-9.-])", re.IGNORECASE)


class ApkAnalyzer(Analyzer):
    """Performs static manifest and archive inspection without loading APK code."""

    def __init__(
        self, detector: FileTypeDetectionService, metadata_service: MetadataService,
        string_service: StringExtractionServiceContract,
    ) -> None:
        self._detector = detector
        self._metadata_service = metadata_service
        self._string_service = string_service

    @property
    def descriptor(self) -> AnalyzerDescriptor:
        return AnalyzerDescriptor("apk.static", "1.0", frozenset({TargetFormat.APK}), "Static APK archive analyzer")

    def supports(self, target: AnalysisTarget) -> bool:
        return target.declared_format is TargetFormat.APK

    def analyze(self, target: AnalysisTarget, context: AnalysisContext) -> AnalyzerOutcome:
        result = self.extract(target.reference)
        return AnalyzerOutcome(
            analyzer_id=self.descriptor.identifier,
            status=AnalysisStatus.COMPLETED if result.info else AnalysisStatus.FAILED,
            warnings=(result.error,) if result.error else (),
            attributes={"package_name": result.info.package_name or ""} if result.info else {},
        )

    def extract(self, path: str | Path) -> ApkAnalysisResult:
        """Return APK-specific static facts or a controlled parsing error."""
        source = Path(path)
        metadata = self._metadata_service.extract(source)
        if metadata.status is MetadataStatus.FAILED:
            return ApkAnalysisResult(str(source), None, metadata, (), metadata.failure.value if metadata.failure else "metadata_failed")
        detection = self._detector.detect(source)
        if detection.file_format is not FileFormat.APK:
            return ApkAnalysisResult(str(source), None, metadata, (), "unsupported_apk")
        strings = self._string_service.extract(source, metadata).strings
        try:
            with zipfile.ZipFile(source) as archive:
                manifest = archive.read("AndroidManifest.xml")
                root = parse_manifest(manifest)
                return ApkAnalysisResult(str(source), self._build_info(root, archive, metadata.file_size or 0), metadata, strings)
        # Python raises RuntimeError for encrypted ZIP entries. Keep the case analysable even when the manifest cannot be decrypted.
        except (KeyError, OSError, RuntimeError, NotImplementedError, zipfile.BadZipFile, ManifestParseError) as error:
            return ApkAnalysisResult(str(source), None, metadata, strings, self._error_name(error))

    def _build_info(self, root: XmlNode, archive: zipfile.ZipFile, apk_size: int) -> ApkInfo:
        if root.name != "manifest":
            raise ManifestParseError("Manifest root element is missing")
        manifest_attributes = tuple(sorted(root.attributes.items()))
        app = _child(root, "application")
        components = {kind: self._components(app, kind) for kind in ("activity", "service", "receiver", "provider")}
        requested = tuple(self._permission(node, True) for node in _children(root, "uses-permission"))
        custom = tuple(self._permission(node, False) for node in _children(root, "permission"))
        all_components = tuple(component for group in components.values() for component in group)
        security = self._security(root, app, requested, all_components)
        structure = self._structure(archive, apk_size, all_components)
        values = " ".join(value for _, value in manifest_attributes)
        if app:
            values += " " + " ".join(app.attributes.values())
        return ApkInfo(
            package_name=root.attributes.get("package"), version_name=root.attributes.get(_ANDROID + "versionName"),
            version_code=root.attributes.get(_ANDROID + "versionCode"), min_sdk=_sdk(root, "minSdkVersion"),
            target_sdk=_sdk(root, "targetSdkVersion"), compile_sdk=root.attributes.get(_ANDROID + "compileSdkVersion"),
            application_label=app.attributes.get(_ANDROID + "label") if app else None,
            application_class=app.attributes.get(_ANDROID + "name") if app else None,
            activities=components["activity"], services=components["service"], receivers=components["receiver"], providers=components["provider"],
            requested_permissions=requested, custom_permissions=custom,
            features=tuple(node.attributes.get(_ANDROID + "name", "") for node in _children(root, "uses-feature") if node.attributes.get(_ANDROID + "name")),
            certificates=self._certificates(archive), manifest_attributes=manifest_attributes,
            manifest_urls=tuple(sorted(set(_URL.findall(values)))), manifest_domains=tuple(sorted(set(_DOMAIN.findall(values)))),
            security_flags=security, structure=structure,
        )

    def _components(self, app: XmlNode | None, kind: str) -> tuple[ApkComponent, ...]:
        if not app:
            return ()
        return tuple(self._component(node, kind) for node in _children(app, kind))

    def _component(self, node: XmlNode, kind: str) -> ApkComponent:
        filters = tuple(_intent_filter(item) for item in _children(node, "intent-filter"))
        exported = _boolean(node.attributes.get(_ANDROID + "exported"))
        if exported is None and filters:
            exported = True
        return ApkComponent(node.attributes.get(_ANDROID + "name", ""), kind, exported, _boolean(node.attributes.get(_ANDROID + "enabled")), node.attributes.get(_ANDROID + "permission"), node.attributes.get(_ANDROID + "process"), filters)

    def _permission(self, node: XmlNode, requested: bool) -> ApkPermission:
        name = node.attributes.get(_ANDROID + "name", "")
        return ApkPermission(name, node.attributes.get(_ANDROID + "protectionLevel"), requested, requested and name in _DANGEROUS)

    def _security(self, root: XmlNode, app: XmlNode | None, permissions: tuple[ApkPermission, ...], components: tuple[ApkComponent, ...]) -> ApkSecurityFlags:
        names = {item.name for item in permissions}
        suspicious = tuple(component.name for component in components if component.exported and any("BOOT_COMPLETED" in action or "ACCESSIBILITY" in action for item in component.intent_filters for action in item.actions))
        return ApkSecurityFlags(_boolean(app.attributes.get(_ANDROID + "debuggable")) if app else None, _boolean(app.attributes.get(_ANDROID + "allowBackup")) if app else None, _boolean(app.attributes.get(_ANDROID + "usesCleartextTraffic")) if app else None, tuple(sorted(item.name for item in permissions if item.is_dangerous)), tuple(sorted(item.name for item in components if item.exported)), any("BIND_ACCESSIBILITY_SERVICE" in name for name in names), any("SMS" in name for name in names), any("CONTACT" in name for name in names), any("LOCATION" in name for name in names), any("RECORD_AUDIO" in name for name in names), any("CAMERA" in name for name in names), suspicious)

    def _structure(self, archive: zipfile.ZipFile, apk_size: int, components: tuple[ApkComponent, ...]) -> ApkStructureInfo:
        names = tuple(item.filename for item in archive.infolist())
        dex = tuple(name for name in names if re.fullmatch(r"classes(?:\d+)?\.dex", Path(name).name))
        libraries = tuple(name for name in names if name.startswith("lib/") and name.endswith(".so"))
        architectures = tuple(sorted({name.split("/")[1] for name in libraries if len(name.split("/")) > 2}))
        assets = tuple(name for name in names if name.startswith("assets/"))
        indicators = []
        if any(not re.fullmatch(r"classes(?:\d+)?\.dex", Path(name).name) for name in names if name.endswith(".dex")):
            indicators.append("nonstandard_dex_filename")
        if any(any(len(part) == 1 for part in component.name.split(".")[:-1]) for component in components if component.name):
            indicators.append("short_component_name_segments")
        return ApkStructureInfo(apk_size, len(names), dex, libraries, architectures, assets, len(dex) > 1, tuple(indicators))

    @staticmethod
    def _certificates(archive: zipfile.ZipFile) -> tuple[ApkCertificate, ...]:
        entries = [item for item in archive.infolist() if item.filename.upper().startswith("META-INF/") and item.filename.upper().endswith((".RSA", ".DSA", ".EC"))]
        result = [ApkCertificate(item.filename, "v1", item.file_size) for item in entries]
        if _has_apk_signing_block(archive):
            result.append(ApkCertificate(None, "v2_or_v3", None))
        return tuple(result)

    @staticmethod
    def _error_name(error: Exception) -> str:
        if isinstance(error, KeyError): return "missing_manifest"
        if isinstance(error, zipfile.BadZipFile): return "invalid_zip"
        if isinstance(error, RuntimeError) and "encrypted" in str(error).lower(): return "encrypted_manifest"
        if isinstance(error, ManifestParseError): return "manifest_parse_error"
        return "read_error"


def _children(node: XmlNode, name: str) -> tuple[XmlNode, ...]: return tuple(child for child in node.children if child.name == name)
def _child(node: XmlNode, name: str) -> XmlNode | None: return next(iter(_children(node, name)), None)
def _boolean(value: str | None) -> bool | None: return None if value is None else value.lower() == "true"
def _sdk(root: XmlNode, name: str) -> str | None:
    uses_sdk = _child(root, "uses-sdk")
    return uses_sdk.attributes.get(_ANDROID + name) if uses_sdk else None
def _intent_filter(node: XmlNode) -> ApkIntentFilter:
    return ApkIntentFilter(tuple(item.attributes.get(_ANDROID + "name", "") for item in _children(node, "action") if item.attributes.get(_ANDROID + "name")), tuple(item.attributes.get(_ANDROID + "name", "") for item in _children(node, "category") if item.attributes.get(_ANDROID + "name")), tuple(str(item.attributes) for item in _children(node, "data")))
def _has_apk_signing_block(archive: zipfile.ZipFile) -> bool:
    try:
        stream = archive.fp
        if stream is None:
            return False
        stream.seek(0, 2); size = stream.tell(); stream.seek(max(0, size - 65557)); tail = stream.read(); marker = tail.rfind(b"PK\x05\x06")
        if marker < 0 or marker + 20 > len(tail): return False
        central_offset = struct.unpack_from("<I", tail, marker + 16)[0]
        if central_offset < 24: return False
        stream.seek(central_offset - 24); footer = stream.read(24)
        return footer[-16:] == b"APK Sig Block 42"
    except (AttributeError, OSError, ValueError): return False
