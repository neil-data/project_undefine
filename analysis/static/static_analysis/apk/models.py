"""APK-specific static analysis contracts."""

from dataclasses import dataclass

from static_analysis.metadata.models import MetadataResult
from static_analysis.strings.models import ExtractedString


@dataclass(frozen=True, slots=True)
class ApkIntentFilter:
    actions: tuple[str, ...] = ()
    categories: tuple[str, ...] = ()
    data: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class ApkComponent:
    name: str
    component_type: str
    exported: bool | None
    enabled: bool | None
    permission: str | None
    process: str | None
    intent_filters: tuple[ApkIntentFilter, ...] = ()


@dataclass(frozen=True, slots=True)
class ApkPermission:
    name: str
    protection_level: str | None = None
    is_requested: bool = False
    is_dangerous: bool = False


@dataclass(frozen=True, slots=True)
class ApkCertificate:
    entry_name: str | None
    signature_scheme: str
    size: int | None = None


@dataclass(frozen=True, slots=True)
class ApkSecurityFlags:
    debuggable: bool | None
    backup_enabled: bool | None
    cleartext_traffic_allowed: bool | None
    dangerous_permissions: tuple[str, ...]
    exported_components: tuple[str, ...]
    uses_accessibility: bool
    uses_sms: bool
    uses_contacts: bool
    uses_location: bool
    uses_microphone: bool
    uses_camera: bool
    suspicious_intent_filters: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class ApkStructureInfo:
    apk_size: int
    file_count: int
    dex_files: tuple[str, ...]
    native_libraries: tuple[str, ...]
    native_library_architectures: tuple[str, ...]
    embedded_assets: tuple[str, ...]
    multidex: bool
    obfuscation_indicators: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class ApkInfo:
    package_name: str | None
    version_name: str | None
    version_code: str | None
    min_sdk: str | None
    target_sdk: str | None
    compile_sdk: str | None
    application_label: str | None
    application_class: str | None
    activities: tuple[ApkComponent, ...]
    services: tuple[ApkComponent, ...]
    receivers: tuple[ApkComponent, ...]
    providers: tuple[ApkComponent, ...]
    requested_permissions: tuple[ApkPermission, ...]
    custom_permissions: tuple[ApkPermission, ...]
    features: tuple[str, ...]
    certificates: tuple[ApkCertificate, ...]
    manifest_attributes: tuple[tuple[str, str], ...]
    manifest_urls: tuple[str, ...]
    manifest_domains: tuple[str, ...]
    security_flags: ApkSecurityFlags
    structure: ApkStructureInfo


@dataclass(frozen=True, slots=True)
class ApkAnalysisResult:
    source: str
    info: ApkInfo | None
    metadata: MetadataResult
    strings: tuple[ExtractedString, ...]
    error: str | None = None
