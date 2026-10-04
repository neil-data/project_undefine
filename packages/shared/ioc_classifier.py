# E-Rakshak IoC Classifier — Single Source of Truth
# Types: URL, DOMAIN, IP, EMAIL, FILE_PATH, HASH, SYMBOL, LIBRARY, BASE64, PACKAGE_ENTRY, SYSTEM_INFRASTRUCTURE, UNKNOWN
# Conforms to Day 2 forensic contracts (B3).

from __future__ import annotations
import re
import ipaddress
from enum import Enum
from typing import Optional, Tuple, Dict, Any, List
from pydantic import BaseModel, Field, model_validator

try:
    from publicsuffixlist import PublicSuffixList
    _PSL = PublicSuffixList(only_icann=False)
except Exception:
    _PSL = None

from packages.shared.allowlist import (
    PUBLIC_DNS_RESOLVERS,
    LEGITIMATE_BENIGN_DOMAINS,
    SYSTEMD_SUFFIXES,
    COMMON_FILE_EXTENSIONS,
    GO_PACKAGE_PREFIXES,
    SYSTEM_LIBRARIES,
)


class IOCType(str, Enum):
    URL = "URL"
    DOMAIN = "DOMAIN"
    IP = "IP"
    EMAIL = "EMAIL"
    FILE_PATH = "FILE_PATH"
    HASH = "HASH"
    SYMBOL = "SYMBOL"
    LIBRARY = "LIBRARY"
    BASE64 = "BASE64"
    PACKAGE_ENTRY = "PACKAGE_ENTRY"
    SYSTEM_INFRASTRUCTURE = "SYSTEM_INFRASTRUCTURE"
    UNKNOWN = "UNKNOWN"


def truncate_display_value(value: str, max_len: int = 60) -> str:
    """Truncate long display values with '…(N more)'."""
    if len(value) <= max_len:
        return value
    n_more = len(value) - max_len
    return f"{value[:max_len]}…({n_more} more)"


def strip_glued_hex(url: str) -> str:
    """Strip glued hex/hash fragments concatenated to URL heads or tails."""
    s = url.strip()
    # Strip leading hex like 0x4a or \x4a
    s = re.sub(r"^(?:0x[0-9a-fA-F]+|\\x[0-9a-fA-F]{2})+", "", s)
    idx = s.find("http://")
    if idx == -1:
        idx = s.find("https://")
    if idx > 0:
        prefix = s[:idx]
        if all(c in "0123456789abcdefABCDEFxX_\\ " for c in prefix):
            s = s[idx:]

    # Strip trailing glued hex (0x2f, null bytes, hashes)
    s = re.sub(r"(?:0x[0-9a-fA-F]+|\\x[0-9a-fA-F]{2})+$", "", s)
    m = re.search(r"^(https?://[^\s\"\'<>]+?\.(?:exe|bin|sh|elf|dll|php|asp|aspx|jsp|html|htm|zip|tar|gz|txt|dat|py|pl|apk|so))([0-9a-fA-F]{16,64}|0+)$", s)
    if m:
        return m.group(1)
    m2 = re.search(r"^(https?://[^\s\"\'<>]+?/[a-zA-Z0-9_\-\.]+?)([0-9a-fA-F]{16,64}|0+)$", s)
    if m2:
        return m2.group(1)
    return s


def is_base64_blob(val: str) -> bool:
    """Check if string is a base64 blob (>32 chars, base64 charset, padding if present)."""
    s = val.strip()
    if len(s) < 32:
        return False
    if "/" in s and (" " in s or s.startswith("/") or "/tmp/" in s or "/etc/" in s or "/var/" in s or "/lib" in s):
        return False
    if "\\" in s or ":\\" in s:
        return False
    if re.match(r"^[a-zA-Z0-9+/=]{32,}$", s):
        if "=" in s:
            eq_idx = s.index("=")
            if not all(c == "=" for c in s[eq_idx:]):
                return False
        return True
    return False


def is_system_library(val: str) -> bool:
    """Check if string is a system library/dylib rather than an installed malware path."""
    s = val.strip().lower()
    if s in SYSTEM_LIBRARIES:
        return True
    base = s.replace("\\", "/").split("/")[-1]
    if base in SYSTEM_LIBRARIES:
        return True
    if re.match(r"^libc\.so(?:\.\d+)*$", base) or re.match(r"^ld-linux.*\.so(?:\.\d+)*$", base):
        return True
    if re.match(r"^(?:kernel32|ntdll|user32|advapi32|gdi32|ws2_32|shell32|ole32)\.dll$", base):
        return True
    return False


def is_package_entry(val: str) -> bool:
    """Check if string is an archive or package entry (ZIP, APK, etc.)."""
    s = val.strip()
    if s.startswith("META-INF/") or s.startswith("assets/") or s.startswith("res/"):
        return True
    if s in ("classes.dex", "AndroidManifest.xml", "resources.arsc"):
        return True
    return False


def is_symbol(val: str) -> bool:
    """Check if string is a Go/Java/runtime symbol."""
    s = val.strip()
    if re.search(r"\b[a-zA-Z0-9_\-]+/[a-zA-Z0-9_\-]+\.[A-Z][a-zA-Z0-9_]+\b", s):
        return True
    parts = s.split(".")
    if len(parts) == 2 and parts[0].lower() in GO_PACKAGE_PREFIXES:
        return True
    return False


def is_valid_ip(val: str) -> bool:
    """Validate IPv4 or IPv6 address."""
    try:
        ipaddress.ip_address(val.strip())
        return True
    except Exception:
        return False


def validate_domain(domain: str, *, allow_short_sld: bool = False) -> Tuple[bool, str]:
    """
    Validates domain requirements per B3:
    - SLD length >= 3 chars
    - No file extensions
    - No systemd unit suffixes
    - No mixed-case TLD
    - Offline PSL snapshot validation
    - Not pkg.symbol (Go/Java)
    - Not a zip/package entry
    """
    if not domain or "." not in domain:
        return False, "No dot in domain"

    if any(c in domain for c in ('/', '\\', ':', '*', '?', '"', '<', '>', '|', ' ', '\t', '\r', '\n')):
        return False, "Invalid characters in domain"

    if domain.startswith("./") or domain.startswith("../") or domain.startswith("/"):
        return False, "Path structure in domain"

    parts = domain.strip(".").split(".")
    if len(parts) < 2:
        return False, "Domain must have at least two labels"

    tld = parts[-1]
    sld = parts[-2]

    # 1. Legitimate benign domains allowlist bypass
    if domain.lower() in LEGITIMATE_BENIGN_DOMAINS:
        return True, "Legitimate benign domain"
    for b in LEGITIMATE_BENIGN_DOMAINS:
        if domain.lower().endswith(f".{b}"):
            return True, "Legitimate benign subdomain"

    # 2. Mixed-case TLD check (e.g. .Com, .Org)
    if not (tld.islower() or tld.isupper()):
        return False, f"Mixed-case TLD: {tld}"

    # 3. Mixed-case SLD fragment check (e.g. jC, QMrS)
    if re.search(r"[a-z][A-Z]|[A-Z]{2,}[a-z]", sld):
        return False, f"Mixed-case SLD fragment: {domain}"

    # 4. Go symbol check
    if is_symbol(domain):
        return False, f"Go symbol/package prefix detected as domain: {domain}"

    # 5. Systemd unit suffix check
    tld_lower = tld.lower()
    if tld_lower in SYSTEMD_SUFFIXES:
        return False, f"Domain matches systemd unit suffix: {domain}"

    # 6. File extension check
    if tld_lower in COMMON_FILE_EXTENSIONS:
        return False, f"Domain matches file extension: {domain}"

    # 7. Package entry check
    if is_package_entry(domain):
        return False, f"Package entry detected as domain: {domain}"

    # 8. Character validation per label
    for part in parts:
        if not part or len(part) > 63:
            return False, f"Invalid label length in domain: {domain}"
        if not re.match(r"^[a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?$", part):
            return False, f"Invalid label format: {part}"

    # 9. Offline PSL validation & SLD length
    if _PSL is not None:
        try:
            priv = _PSL.privatesuffix(domain.lower())
            if not priv:
                return False, f"Domain '{domain}' does not have a valid private suffix under PSL"
            priv_parts = priv.split(".")
            sld_label = priv_parts[0]
            if len(sld_label) < 3 and not allow_short_sld:
                return False, f"SLD '{sld_label}' is shorter than 3 characters in domain {domain}"
        except Exception:
            if len(sld) < 3 and not allow_short_sld:
                return False, f"SLD '{sld}' is shorter than 3 characters in domain {domain}"
    else:
        if len(sld) < 3:
            return False, f"SLD '{sld}' is shorter than 3 characters in domain {domain}"

    return True, "Valid domain"


class ClassifiedIoC(BaseModel):
    indicator: str
    display_value: str
    type: str  # Matches IOCType
    classification: str = "UNKNOWN"  # BENIGN, SUSPICIOUS, MALICIOUS, UNKNOWN
    confidence: str = "LOW"  # LOW, MEDIUM, HIGH
    source: str = "Static Analysis"
    source_type: str = "STATIC"  # STATIC, DYNAMIC, INTEL
    evidence_state: str = "STATIC"  # STATIC, OBSERVED, INTEL, NOT_PERFORMED
    related_behavior: Optional[str] = None
    intel_note: Optional[str] = None
    intel_corroborated: bool = False
    first_seen: Optional[str] = None
    occurrence_count: int = 1

    @model_validator(mode="before")
    @classmethod
    def sync_notes(cls, values: Any) -> Any:
        if isinstance(values, dict):
            if "related_behavior" in values and "intel_note" not in values:
                values["intel_note"] = values["related_behavior"]
            elif "intel_note" in values and "related_behavior" not in values:
                values["related_behavior"] = values["intel_note"]
        return values

    def to_dict(self) -> dict:
        return {
            "indicator": self.indicator,
            "display_value": self.display_value,
            "type": self.type,
            "category": self.type,
            "classification": self.classification,
            "confidence": self.confidence,
            "source": self.source,
            "source_type": self.source_type,
            "evidence_state": self.evidence_state,
            "related_behavior": self.related_behavior,
            "intel_note": self.intel_note or self.related_behavior,
            "threat_intel": self.intel_corroborated,
            "intel_corroborated": self.intel_corroborated,
            "first_seen": self.first_seen,
            "occurrence_count": self.occurrence_count,
        }


class IoCClassifier:
    """Canonical classifier implementing extract -> normalize -> classify -> validate -> confidence."""

    @classmethod
    def classify(
        cls,
        raw_indicator: str,
        hint_type: Optional[str] = None,
        source: Optional[str] = None,
        source_type: Optional[str] = None,
        evidence_state: Optional[str] = None,
        first_seen: Optional[str] = None,
        malware_bazaar: Optional[dict] = None,
        is_dynamic_observed: bool = False,
        threat_intel: Optional[dict] = None,
    ) -> ClassifiedIoC:
        ind = str(raw_indicator).strip()
        # Clean incoming truncation markers so literal marker is never emitted as IoC
        ind = re.sub(r"[…\.]{1,3}\(\d+\s+more\)$", "", ind).strip()
        display = truncate_display_value(ind)

        # Check for glued hex URL
        url_cand = strip_glued_hex(ind)
        if url_cand.startswith("http://") or url_cand.startswith("https://") or url_cand.startswith("ftp://"):
            ind = url_cand
            display = truncate_display_value(ind)

        src = source or ("Dynamic Sandbox" if is_dynamic_observed else "Static Analysis")
        stype = source_type or ("DYNAMIC" if is_dynamic_observed else "STATIC")
        estate = evidence_state or ("OBSERVED" if is_dynamic_observed else "STATIC")

        # 1. Public DNS Resolvers -> SYSTEM_INFRASTRUCTURE (informational, never C2/blocked)
        if ind in PUBLIC_DNS_RESOLVERS:
            return ClassifiedIoC(
                indicator=ind,
                display_value=display,
                type=IOCType.SYSTEM_INFRASTRUCTURE.value,
                classification="BENIGN",
                confidence="LOW",
                source=src,
                source_type=stype,
                evidence_state=estate,
                related_behavior="Public DNS resolver (informational)",
                intel_corroborated=False,
                first_seen=first_seen,
            )

        # 2. Benign hosts -> SYSTEM_INFRASTRUCTURE, never SUSPICIOUS
        low_ind = ind.lower()
        if low_ind in LEGITIMATE_BENIGN_DOMAINS or any(low_ind.endswith(f".{b}") for b in LEGITIMATE_BENIGN_DOMAINS):
            return ClassifiedIoC(
                indicator=ind,
                display_value=display,
                type=IOCType.SYSTEM_INFRASTRUCTURE.value,
                classification="BENIGN",
                confidence="LOW",
                source=src,
                source_type=stype,
                evidence_state=estate,
                related_behavior="Legitimate platform/developer infrastructure",
                intel_corroborated=False,
                first_seen=first_seen,
            )

        # 3. Base64 blobs -> BASE64, never FILE_PATH
        if is_base64_blob(ind):
            return ClassifiedIoC(
                indicator=ind,
                display_value=display,
                type=IOCType.BASE64.value,
                classification="UNKNOWN",
                confidence="LOW",
                source=src,
                source_type=stype,
                evidence_state=estate,
                related_behavior="Base64 encoded payload/blob",
                intel_corroborated=False,
                first_seen=first_seen,
            )

        # 4. System libraries -> LIBRARY (dependencies), not install paths
        if is_system_library(ind):
            return ClassifiedIoC(
                indicator=ind,
                display_value=display,
                type=IOCType.LIBRARY.value,
                classification="BENIGN",
                confidence="LOW",
                source=src,
                source_type=stype,
                evidence_state=estate,
                related_behavior="Standard system library dependency",
                intel_corroborated=False,
                first_seen=first_seen,
            )

        # 5. Archive / package entries -> PACKAGE_ENTRY
        if is_package_entry(ind):
            return ClassifiedIoC(
                indicator=ind,
                display_value=display,
                type=IOCType.PACKAGE_ENTRY.value,
                classification="UNKNOWN",
                confidence="LOW",
                source=src,
                source_type=stype,
                evidence_state=estate,
                related_behavior="Package or archive entry artifact",
                intel_corroborated=False,
                first_seen=first_seen,
            )

        # 6. Symbols -> SYMBOL
        if is_symbol(ind):
            return ClassifiedIoC(
                indicator=ind,
                display_value=display,
                type=IOCType.SYMBOL.value,
                classification="UNKNOWN",
                confidence="LOW",
                source=src,
                source_type=stype,
                evidence_state=estate,
                related_behavior="Runtime or language package symbol",
                intel_corroborated=False,
                first_seen=first_seen,
            )

        # 7. File Hashes
        if re.match(r"^[a-fA-F0-9]{64}$", ind):
            has_mb = bool(malware_bazaar and malware_bazaar.get("found"))
            return ClassifiedIoC(
                indicator=ind,
                display_value=display,
                type=IOCType.HASH.value,
                classification="MALICIOUS" if has_mb else "UNKNOWN",
                confidence="HIGH" if has_mb else "LOW",
                source="MalwareBazaar (abuse.ch)" if has_mb else src,
                source_type="INTEL" if has_mb else stype,
                evidence_state="INTEL" if has_mb else estate,
                related_behavior=("Known malware family: " + str(malware_bazaar.get("signature") or "Confirmed")) if has_mb else "SHA-256 hash",
                intel_corroborated=has_mb,
                first_seen=first_seen,
            )
        if re.match(r"^[a-fA-F0-9]{32}$", ind) or re.match(r"^[a-fA-F0-9]{40}$", ind):
            return ClassifiedIoC(
                indicator=ind,
                display_value=display,
                type=IOCType.HASH.value,
                classification="UNKNOWN",
                confidence="LOW",
                source=src,
                source_type=stype,
                evidence_state=estate,
                related_behavior="File digest hash",
                intel_corroborated=False,
                first_seen=first_seen,
            )

        # 8. URLs
        if ind.startswith("http://") or ind.startswith("https://") or ind.startswith("ftp://"):
            clean_url = strip_glued_hex(ind)
            display = truncate_display_value(clean_url)
            host_m = re.match(r"^https?://([^/:?#]+)", clean_url)
            host = host_m.group(1).lower() if host_m else ""
            if host in LEGITIMATE_BENIGN_DOMAINS or any(host.endswith(f".{b}") for b in LEGITIMATE_BENIGN_DOMAINS):
                return ClassifiedIoC(
                    indicator=clean_url,
                    display_value=display,
                    type=IOCType.SYSTEM_INFRASTRUCTURE.value,
                    classification="BENIGN",
                    confidence="LOW",
                    source=src,
                    source_type=stype,
                    evidence_state=estate,
                    related_behavior="Benign developer/vendor infrastructure URL",
                    intel_corroborated=False,
                    first_seen=first_seen,
                )
            has_ti = bool(threat_intel and threat_intel.get("malicious"))
            return ClassifiedIoC(
                indicator=clean_url,
                display_value=display,
                type=IOCType.URL.value,
                classification="MALICIOUS" if has_ti else "SUSPICIOUS" if is_dynamic_observed else "UNKNOWN",
                confidence="HIGH" if has_ti else "MEDIUM" if is_dynamic_observed else "LOW",
                source=src,
                source_type="INTEL" if has_ti else stype,
                evidence_state="INTEL" if has_ti else estate,
                related_behavior="Observed network request" if is_dynamic_observed else "Embedded URL string",
                intel_corroborated=has_ti,
                first_seen=first_seen,
            )

        # 9. IPs
        if is_valid_ip(ind):
            has_ti = bool(threat_intel and threat_intel.get("malicious"))
            return ClassifiedIoC(
                indicator=ind,
                display_value=display,
                type=IOCType.IP.value,
                classification="MALICIOUS" if has_ti else "SUSPICIOUS" if is_dynamic_observed else "UNKNOWN",
                confidence="HIGH" if has_ti else "MEDIUM" if is_dynamic_observed else "LOW",
                source=src,
                source_type="INTEL" if has_ti else stype,
                evidence_state="INTEL" if has_ti else estate,
                related_behavior="Observed network connection" if is_dynamic_observed else "Embedded IP address",
                intel_corroborated=has_ti,
                first_seen=first_seen,
            )

        # 10. Domains
        # Observed DNS names may use short labels (for example x.com). Keep
        # the stricter three-character rule for uncontextualized strings.
        valid_dom, reason = validate_domain(ind, allow_short_sld=is_dynamic_observed)
        if valid_dom:
            has_ti = bool(threat_intel and threat_intel.get("malicious"))
            return ClassifiedIoC(
                indicator=ind,
                display_value=display,
                type=IOCType.DOMAIN.value,
                classification="MALICIOUS" if has_ti else "SUSPICIOUS" if is_dynamic_observed else "UNKNOWN",
                confidence="HIGH" if has_ti else "MEDIUM" if is_dynamic_observed else "LOW",
                source=src,
                source_type="INTEL" if has_ti else stype,
                evidence_state="INTEL" if has_ti else estate,
                related_behavior="Observed DNS resolution" if is_dynamic_observed else "Embedded domain",
                intel_corroborated=has_ti,
                first_seen=first_seen,
            )

        # 11. File Paths
        if ind.startswith("/") or (len(ind) > 2 and ind[1:3] == ":\\") or "\\" in ind or "/bin/" in ind or "/usr/" in ind or "/etc/" in ind or "/tmp/" in ind or "/var/" in ind:
            return ClassifiedIoC(
                indicator=ind,
                display_value=display,
                type=IOCType.FILE_PATH.value,
                classification="SUSPICIOUS" if is_dynamic_observed else "UNKNOWN",
                confidence="MEDIUM" if is_dynamic_observed else "LOW",
                source=src,
                source_type=stype,
                evidence_state=estate,
                related_behavior="Dropped file or file path artifact",
                intel_corroborated=False,
                first_seen=first_seen,
            )

        # 12. Email
        if re.match(r"^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$", ind):
            return ClassifiedIoC(
                indicator=ind,
                display_value=display,
                type=IOCType.EMAIL.value,
                classification="UNKNOWN",
                confidence="LOW",
                source=src,
                source_type=stype,
                evidence_state=estate,
                related_behavior="Embedded email address",
                intel_corroborated=False,
                first_seen=first_seen,
            )

        # 13. Fallback UNKNOWN
        return ClassifiedIoC(
            indicator=ind,
            display_value=display,
            type=IOCType.UNKNOWN.value,
            classification="UNKNOWN",
            confidence="LOW",
            source=src,
            source_type=stype,
            evidence_state=estate,
            related_behavior="Unclassified indicator artifact",
            intel_corroborated=False,
            first_seen=first_seen,
        )
