"""Vendor label normalization. Reviewed 2026-10-04; keep vendor-specific aliases here."""
from __future__ import annotations

CLEAN_LABELS = {
    "clean", "clean1", "legit file", "no threats detected", "not malicious",
    "benign", "safe", "whitelist", "whitelisted", "false positive", "non-malicious", "legitimate",
}
UNRATED_LABELS = {"not_supported", "not supported", "unknown", "none", "null", "notcategorized", "unrated", ""}
MALICIOUS_LABELS = {"malware2", "mirai", "amos", "known", "suspicious"}
MALICIOUS_PREFIXES = ("macos.infostealer.",)


def normalize_vendor_label(value: object) -> str | None:
    if value is None:
        return None
    normalized = " ".join(str(value).strip().casefold().replace("_", " ").split())
    return normalized or None


def is_unrated_vendor_label(value: object) -> bool:
    normalized = normalize_vendor_label(value)
    return normalized is None or normalized in UNRATED_LABELS


def is_clean_vendor_label(value: object) -> bool:
    normalized = normalize_vendor_label(value)
    return normalized in CLEAN_LABELS if normalized else False


def is_malicious_vendor_label(value: object) -> bool:
    normalized = normalize_vendor_label(value)
    if not normalized:
        return False
    return normalized in MALICIOUS_LABELS or any(normalized.startswith(prefix) for prefix in MALICIOUS_PREFIXES)
