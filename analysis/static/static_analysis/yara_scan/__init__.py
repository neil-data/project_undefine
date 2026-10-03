"""YARA signature scanning, including the India-specific scam rule set."""

from static_analysis.yara_scan.bootstrap import create_yara_scanner
from static_analysis.yara_scan.models import (
    YaraMatch,
    YaraScanResult,
    YaraStatus,
    YaraStringHit,
)
from static_analysis.yara_scan.scanner import (
    YARA_AVAILABLE,
    YaraScanner,
    default_rules_directory,
)

__all__ = (
    "YARA_AVAILABLE",
    "YaraMatch",
    "YaraScanResult",
    "YaraScanner",
    "YaraStatus",
    "YaraStringHit",
    "create_yara_scanner",
    "default_rules_directory",
)
