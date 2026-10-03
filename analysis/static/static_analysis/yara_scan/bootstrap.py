"""Explicit assembly for the YARA scanner."""

from pathlib import Path

from static_analysis.yara_scan.scanner import YaraScanner, default_rules_directory


def create_yara_scanner(
    rules_directory: str | Path | None = None,
    timeout_seconds: int = 60,
) -> YaraScanner:
    """
    Create a scanner over the shipped rule tree.

    Compilation happens once, here, rather than per sample: a batch of two
    hundred samples should pay the rule-compile cost once.
    """
    return YaraScanner(
        rules_directory=rules_directory or default_rules_directory(),
        timeout_seconds=timeout_seconds,
    )
