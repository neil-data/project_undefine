"""
Shared fixtures and forensic verification helpers for E2E baseline tests.
"""
from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, Dict, List, Set, Tuple
import pytest

FIXTURES_DIR = Path(__file__).parent / "fixtures"

PUBLIC_DNS_RESOLVERS: Set[str] = {
    "8.8.8.8",
    "8.8.4.4",
    "1.1.1.1",
    "1.0.0.1",
    "9.9.9.9",
    "149.112.112.112",
}

LEGITIMATE_BENIGN_DOMAINS: Set[str] = {
    "go.dev",
    "golang.org",
    "microsoft.com",
    "android.googlesource.com",
    "google.com",
    "github.com",
}

SYSTEMD_SUFFIXES: Set[str] = {
    ".service",
    ".socket",
    ".target",
    ".timer",
    ".mount",
    ".automount",
    ".swap",
    ".device",
}

COMMON_FILE_EXTENSIONS: Set[str] = {
    ".exe",
    ".dll",
    ".so",
    ".bin",
    ".elf",
    ".o",
    ".py",
    ".sh",
    ".txt",
    ".json",
    ".xml",
    ".html",
    ".log",
    ".tar",
    ".gz",
    ".zip",
    ".png",
    ".jpg",
    ".jpeg",
    ".gif",
}

REFUSAL_PHRASES: List[str] = [
    "i'm sorry",
    "i am sorry",
    "can't help",
    "cannot help",
    "as an ai",
    "as a language model",
    "i apologize",
]

CREDENTIAL_ADVICE_KEYWORDS: List[str] = [
    "password",
    "oauth",
    "kerberos",
    "credential",
    "token rotation",
    "reset credentials",
]

CREDENTIAL_CAPABILITIES: Set[str] = {
    "credential_access",
    "credential_dumping",
    "password_theft",
    "keylogging",
}


def load_all_fixtures() -> Dict[str, Dict[str, Any]]:
    """Loads all JSON report fixtures available in tests/e2e/fixtures."""
    fixtures = {}
    if FIXTURES_DIR.exists():
        for p in FIXTURES_DIR.glob("*.json"):
            try:
                data = json.loads(p.read_text(encoding="utf-8"))
                fixtures[p.stem] = data
            except Exception:
                pass
    return fixtures


def get_fixture_items() -> List[Tuple[str, Dict[str, Any]]]:
    """Returns a list of (fixture_name, fixture_dict) tuples for pytest parametrization."""
    items = list(load_all_fixtures().items())
    return items


@pytest.fixture(scope="session")
def all_fixtures() -> Dict[str, Dict[str, Any]]:
    return load_all_fixtures()


# ─── Domain & Path Validation Helpers ──────────────────────────────────────────

def is_valid_domain(domain: str) -> Tuple[bool, str]:
    """
    Validates domain requirements:
    - SLD length >= 3 chars
    - No file extensions
    - No systemd unit suffixes
    - No mixed-case TLD
    - Valid public-suffix / standard TLD structure
    """
    if not domain or "." not in domain:
        return False, "No dot in domain"

    parts = domain.split(".")
    tld = parts[-1]
    sld = parts[-2]

    # Mixed-case TLD check (e.g. .Com, .Org)
    if not (tld.islower() or tld.isupper()):
        return False, f"Mixed-case TLD: {tld}"

    tld_lower = f".{tld.lower()}"
    if tld_lower in SYSTEMD_SUFFIXES:
        return False, f"Domain matches systemd unit suffix: {domain}"

    if tld_lower in COMMON_FILE_EXTENSIONS:
        return False, f"Domain matches file extension: {domain}"

    if len(sld) < 3:
        return False, f"SLD '{sld}' is shorter than 3 characters in domain {domain}"

    if not re.match(r"^[a-zA-Z0-9_\-\.]+$", domain):
        return False, f"Invalid characters in domain: {domain}"

    return True, "Valid domain"


def is_rejected_path(path: str) -> Tuple[bool, str]:
    """
    Checks if a path string is an invalid artifact:
    - Go symbols (pkg.symbol)
    - Zip entry names
    - Base64 blobs falsely identified as paths
    - System libraries claimed as install paths
    """
    # Go symbol pattern (e.g. runtime.main, net/http.Get, sync/atomic.Store)
    if re.search(r"\b[a-zA-Z0-9_\-]+/[a-zA-Z0-9_\-]+\.[A-Z][a-zA-Z0-9_]+\b", path):
        return True, f"Go symbol detected as path: {path}"

    # Zip entry artifact (e.g. META-INF/MANIFEST.MF, classes.dex without root /)
    if path.startswith("META-INF/") or path.startswith("assets/") or path.startswith("res/"):
        return True, f"Zip/archive entry artifact detected as system path: {path}"

    # Base64 blob pattern falsely treated as path
    if len(path) > 32 and re.match(r"^[a-zA-Z0-9+/=]{32,}$", path):
        return True, f"Base64 blob detected as path: {path}"

    # System libraries treated as installed malware path
    system_libs = {"/lib/libc.so", "/lib64/ld-linux", "kernel32.dll", "ntdll.dll", "user32.dll"}
    for lib in system_libs:
        if path.strip().lower() == lib.lower():
            return True, f"System library flagged as installed malware path: {path}"

    return False, "Not rejected"


# ─── Evidence & Narrative Helpers ─────────────────────────────────────────────

def collect_all_evidence_values(fixture: Dict[str, Any]) -> Set[str]:
    """Recursively collects all grounded strings, IPs, domains, paths, and hashes from fixture."""
    evidence: Set[str] = set()

    def _walk(item: Any):
        if isinstance(item, str):
            evidence.add(item)
            # Add normalized tokens
            for token in item.split():
                evidence.add(token.strip(" '\"(),;[]{}"))
        elif isinstance(item, dict):
            for k, v in item.items():
                evidence.add(k)
                _walk(v)
        elif isinstance(item, list):
            for v in item:
                _walk(v)

    # Specific evidence areas
    for key in ("extracted_strings", "ioc_intelligence", "network_indicators", "yara_matches", "capabilities", "capability_tags"):
        if key in fixture:
            _walk(fixture[key])

    return evidence


def find_recursive_states(fixture: Dict[str, Any], states: Set[str]) -> List[str]:
    """Finds occurrences of specified evidence_state values across the entire fixture."""
    found = []

    def _walk(obj: Any):
        if isinstance(obj, dict):
            for k, v in obj.items():
                if k == "evidence_state" and v in states:
                    found.append(v)
                _walk(v)
        elif isinstance(obj, list):
            for elem in obj:
                _walk(elem)

    _walk(fixture)
    return found
