"""Centralized configuration loader and secret redaction.

Loads environment variables from both root .env and sandbox/adapters/mobsf/.env.
Never logs or prints secret values.
"""
from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Any, Iterable

ROOT_DIR = Path(__file__).resolve().parents[2]
MOBSF_ENV_PATH = ROOT_DIR / "sandbox" / "adapters" / "mobsf" / ".env"
MAIN_ENV_PATH = ROOT_DIR / ".env"

_LOADED = False

def _init_dotenv() -> None:
    global _LOADED
    if _LOADED:
        return
    _LOADED = True
    try:
        from dotenv import load_dotenv
        if MAIN_ENV_PATH.exists():
            load_dotenv(MAIN_ENV_PATH, override=False)
        if MOBSF_ENV_PATH.exists():
            load_dotenv(MOBSF_ENV_PATH, override=False)
    except ImportError:
        pass

_init_dotenv()


def load_config() -> dict[str, str]:
    """Load configuration dictionary from current environment.
    
    Never logs or prints secret values.
    """
    return dict(os.environ)


def get_setting(key: str, default: str | None = None) -> str | None:
    load_config()
    return os.environ.get(key, default)


KNOWN_SECRET_KEYS = (
    "HYBRID_ANALYSIS_API_KEY",
    "MOBSF_API_KEY",
    "JWT_SECRET_KEY",
    "GROQ_API_KEY",
    "NVIDIA_NIM_API_KEY",
    "MALWARE_BAZAAR_API_KEY",
    "CHAIN_VERIFICATION_SECRET",
    "SANDBOX_API_TOKEN",
)


def get_active_secrets(extra_secrets: Iterable[str] | None = None) -> list[str]:
    """Return all non-empty configured secrets for redaction (values only)."""
    load_config()
    secrets: set[str] = set()
    for key in KNOWN_SECRET_KEYS:
        val = os.environ.get(key)
        if val and len(val.strip()) >= 6:
            secrets.add(val.strip())
    if extra_secrets:
        for s in extra_secrets:
            if s and len(s.strip()) >= 6:
                secrets.add(s.strip())
    return sorted(secrets, key=len, reverse=True)


_HEADER_PATTERNS = [
    re.compile(r"(?i)(authorization\s*[:=]\s*bearer\s+)([^'\"\s,\}]+)"),
    re.compile(r"(?i)(bearer\s+)([^'\"\s,\}]+)"),
    re.compile(r"(?i)(authorization\s*[:=]\s*['\"]?)([^'\"\s,\}]+)(['\"]?)"),
    re.compile(r"(?i)(api[-_]?key\s*[:=]\s*['\"]?)([^'\"\s,\}]+)(['\"]?)"),
    re.compile(r"(?i)(token\s*[:=]\s*['\"]?)([^'\"\s,\}]+)(['\"]?)"),
    re.compile(r"(?i)(x-mobsf-api-key\s*[:=]\s*['\"]?)([^'\"\s,\}]+)(['\"]?)"),
]


def redact_sensitive(text: str, extra_secrets: Iterable[str] | None = None) -> str:
    """Redact sensitive API keys, auth headers, and tokens from text."""
    if not isinstance(text, str) or not text:
        return text

    out = text

    # Redact known configured secret values
    for secret in get_active_secrets(extra_secrets):
        out = out.replace(secret, "[REDACTED]")

    # Redact header-like key patterns
    for pattern in _HEADER_PATTERNS:
        out = pattern.sub(r"\g<1>[REDACTED]\g<3>", out) if pattern.groups == 3 else pattern.sub(r"\g<1>[REDACTED]", out)

    return out


def redact_structure(data: Any, extra_secrets: Iterable[str] | None = None) -> Any:
    """Recursively redact dictionary, list, or string structures."""
    if isinstance(data, str):
        return redact_sensitive(data, extra_secrets)
    elif isinstance(data, dict):
        new_dict = {}
        for k, v in data.items():
            key_lower = str(k).lower()
            if any(s in key_lower for s in ("api_key", "apikey", "api-key", "authorization", "token", "password", "secret")):
                new_dict[k] = "[REDACTED]"
            else:
                new_dict[k] = redact_structure(v, extra_secrets)
        return new_dict
    elif isinstance(data, list):
        return [redact_structure(item, extra_secrets) for item in data]
    return data
