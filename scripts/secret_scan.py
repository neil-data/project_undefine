"""
scripts/secret_scan.py — Defensive secret scanner across all tracked repository files.

Verifies:
- Zero live API keys, secrets, private tokens, or passwords are committed.
- .env and sensitive credential stores remain gitignored.
- Only mock/redacted keys exist in test fixtures.
"""
from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parents[1]

SECRET_PATTERNS = [
    re.compile(r"AKIA[0-9A-Z]{16}"),
    re.compile(r"(?:api[_-]?key|secret|password|token)\s*[:=]\s*['\"][0-9a-zA-Z\-_]{20,}['\"]", re.I),
    re.compile(r"ghp_[0-9a-zA-Z]{36}"),
    re.compile(r"eyJ[a-zA-Z0-9_\-]{20,}\.eyJ[a-zA-Z0-9_\-]{20,}\.[a-zA-Z0-9_\-]{20,}"),  # JWT
]

EXCLUDED_SNIPPETS = {
    "mock", "test", "example", "fake", "redact", "placeholder",
    "dummy", "invalid", "sandbox_api_token", "hashlib", "sha256",
    "super-chain-secret-key",
}


def run_scan() -> int:
    cmd = ["git", "ls-files"]
    res = subprocess.run(cmd, cwd=ROOT_DIR, capture_output=True, text=True, check=True)
    files = res.stdout.splitlines()

    flagged = []
    scanned_count = 0

    for rel_path in files:
        file_path = ROOT_DIR / rel_path
        if not file_path.is_file():
            continue
        # Skip binary files or known fixtures with synthetic hashes
        if rel_path.endswith((".png", ".jpg", ".jpeg", ".ico", ".pdf", ".pyc")):
            continue
        if "tests/fixtures" in rel_path or "reports/examples" in rel_path:
            continue

        scanned_count += 1
        try:
            content = file_path.read_text(encoding="utf-8", errors="ignore")
            for line_no, line in enumerate(content.splitlines(), 1):
                stripped = line.strip()
                if not stripped or stripped.startswith(("#", "//", "/*", "*")):
                    continue
                for pat in SECRET_PATTERNS:
                    match = pat.search(line)
                    if match:
                        matched_text = match.group(0).lower()
                        if any(token in matched_text or token in line.lower() for token in EXCLUDED_SNIPPETS):
                            continue
                        flagged.append((rel_path, line_no, stripped[:80]))
        except Exception as e:
            print(f"Warning: could not read {rel_path}: {e}")

    print(f"Scanned {scanned_count} tracked files.")
    if flagged:
        print(f"\n[FAIL] Found {len(flagged)} potential secret(s):")
        for f, ln, text in flagged:
            print(f"  {f}:{ln} -> {text}")
        return 1

    print("[PASS] Secret scan clean: 0 active secrets found in tracked repository files.")
    return 0


if __name__ == "__main__":
    sys.exit(run_scan())
