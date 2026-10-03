"""
sandbox-host/app/config.py — Configuration for decoupled dynamic sandbox host.
"""

import os
from pathlib import Path

SANDBOX_API_TOKEN = os.environ.get("SANDBOX_API_TOKEN", "erakshak-sandbox-secret-token")
DEFAULT_TIMEOUT_SECONDS = int(os.environ.get("SANDBOX_TIMEOUT_SECONDS", "90"))
MAX_TIMEOUT_SECONDS = 120
ARTIFACTS_DIR = Path(os.environ.get("SANDBOX_ARTIFACTS_DIR", str(Path(__file__).resolve().parent.parent / "artifacts")))
INETSIM_IP = os.environ.get("INETSIM_IP", "192.168.100.2")
CANARY_URL = os.environ.get("CANARY_URL", "http://1.1.1.1")
ROOTFS_BASE_DIR = Path(os.environ.get("SANDBOX_ROOTFS_DIR", "/opt/sandbox/rootfs"))

SUPPORTED_ARCHITECTURES = {
    "x86_64",
    "x86",
    "i386",
    "arm",
    "aarch64",
    "mips",
    "mipsel",
    "riscv64",
    "ppc",
    "ppc64",
}

def normalize_arch(arch_str: str | None) -> str:
    if not arch_str:
        return "x86_64"
    s = str(arch_str).lower()
    if "x86_64" in s or "amd64" in s:
        return "x86_64"
    if "x86" in s or "i386" in s or "i686" in s:
        return "i386"
    if "aarch64" in s or "arm64" in s:
        return "aarch64"
    if "arm" in s:
        return "arm"
    if "mipsel" in s:
        return "mipsel"
    if "mips" in s:
        return "mips"
    if "riscv" in s or "risc-v" in s:
        return "riscv64"
    if "ppc64" in s:
        return "ppc64"
    if "ppc" in s:
        return "ppc"
    return s.strip()
