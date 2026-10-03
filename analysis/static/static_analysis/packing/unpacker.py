"""Best-effort unpacking of UPX-packed samples.

Never raises to the caller: a missing `upx` binary, a non-UPX sample, or any
subprocess failure all degrade to a structured `UnpackResult` with
`succeeded=False` and an `error` code, so the engine's overall analysis is
never blocked on unpacking being unavailable — the same defensive posture
already used elsewhere in this codebase (e.g. the MobSF dynamic-sandbox
pipeline's try/except/finally cleanup).
"""

import hashlib
import logging
import os
import shutil
import subprocess
import tempfile
from pathlib import Path

from static_analysis.packing.models import UnpackResult

_LOGGER = logging.getLogger(__name__)
_UPX_TIMEOUT_SECONDS = 30


class UpxUnpacker:
    """Shells out to the `upx` CLI (if installed) to decompress a packed sample."""

    def __init__(self, upx_executable: str | None = None) -> None:
        self._upx_executable = upx_executable

    def unpack(self, source: str | Path) -> UnpackResult:
        source_path = Path(source)
        upx_path = self._upx_executable or shutil.which("upx")
        if not upx_path:
            return UnpackResult(attempted=True, succeeded=False, method="upx", error="upx_not_installed")
        if not source_path.exists() or not source_path.is_file():
            return UnpackResult(attempted=True, succeeded=False, method="upx", error="source_not_found")

        # mkstemp returns an *open* low-level file descriptor as well as the path;
        # it must be closed immediately or it leaks — on Windows a leaked handle
        # blocks later cleanup (unlink) of this very file.
        fd, raw_path = tempfile.mkstemp(prefix="sentinel_unpacked_", suffix=source_path.suffix)
        os.close(fd)
        output_path = Path(raw_path)
        try:
            completed = subprocess.run(
                [upx_path, "-d", "-o", str(output_path), str(source_path)],
                capture_output=True,
                timeout=_UPX_TIMEOUT_SECONDS,
                check=False,
            )
        except subprocess.TimeoutExpired:
            self._cleanup(output_path)
            return UnpackResult(attempted=True, succeeded=False, method="upx", error="unpack_timeout")
        except OSError as error:
            self._cleanup(output_path)
            return UnpackResult(attempted=True, succeeded=False, method="upx", error=f"unpack_failed: {error}")

        if completed.returncode != 0 or not output_path.exists() or output_path.stat().st_size == 0:
            self._cleanup(output_path)
            stderr = completed.stderr.decode("utf-8", "replace").strip() if completed.stderr else ""
            reason = "not_upx_packed" if "NotPackedException" in stderr else "unpack_failed"
            return UnpackResult(attempted=True, succeeded=False, method="upx", error=reason)

        sha256 = hashlib.sha256(output_path.read_bytes()).hexdigest()
        return UnpackResult(
            attempted=True,
            succeeded=True,
            method="upx",
            output_path=str(output_path),
            sha256=sha256,
        )

    @staticmethod
    def _cleanup(path: Path) -> None:
        try:
            path.unlink(missing_ok=True)
        except OSError:
            _LOGGER.warning("Failed to remove temporary unpack artifact: %s", path)
