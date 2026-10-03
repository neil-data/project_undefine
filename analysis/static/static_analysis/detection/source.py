"""Bounded random-access reader used by signature detectors."""

from pathlib import Path


class BinarySource:
    """Read a local file without loading its complete contents into memory."""

    def __init__(self, path: Path) -> None:
        self.path = path

    def read_at(self, offset: int, length: int) -> bytes:
        """Read up to *length* bytes from a non-negative byte offset."""
        if offset < 0 or length < 0:
            raise ValueError("offset and length must be non-negative")
        with self.path.open("rb") as stream:
            stream.seek(offset)
            return stream.read(length)
