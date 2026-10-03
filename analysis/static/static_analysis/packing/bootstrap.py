"""Composition helpers for the packing detector and unpacker."""

from static_analysis.packing.detector import PackerDetector
from static_analysis.packing.unpacker import UpxUnpacker


def create_packing_detector() -> PackerDetector:
    return PackerDetector()


def create_unpacker() -> UpxUnpacker:
    return UpxUnpacker()
