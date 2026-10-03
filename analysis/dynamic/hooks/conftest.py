"""
conftest.py — Makes the `hooks` package importable regardless of pytest's cwd.

See stages/conftest.py for the full explanation: modules here use relative
imports, so they must be loaded through the package rather than as top-level
modules. This puts the package's parent directory on sys.path so that
`from hooks.api_catalog import ...` resolves from any working directory.
"""

import sys
from pathlib import Path

_PARENT = Path(__file__).parent.parent.resolve()
_GRANDPARENT = _PARENT.parent.resolve()

if str(_PARENT) not in sys.path:
    sys.path.insert(0, str(_PARENT))
if str(_GRANDPARENT) not in sys.path:
    sys.path.insert(0, str(_GRANDPARENT))
