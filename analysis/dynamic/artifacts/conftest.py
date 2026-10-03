"""
conftest.py — Makes this package importable regardless of pytest's cwd.

Same convention as stages/ and hooks/: modules here use relative imports, so
they must be loaded through the package rather than as top-level modules.
"""

import sys
from pathlib import Path

_PARENT = Path(__file__).parent.parent.resolve()
_GRANDPARENT = _PARENT.parent.resolve()

if str(_PARENT) not in sys.path:
    sys.path.insert(0, str(_PARENT))
if str(_GRANDPARENT) not in sys.path:
    sys.path.insert(0, str(_GRANDPARENT))
