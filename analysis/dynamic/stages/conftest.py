"""
conftest.py — Makes the `stages` package importable regardless of pytest's cwd.

WHY THIS IS NEEDED
------------------
The modules in this package use relative imports (`from .stage_definitions
import ...`), which is correct for package code but means they cannot be loaded
as top-level modules — a relative import in a top-level module raises
ImportError.

So the tests import through the package (`from stages.stage_definitions import
...`), and this file guarantees the package's *parent* directory is on
sys.path. That makes every invocation work:

    pytest                                   # from repo root
    pytest dynamic-sandbox/stages/           # from repo root
    cd dynamic-sandbox/stages && pytest      # from inside the package
"""

import sys
from pathlib import Path

_PARENT = Path(__file__).parent.parent.resolve()
_GRANDPARENT = _PARENT.parent.resolve()

if str(_PARENT) not in sys.path:
    sys.path.insert(0, str(_PARENT))
if str(_GRANDPARENT) not in sys.path:
    sys.path.insert(0, str(_GRANDPARENT))
