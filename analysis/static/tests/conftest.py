"""
conftest.py — Makes `static_analysis` importable without an editable install.

The package lives under `src/`, so `from static_analysis...` only resolves
after `pip install -e .`. Tests that silently fail to collect are tests that
do not run, which is how the whole suite sat at five collection errors — so
the path is wired here instead, matching the conftest convention the rest of
this repo uses (see dynamic-sandbox/hooks/conftest.py).
"""

import sys
from pathlib import Path

_SRC = (Path(__file__).parent.parent / "src").resolve()

if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))
