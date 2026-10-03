# Changes — Static Analysis Engine

## Fixed: file-type detection was non-functional for every format

**Found:** `src/static_analysis/detection/detectors.py` had doubled
backslashes in all 11 magic-byte signature literals (ZIP/APK, PE,
ELF, and both Mach-O byte-order/bitness variants), e.g.:

```python
# Before (broken):
if source.read_at(0, 4) not in (b"PK\\x03\\x04", b"PK\\x05\\x06", b"PK\\x07\\x08"):

# After (fixed):
if source.read_at(0, 4) not in (b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08"):
```

The doubled backslash made Python treat each signature as the literal
4-character string `\x03` instead of the actual byte `0x03` — so no
real file could ever match, and every file type detected as
`UNKNOWN` silently. This passed a code read-through but failed
immediately once actually executed against a real file.

**Verified fix** by building a real test APK (valid ZIP containing an
`AndroidManifest.xml`) and running it through `create_apk_analyzer()`
end-to-end: package name, application label, all requested
permissions (with per-permission `is_dangerous` flagging), and the
aggregated security-flags summary all extracted correctly after the
fix.

## Added: `tests/` directory (none existed before)

- `tests/test_detection.py` — one test per format's magic bytes,
  using structurally valid minimal fixtures (not just zero-padded
  magic bytes) so the tests reflect the real validation each detector
  performs. Includes a false-positive check against plain text.
- `tests/test_apk_extraction.py` — end-to-end test of the full APK
  analyzer: package name, app label, permission extraction, dangerous
  permission flagging, security-flags summary, and graceful error
  handling on a non-APK file.

Confirmed the test suite actually catches the original bug by
temporarily reintroducing it (mutation test) — the suite failed with
a clear, specific error message before the fix was restored.

**Run tests:**
```bash
pip install -e .
pip install pytest
python -m pytest tests/ -v
```
Expected: 13 passed.

## Not yet addressed (flagging for next pass)

- `core/engine.py` is still an explicitly non-operational composition
  root ("Non-operational composition root for future analysis
  orchestration") — the individual analyzers (APK/PE/ELF/Mach-O) work
  correctly when called directly via their `create_*_analyzer()`
  factories, but there's no single top-level "analyze any file"
  entry point wiring them together yet.
- No tests yet for PE, ELF, or Mach-O analyzers specifically (only
  detection-layer tests cover those formats) — APK is the only format
  with full end-to-end extraction tests so far.
