# Artifact Custody

Packet captures, memory dumps, screenshots, dropped files, guest logs — the
exhibits that outlive a run and end up attached to a case file.

## What makes them evidence rather than files

**Hashed at capture.** An artifact recorded without a digest cannot later be
shown to be the same bytes. The hash is taken when the file is registered, not
when the report is written.

**Chained.** Each entry carries the digest of the one before it, so the
manifest detects its own alteration: deleting the packet capture that
contradicts a finding breaks the chain visibly rather than silently.

**Immutable.** Re-registering the same logical artifact with different bytes is
refused, not overwritten. Losing the original is the one failure that cannot be
recovered from.

`verify()` distinguishes three failures, because they mean different things:

| Result | Meaning |
|--------|---------|
| `modified` | The bytes on disk changed since capture |
| `missing` | The file is gone |
| `chain_broken` | The manifest itself was edited |

## Memory dumps get read, not just filed

A packed sample has to decrypt itself to run. Whatever the file on disk
concealed — the real strings, the C2 domain, the configuration, the second
stage — is sitting in the process image in plaintext.

`MemoryDumpAnalyzer` runs the Phase 1 static engine over the captured image and
reports the **difference** against what the file itself gave up:

```python
result = MemoryDumpAnalyzer().analyze(dump_path, disk_indicators=static_iocs)
result.indicators_absent_from_disk   # what the sample was hiding
result.signature_matches             # rules that fired on the image
```

The image is scanned in windows, so a multi-gigabyte dump is never resident.

When the static package is not installed on the detonation plane — it is a
separate distribution and the plane is deliberately minimal — this reports
`engine_unavailable`. It never reports "nothing found", which is
indistinguishable from a clean dump.

## Usage

```python
from artifacts import ArtifactStore

store = ArtifactStore("evidence", analysis_id)
store.register("/tmp/capture.pcap", "pcap", stage_id="network")
store.register("/tmp/memory.raw", "memdump", move=True)   # don't duplicate 4GB
store.register_bytes(png_bytes, "screenshot", "stage3.png")

store.verify()      # {'intact': True, 'artifact_count': 3, ...}
```

Copying is the default because the guest-side path is reverted out from under
you by the next snapshot restore; `move=True` is for artifacts already on this
host that should not be duplicated.
