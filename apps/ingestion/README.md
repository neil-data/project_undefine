# Ingestion Gateway — Layer 1

The front door of the SentinelScan pipeline. Accepts a suspect sample, decides
whether it is analyzable at all, and hands it to the isolation queue.

Runs as its own small FastAPI app, separate from `backend/app/main.py` — matching
the architecture diagram's standalone "Ingestion Gateway" box. It has its own
container (`ingestion/Dockerfile`) and its own four-package dependency set.

```bash
uvicorn ingestion.gateway:app --port 8001
```

---

## Responsibilities

```
upload ─▶ stream to temp ─▶ validate ─▶ hash ─▶ dedup ─▶ store ─▶ queue
              (bounded)     (reject)   (sha256)          (samples) (redis)
```

1. **Stream** the upload to a temporary file, aborting past the size cap
2. **Validate** — size bounds, magic-header format detection, MIME derivation
3. **Hash** (SHA-256) — becomes the `sample_id` for the entire platform
4. **Dedup** — a hash already seen is not re-queued
5. **Store** the bytes in `SAMPLES_DIR`, keyed by hash
6. **Triage** (optional) — India-scam heuristic, see `india_scam_triage.py`
7. **Queue** onto the Redis `isolation_queue` list for `backend/app/ingestion_worker.py`

Validation runs **before** hashing, storing, or queueing, so a rejected upload
costs no permanent disk and no queue slot, and never reaches the analysis
pipeline.

---

## Validation policy

Implemented in [`validation.py`](./validation.py). Three checks, in order.

### 1. Size bounds

| Bound | Value | Rationale |
| --- | --- | --- |
| Minimum | 64 bytes | Below every real executable header; catches truncated and empty uploads |
| Maximum | 256 MiB | Above the largest realistic APK/PE; bounds what one request can force the gateway to hash and persist |

Override the maximum with `INGESTION_MAX_SAMPLE_BYTES` (bytes). A malformed or
non-positive value falls back to the default rather than disabling the cap.

The limit is enforced *during* streaming, so an oversized upload is refused
after one chunk crosses the line rather than being fully buffered first.

### 2. Magic-header format detection

A sample must actually be one of the formats the pipeline can analyze:

| Format | Detection | Platform |
| --- | --- | --- |
| `apk` | ZIP magic **and** `AndroidManifest.xml` in the archive listing | android |
| `exe` / `dll` | `MZ` → `e_lfanew` → `PE\0\0`; DLL via COFF `IMAGE_FILE_DLL` | windows |
| `elf` | `\x7fELF` with valid class/encoding/version, `ET_EXEC` or `ET_DYN` | linux |
| `mach_o` | Thin (32/64-bit, either endianness) or universal/fat magic | macos |

The APK check reads only the ZIP central directory, so a zip bomb cannot
detonate during validation.

### 3. MIME derivation

The MIME type is derived from the detected magic bytes. The client-declared
`Content-Type` is recorded but **never** used to decide the format — it is
attacker-controlled.

### What is deliberately *not* rejected

**Extension mismatch.** A Windows trojan named `invoice.pdf` is exactly the kind
of sample this platform exists to analyze. Refusing it would discard evidence.
The detected magic is authoritative, and the disagreement is reported as
`extension_mismatch: true` for the case record — signal, not an error.

On disk the sample is stored as `{sha256}.{detected_format}`, so the filesystem
reflects what the file actually is. This also means a hostile filename
(`../../etc/passwd`) has nowhere to go: the stored name is derived entirely from
the content hash and the detected format.

---

## API

### `POST /ingest`

`multipart/form-data`

| Field | Type | Required | Notes |
| --- | --- | --- | --- |
| `file` | file | yes | The sample |
| `package_name` | string | no | Enables India-scam triage |
| `app_label` | string | no | Improves triage confidence |
| `permissions` | string | no | Comma-separated Android permissions |

Triage only runs when `package_name` is supplied — not every format exposes this
at intake (a Windows PE will not).

**`200 OK`**

```json
{
  "sample_id": "e3b0c44298fc1c14...",
  "is_duplicate": false,
  "triage_flagged": true,
  "triage_category": "loan_app_scam",
  "triage_confidence": 0.85,
  "queue_priority": "high",
  "submitted_at": "2026-08-06T10:15:00+00:00",
  "sample_path": "ingestion_samples/e3b0c442....apk",
  "file_format": "apk",
  "platform": "android",
  "mime_type": "application/vnd.android.package-archive",
  "file_size_bytes": 4821004,
  "extension_mismatch": false
}
```

`sample_path` is `null` for a duplicate — the original submission's copy is
retained rather than rewritten.

**Errors** — body is `{"detail": {"error": "...", "message": "..."}}`

| Status | `error` | Cause |
| --- | --- | --- |
| 400 | `empty_file` | Zero bytes |
| 400 | `file_too_small` | Below 64 bytes; likely truncated |
| 413 | `file_too_large` | Exceeds `INGESTION_MAX_SAMPLE_BYTES` |
| 415 | `unsupported_format` | Magic bytes match no supported format |
| 422 | — | FastAPI validation; e.g. missing `file` part |

### `GET /queue/length`

Development helper. Reports isolation-queue depth and which backend is in use
(`redis` or `in-memory-fallback`).

---

## Queue contract

The job pushed onto `isolation_queue`, consumed by
`backend/app/ingestion_worker.py`:

```json
{
  "sample_id": "e3b0c442...",
  "filename": "Aadhaar_Update.apk",
  "sample_path": "ingestion_samples/e3b0c442....apk",
  "submitted_at": "2026-08-06T10:15:00+00:00",
  "validation": {
    "file_format": "apk",
    "platform": "android",
    "mime_type": "application/vnd.android.package-archive",
    "file_size_bytes": 4821004,
    "extension_mismatch": false
  },
  "triage": { "flagged": true, "category": "loan_app_scam", "confidence": 0.85 }
}
```

`triage` is `null` when no `package_name` was supplied. Jobs whose triage
priority is `high` are `LPUSH`ed to the front of the queue; everything else is
`RPUSH`ed to the back — the actual payoff of triaging at intake time.

`filename` preserves the caller's original name as evidence, even though it is
never used to build the storage path.

---

## Configuration

| Variable | Default | Purpose |
| --- | --- | --- |
| `REDIS_URL` | *(unset)* | Redis connection. Unset → in-memory queue fallback |
| `INGESTION_SAMPLES_DIR` | `ingestion_samples` | Where validated sample bytes are persisted |
| `INGESTION_MAX_SAMPLE_BYTES` | `268435456` | Upload size cap |

Without `REDIS_URL` the gateway falls back to an in-memory queue so it stays
runnable and demoable — but queue state is lost on restart, so that mode is for
development only, not the real isolation-controller integration.

`SAMPLES_DIR` is shared with the `backend` container via a Docker volume (see
`docker-compose.yml`); without that, a saved sample would be unreachable by the
consumer that is supposed to analyze it.

---

## Design note: why validation is duplicated

`validation.py` deliberately re-implements a subset of the signatures in
`static-analysis/src/static_analysis/detection/detectors.py`, using stdlib only.

`ingestion/Dockerfile` copies only `ingestion/` and installs only
`ingestion/requirements.txt` — the gateway is its own container and must not
depend on the static-analysis engine. The duplication is bounded and
intentional: this is a cheap **gate** that reads headers, while the
authoritative deep parse (section tables, imports, architecture) happens
downstream in the engine.

**Keep the two in sync when a new format is added to `TargetFormat`.**

---

## Tests

```bash
python -m pytest ingestion -q
```

| File | Scope |
| --- | --- |
| `test_validation.py` | Unit — detection per format, rejections, size boundaries, MIME derivation, extension-mismatch policy |
| `test_gateway.py` | Integration — `/ingest` and `/queue/length` through the real ASGI stack: multipart parsing, persistence, dedup, queue ordering, error codes, path safety |
| `test_pipeline_e2e.py` | End-to-end — upload → validate → hash → store → Redis → consumer pick-up, driving the real `ingestion_worker` loop |
| `test_india_scam_triage.py` | Unit — the India-scam triage heuristic |

`conftest.py` builds structurally valid APK/PE/ELF/Mach-O headers in memory, so
the suite needs no sample files on disk and never trips the repo's
"never commit real malware samples" rule.

Redis is not required — the tests drive the gateway's in-memory fallback. The
end-to-end test stubs `backend.app.analysis` at the far boundary so it does not
pull in the static-analysis engine and LangGraph graph; its scope ends at
consumer pick-up, and the engine has its own suite under `static-analysis/tests/`.
