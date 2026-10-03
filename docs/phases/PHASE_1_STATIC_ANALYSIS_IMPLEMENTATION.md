# Phase 1 — Complete Static Analysis

## Overview

The static engine already parsed four formats (APK, PE, ELF, Mach-O), hashed,
extracted strings and ran a heuristic rule engine. Six of the twelve modules
the phase called for were missing, and one silent defect made the Android path
non-functional on real samples.

This phase completed the chain end to end:

```
File identification → hashing → parsing → metadata → strings
  → IOC extraction → permissions → YARA → entropy
  → threat classification → storage → tests → documentation
```

## What was found

### 1. The test suite was not running

All five test modules failed to import — `static_analysis` lives under `src/`
and resolves only after `pip install -e .`. Zero tests executed, and the
directory was absent from the root `pytest.ini`, so a full-repo run never
touched it either.

### 2. YARA detection did not exist

`README.md` advertised `static-analysis/yara_rules/india_scam_rules/` as
differentiator #1. The directory did not exist, `yara` was not a dependency,
and the report's `yara_matches` field was the heuristic rule engine's output
relabelled — an investigator reading "YARA matches" was reading something else
entirely.

### 3. Compressed APK members were never scanned  ← the serious one

An APK deflate-compresses its members, so scanning the file on disk reads
compressed bytes. Verified directly, with identical content:

```
stored.apk    -> ['Android_SMS_Interception', 'IN_Bank_OTP_Interception', 'IN_Fake_EChallan_App']
deflated.apk  -> []
```

Every Android signature and every string-derived indicator would have found
**nothing** on a real sample. It hides in testing because `ZipFile.writestr`
defaults to `ZIP_STORED`: fixtures are uncompressed, rules pass their tests,
and the engine detects nothing in the field.

### 4. IOC extraction was three inline list comprehensions

```python
urls = [s.value for s in extracted_strings if ... or "http" in s.value]
```

No validation, no deduplication, no scoping, no defanging. `libssl.so` and
`schemas.android.com` were reported alongside real C2 domains.

### 5. Entropy existed only per PE/ELF section

APKs have no sections, so Android samples got no packing assessment at all —
and the section-level view cannot see a payload appended past the last
declared section.

### 6. There was no verdict and no persistence

The pipeline ended at `risk_score: 62`. No verdict, family, scam type or
explanation, and nothing wrote the report anywhere.

### 7. `StaticAnalysisEngine()` raised TypeError

`AnalyzerRegistry.__init__` required `settings` positionally, so constructing
the engine without going through `create_engine()` failed outright.

## What was implemented

### New modules

| Module | Contents |
|--------|----------|
| `ioc/` | `models`, `contracts`, `extractor`, `keccak`, `bootstrap` — 14 indicator types, validated, scoped, deduplicated, defanged |
| `entropy/` | Whole-file, windowed and container-member entropy; appended-payload and disguised-blob detection |
| `yara_scan/` | Scanner over the rule tree, namespaced, with metadata resolution and graceful degradation |
| `classification/` | Verdict, confidence, family, scam type, capabilities, plain-language summary, stated limitations |
| `storage/` | Atomic per-sample JSON reports keyed by SHA-256, index, cross-case IOC feed |
| `container/` | Bounded decompressed access to zip-family members |

### Rule set — `static-analysis/yara_rules/`

25 rules, two namespaces.

**`india_scam_rules/`** (11 rules): loan-app contact harvesting and extortion,
fake e-Challan/Parivahan, e-Challan OTP interception, electricity-bill
("light bill") scam and its remote-access variant, UPI collect-request abuse,
bank OTP interception against Indian sender IDs, fake KYC.

**`generic/`** (14 rules): Android accessibility abuse, overlay attacks, SMS
interception, runtime DEX loading, device-admin persistence; Windows
injection, hollowing, ransomware, credential theft, UPX, anti-analysis; C2 via
Telegram bot, Discord webhook, Tor, dynamic DNS, paste sites.

Rule `meta` blocks carry severity, confidence, family, category and MITRE
techniques, which flow directly into the score, the classification and the
MITRE mapping. **A new fraud pattern needs a rule file and no Python change.**

### Engine

- Pipeline extended from 9 steps to 14 (signatures, indicators, entropy,
  classification, persistence).
- Container-aware scanning: per-member for attribution, plus a combined view
  so cross-member rules still fire (permissions live in the manifest,
  behaviour in the DEX).
- `AnalyzerRegistry` settings defaulted; `create_engine()` wires storage and an
  optional rule directory.

### Report additions

`signatures`, `iocs`, `entropy`, `classification`, `rule_risk_score`, and
`located_in` on each signature match naming the container member that carried
it.

## Correctness fixes made under test

Two design errors were caught by tests written to catch exactly them:

- **Every APK was "packed."** A zip's last member is compressed data at the end
  of the file, so the appended-payload heuristic fired on every benign APK.
  Containers now suppress the trailing-region test and rely on member-level
  contradiction instead.
- **Family typing was non-deterministic.** `Counter.most_common` leaves ties in
  insertion order, which is scan order — so the same sample could be typed
  `otp_theft` or `echallan_scam` depending on how it was compressed.

## Performance

A 12MB APK with an 8MB native library:

| | Before | After |
|---|---|---|
| Wall time | ~88s | **7.4s** |
| Peak memory | 110MB | **35MB** |

Two changes, both in string extraction:

- **Memoized on (path, size, mtime).** One analysis extracted the same file
  three times — once in the engine, twice more inside the format analyzer.
- **Near-random regions skipped.** Ciphertext holds no recoverable text; an
  8MB encrypted section produces millions of coincidental four-character
  runs. Those regions are still reported by the entropy analyzer and become a
  stated limitation in the verdict, so nothing is lost silently.

## Testing

| Suite | Tests |
|-------|-------|
| `test_ioc_extraction.py` | 49 |
| `test_yara_detection.py` | 24 |
| `test_classification.py` | 25 |
| `test_storage_and_pipeline.py` | 18 |
| `test_entropy_analysis.py` | 15 |
| `test_container_scanning.py` | 15 |
| Pre-existing (detection, APK, engine, packing, strings) | 35 |
| **Total** | **181 passing** |

Weighted toward negative cases: the real mParivahan app is not flagged as an
imitation of itself, a bank app that mentions OTP is not an interceptor, an app
drawing its own window is not an overlay attack, `README.md` is not a Moldovan
domain, and a ten-digit build number is not a phone number.

Keccak-256 is verified against published vectors, and the EIP-55 checksum
against the specification's test addresses.

## Verification

```bash
pip install -e "static-analysis[signatures,test]"
python -m pytest static-analysis/tests -v
```

181 passed. `static-analysis/tests` is now in the root `pytest.ini`, so a
full-repo run includes it.

## Status

Complete. Unrelated pre-existing failures elsewhere in the repository
(`pytest-asyncio` missing, `RiskScoringAgent` attribute errors, ingestion
end-to-end) are untouched by this phase.
