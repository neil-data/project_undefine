# Static Analysis Engine

Identifies, parses and assesses a suspect file — Android APK, Windows PE,
Linux ELF or macOS Mach-O — without executing it, and produces one verdict an
investigating officer can act on.

```
File identification → hashing → format parsing → metadata → strings
        → IOC extraction → permissions → YARA → entropy
        → threat classification → storage
```

## The design premise

Static analysis fails in two directions, and both are worse than no tool.

**Reporting everything.** A mid-size APK yields several hundred "domains",
almost all of which are `schemas.android.com`, `libssl.so` and `index.php`
caught by a domain regex. Hand that list to an investigator and they redo the
triage the tool was supposed to do, with the one real C2 domain on line 214.

**Reporting a number.** "Risk: 62" is not a finding. Nobody can act on it, put
it in a case file, or explain it to a magistrate.

So the engine spends most of its effort on rejection, and finishes with a
verdict that carries its reasons:

> This application matches the pattern of a counterfeit traffic-challan
> application: it imitates the government service, takes a "fine" payment, and
> intercepts the bank one-time password so the victim never sees the
> transaction. The evidence is strong enough to act on.

## Pipeline

| Step | Module | What it produces |
|------|--------|------------------|
| 1 | `detection/` | File type from magic bytes and structure, not extension |
| 2 | `hashing/` | MD5, SHA-1, SHA-256 — the sample's identity |
| 3 | `metadata/` | Size, timestamps, container facts |
| 4 | `apk/` `pe/` `elf/` `mach_o/` | Manifest, permissions, sections, imports, signature |
| 5 | `strings/` | ASCII/UTF-8/UTF-16 literals with byte offsets |
| 6 | `container/` | Decompressed APK/JAR members — see below |
| 7 | `ioc/` | Validated, scoped, deduplicated indicators |
| 8 | `yara_scan/` | Signature matches, including the India scam rule set |
| 9 | `entropy/` | Whole-file, windowed and per-member entropy |
| 10 | `rules/` | Format-agnostic heuristics and a weighted score |
| 11 | `packing/` | Packer detection and best-effort UPX unpacking |
| 12 | `classification/` | Verdict, family, scam type, reasons, limitations |
| 13 | `storage/` | JSON report per sample, keyed by SHA-256, plus an IOC feed |

## Containers: the failure that hides in testing

An APK is a zip and its members are deflate-compressed. Scanning the file on
disk reads *compressed* bytes — the DEX never appears, the manifest never
appears, and every Android signature matches nothing.

This is invisible in tests, because `ZipFile.writestr` defaults to
`ZIP_STORED`: fixtures are uncompressed, rules match, and the engine detects
nothing in the field. Verified directly:

```
stored.apk    -> ['Android_SMS_Interception', 'IN_Bank_OTP_Interception', 'IN_Fake_EChallan_App']
deflated.apk  -> []
```

So `container/` decompresses members and scans each one, which also gives
per-member attribution — "the OTP interceptor is in `classes.dex`" is
evidence in a way that "somewhere in the APK" is not. A combined view is
scanned as well, because an APK declares permissions in the manifest and
implements behaviour in the DEX, so cross-member rules match neither member
alone.

Every fixture in `tests/test_container_scanning.py` uses `ZIP_DEFLATED`.

## Indicator extraction is mostly rejection

| Check | Removes |
|-------|---------|
| TLD validation against a curated suffix set | `libc.so`, `System.Data.dll`, `index.php`, `README.md` |
| Base58Check verification | Bitcoin-shaped build IDs and hashes |
| EIP-55 checksum (Keccak-256, see `ioc/keccak.py`) | 40-hex runs that are not wallets |
| Private/loopback/reserved classification | `127.0.0.1`, `192.168.x.x` as "destinations" |
| Platform and SDK host list | `schemas.android.com`, `w3.org`, Firebase |
| Phone-number context requirement | Ten-digit timestamps and identifiers |

What survives is defanged (`hxxps://c2[.]badactor[.]in`), deduplicated with an
occurrence count, and scoped `EXTERNAL` / `INTERNAL` /
`KNOWN_INFRASTRUCTURE`. Only external network, payment and contact indicators
appear in the actionable list.

`ioc/keccak.py` exists because Ethereum uses original Keccak-256 and
`hashlib.sha3_256` is a different function — using it would silently fail
every real address. It is verified against the published vectors.

## Entropy is evidence only where it contradicts structure

Every APK measures above 7.5 bits per byte, because a zip is compressed.
Reporting that as "packed" flags every Android sample ever submitted. What the
engine reports instead:

- A near-random run past the end of the last declared section — a second stage
  appended to a dropper, which section-level entropy cannot see.
- A member whose contents contradict its own name: `assets/config.json` at
  entropy 7.99 is an encrypted payload, and something in the app decrypts it.

For containers the trailing-region test is suppressed entirely, since a zip's
last member is compressed data at the end of the file by construction.

## Signatures

25 rules across two namespaces under `yara_rules/`.

**`india_scam_rules/`** — the fraud patterns named in the problem statement:
loan-app extortion, fake e-Challan/RTO, electricity-disconnection ("light
bill"), UPI collect-request abuse, bank OTP interception, fake KYC.

**`generic/`** — Android capabilities (accessibility abuse, overlay attacks,
SMS interception, runtime DEX loading, device admin), Windows behaviour
(injection, hollowing, ransomware, credential theft, UPX, anti-analysis), and
C2 infrastructure (Telegram bots, Discord webhooks, Tor, dynamic DNS).

Each rule carries `severity`, `confidence`, `family`, `category` and `mitre` in
its `meta` block, and those values flow straight into the score, the
classification and the MITRE mapping — **adding a rule file is enough to teach
the engine a new fraud pattern**, with no Python change.

Rules are written to discriminate, and each is tested against a legitimate
counterpart that must stay silent: the real mParivahan app is not flagged as an
imitation of itself, a bank app that mentions OTP constantly is not an
interceptor, and an app that draws its own window is not an overlay attack.

If `yara-python` is not installed, the scan reports `ENGINE_UNAVAILABLE` and
the classification records it as a limitation. It never silently returns "no
matches" — that is the failure mode that makes a tool untrustworthy.

## Verdicts

| Verdict | Meaning |
|---------|---------|
| `MALICIOUS` | Evidence of intent, not just capability |
| `SUSPICIOUS` | Capability established; the sandbox settles it |
| `UNDETERMINED` | Something was unreadable — packed, encrypted, or a stage did not run |
| `BENIGN` | Nothing found, stated with the limits of static analysis |

An app that *can* read SMS is a capability. An app that reads SMS, matches the
interception signature and ships a hardcoded UPI payee is intent. Capability
alone lands at `SUSPICIOUS`, deliberately.

`UNDETERMINED` exists for the case that matters most: a packed sample whose
payload never appears statically. Calling that benign would be the worst
answer the engine could give.

## Usage

```python
from static_analysis.bootstrap import create_engine

engine = create_engine(results_directory="analysis_results")
report = engine.analyze("suspect.apk")

print(report["classification"]["verdict"])      # 'malicious'
print(report["classification"]["scam_type"])    # 'echallan_scam'
print(report["classification"]["summary"])      # plain-language paragraph
```

Stored results and the cross-case IOC feed:

```python
from static_analysis.storage import create_result_repository

repository = create_result_repository("analysis_results")
repository.find_by_verdict("malicious")
repository.export_iocs()      # indicators shared across samples first
```

The engine compiles rules once at construction, so a batch of seized samples
should reuse one instance.

## Report shape

```json
{
  "sample_id": "ER-4F2A9C31",
  "sha256": "...", "md5": "...", "sha1": "...",
  "file_name": "challan.apk", "file_type": "apk", "platform": "android",
  "classification": {
    "verdict": "malicious", "confidence": "high",
    "risk_score": 100, "risk_band": "critical",
    "primary_family": "sms_stealer", "scam_type": "echallan_scam",
    "capabilities": ["Reads and sends text messages without the user"],
    "mitre_techniques": ["T1582", "T1636.004", "T1660"],
    "summary": "This application matches the pattern of ...",
    "limitations": [],
    "reasons": [{"summary": "...", "severity": "critical", "source": "yara",
                 "evidence": ["$sender1 @ 0x1f0: HDFCBK"]}]
  },
  "signatures": {"status": "completed", "rules_loaded": 25,
                 "india_scam_matches": ["IN_EChallan_OTP_Interceptor"]},
  "iocs": {"actionable": [{"value": "scamcollect@okhdfcbank", "type": "upi_id",
                           "defanged": "scamcollect@okhdfcbank"}]},
  "entropy": {"overall_entropy": 7.78, "is_container": true,
              "is_likely_packed": false, "embedded_blobs": []},
  "yara_matches": [...], "format_details": {...}, "packing": {...}
}
```

## Performance

A 12MB APK containing an 8MB native library analyzes in ~7s with a 35MB peak
working set. Two things got it there from ~90s:

- **String extraction is memoized** on (path, size, mtime). One analysis used
  to extract the same file three times — once in the engine and twice more
  inside the format analyzer.
- **Near-random regions are skipped.** Ciphertext contains no recoverable
  text; the four-character printable runs a regex finds inside it are
  coincidences, and an 8MB encrypted section produces millions of them. What
  is in those regions is not lost — the entropy analyzer reports the region
  and the classifier turns it into a stated limitation.

## Testing

```bash
pip install -e ".[signatures,test]"
python -m pytest static-analysis/tests -v
```

181 tests. The suite is weighted toward negative cases, because the difference
between a usable engine and an ignored one is what it declines to report: a
messaging app reading SMS, a maps app polling location, an app drawing its own
window, a private IP address, a platform SDK endpoint and a README filename
must all stay silent.

`tests/conftest.py` puts `src/` on the path so the suite runs without an
editable install — before it existed, all five test modules failed to import
and the entire suite silently did not run.
