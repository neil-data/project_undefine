# Day 4 provider notes

## Part 0 self-check status

| Provider operation | Status | Reason |
| --- | --- | --- |
| Hybrid Analysis key presence | PASS/SKIP | Reports presence only; never displays key material. |
| Hybrid Analysis key-info/authentication | UNVERIFIED | No request is made until the exact documented operation is verified. |
| Hybrid Analysis public-hash lookup | UNVERIFIED for implementation | Official changelog documents GET `/search/hash`, replacing POST; request/response details and all following operations are not exposed by the official rendered API page used here. |
| Hybrid Analysis submission permission/quota | UNVERIFIED | No sample is uploaded; no undocumented operation is guessed. |
| MobSF reachability/API key/dynamic readiness | UNVERIFIED when configured | This checkout does not identify the installed MobSF version's API routes/docs. |

The user supplied a Hybrid Analysis key in chat. It was not copied into a file,
command, test, or self-check output. Provider tests use fake keys and mocked
responses. No provider request or sample submission was made.

## Part 1 trust boundary

Implemented under `providers/dynamic/`: abstract interface, provider selection,
normalized-only TTL cache, manual import adapter, deterministic fake provider,
all-or-nothing payload validation and normalization, evidence invariant
enforcement, DYNAMIC OBSERVED findings, separate INTEL verdicts, capped
confidence, provenance, IoC classification, endpoint correlation, and an
orchestrator adapter. Provider text is bounded and excluded from narrative
markup; data passed onward as provider text is delimited and JSON-escaped.
The proof suite uses the existing static-analysis mock and deterministic
provider responses; it never calls a provider or stores sample bytes.

## Verdict versus behavior policy

Provider-reported behavior is eligible for capped DYNAMIC evidence only after
passing the common trust boundary. A provider verdict or score is displayed as
separate INTEL attribution and may count as at most one vendor. It adds no intel
floor and never changes `risk_score`; a verdict without reported behavior does
not create DYNAMIC evidence.

## Live status

Part 0 has no live provider checks. Hybrid Analysis submit, poll, report fetch,
environment enumeration, submission permission, and remaining API budget
operations are UNVERIFIED. The official MobSF image in compose is tagged
`latest`; Docker is unavailable here, so the installed-version routes/docs,
auth behavior, and delete operation are UNVERIFIED. No live provider requests
or uploads have been made. Provider operations needing these contracts remain
unimplemented.
