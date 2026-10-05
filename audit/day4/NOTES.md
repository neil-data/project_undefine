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

## Part 2 Hybrid Analysis documentation gate

Verified from official sources: API v2 changelog v2.35.0 specifies `GET
/search/hash` replacing the deprecated `POST /search/hash`; official account
guidance says API key and secret are both required; full automated submission
requires the full key capability/vetting; public sandbox submissions are
searchable and available to the world. Sources:

* https://www.hybrid-analysis.com/docs/api/v2-changelog
* https://www.hybrid-analysis.com/knowledge-base/issuing-self-signed-api-key
* https://www.hybrid-analysis.com/knowledge-base/issuing-full-api-key-for-automated-submissions
* https://www.hybrid-analysis.com/knowledge-base/removing-uploaded-sensitive-files

UNVERIFIED and intentionally unimplemented: exact current lookup query
parameters/response schema, auth header, environment-list operation and
response, submit endpoint/multipart fields, submission-permission check,
polling/status endpoint and states, report fetch schema, request deletion, and
quota response. The official API reference is client-rendered and did not
expose its schema here. No guessed methods or endpoints were added.

## Part 3 MobSF documentation gate

`docker-compose.yml` uses the floating image tag
`opensecurity/mobile-security-framework-mobsf:latest`; the Docker engine is
not available in this environment, so there is no installed version whose own
routes or docs can be verified. UNVERIFIED and intentionally unimplemented:
URL health route, API-key validation route/header, upload/scan/report schema,
scan deletion operation, dynamic analyzer readiness, start/install/run/stop
routes, and dynamic report schema. The existing `sandbox/adapters/mobsf` files
are legacy code and are not treated as documentation for the installed build.
No MobSF request or APK upload was made.

## Part 4 Mach-O

Mach-O resolves to `NOT_SUPPORTED_PLATFORM`, creates no dynamic findings, and
renders exactly `Dynamic analysis: not performed (static-only)`. Non-x86_64
ELF similarly returns `NOT_SUPPORTED_PLATFORM` with its architecture in the
reason.

## State and test matrix

| State | Shared pipeline behavior | Real provider lane |
| --- | --- | --- |
| COMPLETED | Validated behavior only; verdict remains separate INTEL | No live lane |
| NO_RESULT | No dynamic evidence; one clean not-performed line | Generic path tested |
| NOT_SUPPORTED_PLATFORM | No dynamic evidence; architecture reason, or exact Mach-O static-only line | Tested |
| SUBMISSION_DISABLED | Represented by shared result state | Provider gate UNVERIFIED |
| KEY_MISSING | Represented by shared result state | Auth probes UNVERIFIED |
| KEY_RESTRICTED | Represented by shared result state | Permission probe UNVERIFIED |
| RATE_LIMITED | Represented by shared result state | Persistent provider budget not implemented |
| TIMEOUT | No dynamic evidence; clean line | Generic path tested |
| PROVIDER_UNAVAILABLE | No dynamic evidence; clean line | Generic path tested |
| INVALID_RESPONSE | Whole response rejected; no partial evidence | Fake/recorded path tested |

Part 1 uses deterministic fake responses only. Part 0 key-presence and config
tests do not make HTTP calls. There are no live provider checks. The shared
trust boundary has unit coverage; no full-suite run was repeated after the
provider/parser changes because the requested full-suite maximum was already
used.

## Part 5 parser status

LIEF and androguard are not installed. No package was downloaded. The facade
uses the repository's defensive ELF, PE, and Mach-O parsers and emits bounded
STATIC hints at confidence 0.5 or lower. It reports unknown packing unless a
native parser's packer/entropy indicator ran, reports Go build-info marker
presence only, and returns partial APK data because neither androguard nor
verified MobSF static data is available. Zip entry names are never emitted as
paths, URLs, or domains. Parser byte buffers are processed in memory and are
not retained.
