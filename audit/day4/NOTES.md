# Day 4 provider notes

## Part 0 self-check status

| Provider operation | Status | Reason |
| --- | --- | --- |
| Hybrid Analysis key presence | PASS/SKIP | Reports presence only; never displays key material. |
| Hybrid Analysis key-info/authentication | UNVERIFIED | No request is made until the exact documented operation is verified. |
| Hybrid Analysis public-hash lookup | UNVERIFIED | No request is made until the operation and response are verified. |
| Hybrid Analysis submission permission/quota | UNVERIFIED | No sample is uploaded; no undocumented operation is guessed. |
| MobSF reachability/API key/dynamic readiness | UNVERIFIED when configured | This checkout does not identify the installed MobSF version's API routes/docs. |

The user supplied a Hybrid Analysis key in chat. It was not copied into a file,
command, test, or self-check output. Provider tests must use fake keys and
mocked responses. No provider request or sample submission was made.

## Verdict versus behavior policy

Provider-reported behavior is eligible for capped DYNAMIC evidence only after
passing the common trust boundary. A provider verdict or score is displayed as
separate INTEL attribution and may count as at most one vendor. It adds no intel
floor and never changes `risk_score`; a verdict without reported behavior does
not create DYNAMIC evidence.

## Live status

Part 0 has no live provider checks. The API operations above remain
UNVERIFIED. No Hybrid Analysis or MobSF network implementation is present.
