# Day 2b Results

## Layer counts

- Layer 1: 13/13 passed: 12 frozen bad fixtures each triggered the explicitly mapped expected violation; `clean_control` triggered zero.
- Layer 2: 14/14 passed: 11 raw IOC/report-builder cases, two mocked narrative replies through `analyze_and_save`, and one static YARA case through `analyze_and_save`.
- Integrity guard: 1 passed. Targeted B1/B3 unit suites: 21 passed.
- E2E verification command completed with 33 passed; no skips or xfails were introduced.

## Coverage

`tests/e2e/inputs/` contains raw strings, LLM responses, YARA matches, vendor verdicts, capability inputs, score inputs, timeline events, recommendations, and evidence flags for all requested scenarios. Layer 2 invokes production `_extract_network_indicators` and `_build_ioc_intelligence`; narrative and static YARA scenarios additionally invoke `analyze_and_save`. The report-builder cases enforce canonical evidence-state and domain rejection invariants. Day 3 score, timeline, recommendation, and MITRE output validators remain in the existing report validator suite for the Day 3 changes.

Static YARA/network-rule evidence now yields `network_communication` with `STATIC` evidence. `_cap_c2_communication` emits a capability only for observed dynamic evidence. Short SLDs remain invalid for bare strings; valid PSL domains are admitted in URL-host and observed DNS contexts.

## Day 3 Changes

- Risk scoring keeps the static MITRE + capability portion at or below 20 points and reconciles the risk explanation to the final score. Generic, compiler, and hash-constant YARA rules are zero-weight.
- Scores at or above 85 are capped at 84 without a confirmed intelligence floor, observed telemetry, or a recognized family-specific YARA rule. Uncorroborated scores therefore cannot yield CRITICAL.
- Timeline entries preserve source timestamps and sequence numbers. Missing timestamps stay null instead of being fabricated as approximate offsets; duplicate source timestamps remain distinguishable by sequence.
- Credential rotation and revocation advice is emitted only when a credential capability is present. Uncorroborated T1056.001 alone does not authorize credential advice.
- T1071/T1071.001 mapping now requires observed network traffic; static IPs, URLs, and YARA flags do not independently claim those techniques.

Targeted Day 3, MITRE, risk-scoring, B1, and B3 unit suites passed: 56 tests. E2E was not rerun after the Day 2b three-run limit; the Day 3 changes have unit coverage but still need Layer 2 e2e confirmation.
