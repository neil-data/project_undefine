# Day 2b Results

## Layer counts

- Layer 1: 13/13 passed: 12 frozen bad fixtures each triggered the explicitly mapped expected violation; `clean_control` triggered zero.
- Layer 2: 14/14 passed: 11 raw IOC/report-builder cases, two mocked narrative replies through `analyze_and_save`, and one static YARA case through `analyze_and_save`.
- Integrity guard: 1 passed. Targeted B1/B3 unit suites: 21 passed.
- E2E verification command completed with 33 passed; no skips or xfails were introduced.

## Coverage

`tests/e2e/inputs/` contains raw strings, LLM responses, YARA matches, vendor verdicts, capability inputs, score inputs, timeline events, recommendations, and evidence flags for all requested scenarios. Layer 2 invokes production `_extract_network_indicators` and `_build_ioc_intelligence`; narrative and static YARA scenarios additionally invoke `analyze_and_save`. The report-builder cases enforce canonical evidence-state and domain rejection invariants. Day 3 score, timeline, recommendation, and MITRE output validators remain in the existing report validator suite for the Day 3 changes.

Static YARA/network-rule evidence now yields `network_communication` with `STATIC` evidence. `_cap_c2_communication` emits a capability only for observed dynamic evidence. Short SLDs remain invalid for bare strings; valid PSL domains are admitted in URL-host and observed DNS contexts.
