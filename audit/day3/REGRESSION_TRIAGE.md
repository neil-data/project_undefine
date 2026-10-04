# Day 3 regression triage (starting at 2297e05)

Recorded suite: 25 failed, 1 collection error, 1034 passed. Commit attribution below is from the first post-Day-1 change touching the affected implementation; no bisect was needed to identify the direct edits.

| Failing test | Protected guarantee | Breaking commit | Classification |
|---|---|---|---|
| `test_vendor_confidence_math` | 71% confidence for existing vendor mix | 2297e05 | REGRESSION: confidence counted-label change |
| `test_a4_legit_file_counted_as_benign_disagreement_produces_71` | Legit File counts as benign disagreement | 2297e05 | REGRESSION: clean label mapping omitted alias |
| `test_a4_various_benign_verdicts_not_counted_as_agreeing[Legitimate]` | Legitimate is not malicious agreement | 2297e05 | REGRESSION: clean label mapping omitted alias |
| `test_a4_unrated_and_unknown_are_not_counted` | Unrated labels excluded | 2297e05 | INTENDED POLICY CHANGE: fewer than three counted vendors caps confidence at 70; updated assertion |
| `TestSmsAccessRule::test_confidence_is_exactly_07_when_only_static_signal` | Day 3 policy bounds static-only MITRE confidence | 2297e05 | INTENDED POLICY CHANGE: static-only confidence <= 0.5; assertion and changelog updated |
| `TestC2CommsRule::test_fires_on_flagged_c2_connection` | Observed flagged Android C2 maps to Mobile ATT&CK | 2297e05 | INTENDED POLICY CHANGE: Android uses T1437.001; assertion updated |
| `TestRegistryPersistenceRule::test_fires_on_run_key_write` | Observed registry persistence maps to technique | 2297e05 | REGRESSION: rule input/evidence-state handling |
| `TestKeyloggingRule::test_fires_on_static_keyword_alone_lower_confidence` | Static keylogging indicator retained at reduced confidence | 2297e05 | INTENDED POLICY CHANGE: static-only confidence <= 0.5; assertion and changelog updated |
| `test_detects_setuid_privilege_escalation` | Linux setuid detection | 2297e05 | REGRESSION: capability rule input normalization |
| `test_detects_ld_preload_hijack` | Linux LD_PRELOAD detection | 2297e05 | REGRESSION: capability rule input normalization |
| `test_detects_launchd_persistence` | macOS launchd detection | 2297e05 | REGRESSION: capability rule input normalization |
| `test_graph_produces_expected_findings_for_known_mock_sample` | Pipeline keeps typed capability findings | 2297e05 | INTENDED POLICY CHANGE: Android C2 uses T1437.001; assertion updated; capability dict crash fixed |
| `test_ioc_extractor_sanitizes_bridge_ips_and_binaries` | Bridge IPs and binaries excluded from IoCs | 69b1992 | REGRESSION: IoC normalization/allowlist boundary |
| `test_narrative_grounded_validation` | Grounded narrative accepted | 69b1992 | REGRESSION: grounding validator compatibility |
| `test_known_android_domain_is_classified_benign` | Known Android host remains benign | 69b1992 | REGRESSION: benign host allowlist compatibility |
| `test_recommendations_synthesis_high_risk` | High-risk report has useful recommendations | 2297e05 | REGRESSION: recommendation synthesis compatibility |
| `TestBuildThreatAssessment::test_high_score_gives_malicious` | Corroborated high score is MALICIOUS | 94bd0bd | INTENDED POLICY CHANGE: uncorroborated high score is capped; update input with family/observed/intel evidence |
| `test_a1_threat_intel_yara_is_labeled_intel` | Provider YARA provenance is INTEL; local scan is STATIC | 69b1992 | REGRESSION: source attribution must distinguish API vs local rules |
| `test_a2_narrative_agent_refusal_falls_back` | Refusal yields safe fallback | 69b1992 | REGRESSION: refusal fallback compatibility |
| `test_a3_threat_assessment_wording_capabilities_identified` | Capability counts use evidence-aware wording | 2297e05 | INTENDED POLICY CHANGE: observed/intel vs static indicator wording; update assertion and changelog |
| `test_a7_ordinary_ips_continue_normal_classification` | Public resolver remains informational evidence | 69b1992 | REGRESSION: resolver visibility/classification |
| `test_a7_dynamic_flagged_evidence_still_represented_for_resolver` | Observed resolver evidence remains visible | 69b1992 | INTENDED POLICY CHANGE: public resolver stays benign informational evidence while retaining OBSERVED provenance |
| `test_a10_mitre_and_capabilities_surface_static_persistence` | Static paths surface as low-confidence MITRE/capabilities | 2297e05 | REGRESSION: static path rule lost its finding |
| `test_a12_structured_perimeter_firewall_rules_for_c2_ips` | Observed/intel C2 yields structured firewall rule | 2297e05 | REGRESSION: firewall recommendation synthesis |
| `test_a13_timestamp_cell_is_clean_not_long_sentence` | Null timestamp displays concise text | 2297e05 | INTENDED POLICY CHANGE: assert timestamp_display and `not recorded` for nulls |
| Collection: `apps/backend/tests/test_elf_review_fixes.py` (`_is_grounded`) | Grounding regression tests remain collectable | 69b1992 | REGRESSION: restore wrapper around current grounding validator |

### Required e2e layering change

The product-output suite will use only `clean_control`; frozen bad fixtures remain asserted by their mapped detector in `tests/e2e/test_detectors.py`. Add the Mirai fixture's missing detector IDs to that map. This changes fixture assignment, not assertion strength: each bug remains an explicit detector contract and the raw-input pipeline tests remain separate.

## Final disposition

17 failures were code regressions and are fixed. 9 assertion/input changes encode the listed Day 3 policy changes as platform/evidence-aware contracts. The collection error was fixed by restoring `_is_grounded` as a wrapper over `_validate_narrative`; the MITRE dict crash was fixed by normalizing typed and dict YARA matches. Final full and e2e runs are recorded in `BASELINE_AFTER.md`.
