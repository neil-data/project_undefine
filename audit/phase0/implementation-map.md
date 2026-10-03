# A1–A16 Implementation Paths & Root Cause Map

This document traces the exact data flow for every issue A1 through A16 from raw input to rendered report.

---

### A1 — Static findings incorrectly labeled OBSERVED
- **Input**: `raw_static` dict (YARA matches, extracted strings) and `dynamic_out` (`DynamicAnalysisOutput` with `dynamic_status="unavailable"` or no behavior).
- **Module & Function**: `backend/app/analysis.py:_build_evidence_correlations()` lines 448–474.
- **Intermediate Representation**:
  - Line 455: `for match in raw_static.get("yara_matches", []): ... "evidence_state": "OBSERVED"` (hardcoded for all static YARA matches).
  - Line 462–463: `ev_state = "OBSERVED" if dyn_dict else "STATIC"`, `dyn_ev = "See correlated runtime findings" if dyn_dict else "Dynamic evidence unavailable"`. When `dyn_dict` exists (even if `dynamic_status="unavailable"`), every MITRE technique receives `ev_state="OBSERVED"`.
  - In `agents/orchestrator/schema.py`: `MitreTechnique` model has no `evidence_state` field.
- **Report / Output**: Rendered in `reportPdf.tsx` Unit 9 Correlation Table (`item.evidence_state` = `OBSERVED`, `item.dynamic_evidence` = `"See correlated runtime findings"`).

---

### A2 — LLM refusal appears in report
- **Input**: Unsanitized evidence strings dumped into LLM prompt; sample strings or format context trigger Groq safety refusal.
- **Module & Function**:
  - `agents/investigation_engine/investigation_engine.py:_explain_malware()` lines 224–280.
  - `agents/narrative_agent/narrative.py:generate_narrative()` lines 270–320.
- **Intermediate Representation**:
  - Groq returns HTTP 200 with text: `"I'm sorry, but I can't help with that."`.
  - In `investigation_engine.py`: `ai_response` is stored directly into `MalwareExplanation(technical_details=ai_response, ...)`. No refusal check ("I'm sorry", "I can't help", etc.) is performed.
  - In `narrative.py`: `_is_grounded()` only checks `FORBIDDEN_UNGROUNDED_TERMS` ("systemd", "rc.local", etc.). Refusal phrases pass grounding, and `_clean_or_render_text()` returns the raw refusal text when JSON parsing fails.
- **Report / Output**:
  - Placed into `ai_analysis["malware_behavior"]` in `backend/app/analysis.py:_build_ai_analysis()`.
  - Rendered in `reportPdf.tsx:744` under `<b>Behaviour:</b>`.

---

### A3 — Capabilities incorrectly confirmed from static strings
- **Input**: `static.extracted_strings.urls` or `ips` populated from raw binary strings without dynamic execution.
- **Module & Function**: `agents/capability_classifier/capability_rules.py:_cap_data_exfiltration()` (lines 74–94) and `_cap_c2_communication()` (lines 251–276).
- **Intermediate Representation**:
  - In `_cap_data_exfiltration()`: presence of static URLs or IPs gives 0.3 score, immediately returning `CapabilityTag(capability="data_exfiltration", ...)`.
  - In `_cap_c2_communication()`: `static_c2 = "hardcoded_c2_ip" in static.static_risk_flags` (which was triggered by any static YARA IP rule) returns `CapabilityTag(capability="c2_communication", ...)`.
  - In `backend/app/analysis.py:678`: `key_findings.append(f"Malicious capabilities confirmed: {', '.join(caps)}")`.
- **Report / Output**: Threat assessment header states "Malicious capabilities confirmed: data_exfiltration, c2_communication, network_communication" on static-only samples.

---

### A4 — Confidence should be 71
- **Input**: Threat intel dictionary containing vendor verdicts (e.g., CERT-PL: malicious, vxCube: malicious, MalwareBazaar: signature hit, YOROI: "Legit File").
- **Module & Function**: `backend/app/analysis.py:_build_threat_assessment()` lines 685–715.
- **Intermediate Representation**:
  - Loop checks: `if v_low not in ("clean", "unrated", "benign"): agreeing += 1`.
  - `"legit file"` is not in `("clean", "unrated", "benign")`. It is erroneously treated as agreeing (malicious).
  - Agreeing count evaluates to 4/4 instead of 3/4.
  - Confidence calculation: `max(50, round(95 * (4 / 4))) = 95` instead of `max(50, round(95 * (3 / 4))) = 71`.
- **Report / Output**: `threat_assessment["confidence"]` = 95% in JSON and PDF.

---

### A5 — Combined static MITRE/capability cap
- **Input**: Static analysis findings producing MITRE techniques (+16 pts) and capabilities (+23 pts), totaling 39 static points.
- **Module & Function**:
  - `agents/orchestrator/risk_scoring.py:compute_risk_score()` lines 124–176.
  - `backend/app/analysis.py:_build_risk_explanation()` lines 541–614.
- **Intermediate Representation**:
  - In `risk_scoring.py`: `static_contrib` caps YARA at `SCORE_STATIC_CAP` (20), but `mitre_contrib` (+16) and `cap_contrib` (+23) are added directly to the total score without being bounded by `SCORE_STATIC_CAP`.
  - In `_build_risk_explanation()`: contributions list has separate lines for `mitre` (+16) and `capabilities` (+23). There is no combined static cap of 20 with a `{kind: "cap"}` reduction line.
- **Report / Output**: Risk explanation in PDF/JSON shows static points totaling 39, violating the static ceiling of 20.

---

### A6 — `index.html` / `rc.local` classified as domains
- **Input**: Strings "index.html", "rc.local", "network.target", "f.Hx" in binary or decompiled code.
- **Module & Function**:
  - `static-analysis/src/static_analysis/strings/service.py:_DOMAIN_PATTERN` (lines 72, 330–353).
  - `static-analysis/src/static_analysis/strings/explain.py` (lines 77–78).
  - `backend/app/analysis.py:_is_valid_domain()` (lines 150–183).
- **Intermediate Representation**:
  - `_DOMAIN_PATTERN` matches `(?:[A-Z0-9-]+\.)+[A-Z]{2,63}`. "html" and "local" match the 2–63 character length requirement.
  - `service.py` assigns `StringType.DOMAIN` without validating against public suffix lists or rejected file extensions.
  - `explain.py` labels them "Embedded domain name — a potential C2 or exfiltration destination".
  - `backend/app/analysis.py:_is_valid_domain()` rejects `.so` and some names, but does not check common file extensions (`.html`, `.local`, `.target`) or public suffixes.
  - `network_indicators["domains"]` includes `index.html`.
- **Report / Output**:
  - `index.html` appears in IoC intelligence as a domain.
  - `_generate_recommendations()` adds: `"Sinkhole or blacklist malicious domain queries at internal DNS resolvers: index.html"`.
  - `rc.local` is labeled "Embedded domain name".

---

### A7 — `8.8.8.8` classified as C2
- **Input**: `8.8.8.8` in binary strings or network connections.
- **Module & Function**: `backend/app/analysis.py:_extract_network_indicators()`, `backend/app/geoip.py:lookup_ip()`.
- **Intermediate Representation**:
  - No public DNS allowlist exists in `backend/app/`.
  - MaxMind ASN lookup identifies ASN 15169 (Google LLC), flagging `is_hosting=True` or `is_proxy=True`.
  - `backend/app/geoip.py:73` sets `threat_level = "high"`.
  - `_generate_recommendations()` includes `8.8.8.8` as a candidate IP for blocking.
- **Report / Output**:
  - Geo-IP Flags column displays `Proxy, Hosting, HIGH`.
  - C2 endpoints table and block recommendations include Google's public resolver.

---

### A8 — GeoIP severity disagrees with IoC severity
- **Input**: Public IP address belonging to a cloud/hosting ASN.
- **Module & Function**: `backend/app/geoip.py:lookup_ip()` vs `backend/app/analysis.py:_build_ioc_intelligence()`.
- **Intermediate Representation**:
  - `geoip.py` sets `threat_level = "high"` based strictly on `is_hosting or is_proxy`.
  - `_build_ioc_intelligence()` sets `classification = "UNKNOWN"` or `"LOW"` because no threat intelligence database (MalwareBazaar/ThreatFox) corroborates malicious activity.
- **Report / Output**: On the same report page, Geo-IP table column "Flags" says "HIGH", while the IoC intelligence table says "UNKNOWN" or "LOW".

---

### A9 — Proxy-style URLs incorrectly treated as suspicious/C2
- **Input**: Hardcoded URLs with proxy ports (e.g., `http://...:3128`, `:8080`, `:8888`, `:1111`).
- **Module & Function**: `backend/app/analysis.py:_extract_network_indicators()`, `_build_ioc_intelligence()`.
- **Intermediate Representation**: Hardcoded URLs are marked SUSPICIOUS by default and fed to the LLM and recommendations as C2 candidates without dynamic connection or threat intel backing.
- **Report / Output**: Narrative and IoC table speculate about proxy ports as active C2 infrastructure.

---

### A10 — Persistence paths not surfaced
- **Input**: Paths `/etc/cron.d/qv3b`, `/etc/init.d/qv3b`, `/etc/rc%d.d/S90qv3b`, `/tmp/.qv3b`, `/var/run/.qv3b`, `/usr/lib/.qv3b` present in ELF strings.
- **Module & Function**:
  - `agents/capability_classifier/capability_rules.py:_cap_cron_persistence()`, `_cap_persistence_init()`.
  - `agents/mitre_mapper/mitre_rules.py:_rule_cron_persistence()`, `_rule_init_persistence()`.
  - `backend/app/analysis.py:_generate_recommendations()`.
- **Intermediate Representation**:
  - Capability rules only inspect `dynamic.persistence_artifacts` or `dynamic.files_written`.
  - Static persistence strings are ignored when dynamic analysis is unavailable.
  - MITRE rules (T1053.003, T1037, T1543.002, T1564.001) are not emitted from static persistence paths.
- **Report / Output**: No persistence capabilities, no persistence MITRE techniques, and recommendations fail to advise hunting for these specific paths.

---

### A11 — Duplicate dynamic failure / `nulls` duration
- **Input**: Sandbox unconfigured or unreachable (`dynamic_out.dynamic_status = "unavailable"`, `dynamic_out.duration_seconds = None`).
- **Module & Function**: `backend/app/sandbox.py:run_dynamic_analysis()`, `frontend/src/lib/reportPdf.tsx:367–372`.
- **Intermediate Representation**:
  - `backend/app/sandbox.py` sets `failure_reason = "Dynamic analysis not performed: sandbox unavailable."`.
  - In `frontend/src/lib/reportPdf.tsx:370`: string concatenation prepends `"Dynamic analysis not performed: "` again.
  - Template interpolates `Duration: ${duration}s`, resulting in `"Duration: nulls"`.
- **Report / Output**: PDF displays `"Dynamic analysis not performed: Dynamic analysis not performed: ..."` and `"Duration: nulls"`.

---

### A12 — Recommendations incorrect/repeated
- **Input**: Case data with verdict MALICIOUS, `c2_domains` containing `index.html`.
- **Module & Function**: `backend/app/analysis.py:_generate_recommendations()` + `agents/investigation_engine/investigation_engine.py:_generate_recommendations()`.
- **Intermediate Representation**:
  - Both engines generate isolation advice independently with different phrasing, bypassing deduplication.
  - `index.html` is pulled from `c2_domains` and emitted as `"Sinkhole or blacklist malicious domain queries at internal DNS resolvers: index.html"`.
  - Non-allowlisted IPs are not formatted into structured perimeter firewall block rules.
- **Report / Output**: Repeated isolate recommendations, sinkholing `index.html`, missing IP block and persistence hunt items.

---

### A13 — Timeline/caption layout issue
- **Input**: `evidence_timeline` list in `backend/app/analysis.py:_build_evidence_timeline()`.
- **Module & Function**: `backend/app/analysis.py:_build_evidence_timeline()`, `frontend/src/lib/reportPdf.tsx:855–866`.
- **Intermediate Representation**:
  - `submitted_at` timestamp is assigned to both "Sample received" and "Static analysis completed".
  - In line 524: `ts = f"Approximate relative execution sequence (event timestamps unrecorded) [Seq #{event_idx}]"` is inserted as the `timestamp` cell value of a table row.
- **Report / Output**: Two rows have identical timestamps; table column is distorted by huge text in the timestamp cell; missing separate `Seq #` column and top-level caption.

---

### A14 — PDF page 2 footer overflow
- **Input**: Sample with 100+ explained strings.
- **Module & Function**: `frontend/src/lib/reportPdf.tsx` Unit 5 (Static Analysis).
- **Intermediate Representation**:
  - Pages are set to fixed `height: 1123px; overflow: hidden;` with `footer` positioned at `bottom: 18px`.
  - All explained strings are dumped into a single `<ul>` without pagination or top-N truncation.
  - Elements overflow the bottom margin and are cut off or rendered beneath the opaque footer.
- **Report / Output**: Explained strings list on page 2 is cut off mid-text.

---

### A15 — Raw MalwareBazaar rule name shown
- **Input**: Threat intel match with rule `Linux_Trojan_Gafgyt_0cd591cd`.
- **Module & Function**: `backend/app/analysis.py` (line 1388: `f"[MalwareBazaar] {yrule.get('rule_name')}"`) and narrative generation prompt.
- **Intermediate Representation**: The raw string `[MalwareBazaar] Linux_Trojan_Gafgyt_0cd591cd` is passed without normalization to the threat assessment summary and LLM prompt.
- **Report / Output**: Family sentence displays: `"[MalwareBazaar] Linux_Trojan_Gafgyt_0cd591cd"`.

---

### A16 — GeoIP missing-database handling
- **Input**: `GEOIP_DB_PATH` environment variable unset or pointing to a non-existent file.
- **Module & Function**: `backend/app/geoip.py:_ensure_loaded()`, `lookup_ip()`.
- **Intermediate Representation**:
  - `_city_reader` remains `None`.
  - `lookup_ip()` returns `None`.
  - The return value does not convey whether the database was missing/unconfigured vs whether the IP had no matching record.
- **Report / Output**: Both cases render identical fallback dashes (`—`), hiding database configuration failure from analysts.
