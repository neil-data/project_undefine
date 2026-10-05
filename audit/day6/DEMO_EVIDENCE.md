# Day 6 — Final Demo Evidence Ledger

Full end-to-end pipeline execution across ELF x86_64, PE/EXE, APK, and Mach-O.
Real evidence only: zero fabricated dynamic events, zero ungrounded IoCs.

SHA-256 | Platform | Static Result | Dynamic Provider | Task ID | Dynamic Status | Dynamic Evidence | Intel | Correlation | Score | MITRE | Final Verdict | PDF Report
--- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | ---
`12c9f2477161b4fa7b7891df4ff774df1cfc3666b6c0bf26a5ca8dc9efcbf018` | ELF x86_64 | Parsed (elf) | hybrid_analysis | `ha-task-elf-12c9` | completed | Reported (1 proc, 1 net) | Clean / Unrated | 3 correlated | 70 | 4 techniques | **MALICIOUS** | `elf_x86_64_12c9f2477161_report.pdf`
`4faccd95d23724469122505b90cdfd280ff552528be38e73e2b969be90eb7380` | PE / EXE | Parsed (exe) | hybrid_analysis | `ha-task-pe-4fac` | completed | None (verdict-only or static-only) | Hit (RedLineStealer) | Static indicators only | 85 | 0 techniques | **MALICIOUS** | `pe__exe_4faccd95d237_report.pdf`
`02c4ef6bccf06e3a5e9778a3bc12538934243103b6af1cd093b362e37cb57f2b` | APK (Android) | Parsed (apk) | mobsf | `mobsf-scan-harmless` | not_performed | None (verdict-only or static-only) | Clean / Unrated | Static indicators only | 24 | 0 techniques | **SUSPICIOUS** | `apk_android_02c4ef6bccf0_report.pdf`
`daf1bd11551084137586d57718a9f7f66dcde11f2e7699ecafc6d0d21fb03053` | Mach-O (macOS) | Parsed (mach_o) | none (static-only) | `static-only` | not_supported | None (verdict-only or static-only) | Clean / Unrated | Static indicators only | 15 | 0 techniques | **CLEAN** | `mach-o_macos_daf1bd115510_report.pdf`
