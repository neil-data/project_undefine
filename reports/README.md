# E-Rakshak Reports Subsystem

The `reports/` directory manages generated analysis reports, reference report fixtures, and sample outputs produced by the E-Rakshak reporting pipeline.

---

## Directory Organization

```
reports/
├── examples/                      # Canonical reference reports for verified malware samples
│   ├── control_benign_report.json # Reference analysis report for a clean/benign control sample
│   └── mirai_droppee_report.json  # Reference analysis report for a real Mirai IoT dropper
└── fixtures/                      # Test reporting fixtures and validation templates
```

---

## Report Formats & Generation Pipeline

The reporting engine translates raw static, dynamic, memory, and threat-intel analysis results into authoritative reports in two primary formats:

1. **JSON Format (`.json`)**:
   - Machine-readable, structured data representation conforming to the platform schema (`packages/schemas/schema.py`).
   - Contains raw indicator sets, MITRE ATT&CK matrix mappings, behavioral event timelines, and chain-of-custody cryptographic hashes.
   - Used for programmatic consumption by SIEM/SOAR platforms, automated ticketing, and frontend dashboard rendering.

2. **PDF Format (`.pdf`)**:
   - High-fidelity executive and technical documents compiled via ReportLab (`apps/backend/app/pdf.py`).
   - Includes custom styled layout, risk gauge visualization, severity-coded tables, MITRE tactic breakdowns, and evidentiary footers.
   - Designed for digital forensics investigators, SOC tier-3 teams, and regulatory compliance reports.
