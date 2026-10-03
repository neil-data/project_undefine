"""
ingestion/india_scam_triage.py — Fast pre-triage heuristics for
India-specific scam patterns, run at INGESTION time — before the
sample even reaches the full static-analysis pipeline.

Why this is separate from static-analysis/yara_rules/india_scam_rules/:
This module doesn't unpack or deeply inspect the file. It only looks
at cheap, immediately-available metadata (declared package name/app
label, requested permissions) to decide "does this look worth
prioritizing?" — a fast queue-ordering signal, not a detection
verdict. The real detection (YARA matching, full permission
analysis) still happens in static-analysis. Ingestion triage exists so
a flood of samples can be triaged in the order most likely to matter
to an investigator, without waiting for the full pipeline on each one.

Three scam categories targeted, matching what's named in the PS:
  - loan_app_scam      (predatory instant-loan apps)
  - echallan_scam       (fake traffic-fine / RTO payment apps)
  - utility_bill_scam   (fake electricity/water bill payment apps)
"""

from __future__ import annotations
from dataclasses import dataclass, field
from typing import Optional


# Keyword sets — package name / app label matching (case-insensitive).
# Deliberately broad; this is triage, not final judgment, so false
# positives here just mean "checked a bit earlier," not "wrongly accused."
LOAN_APP_KEYWORDS = [
    "loan", "cash", "credit", "instant", "emi", "fastcash", "quickloan",
    "moneyloan", "rupee", "urgentcash", "microloan", "advance",
]

ECHALLAN_KEYWORDS = [
    "echallan", "e-challan", "challan", "rto", "trafficfine", "vahan",
    "parivahan", "trafficpolice",
]

UTILITY_BILL_KEYWORDS = [
    "bijli", "vidyut", "electricitybill", "powerbill", "waterbill",
    "gasbill", "utilitypay", "billpay", "lightbill",
]

# Permission combinations that, alongside the keyword match, raise
# confidence — these are the actual capability the scam relies on.
HIGH_RISK_PERMISSIONS = {
    "android.permission.READ_SMS",
    "android.permission.RECEIVE_SMS",
    "android.permission.SYSTEM_ALERT_WINDOW",
    "android.permission.READ_CONTACTS",
    "android.permission.READ_CALL_LOG",
}


@dataclass
class TriageResult:
    is_flagged: bool
    category: Optional[str]
    confidence: float
    matched_keywords: list[str] = field(default_factory=list)
    matched_permissions: list[str] = field(default_factory=list)
    priority: str = "normal"  # "high" | "normal" — used for queue ordering


def _keyword_match(text: str, keywords: list[str]) -> list[str]:
    text_lower = text.lower()
    return [kw for kw in keywords if kw in text_lower]


def triage_sample(
    package_name: str,
    app_label: Optional[str] = None,
    permissions: Optional[list[str]] = None,
) -> TriageResult:
    """
    Fast pre-triage check. Call this at ingestion time, immediately
    after hash computation, before queuing for full static analysis.

    Args:
        package_name: declared package/bundle identifier
        app_label: human-readable app name if available (often more
                   telling than package name for scam apps)
        permissions: requested permission list, if already extractable
                     cheaply at ingestion (e.g. from the manifest
                     without full unpacking)
    """
    permissions = permissions or []
    search_text = f"{package_name} {app_label or ''}"

    categories = [
        ("loan_app_scam", LOAN_APP_KEYWORDS),
        ("echallan_scam", ECHALLAN_KEYWORDS),
        ("utility_bill_scam", UTILITY_BILL_KEYWORDS),
    ]

    best_category = None
    best_keywords: list[str] = []

    for category, keywords in categories:
        matches = _keyword_match(search_text, keywords)
        if matches and len(matches) > len(best_keywords):
            best_category = category
            best_keywords = matches

    matched_perms = [p for p in permissions if p in HIGH_RISK_PERMISSIONS]

    if not best_category:
        return TriageResult(is_flagged=False, category=None, confidence=0.0)

    # Confidence: keyword match alone is a weak signal (naming can be
    # coincidental); keyword + high-risk permissions together is what
    # actually justifies fast-tracking the sample.
    confidence = 0.4
    if matched_perms:
        confidence += min(0.5, 0.15 * len(matched_perms))

    priority = "high" if confidence >= 0.7 else "normal"

    return TriageResult(
        is_flagged=True,
        category=best_category,
        confidence=round(min(confidence, 1.0), 2),
        matched_keywords=best_keywords,
        matched_permissions=matched_perms,
        priority=priority,
    )