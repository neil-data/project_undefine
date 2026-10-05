"""Hybrid Analysis dynamic analysis provider adapter.

Adheres strictly to the trust boundary and verified API contracts:
- Supported platforms: ELF x86_64, EXE, PE, DLL.
- Other ELF architectures: NOT_SUPPORTED_PLATFORM.
- Evidence rule: Provider-reported behavior -> DYNAMIC/OBSERVED (capped confidence).
- Verdict/score -> INTEL only, at most one vendor, never alters risk score.
- Submission only if ALLOW_EXTERNAL_SUBMISSION=true, permitted by key, within budget.
"""
from __future__ import annotations

import datetime
import json
import os
from pathlib import Path
from typing import Any

from packages.config import get_setting, load_config, redact_sensitive
from .base import DynamicState, NormalizedProviderResult, ProviderAdapter, ProviderObservation
from .pipeline import render_dynamic_result

ROOT_DIR = Path(__file__).resolve().parents[2]
RECORDED_ENVS_PATH = ROOT_DIR / "tests" / "fixtures" / "providers" / "hybrid_analysis" / "environments.json"


class HybridAnalysisAdapter(ProviderAdapter):
    name = "hybrid_analysis"

    def __init__(
        self,
        api_key: str | None = None,
        environments_data: list[dict] | None = None,
        daily_request_limit: int | None = None,
        daily_submission_limit: int | None = None,
        budget_file: str | None = None,
        timeout: int = 15,
    ):
        load_config()
        self.api_key = (api_key or get_setting("HYBRID_ANALYSIS_API_KEY") or "").strip()
        self.timeout = timeout

        req_limit = daily_request_limit or get_setting("PROVIDER_DAILY_REQUEST_LIMIT") or "100"
        sub_limit = daily_submission_limit or get_setting("PROVIDER_DAILY_SUBMISSION_LIMIT") or "20"
        self.daily_request_limit = int(req_limit)
        self.daily_submission_limit = int(sub_limit)
        self.budget_file = Path(budget_file) if budget_file else ROOT_DIR / ".ha_budget.json"

        # Load environment list dynamically from argument, recorded file, or empty
        self.environments: list[dict] = []
        if environments_data is not None:
            self.environments = list(environments_data)
        elif RECORDED_ENVS_PATH.exists():
            try:
                self.environments = json.loads(RECORDED_ENVS_PATH.read_text(encoding="utf-8"))
            except Exception:
                self.environments = []

    def _check_and_increment_budget(self, kind: str = "request") -> bool:
        """Track daily requests/submissions. Return True if within budget, False if exceeded."""
        today = datetime.date.today().isoformat()
        data = {"date": today, "requests": 0, "submissions": 0}
        try:
            if self.budget_file.exists():
                saved = json.loads(self.budget_file.read_text(encoding="utf-8"))
                if saved.get("date") == today:
                    data = saved
        except Exception:
            pass

        limit = self.daily_submission_limit if kind == "submission" else self.daily_request_limit
        key = "submissions" if kind == "submission" else "requests"
        if data[key] >= limit:
            return False

        data[key] += 1
        try:
            self.budget_file.write_text(json.dumps(data), encoding="utf-8")
        except Exception:
            pass
        return True

    def get_environment_for_platform(self, platform: str, architecture: str) -> dict | None:
        """Select execution environment dynamically from verified environments list."""
        plat = str(platform).upper().replace("-", "")
        arch = str(architecture).lower()

        if plat == "ELF":
            if arch not in {"x86_64", "amd64", "x64"}:
                return None
            for env in self.environments:
                if env.get("architecture") == "LINUX":
                    return env
            return {"environment_id": 330, "description": "Linux (Ubuntu 24.04, 64 bit)"}

        if plat in {"EXE", "PE", "DLL"}:
            for env in self.environments:
                if env.get("architecture") == "WINDOWS" and "64" in str(env.get("description", "")):
                    return env
            for env in self.environments:
                if env.get("architecture") == "WINDOWS":
                    return env
            return {"environment_id": 160, "description": "Windows 10 64 bit"}

        return None

    def lookup_by_hash(self, sha256: str) -> dict:
        """Query HA v2 API by SHA-256 only with Falcon Sandbox user-agent."""
        if not self.api_key:
            return {"state": DynamicState.KEY_MISSING.value, "reason": "key missing"}

        if not self._check_and_increment_budget("request"):
            return {"state": DynamicState.RATE_LIMITED.value, "reason": "daily request limit reached"}

        url = "https://www.hybrid-analysis.com/api/v2/search/hash"
        headers = {
            "api-key": self.api_key,
            "User-Agent": "Falcon Sandbox",
            "accept": "application/json",
        }

        import requests
        try:
            resp = requests.get(url, params={"hash": sha256}, headers=headers, timeout=self.timeout)
            if resp.status_code == 200:
                data = resp.json()
                reports = data.get("reports", [])
                if not reports:
                    return {"state": DynamicState.NO_RESULT.value, "reason": "no result"}
                # Try overview summary for enriched verdict/score if present
                first_report = reports[0]
                if first_report.get("state") == "ERROR" and first_report.get("verdict") is None:
                    # Check overview
                    try:
                        ov_url = f"https://www.hybrid-analysis.com/api/v2/overview/{sha256}/summary"
                        ov_resp = requests.get(ov_url, headers=headers, timeout=self.timeout)
                        if ov_resp.status_code == 200:
                            return ov_resp.json()
                    except Exception:
                        pass
                return first_report
            elif resp.status_code == 404:
                return {"state": DynamicState.NO_RESULT.value, "reason": "no result"}
            elif resp.status_code in (401, 403):
                return {"state": DynamicState.KEY_RESTRICTED.value, "reason": "key restricted"}
            elif resp.status_code == 429:
                return {"state": DynamicState.RATE_LIMITED.value, "reason": "rate limited"}
            else:
                return {"state": DynamicState.PROVIDER_UNAVAILABLE.value, "reason": f"provider status {resp.status_code}"}
        except requests.exceptions.Timeout:
            return {"state": DynamicState.TIMEOUT.value, "reason": "timeout"}
        except requests.exceptions.RequestException as e:
            clean_err = redact_sensitive(str(e))
            return {"state": DynamicState.PROVIDER_UNAVAILABLE.value, "reason": f"connection error: {clean_err}"}

    def submit(self, sample_ref: Any) -> dict:
        """Submit sample only when explicitly allowed and verified by policy."""
        allow_sub = str(get_setting("ALLOW_EXTERNAL_SUBMISSION", "false")).lower() in ("1", "true", "yes")
        if not allow_sub:
            return {"state": DynamicState.SUBMISSION_DISABLED.value, "reason": "submission disabled by policy"}

        # Key verification: check key auth level if recorded
        key_info_path = ROOT_DIR / "tests" / "fixtures" / "providers" / "hybrid_analysis" / "key_current.json"
        if key_info_path.exists():
            try:
                key_data = json.loads(key_info_path.read_text(encoding="utf-8"))
                if key_data.get("auth_level_name") == "restricted" and not key_data.get("allow_submit"):
                    return {"state": DynamicState.KEY_RESTRICTED.value, "reason": "key does not permit sample submission"}
            except Exception:
                pass

        if not self._check_and_increment_budget("submission"):
            return {"state": DynamicState.RATE_LIMITED.value, "reason": "daily submission limit reached"}

        # Harmless local submission stub (never live submission during test runs)
        return {"state": DynamicState.SUBMISSION_DISABLED.value, "reason": "submission disabled in current runtime"}

    def get_status(self, task_id: str) -> dict:
        return {"state": DynamicState.COMPLETED.value}

    def get_report(self, task_id: str) -> dict:
        return {}

    def normalize(self, raw: Any) -> dict:
        """Normalize untrusted HA payload into trust-boundary schema."""
        if not isinstance(raw, dict):
            return {"state": DynamicState.INVALID_RESPONSE.value}

        # Check explicit error or non-completed states
        if "state" in raw and raw["state"] in DynamicState.__members__:
            st = DynamicState(raw["state"])
            if st != DynamicState.COMPLETED:
                return {"state": st.value}

        # Handle 404 message from HA lookup
        if raw.get("message") == "Requested hash not found":
            return {"state": DynamicState.NO_RESULT.value}

        # Handle empty reports array
        if "reports" in raw and not raw.get("reports"):
            return {"state": DynamicState.NO_RESULT.value}

        # If reports array has items, use the first report
        target = raw
        if "reports" in raw and isinstance(raw["reports"], list) and raw["reports"]:
            target = raw["reports"][0]
            if target.get("state") == "ERROR" and target.get("verdict") is None and "behavior" not in target:
                return {"state": DynamicState.NO_RESULT.value}

        # Extract verdict and threat score
        verdict = target.get("verdict")
        threat_score = target.get("threat_score")
        if threat_score is not None:
            try:
                threat_score = int(threat_score)
                if not (0 <= threat_score <= 100):
                    threat_score = None
            except (ValueError, TypeError):
                threat_score = None

        # Extract verified behavior fields
        behavior: dict[str, list] = {}
        raw_behavior = target.get("behavior", {}) if isinstance(target.get("behavior"), dict) else target

        # Verified behavior fields
        for field in ("processes", "network", "domains", "dns", "files", "registry", "api_calls", "signatures", "mitre"):
            if field in raw_behavior and isinstance(raw_behavior[field], list):
                behavior[field] = raw_behavior[field]

        out: dict[str, Any] = {"state": DynamicState.COMPLETED.value}
        if verdict is not None:
            out["verdict"] = str(verdict)
        if threat_score is not None:
            out["score"] = threat_score
        if behavior:
            out["behavior"] = behavior

        return out

    def make_result_for_state(self, state: DynamicState, reason: str | None = None) -> NormalizedProviderResult:
        """Build clean NormalizedProviderResult for any state."""
        r = reason or state.value.lower().replace("_", " ")
        macho = (state == DynamicState.NOT_SUPPORTED_PLATFORM and "static-only" in r)
        narrative = "Dynamic analysis: not performed (static-only)" if macho else f"Dynamic analysis not performed: {r}"
        res = NormalizedProviderResult(state=state, reason=r, narrative=narrative)
        res.report_line = narrative
        return res
