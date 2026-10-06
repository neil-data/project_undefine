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
import hashlib
import time
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
        poll_interval: float = 3.0,
    ):
        load_config()
        self.api_key = (api_key or get_setting("HYBRID_ANALYSIS_API_KEY") or "").strip()
        self.timeout = timeout
        self.poll_interval = max(0.1, float(poll_interval))

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
        """Upload a local sample using HA's documented v2 file submission API."""
        allow_sub = str(get_setting("ALLOW_EXTERNAL_SUBMISSION", "false")).lower() in ("1", "true", "yes")
        if not allow_sub:
            return {"state": DynamicState.SUBMISSION_DISABLED.value, "reason": "submission disabled by policy"}

        if not self.api_key:
            return {"state": DynamicState.KEY_MISSING.value, "reason": "HYBRID_ANALYSIS_API_KEY is not configured"}

        path = Path(sample_ref) if isinstance(sample_ref, (str, os.PathLike)) else None
        if path is None or not path.is_file():
            return {"state": DynamicState.INVALID_RESPONSE.value, "reason": "sample_ref must be a readable local file path"}

        # The caller passes the selected platform/environment explicitly using
        # submit_sample; do not infer architecture from a filename here.
        environment = getattr(self, "_submission_environment", None)
        if not isinstance(environment, dict) or not isinstance(environment.get("environment_id"), int):
            return {"state": DynamicState.NOT_SUPPORTED_PLATFORM.value, "reason": "no verified Hybrid Analysis environment selected"}

        if not self._check_and_increment_budget("submission"):
            return {"state": DynamicState.RATE_LIMITED.value, "reason": "daily submission limit reached"}

        import requests
        headers = {"api-key": self.api_key, "User-Agent": "Falcon Sandbox", "accept": "application/json"}
        try:
            digest = hashlib.sha256(path.read_bytes()).hexdigest()
            with path.open("rb") as sample:
                response = requests.post(
                    "https://www.hybrid-analysis.com/api/v2/submit/file",
                    headers=headers,
                    data={"environment_id": str(environment["environment_id"])},
                    files={"file": (path.name, sample, "application/octet-stream")},
                    timeout=self.timeout,
                )
            if response.status_code not in (200, 201):
                return self._http_failure(response)
            payload = response.json()
            job_id = payload.get("job_id") if isinstance(payload, dict) else None
            if not isinstance(job_id, str) or not job_id.strip():
                return {"state": DynamicState.INVALID_RESPONSE.value, "reason": "HA submission response omitted job_id"}
            returned_sha = payload.get("sha256")
            if returned_sha and str(returned_sha).lower() != digest:
                return {"state": DynamicState.INVALID_RESPONSE.value, "reason": "HA submission response SHA-256 does not match uploaded sample"}
            return {"state": "SUBMITTED", "task_id": job_id, "sha256": digest,
                    "environment_id": environment["environment_id"], "environment": environment.get("description", "")}
        except requests.exceptions.Timeout:
            return {"state": DynamicState.TIMEOUT.value, "reason": "Hybrid Analysis file submission timed out"}
        except (requests.exceptions.RequestException, ValueError, OSError) as exc:
            return {"state": DynamicState.PROVIDER_UNAVAILABLE.value, "reason": redact_sensitive(str(exc))}

    def get_status(self, task_id: str) -> dict:
        if not self.api_key:
            return {"state": DynamicState.KEY_MISSING.value, "reason": "HYBRID_ANALYSIS_API_KEY is not configured"}
        import requests
        try:
            response = requests.get(
                f"https://www.hybrid-analysis.com/api/v2/report/{task_id}/state",
                headers={"api-key": self.api_key, "User-Agent": "Falcon Sandbox", "accept": "application/json"},
                timeout=self.timeout,
            )
            if response.status_code != 200:
                return self._http_failure(response)
            data = response.json()
            if not isinstance(data, dict) or not isinstance(data.get("state"), str):
                return {"state": DynamicState.INVALID_RESPONSE.value, "reason": "HA task state response omitted state"}
            state = data["state"].upper()
            if state == "SUCCESS":
                return {"state": "COMPLETED", "provider_state": state}
            if state in {"ERROR", "FAILED", "CANCELLED", "CANCELED"}:
                detail = ": ".join(str(data.get(k)) for k in ("error_type", "error_origin", "error") if data.get(k))
                return {"state": DynamicState.PROVIDER_UNAVAILABLE.value, "provider_state": state,
                        "reason": detail or f"Hybrid Analysis task ended in {state}"}
            if state in {"IN_QUEUE", "IN_PROGRESS", "QUEUED", "RUNNING", "STARTED"}:
                return {"state": "PENDING", "provider_state": state}
            return {"state": DynamicState.INVALID_RESPONSE.value, "reason": f"Unrecognized HA task state: {state}"}
        except requests.exceptions.Timeout:
            return {"state": DynamicState.TIMEOUT.value, "reason": "Hybrid Analysis task status request timed out"}
        except (requests.exceptions.RequestException, ValueError) as exc:
            return {"state": DynamicState.PROVIDER_UNAVAILABLE.value, "reason": redact_sensitive(str(exc))}

    def get_report(self, task_id: str) -> dict:
        if not self.api_key:
            return {"state": DynamicState.KEY_MISSING.value, "reason": "HYBRID_ANALYSIS_API_KEY is not configured"}
        import requests
        try:
            response = requests.get(
                f"https://www.hybrid-analysis.com/api/v2/report/{task_id}/report/json",
                headers={"api-key": self.api_key, "User-Agent": "Falcon Sandbox", "accept": "application/octet-stream"},
                timeout=self.timeout,
            )
            if response.status_code != 200:
                return self._http_failure(response)
            content = response.content
            if content[:2] == b"\x1f\x8b":
                import gzip
                content = gzip.decompress(content)
            data = json.loads(content.decode("utf-8"))
            if not isinstance(data, dict):
                return {"state": DynamicState.INVALID_RESPONSE.value, "reason": "HA report was not a JSON object"}
            return {"state": "COMPLETED", "report": data}
        except requests.exceptions.Timeout:
            return {"state": DynamicState.TIMEOUT.value, "reason": "Hybrid Analysis behavioral report request timed out"}
        except (requests.exceptions.RequestException, ValueError, OSError) as exc:
            return {"state": DynamicState.PROVIDER_UNAVAILABLE.value, "reason": redact_sensitive(str(exc))}

    @staticmethod
    def _http_failure(response):
        if response.status_code in (401, 403):
            state = DynamicState.KEY_RESTRICTED
        elif response.status_code == 429:
            state = DynamicState.RATE_LIMITED
        elif response.status_code == 404:
            state = DynamicState.NO_RESULT
        else:
            state = DynamicState.PROVIDER_UNAVAILABLE
        try:
            detail = response.json()
        except Exception:
            detail = response.text
        if isinstance(detail, dict):
            detail = detail.get("message") or detail.get("error") or json.dumps(detail)
        return {"state": state.value, "reason": f"Hybrid Analysis HTTP {response.status_code}: {redact_sensitive(str(detail))}"}

    def submit_sample(self, sample_path: str | os.PathLike, platform: str, architecture: str) -> dict:
        environment = self.get_environment_for_platform(platform, architecture)
        if environment is None:
            return {"state": DynamicState.NOT_SUPPORTED_PLATFORM.value,
                    "reason": f"Hybrid Analysis does not have a supported environment for {platform} {architecture}"}
        self._submission_environment = environment
        try:
            return self.submit(sample_path)
        finally:
            self._submission_environment = None

    def execute_sample(self, sample_path: str | os.PathLike, platform: str, architecture: str,
                       timeout_seconds: float = 90, poll_interval: float | None = None) -> dict:
        """Run a real submit/poll/report lifecycle; only completed reports yield behavior."""
        submission = self.submit_sample(sample_path, platform, architecture)
        if submission.get("state") != "SUBMITTED":
            return submission
        task_id = submission["task_id"]
        deadline = time.monotonic() + max(0.1, timeout_seconds)
        interval = self.poll_interval if poll_interval is None else max(0.1, poll_interval)
        while time.monotonic() < deadline:
            status = self.get_status(task_id)
            if status.get("state") == "COMPLETED":
                report = self.get_report(task_id)
                if report.get("state") != "COMPLETED":
                    return {**report, "task_id": task_id, "provider_state": status.get("provider_state")}
                normalized = self.normalize_execution_report(report["report"])
                return {**normalized, "task_id": task_id, "sha256": submission.get("sha256"),
                        "environment": submission.get("environment"), "environment_id": submission.get("environment_id")}
            if status.get("state") != "PENDING":
                return {**status, "task_id": task_id}
            time.sleep(min(interval, max(0, deadline - time.monotonic())))
        return {"state": DynamicState.TIMEOUT.value, "reason": f"Hybrid Analysis task {task_id} did not complete within {timeout_seconds} seconds", "task_id": task_id}

    def normalize_execution_report(self, report: Any) -> dict:
        """Map documented full-report behavior fields to the trust-boundary schema."""
        if not isinstance(report, dict):
            return {"state": DynamicState.INVALID_RESPONSE.value, "reason": "invalid HA report"}
        # These keys are part of HA's documented analysis-report response.
        # Reduce records to scalar values because provider metadata may contain
        # nested objects that are not evidence rows accepted by our boundary.
        behavior: dict[str, list] = {}
        for source, destination in (("processes", "processes"), ("domains", "domains"),
                                   ("hosts", "network"), ("extracted_files", "files"),
                                   ("signatures", "signatures"), ("mitre_attcks", "mitre")):
            values = report.get(source)
            if not isinstance(values, list):
                continue
            rows = []
            for item in values[:100]:
                if isinstance(item, str):
                    rows.append(item[:512])
                elif isinstance(item, dict):
                    row = {str(k)[:512]: v[:512] if isinstance(v, str) else v
                           for k, v in item.items()
                           if isinstance(k, str) and isinstance(v, (str, int, float, bool, type(None)))}
                    if row:
                        rows.append(row)
            if rows:
                behavior[destination] = rows
        if not any(behavior.values()):
            return {"state": DynamicState.INVALID_RESPONSE.value, "reason": "completed HA report contains no behavioral evidence"}
        output = {"state": "COMPLETED", "behavior": behavior}
        if report.get("verdict") is not None:
            output["verdict"] = str(report["verdict"])
        score = report.get("threat_score")
        if isinstance(score, int) and 0 <= score <= 100:
            output["score"] = score
        return output

    def normalize(self, raw: Any) -> dict:
        """Normalize HA hash-lookup data as intelligence, never as execution.

        Hash search/overview responses do not prove that E-Rakshak submitted or
        observed an execution task. Behavioral output can only be normalized
        after a separately verified submit/poll/report flow.
        """
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
        # This call path is a hash lookup. Any behavior-shaped data it returns
        # is historical/provider intelligence without an execution task ID.
        # Do not elevate it to DYNAMIC/OBSERVED evidence.

        out: dict[str, Any] = {"state": DynamicState.COMPLETED.value}
        if verdict is not None:
            out["verdict"] = str(verdict)
        if threat_score is not None:
            out["score"] = threat_score
        return out

    def make_result_for_state(self, state: DynamicState, reason: str | None = None) -> NormalizedProviderResult:
        """Build clean NormalizedProviderResult for any state."""
        r = reason or state.value.lower().replace("_", " ")
        macho = (state == DynamicState.NOT_SUPPORTED_PLATFORM and "static-only" in r)
        narrative = "Dynamic analysis: not performed (static-only)" if macho else f"Dynamic analysis not performed: {r}"
        res = NormalizedProviderResult(state=state, reason=r, narrative=narrative)
        res.report_line = narrative
        return res
