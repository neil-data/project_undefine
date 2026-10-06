"""Entry point from platform selection through validated dynamic evidence."""
import html
import hashlib
import json

from .base import DynamicState, NormalizedProviderResult, ProviderObservation
from .cache import NormalizedResultCache
from .registry import select_provider
from .trust_boundary import normalize_provider_result


class DynamicAnalysisPipeline:
    def __init__(self, providers=None, cache=None):
        self.providers = dict(providers or {})
        self.cache = cache or NormalizedResultCache()
        self.evidence_store = []

    def run(self, sha256, platform, architecture, task_id="lookup", environment="static-only", executed_by=None, static_endpoints=()):
        provider_name = select_provider(platform, architecture)
        if provider_name is None:
            return unsupported_platform_result(platform, architecture)
        cached = self.cache.get(sha256)
        if cached is not None:
            return cached
        provider = self.providers.get(provider_name)
        if provider is None:
            result = NormalizedProviderResult(DynamicState.PROVIDER_UNAVAILABLE, reason="provider unavailable", narrative="Dynamic analysis not performed: provider unavailable")
            result.report_line = render_dynamic_result(result)
            return result
        try:
            raw = provider.lookup_by_hash(sha256)
            raw = provider.normalize(raw)
        except Exception:
            result = NormalizedProviderResult(DynamicState.PROVIDER_UNAVAILABLE, reason="provider unavailable", narrative="Dynamic analysis not performed: provider unavailable")
            result.report_line = render_dynamic_result(result)
            return result
        result = normalize_provider_result(provider, raw, task_id, environment, executed_by or provider.name)
        if result.state == DynamicState.COMPLETED and not result.observation.has_behavior() and result.verdict is None:
            result.state = DynamicState.NO_RESULT
            result.reason = "no result"
            result.narrative = "Dynamic analysis not performed: no result"
        if result.state != DynamicState.COMPLETED:
            result.findings = []
            result.observation = ProviderObservation()
            if result.narrative is None:
                result.narrative = f"Dynamic analysis not performed: {result.reason or result.state.value.lower().replace('_', ' ')}"
            result.report_line = render_dynamic_result(result)
            return result
        static = set(static_endpoints)
        from packages.shared.ioc_classifier import IoCClassifier
        for row in result.observation.network + result.observation.dns:
            for key in ("domain", "ip", "url", "name", "endpoint"):
                indicator = row.get(key)
                if isinstance(indicator, str) and indicator:
                    result.classified_iocs.append(IoCClassifier.classify(
                        indicator, hint_type={"domain": "domain", "ip": "ip", "url": "url"}.get(key),
                        source=f"provider:{provider.name}", source_type="DYNAMIC", evidence_state="OBSERVED", is_dynamic_observed=True,
                    ))
        result.correlations = []
        for row in result.observation.network + result.observation.dns:
            endpoint = row.get("domain") or row.get("ip") or row.get("name") or row.get("endpoint")
            if isinstance(endpoint, str) and endpoint in static:
                result.correlations.append({"endpoint": endpoint, "status": "corroborated"})
        self.evidence_store.extend(result.findings)
        result.report_line = render_dynamic_result(result)
        self.cache.put(sha256, result)
        return result

    def run_execution(self, sample_path, sha256, platform, architecture, timeout_seconds=90, static_endpoints=()):
        """Submit and normalize an actual provider execution (never hash lookup)."""
        provider_name = select_provider(platform, architecture)
        if provider_name is None:
            return unsupported_platform_result(platform, architecture)
        provider = self.providers.get(provider_name)
        if provider is None or not hasattr(provider, "execute_sample"):
            return NormalizedProviderResult(DynamicState.PROVIDER_UNAVAILABLE, reason="provider execution unavailable",
                narrative="Dynamic analysis not performed: provider execution unavailable")
        raw = provider.execute_sample(sample_path, platform, architecture, timeout_seconds=timeout_seconds)
        state = raw.get("state") if isinstance(raw, dict) else None
        if state != DynamicState.COMPLETED.value:
            try:
                failure_state = DynamicState(state)
            except (ValueError, TypeError):
                failure_state = DynamicState.INVALID_RESPONSE
            reason = raw.get("reason") if isinstance(raw, dict) else "invalid provider execution response"
            result = NormalizedProviderResult(failure_state, reason=reason or failure_state.value.lower().replace("_", " "),
                narrative=f"Dynamic analysis not performed: {reason or failure_state.value.lower().replace('_', ' ')}",
                provenance={"provider": provider.name, "task_id": raw.get("task_id") if isinstance(raw, dict) else None})
            result.report_line = render_dynamic_result(result)
            return result
        task_id = raw.get("task_id")
        if not isinstance(task_id, str) or not task_id.strip():
            return NormalizedProviderResult(DynamicState.INVALID_RESPONSE, reason="provider completed without a task ID",
                narrative="Dynamic analysis not performed: provider completed without a task ID")
        normalized = {key: raw[key] for key in ("state", "behavior", "verdict", "score") if key in raw}
        result = normalize_provider_result(provider, normalized, task_id,
            raw.get("environment") or str(raw.get("environment_id") or "HA environment"), executed_by="Hybrid Analysis task report")
        if result.state == DynamicState.COMPLETED and not result.observation.has_behavior():
            result.state = DynamicState.INVALID_RESPONSE
            result.reason = "completed HA task contained no normalized behavioral evidence"
            result.narrative = "Dynamic analysis not performed: completed HA task contained no behavioral evidence"
            result.findings = []
            result.verdict = None
        if result.state != DynamicState.COMPLETED:
            result.report_line = render_dynamic_result(result)
            return result
        static = set(static_endpoints)
        from packages.shared.ioc_classifier import IoCClassifier
        for row in result.observation.network + result.observation.dns:
            for key in ("domain", "ip", "url", "name", "endpoint"):
                indicator = row.get(key)
                if isinstance(indicator, str) and indicator:
                    result.classified_iocs.append(IoCClassifier.classify(indicator,
                        hint_type={"domain": "domain", "ip": "ip", "url": "url"}.get(key),
                        source=f"provider:{provider.name}", source_type="DYNAMIC", evidence_state="OBSERVED", is_dynamic_observed=True))
        result.correlations = []
        for row in result.observation.network + result.observation.dns:
            endpoint = row.get("domain") or row.get("ip") or row.get("name") or row.get("endpoint")
            if isinstance(endpoint, str) and endpoint in static:
                result.correlations.append({"endpoint": endpoint, "status": "corroborated"})
        self.evidence_store.extend(result.findings)
        result.report_line = render_dynamic_result(result)
        return result

    def run_static_output(self, static_output, **kwargs):
        platform, architecture = detect_platform(static_output)
        return self.run(static_output.sha256, platform, architecture, **kwargs)


def render_dynamic_result(result):
    if result.state != DynamicState.COMPLETED:
        reason = html.escape(result.reason or result.state.value.lower().replace("_", " "))
        return f"Dynamic analysis not performed: {reason}"
    if result.verdict is not None and not result.observation.has_behavior():
        return "A provider verdict was reported, but no behavior was observed."
    claims = ", ".join(html.escape(f"provider:{result.provenance.get('provider')} reported {len(getattr(result.observation, group))} {group} event(s)") for group in ("process", "network", "dns", "file", "registry", "api_call", "signature", "mitre") if getattr(result.observation, group))
    task = html.escape(str(result.provenance.get("task_id", "unknown")))
    provider = html.escape(str(result.provenance.get("provider", "provider")))
    return f"Provider {provider} task {task} reported behavior: {claims}."


def delimited_provider_data(result):
    """Return hostile provider text only inside an explicit untrusted data block."""
    payload = json.dumps(result.observation.__dict__, ensure_ascii=True, separators=(",", ":"))
    payload = payload.replace("<", "\\u003c").replace(">", "\\u003e").replace("&", "\\u0026")
    return "<UNTRUSTED_PROVIDER_DATA>\n" + payload + "\n</UNTRUSTED_PROVIDER_DATA>"


def sha256_bytes(sample_bytes):
    return hashlib.sha256(sample_bytes).hexdigest()


def detect_platform(static_output):
    """Use the existing static-analysis result contract for provider selection."""
    kind = str(getattr(static_output, "file_type", "")).lower().replace("-", "_")
    binary = getattr(static_output, "binary_analysis", None)
    architecture = getattr(binary, "architecture", None) or getattr(static_output, "target_architecture", None) or "unknown"
    if kind in {"apk", "android"}:
        return "APK", architecture
    if kind in {"exe", "pe", "dll"}:
        return kind.upper(), architecture
    if kind == "elf":
        return "ELF", architecture
    if kind in {"mach_o", "macho"} or (binary and getattr(binary, "format", "") == "MachO"):
        return "Mach-O", architecture
    return kind.upper(), architecture


def unsupported_platform_result(platform, architecture):
    """Return the sole canonical no-dynamic result for unsupported formats."""
    macho = str(platform).upper().replace("-", "") in {"MACHO", "MACHO64"}
    reason = "static-only" if macho else f"unsupported platform ({architecture})"
    result = NormalizedProviderResult(
        DynamicState.NOT_SUPPORTED_PLATFORM,
        reason=reason,
        narrative="Dynamic analysis: not performed (static-only)" if macho else f"Dynamic analysis not performed: {reason}",
    )
    result.report_line = result.narrative
    return result


def enrich_orchestrator_state(state, result):
    """Feed only boundary-approved behavior to the existing scorer and classifiers."""
    if result.state != DynamicState.COMPLETED or not result.observation.has_behavior():
        dynamic = None
    else:
        from analysis.scoring.orchestrator.schema import DynamicAnalysisOutput
        obs = result.observation
        dynamic = DynamicAnalysisOutput(
            sample_id=state.get("sample_id", "provider-sample"),
            execution_mode="real", available=True, status="completed", dynamic_status="completed",
            task_id=result.provenance.get("task_id"),
            process_tree=obs.process,
            api_calls=[row.get("name", "") for row in obs.api_call],
            network_connections=obs.network,
            dns_queries=[row.get("name", row.get("domain", "")) for row in obs.dns],
            files_written=[row.get("path", row.get("name", "")) for row in obs.file],
            registry_changes=[row.get("path", row.get("name", "")) for row in obs.registry],
            provider=result.provenance.get("provider"), source_type="DYNAMIC",
        )
    enriched = {**state, "dynamic_output": dynamic, "provider_evidence": list(result.findings), "provider_verdict": result.verdict}
    if enriched.get("static_output") is not None:
        from analysis.scoring.orchestrator.orchestrator import mitre_mapper, capability_classifier, compute_risk_score
        enriched = mitre_mapper(enriched)
        enriched = capability_classifier(enriched)
        enriched = compute_risk_score(enriched)
    enriched["narrative_summary"] = render_dynamic_result(result)
    enriched["provider_report_line"] = result.report_line or render_dynamic_result(result)
    return enriched
