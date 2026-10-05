"""Manual reports enter through the same schema and evidence trust boundary."""
from .base import ProviderAdapter
from .trust_boundary import normalize_provider_result


class ManualImportProvider(ProviderAdapter):
    name = "manual_import"

    def __init__(self, payload, provider_name, task_link_or_id, imported_at):
        self.payload = payload
        self.provider_name = provider_name
        self.task_link_or_id = task_link_or_id
        self.imported_at = imported_at

    def lookup_by_hash(self, sha256):
        return self.payload

    def submit(self, sample_ref):
        raise RuntimeError("manual imports cannot submit samples")

    def get_status(self, task_id):
        return {"state": "COMPLETED"}

    def get_report(self, task_id):
        return self.payload

    def normalize(self, raw):
        return raw

    def import_result(self):
        result = normalize_provider_result(self, self.payload, self.task_link_or_id, "manual", f"imported manually: {self.provider_name}")
        if result.state.value == "COMPLETED":
            result.provenance["imported_at"] = self.imported_at
            result.provenance["task_link_or_id"] = self.task_link_or_id
            for finding in result.findings + ([result.verdict] if result.verdict else []):
                finding.provenance = str(result.provenance)
        return result
