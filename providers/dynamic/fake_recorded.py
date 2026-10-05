"""Deterministic test-only provider; performs no I/O."""
from copy import deepcopy

from .base import ProviderAdapter


class FakeRecordedProvider(ProviderAdapter):
    name = "fake_recorded"

    def __init__(self, response):
        self.response = deepcopy(response)
        self.lookup_calls = 0

    def lookup_by_hash(self, sha256):
        self.lookup_calls += 1
        return deepcopy(self.response)

    def submit(self, sample_ref):
        return "recorded-task"

    def get_status(self, task_id):
        return {"state": "COMPLETED"}

    def get_report(self, task_id):
        return deepcopy(self.response)

    def normalize(self, raw):
        return deepcopy(raw)
