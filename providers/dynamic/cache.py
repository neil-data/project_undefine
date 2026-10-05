"""TTL cache for normalized results only; raw provider payloads are never retained."""
from copy import deepcopy
import time


class NormalizedResultCache:
    def __init__(self, ttl_seconds=3600, clock=time.time):
        self.ttl_seconds = ttl_seconds
        self.clock = clock
        self._entries = {}

    def get(self, sha256):
        entry = self._entries.get(sha256)
        if not entry:
            return None
        expires, value = entry
        if expires <= self.clock():
            self._entries.pop(sha256, None)
            return None
        return deepcopy(value)

    def put(self, sha256, normalized_result):
        if not isinstance(sha256, str) or len(sha256) != 64:
            raise ValueError("cache key must be SHA-256")
        self._entries[sha256] = (self.clock() + self.ttl_seconds, deepcopy(normalized_result))
