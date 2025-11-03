from dataclasses import dataclass
from typing import Any

@dataclass
class CacheEntry:
    value: Any
    fingerprint: Any

class Cache:
    def __init__(self):
        self._entries = {}

    def get(self, key, fingerprint):
        entry = self._entries.get(key)
        if entry is None:
            return None
        if entry.fingerprint != fingerprint:
            return None
        return entry.value

    def update(self, key, value, fingerprint):
        entry = self._entries.get(key)
        if entry is None:
            self._entries[key] = CacheEntry(value, fingerprint)
        else:
            entry.value = value
            entry.fingerprint = fingerprint

    def __iter__(self):
        for key, entry in self._entries.items():
            yield key, entry.value, entry.fingerprint
