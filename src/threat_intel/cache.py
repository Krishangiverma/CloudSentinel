"""
CloudSentinel Threat Intelligence Cache.

Provides a small in-memory TTL cache for provider lookups.
"""

import time


class ThreatIntelCache:
    """
    Thread-safe in-memory cache with TTL expiration.
    """

    def __init__(self, ttl_seconds=300, time_function=None):
        if ttl_seconds < 0:
            raise ValueError(
                "Cache TTL cannot be negative."
            )

        self.ttl_seconds = float(ttl_seconds)
        self._time = (
            time_function
            if time_function is not None
            else time.monotonic
        )

        self._entries = {}

    def get(self, key):
        """
        Return cached value if present and not expired.

        Returns:
            Cached value or None.
        """

        entry = self._entries.get(key)

        if entry is None:
            return None

        value, expires_at = entry

        if self._time() >= expires_at:
            self._entries.pop(key, None)
            return None

        return value

    def set(self, key, value):
        """Store a value using the configured TTL."""

        expires_at = (
            self._time()
            + self.ttl_seconds
        )

        self._entries[key] = (
            value,
            expires_at,
        )

    def clear(self):
        """Remove all cached entries."""

        self._entries.clear()

    def __len__(self):
        """Return the number of currently stored entries."""

        return len(self._entries)
