#!/usr/bin/env python3
"""
Author: Sathyanarayana

Description:
    Thread-safe TTL cache for reputation lookups. VirusTotal free tier allows
    only a handful of requests per minute, so every successful lookup result is
    cached. Because the web server is multi-threaded (ThreadingHTTPServer), all
    cache state is guarded by a lock so concurrent requests never corrupt it.

Dependencies:
    Python standard library only: threading, time.

Related Files:
    virustotal.py   (calls cached_lookup() before hitting the VirusTotal API)
    app.py          (starts the multi-threaded HTTP server this cache protects)
"""

import threading
import time


class TTLCache:
    """A small in-memory cache with per-entry expiry and an entry cap."""

    def __init__(self, ttl_seconds=3600, max_entries=4000):
        self._ttl = ttl_seconds       # default lifetime of a cached entry
        self._max = max_entries       # cap so memory cannot grow forever
        self._data = {}               # key -> (expires_at, value)
        self._lock = threading.RLock()

    def get(self, key):
        """Return the cached value, or None if absent or expired."""
        with self._lock:
            item = self._data.get(key)
            if item is None:
                return None
            expires_at, value = item
            # Lazily drop expired entries instead of running a janitor thread.
            if time.time() > expires_at:
                del self._data[key]
                return None
            return value

    def set(self, key, value, ttl=None):
        """Store a value, evicting the oldest entry when the cap is reached."""
        with self._lock:
            if len(self._data) >= self._max:
                self._evict()
            self._data[key] = (time.time() + (ttl if ttl is not None else self._ttl),
                               value)

    def _evict(self):
        """Remove the entry closest to expiry (simple FIFO-style cleanup)."""
        oldest = min(self._data, key=lambda k: self._data[k][0])
        del self._data[oldest]

    def clear(self):
        with self._lock:
            self._data.clear()

    def __len__(self):
        with self._lock:
            return len(self._data)


# Shared process-wide cache used by the whole application.
_cache = TTLCache()


def cached_lookup(kind, value, lookup_fn, ttl=None):
    """
    Look up ``value`` under namespace ``kind``, calling ``lookup_fn()`` on a miss.

    Returns (result, cache_hit).  A ``None`` result is deliberately NOT cached
    so a transient upstream error can be retried on the next request instead of
    being remembered as a permanent "no result".
    """
    key = f"{kind}:{value}".lower()
    hit = _cache.get(key)
    if hit is not None:
        return hit, True
    result = lookup_fn()
    if result is not None:
        _cache.set(key, result, ttl=ttl)
    return result, False


def clear_cache():
    """Drop every cached result (used by tests)."""
    _cache.clear()
