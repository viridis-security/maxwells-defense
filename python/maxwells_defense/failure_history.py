# SPDX-License-Identifier: Apache-2.0
"""Bounded per-process failure signals, separate from single-use nonce state."""

from __future__ import annotations

import hashlib
import json
import threading
import time
from collections import OrderedDict
from collections.abc import Callable


class FailedAttemptHistory:
    """Atomic fixed-window counters keyed by transport peer and context.

    Normal challenge requests and successful solutions do not allocate or
    reset history. A window starts at its first failure and expires after
    ``ttl_seconds``. Capacity never evicts live history; saturation is exposed
    to the oracle. Only a digest of the peer/context pair is retained.
    """

    def __init__(
        self,
        *,
        ttl_seconds: int = 300,
        max_entries: int = 10_000,
        max_failures: int = 1_000_000,
        _clock: Callable[[], float] = time.monotonic,
    ) -> None:
        for value in (ttl_seconds, max_entries, max_failures):
            if type(value) is not int or value < 1:
                raise ValueError("history limits must be positive integers")
        self._ttl = ttl_seconds
        self._max_entries = max_entries
        self._max_failures = max_failures
        self._clock = _clock
        self._last_now = _clock()
        self._entries: OrderedDict[bytes, tuple[int, float]] = OrderedDict()
        self._lock = threading.Lock()

    @staticmethod
    def _key(context_id: str, remote_addr: str | None) -> bytes:
        encoded = json.dumps([context_id, remote_addr]).encode()
        return hashlib.sha256(encoded).digest()

    def _gc_locked(self) -> float:
        now = max(self._clock(), self._last_now)
        while self._entries:
            first = next(iter(self._entries))
            if self._entries[first][1] > now:
                break
            self._entries.popitem(last=False)
        self._last_now = now
        return now

    def _snapshot_locked(self, key: bytes) -> tuple[int, bool]:
        count = self._entries.get(key, (0, 0))[0]
        saturated = (
            len(self._entries) >= self._max_entries or count >= self._max_failures
        )
        return count, saturated

    def snapshot(self, context_id: str, remote_addr: str | None) -> tuple[int, bool]:
        key = self._key(context_id, remote_addr)
        with self._lock:
            self._gc_locked()
            return self._snapshot_locked(key)

    def record_failure(
        self, context_id: str, remote_addr: str | None
    ) -> tuple[int, bool]:
        key = self._key(context_id, remote_addr)
        with self._lock:
            now = self._gc_locked()
            if key in self._entries:
                count, expiry = self._entries[key]
                self._entries[key] = min(count + 1, self._max_failures), expiry
            elif len(self._entries) < self._max_entries:
                self._entries[key] = 1, now + self._ttl
            return self._snapshot_locked(key)

    def __len__(self) -> int:
        with self._lock:
            self._gc_locked()
            return len(self._entries)
