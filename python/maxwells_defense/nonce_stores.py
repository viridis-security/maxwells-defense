"""Bounded, atomic single-use state for Maxwell's Defense.

License: Apache-2.0
"""

from __future__ import annotations

import threading
import time
from collections.abc import Callable
from typing import Any, Protocol

from .errors import ExpiredChallenge, NonceStoreUnavailable


class InMemoryNonceStore:
    """Thread-safe store for one process, with lazy expiry and a hard cap.

    An expiry wheel visits only occupied, expired buckets. Each nonce is added
    and removed once; no per-request scan or sorted heap is needed. Operations
    are O(1) amortized for the configured, fixed retention horizon. Capacity
    never evicts unexpired nonces: a full store rejects further acceptance.
    """

    def __init__(
        self,
        *,
        max_entries: int = 100_000,
        max_ttl_seconds: int = 300,
        _clock: Callable[[], float] = time.time,
    ) -> None:
        if max_entries < 1 or max_ttl_seconds < 1:
            raise ValueError("max_entries and max_ttl_seconds must be positive")
        self._max_entries = max_entries
        self._max_ttl_seconds = max_ttl_seconds
        self._slots = max_ttl_seconds + 1
        self._clock = _clock
        self._last_gc = int(_clock())
        self._entries: dict[bytes, int] = {}
        self._buckets: dict[int, set[bytes]] = {}
        self._occupied = 0
        self._lock = threading.Lock()

    def consume(self, nonce: bytes, expires_at: int) -> bool:
        with self._lock:
            now = max(int(self._clock()), self._last_gc)
            self._gc_locked(now)
            if expires_at <= now:
                raise ExpiredChallenge("challenge expired before consumption")
            if expires_at - now > self._max_ttl_seconds:
                raise NonceStoreUnavailable(
                    "expiry exceeds the store retention horizon"
                )
            if nonce in self._entries:
                return False
            if len(self._entries) >= self._max_entries:
                raise NonceStoreUnavailable("nonce store capacity reached")
            slot = expires_at % self._slots
            self._entries[nonce] = expires_at
            self._buckets.setdefault(slot, set()).add(nonce)
            self._occupied |= 1 << slot
            return True

    def gc(self, now: int) -> None:
        """Evict at expiry on the next access; clock rollback fails closed."""
        with self._lock:
            self._gc_locked(now)

    def _gc_locked(self, now: int) -> None:
        elapsed = now - self._last_gc
        if elapsed <= 0:
            return
        if elapsed >= self._slots:
            # Every retained expiry lies inside the configured horizon.
            self._entries.clear()
            self._buckets.clear()
            self._occupied = 0
        else:
            start = (self._last_gc + 1) % self._slots
            mask = ((1 << elapsed) - 1) << start
            mask = (mask & ((1 << self._slots) - 1)) | (mask >> self._slots)
            expired = self._occupied & mask
            self._occupied &= ~expired
            while expired:
                bit = expired & -expired
                slot = bit.bit_length() - 1
                for nonce in self._buckets.pop(slot):
                    del self._entries[nonce]
                expired ^= bit
        self._last_gc = now

    def __len__(self) -> int:
        with self._lock:
            self._gc_locked(int(self._clock()))
            return len(self._entries)


# Checking Redis's own clock in the same transaction avoids accepting a SET
# whose EXAT is already expired when a verifier's clock is behind Redis.
_CONSUME_SCRIPT = """
local expires_at = tonumber(ARGV[1])
local now = tonumber(redis.call('TIME')[1])
if expires_at <= now then return -1 end
local accepted = redis.call('SET', KEYS[1], '1', 'NX', 'EXAT', expires_at)
if accepted then return 1 end
return 0
"""


class _RedisClient(Protocol):
    def eval(self, script: str, numkeys: int, *keys_and_args: str) -> Any: ...


class RedisNonceStore:
    """Shared store using atomic Redis SET NX EXAT (Redis 6.2+).

    Supply a synchronous redis-py client, or use ``from_url`` with the optional
    ``redis`` extra. Nothing connects to Redis unless this store is explicitly
    configured. All workers must share a namespace and a Redis instance with
    persistence/failover suitable for their deployment and ``noeviction``.
    """

    def __init__(
        self, client: _RedisClient, *, key_prefix: str = "maxwell:nonce:"
    ) -> None:
        self._client = client
        self._key_prefix = key_prefix

    @classmethod
    def from_url(cls, url: str, **kwargs: Any) -> RedisNonceStore:
        """Construct an optional redis-py client; its connection is lazy."""
        import redis

        return cls(redis.Redis.from_url(url, **kwargs))

    def consume(self, nonce: bytes, expires_at: int) -> bool:
        try:
            result = self._client.eval(
                _CONSUME_SCRIPT, 1, self._key_prefix + nonce.hex(), str(expires_at)
            )
        except Exception as exc:
            raise NonceStoreUnavailable("Redis nonce state is unavailable") from exc
        if result == -1:
            raise ExpiredChallenge("challenge expired before Redis consumption")
        if result not in (0, 1):
            raise NonceStoreUnavailable("unexpected Redis consume result")
        return result == 1

    def gc(self, now: int) -> None:
        """Redis evicts at EXAT using its own clock; no client GC is needed."""
