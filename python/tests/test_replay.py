"""MX-INV-6: single-use, bounded state, concurrency, and middleware contracts.

License: Apache-2.0
"""

import asyncio
import json
import os
import random
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urlparse

import pytest
from maxwells_defense import (
    ExpiredChallenge,
    InMemoryNonceStore,
    InvalidSolution,
    NonceStoreUnavailable,
    RedisNonceStore,
    ReplayedSolution,
    Solution,
    StaticDifficultyOracle,
    issue_challenge,
    solve_challenge,
    verify_solution,
)
from maxwells_defense.middleware import (
    FastAPIMaxwellMiddleware,
    WSGIMaxwellMiddleware,
)

SECRET = b"a" * 32


class Clock:
    def __init__(self, now: int = 1000) -> None:
        self.now = now

    def __call__(self) -> float:
        return float(self.now)


class FakeRedis:
    """Atomic fake of Redis's independent clock, NX and absolute key expiry."""

    def __init__(self, clock: Clock) -> None:
        self.clock = clock
        self.keys: dict[str, int] = {}
        self.lock = threading.Lock()

    def eval(self, script: str, numkeys: int, *args: str) -> int:
        assert numkeys == 1
        assert "redis.call('TIME')" in script
        assert "'SET', KEYS[1], '1', 'NX', 'EXAT', expires_at" in script
        key, expiry = args
        expires_at = int(expiry)
        with self.lock:
            if expires_at <= self.clock.now:
                return -1
            if self.keys.get(key, 0) > self.clock.now:
                return 0
            self.keys[key] = expires_at
            return 1


def challenge(clock: Clock, context: str = "host/api", ttl: int = 10):
    return issue_challenge(
        server_secret=SECRET,
        context_id=context,
        difficulty=0,
        ttl_seconds=ttl,
        _clock=clock,
    )


@pytest.mark.parametrize("backend", ["memory", "redis"])
def test_valid_solution_is_accepted_once(backend):
    """MX-INV-6: both backends enforce the same core contract."""
    clock = Clock()
    store = (
        InMemoryNonceStore(_clock=clock)
        if backend == "memory"
        else RedisNonceStore(FakeRedis(clock))
    )
    issued = challenge(clock)
    solution = solve_challenge(issued)
    for expected in (None, ReplayedSolution):
        if expected is None:
            verify_solution(
                server_secret=SECRET,
                challenge=issued,
                solution=solution,
                nonce_store=store,
                _clock=clock,
            )
        else:
            with pytest.raises(expected):
                verify_solution(
                    server_secret=SECRET,
                    challenge=issued,
                    solution=solution,
                    nonce_store=store,
                    _clock=clock,
                )


def test_distinct_contexts_and_nonces_are_unaffected():
    clock = Clock()
    store = InMemoryNonceStore(_clock=clock)
    for context in ("host/a", "host/b"):
        issued = challenge(clock, context)
        verify_solution(
            server_secret=SECRET,
            challenge=issued,
            solution=solve_challenge(issued),
            expected_context_id=context,
            nonce_store=store,
            _clock=clock,
        )
    assert len(store) == 2


def test_failed_context_does_not_consume_nonce():
    clock = Clock()
    store = InMemoryNonceStore(_clock=clock)
    issued = challenge(clock)
    solution = solve_challenge(issued)
    with pytest.raises(InvalidSolution):
        verify_solution(
            server_secret=SECRET,
            challenge=issued,
            solution=solution,
            expected_context_id="other",
            nonce_store=store,
            _clock=clock,
        )
    assert len(store) == 0
    verify_solution(
        server_secret=SECRET,
        challenge=issued,
        solution=solution,
        nonce_store=store,
        _clock=clock,
    )


def test_failed_work_does_not_consume_nonce():
    import hashlib

    from maxwells_defense import InsufficientWork
    from maxwells_defense.core import _leading_zero_bits

    clock = Clock()
    store = InMemoryNonceStore(_clock=clock)
    issued = issue_challenge(
        server_secret=SECRET,
        context_id="host/api",
        difficulty=8,
        ttl_seconds=10,
        _clock=clock,
    )
    candidates = (i.to_bytes(4, "big") for i in range(1000))
    bad = next(
        nonce
        for nonce in candidates
        if _leading_zero_bits(hashlib.sha256(issued.server_nonce + nonce).digest()) < 8
    )
    with pytest.raises(InsufficientWork):
        verify_solution(
            server_secret=SECRET,
            challenge=issued,
            solution=Solution(bad),
            nonce_store=store,
            _clock=clock,
        )
    assert len(store) == 0


def test_stateless_verifier_preserves_reuse_and_inclusive_boundary():
    clock = Clock()
    issued = challenge(clock)
    clock.now = issued.expires_at
    for _ in range(2):
        verify_solution(
            server_secret=SECRET,
            challenge=issued,
            solution=solve_challenge(issued),
            _clock=clock,
        )


def test_single_use_expiry_is_exclusive_and_gc_removes_at_expiry():
    clock = Clock()
    store = InMemoryNonceStore(_clock=clock)
    issued = challenge(clock)
    store.consume(issued.server_nonce, issued.expires_at)
    clock.now = issued.expires_at
    store.gc(clock.now)
    assert len(store) == 0
    with pytest.raises(ExpiredChallenge):
        verify_solution(
            server_secret=SECRET,
            challenge=issued,
            solution=solve_challenge(issued),
            nonce_store=store,
            _clock=clock,
        )


def test_gc_handles_out_of_order_expiries_and_wheel_wrap():
    clock = Clock(18)
    store = InMemoryNonceStore(max_ttl_seconds=10, _clock=clock)
    assert store.consume(b"long", 28)
    assert store.consume(b"short", 20)
    assert store.consume(b"middle", 25)
    clock.now = 20
    store.gc(clock.now)
    assert len(store) == 2
    assert not store.consume(b"long", 28)
    clock.now = 25
    store.gc(clock.now)
    assert len(store) == 1
    clock.now = 28
    store.gc(clock.now)
    assert len(store) == 0


def test_expiry_wheel_matches_model_with_idle_gaps():
    """Exercise lazy GC across repeated wraps, arbitrary TTLs and long gaps."""
    clock = Clock()
    store = InMemoryNonceStore(max_ttl_seconds=15, _clock=clock)
    model: dict[bytes, int] = {}
    rng = random.Random(6)
    for i in range(300):
        clock.now += rng.randrange(0, 25)
        model = {nonce: expiry for nonce, expiry in model.items() if expiry > clock.now}
        nonce = i.to_bytes(4, "big")
        expiry = clock.now + rng.randrange(1, 16)
        assert store.consume(nonce, expiry)
        model[nonce] = expiry
        assert len(store) == len(model)
        for retained, retained_expiry in model.items():
            assert not store.consume(retained, retained_expiry)


def test_full_store_preserves_live_nonces_and_recovers_after_expiry():
    clock = Clock()
    store = InMemoryNonceStore(max_entries=1, _clock=clock)
    assert store.consume(b"first", clock.now + 10)
    with pytest.raises(NonceStoreUnavailable):
        store.consume(b"second", clock.now + 20)
    assert not store.consume(b"first", clock.now + 10)
    clock.now += 10
    assert store.consume(b"second", clock.now + 20)


def test_store_rejects_expiry_beyond_its_retention_horizon():
    clock = Clock()
    store = InMemoryNonceStore(max_ttl_seconds=10, _clock=clock)
    with pytest.raises(NonceStoreUnavailable):
        store.consume(b"nonce", clock.now + 11)
    assert len(store) == 0


def test_clock_rollback_cannot_reopen_evicted_nonce():
    clock = Clock()
    store = InMemoryNonceStore(_clock=clock)
    assert store.consume(b"nonce", clock.now + 10)
    clock.now += 10
    store.gc(clock.now)
    clock.now -= 10
    with pytest.raises(ExpiredChallenge):
        store.consume(b"nonce", clock.now + 10)


@pytest.mark.parametrize("backend", ["memory", "redis"])
def test_concurrent_consumption_has_one_winner(backend):
    clock = Clock()
    store = (
        InMemoryNonceStore(_clock=clock)
        if backend == "memory"
        else RedisNonceStore(FakeRedis(clock))
    )
    barrier = threading.Barrier(16)

    def consume(_):
        barrier.wait()
        return store.consume(b"shared-nonce", clock.now + 10)

    with ThreadPoolExecutor(max_workers=16) as pool:
        assert sum(pool.map(consume, range(16))) == 1


def test_redis_state_is_shared_between_verifiers():
    clock = Clock()
    client = FakeRedis(clock)
    first = RedisNonceStore(client)
    second = RedisNonceStore(client)
    assert first.consume(b"nonce", clock.now + 10)
    assert not second.consume(b"nonce", clock.now + 10)
    second.gc(clock.now)
    assert not second.consume(b"nonce", clock.now + 10)
    assert client.keys == {"maxwell:nonce:6e6f6e6365": clock.now + 10}


def test_redis_clock_rejects_expired_nonce_even_if_verifier_clock_is_behind():
    client = FakeRedis(Clock(1020))
    store = RedisNonceStore(client)
    with pytest.raises(ExpiredChallenge):
        store.consume(b"nonce", 1010)
    assert client.keys == {}


def test_redis_connection_failure_fails_closed():
    class OfflineRedis:
        def eval(self, *args):
            raise ConnectionError("offline")

    with pytest.raises(NonceStoreUnavailable):
        RedisNonceStore(OfflineRedis()).consume(b"nonce", 1010)


def test_redis_invalid_reply_fails_closed():
    class UnexpectedRedis:
        def eval(self, *args):
            return None

    with pytest.raises(NonceStoreUnavailable):
        RedisNonceStore(UnexpectedRedis()).consume(b"nonce", 1010)


def test_wsgi_default_rejects_replay_and_issues_fresh_challenge():
    forwarded = []

    def app(environ, start_response):
        forwarded.append(environ)
        start_response("200 OK", [])
        return [b"ok"]

    middleware = WSGIMaxwellMiddleware(
        app,
        server_secret=SECRET,
        difficulty_oracle=StaticDifficultyOracle(0),
    )
    issued = challenge(Clock(int(time.time())))
    environ = {
        "HTTP_HOST": "host",
        "PATH_INFO": "/api",
        "HTTP_X_MAXWELL_CHALLENGE": json.dumps(issued.to_dict()),
        "HTTP_X_MAXWELL_SOLUTION": json.dumps(solve_challenge(issued).to_dict()),
    }
    statuses = []

    def start_response(status, headers):
        statuses.append(status)

    assert middleware(environ, start_response) == [b"ok"]
    body = json.loads(b"".join(middleware(environ, start_response)))
    assert statuses == ["200 OK", "401 Unauthorized"]
    assert len(forwarded) == 1
    assert body["error"] == "maxwell_replayed_solution"
    assert body["challenge"]["server_nonce"] != issued.server_nonce.hex()


def test_asgi_default_rejects_replay_and_issues_fresh_challenge():
    forwarded = []

    async def app(scope, receive, send):
        forwarded.append(scope)
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": b"ok"})

    middleware = FastAPIMaxwellMiddleware(
        app,
        server_secret=SECRET,
        difficulty_oracle=StaticDifficultyOracle(0),
    )
    issued = challenge(Clock(int(time.time())))
    scope = {
        "type": "http",
        "path": "/api",
        "headers": [
            (b"host", b"host"),
            (b"x-maxwell-challenge", json.dumps(issued.to_dict()).encode()),
            (
                b"x-maxwell-solution",
                json.dumps(solve_challenge(issued).to_dict()).encode(),
            ),
        ],
    }

    async def invoke():
        messages = []

        async def send(message):
            messages.append(message)

        async def receive():
            return {"type": "http.request", "body": b""}

        await middleware(scope, receive, send)
        return messages

    assert asyncio.run(invoke())[0]["status"] == 200
    replay = asyncio.run(invoke())
    assert replay[0]["status"] == 401
    assert len(forwarded) == 1
    body = json.loads(replay[1]["body"])
    assert body["error"] == "maxwell_replayed_solution"
    assert body["challenge"]["server_nonce"] != issued.server_nonce.hex()


def test_injected_empty_store_is_used_by_both_middlewares():
    store = InMemoryNonceStore()
    wsgi = WSGIMaxwellMiddleware(lambda *_: [], server_secret=SECRET, nonce_store=store)
    asgi = FastAPIMaxwellMiddleware(
        lambda *_: None, server_secret=SECRET, nonce_store=store
    )
    assert wsgi.nonce_store is asgi.nonce_store is store


def test_optional_local_redis_integration():
    """Only a dedicated, explicitly configured loopback Redis may be tested."""
    url = os.environ.get("MAXWELL_TEST_REDIS_URL")
    if not url:
        pytest.skip("set MAXWELL_TEST_REDIS_URL for optional local Redis integration")
    if urlparse(url).hostname not in ("127.0.0.1", "localhost", "::1"):
        pytest.fail("MAXWELL_TEST_REDIS_URL must use a dedicated loopback Redis")
    redis = pytest.importorskip("redis")
    client = redis.Redis.from_url(url)
    store = RedisNonceStore(client, key_prefix="maxwell:test:nonce:")
    nonce = os.urandom(16)
    expires_at = int(client.time()[0]) + 3
    assert store.consume(nonce, expires_at)
    assert not store.consume(nonce, expires_at)
    assert client.ttl("maxwell:test:nonce:" + nonce.hex()) in (2, 3)
