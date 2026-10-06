# SPDX-License-Identifier: Apache-2.0
"""WP-3 transport identity, bounded failure signals, and opt-in policy."""

from __future__ import annotations

import asyncio
import json
from concurrent.futures import ThreadPoolExecutor
from typing import Any

import pytest
from maxwells_defense import (
    Challenge,
    FailedAttemptDifficultyOracle,
    FailedAttemptHistory,
    NonceStoreUnavailable,
    solve_challenge,
)
from maxwells_defense.middleware import (
    FastAPIMaxwellMiddleware,
    WSGIMaxwellMiddleware,
)

SECRET = b"s" * 32


class Harness:
    def __init__(self, integration: str, **options: Any) -> None:
        self.integration = integration
        self.seen: list[tuple[str, dict[str, Any]]] = []
        self.forwarded = 0
        self.app_error: Exception | None = None

        def oracle(context: str, signals: Any) -> int:
            self.seen.append((context, dict(signals)))
            with pytest.raises(TypeError):
                signals["remote_addr"] = "spoof"
            return 0

        def wsgi_app(environ: Any, start_response: Any) -> list[bytes]:
            self.forwarded += 1
            if self.app_error is not None:
                raise self.app_error
            start_response("200 OK", [])
            return [b'{"ok":true}']

        async def asgi_app(scope: Any, receive: Any, send: Any) -> None:
            self.forwarded += 1
            if self.app_error is not None:
                raise self.app_error
            await send({"type": "http.response.start", "status": 200, "headers": []})
            await send({"type": "http.response.body", "body": b'{"ok":true}'})

        middleware = (
            WSGIMaxwellMiddleware if integration == "wsgi" else FastAPIMaxwellMiddleware
        )
        app = wsgi_app if integration == "wsgi" else asgi_app
        self.middleware = middleware(
            app, server_secret=SECRET, difficulty_oracle=oracle, **options
        )

    def request(
        self,
        *,
        peer: str | None = "192.0.2.1",
        path: str = "/api",
        headers: dict[str, str] | None = None,
    ) -> dict[str, Any]:
        headers = {"host": "example.test", **(headers or {})}
        if self.integration == "wsgi":
            environ: dict[str, Any] = {
                "PATH_INFO": path,
                "REQUEST_METHOD": "POST",
                **{
                    "HTTP_" + key.upper().replace("-", "_"): value
                    for key, value in headers.items()
                },
            }
            if peer is not None:
                environ["REMOTE_ADDR"] = peer
            return json.loads(b"".join(self.middleware(environ, lambda *args: None)))

        async def invoke() -> dict[str, Any]:
            messages: list[dict[str, Any]] = []

            async def send(message: dict[str, Any]) -> None:
                messages.append(message)

            async def receive() -> dict[str, Any]:
                return {"type": "http.request", "body": b""}

            scope = {
                "type": "http",
                "method": "POST",
                "path": path,
                "client": (peer, 1234) if peer is not None else None,
                "headers": [
                    (key.encode(), value.encode()) for key, value in headers.items()
                ],
            }
            await self.middleware(scope, receive, send)
            return json.loads(messages[-1]["body"])

        return asyncio.run(invoke())


def solved_headers(body: dict[str, Any]) -> dict[str, str]:
    challenge = Challenge.from_dict(body["challenge"])
    return {
        "x-maxwell-challenge": json.dumps(challenge.to_dict()),
        "x-maxwell-solution": json.dumps(solve_challenge(challenge).to_dict()),
    }


@pytest.mark.parametrize("integration", ["asgi", "wsgi"])
def test_transport_signals_preserve_context_and_ignore_forwarded(
    integration: str,
) -> None:
    harness = Harness(integration)
    body = harness.request(
        headers={"forwarded": "for=198.51.100.9", "x-forwarded-for": "198.51.100.8"}
    )
    assert body["challenge"]["context_id"] == "example.test/api"
    assert harness.seen[-1] == (
        "example.test/api",
        {
            "remote_addr": "192.0.2.1",
            "method": "POST",
            "path": "/api",
            "failed_attempts": 0,
            "history_saturated": False,
        },
    )
    assert len(harness.middleware.failure_history) == 0
    harness.request(peer=None)
    assert harness.seen[-1][1]["remote_addr"] is None


@pytest.mark.parametrize("integration", ["asgi", "wsgi"])
def test_context_factory_can_bind_peer_without_trusting_headers(
    integration: str,
) -> None:
    def context_factory(default: str, signals: Any) -> str:
        return default + "|" + str(signals["remote_addr"])

    harness = Harness(integration, context_factory=context_factory)
    headers = solved_headers(harness.request())
    denied = harness.request(
        peer="192.0.2.2", headers={**headers, "x-forwarded-for": "192.0.2.1"}
    )
    assert denied["error"] == "InvalidSolution"
    assert harness.seen[-1][1]["failed_attempts"] == 1
    assert harness.request(headers=headers) == {"ok": True}
    harness.request()
    assert harness.seen[-1][1]["failed_attempts"] == 0
    assert harness.forwarded == 1


@pytest.mark.parametrize("integration", ["asgi", "wsgi"])
def test_failure_counts_are_scoped_and_survive_success(integration: str) -> None:
    harness = Harness(integration)
    body = harness.request(headers={"x-maxwell-solution": "{"})
    assert harness.seen[-1][1]["failed_attempts"] == 1
    headers = solved_headers(body)
    assert harness.request(headers=headers) == {"ok": True}
    replay = harness.request(headers=headers)
    assert replay["error"] == "maxwell_replayed_solution"
    assert harness.seen[-1][1]["failed_attempts"] == 2
    harness.request(headers={"forwarded": "for=some-other-peer"})
    assert harness.seen[-1][1]["failed_attempts"] == 2
    harness.request(peer="192.0.2.2")
    assert harness.seen[-1][1]["failed_attempts"] == 0
    harness.request(path="/other")
    assert harness.seen[-1][1]["failed_attempts"] == 0


@pytest.mark.parametrize("integration", ["asgi", "wsgi"])
@pytest.mark.parametrize(
    "headers",
    [
        {"x-maxwell-challenge": "", "x-maxwell-solution": ""},
        {"x-maxwell-challenge": "null", "x-maxwell-solution": "null"},
        {"x-maxwell-challenge": "[]", "x-maxwell-solution": "{}"},
        {"x-maxwell-challenge": "{", "x-maxwell-solution": "{}"},
        {
            "x-maxwell-challenge": '{"server_nonce":"00","difficulty":Infinity}',
            "x-maxwell-solution": "{}",
        },
    ],
)
def test_malformed_submissions_count_once(
    integration: str, headers: dict[str, str]
) -> None:
    harness = Harness(integration)
    harness.request(headers=headers)
    assert harness.seen[-1][1]["failed_attempts"] == 1
    assert harness.forwarded == 0


@pytest.mark.parametrize("integration", ["asgi", "wsgi"])
def test_bad_signature_counts_without_consuming_nonce(integration: str) -> None:
    harness = Harness(integration)
    body = harness.request()
    valid = solved_headers(body)
    body["challenge"]["hmac_sig"] = "00" * 32
    invalid = {**valid, "x-maxwell-challenge": json.dumps(body["challenge"])}
    assert harness.request(headers=invalid)["error"] == "SignatureMismatch"
    assert harness.seen[-1][1]["failed_attempts"] == 1
    assert harness.request(headers=valid) == {"ok": True}


@pytest.mark.parametrize("integration", ["asgi", "wsgi"])
def test_backend_and_application_failures_do_not_count(integration: str) -> None:
    class OfflineStore:
        def consume(self, nonce: bytes, expires_at: int) -> bool:
            raise NonceStoreUnavailable("offline")

        def gc(self, now: int) -> None:
            pass

    harness = Harness(integration, nonce_store=OfflineStore())
    headers = solved_headers(harness.request())
    assert harness.request(headers=headers)["error"] == "NonceStoreUnavailable"
    assert harness.seen[-1][1]["failed_attempts"] == 0
    assert len(harness.middleware.failure_history) == 0

    class BrokenStore(OfflineStore):
        def consume(self, nonce: bytes, expires_at: int) -> bool:
            raise RuntimeError("unexpected backend failure")

    broken = Harness(integration, nonce_store=BrokenStore())
    headers = solved_headers(broken.request())
    with pytest.raises(RuntimeError, match="unexpected backend failure"):
        broken.request(headers=headers)
    assert len(broken.middleware.failure_history) == 0
    normal = Harness(integration)
    headers = solved_headers(normal.request())
    normal.app_error = RuntimeError("application failure")
    with pytest.raises(RuntimeError, match="application failure"):
        normal.request(headers=headers)
    assert len(normal.middleware.failure_history) == 0


@pytest.mark.parametrize("integration", ["asgi", "wsgi"])
def test_injected_history_reports_capacity_and_recovers(integration: str) -> None:
    now = [100.0]
    history = FailedAttemptHistory(ttl_seconds=5, max_entries=1, _clock=lambda: now[0])
    harness = Harness(integration, failure_history=history)
    assert harness.middleware.failure_history is history
    harness.request(headers={"x-maxwell-solution": "{}"})
    assert harness.seen[-1][1]["history_saturated"] is True
    harness.request(peer="192.0.2.2", headers={"x-maxwell-solution": "{}"})
    assert harness.seen[-1][1]["failed_attempts"] == 0
    assert harness.seen[-1][1]["history_saturated"] is True
    assert history.snapshot("example.test/api", "192.0.2.1")[0] == 1
    now[0] = 105
    harness.request()
    assert harness.seen[-1][1]["history_saturated"] is False
    assert len(history) == 0


@pytest.mark.parametrize("integration", ["asgi", "wsgi"])
@pytest.mark.parametrize("context", ["", None, 12])
def test_invalid_factory_result_fails_before_issuance(
    integration: str, context: Any
) -> None:
    harness = Harness(integration, context_factory=lambda default, signals: context)
    with pytest.raises(ValueError, match="nonempty string"):
        harness.request()
    assert harness.seen == []


def test_history_expiry_is_fixed_and_clock_rollback_is_conservative() -> None:
    now = [100.0]
    history = FailedAttemptHistory(ttl_seconds=5, _clock=lambda: now[0])
    assert history.record_failure("route", "peer") == (1, False)
    now[0] = 104
    assert history.record_failure("route", "peer") == (2, False)
    now[0] = 90
    assert history.snapshot("route", "peer") == (2, False)
    now[0] = 105
    assert history.snapshot("route", "peer") == (0, False)
    assert len(history) == 0


def test_history_is_atomic_capped_and_retains_only_digests() -> None:
    history = FailedAttemptHistory(max_failures=50)
    with ThreadPoolExecutor(max_workers=8) as workers:
        list(workers.map(lambda _: history.record_failure("route", "peer"), range(50)))
    assert history.snapshot("route", "peer") == (50, True)
    assert history.record_failure("route", "peer") == (50, True)
    assert len(history) == 1
    assert all(isinstance(key, bytes) and len(key) == 32 for key in history._entries)


@pytest.mark.parametrize(
    "limits",
    [
        {"ttl_seconds": 0},
        {"max_entries": -1},
        {"max_failures": 1.5},
        {"max_entries": True},
    ],
)
def test_history_rejects_invalid_limits(limits: dict[str, Any]) -> None:
    with pytest.raises(ValueError):
        FailedAttemptHistory(**limits)


def test_example_policy_escalates_caps_and_handles_saturation() -> None:
    oracle = FailedAttemptDifficultyOracle(
        base_difficulty=2, max_difficulty=4, failures_per_step=2
    )
    assert [oracle("route", {"failed_attempts": count}) for count in range(7)] == [
        2,
        2,
        3,
        3,
        4,
        4,
        4,
    ]
    assert oracle("route", {"failed_attempts": 0, "history_saturated": True}) == 4
    with pytest.raises(ValueError):
        oracle("route", {"failed_attempts": -1})
    for options in (
        {"max_difficulty": 33},
        {"base_difficulty": True},
        {"failures_per_step": 0},
    ):
        with pytest.raises(ValueError):
            FailedAttemptDifficultyOracle(**options)


@pytest.mark.parametrize("integration", ["asgi", "wsgi"])
def test_example_policy_receives_real_middleware_signals(integration: str) -> None:
    harness = Harness(integration)
    harness.middleware.difficulty_oracle = FailedAttemptDifficultyOracle(
        base_difficulty=0,
        max_difficulty=2,
        failures_per_step=1,
    )
    assert harness.request()["challenge"]["difficulty"] == 0
    assert (
        harness.request(headers={"x-maxwell-solution": "{}"})["challenge"]["difficulty"]
        == 1
    )
    assert (
        harness.request(headers={"x-maxwell-solution": "{}"})["challenge"]["difficulty"]
        == 2
    )
    assert (
        harness.request(headers={"x-maxwell-solution": "{}"})["challenge"]["difficulty"]
        == 2
    )


@pytest.mark.parametrize("integration", ["asgi", "wsgi"])
def test_example_policy_caps_unknown_peer_at_capacity(integration: str) -> None:
    harness = Harness(integration, failure_history=FailedAttemptHistory(max_entries=1))
    harness.middleware.difficulty_oracle = FailedAttemptDifficultyOracle(
        base_difficulty=0,
        max_difficulty=2,
        failures_per_step=1,
    )
    harness.request(headers={"x-maxwell-solution": "{}"})
    assert harness.request(peer="192.0.2.2")["challenge"]["difficulty"] == 2
    assert len(harness.middleware.failure_history) == 1
