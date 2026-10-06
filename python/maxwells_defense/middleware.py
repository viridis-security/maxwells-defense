"""ASGI/WSGI-style middleware shims for Maxwell's Defense.

Two integrations included:

  1. ``FastAPIMaxwellMiddleware`` — Starlette/FastAPI integration. Issues
     a challenge as JSON when a protected route is hit without a valid
     ``X-Maxwell-Solution`` header. Verifies + lets through when present.

  2. ``WSGIMaxwellMiddleware`` — generic WSGI integration with the same
     contract.

Both honour the MX-INV-* invariants in ``core.py``. Neither makes any
claim about the application semantics they protect.

License: Apache-2.0
"""

from __future__ import annotations

import json
import typing as _t
from types import MappingProxyType

from .core import (
    Challenge,
    DifficultyOracle,
    NonceStore,
    Solution,
    StaticDifficultyOracle,
    _warn_if_short_secret,
    issue_challenge,
    verify_solution,
)
from .errors import (
    MaxwellError,
    NonceStoreUnavailable,
    ReplayedSolution,
)
from .failure_history import FailedAttemptHistory
from .nonce_stores import InMemoryNonceStore

SOLUTION_HEADER = "X-Maxwell-Solution"
CHALLENGE_HEADER = "X-Maxwell-Challenge"
PROVIDER_HEADER = "X-Maxwell-Provider"
PROVIDER_VALUE = "viridis-security.com"
ContextFactory = _t.Callable[[str, _t.Mapping[str, _t.Any]], str]


def _validate_http_options(status_code: int, retry_after_seconds: int) -> None:
    if type(status_code) is not int or status_code not in (401, 429):
        raise ValueError("challenge_status_code must be 401 or 429")
    if type(retry_after_seconds) is not int or retry_after_seconds < 0:
        raise ValueError("retry_after_seconds must be a nonnegative integer")


# ---------------------------------------------------------------------------
# Provider header
# ---------------------------------------------------------------------------


def provider_headers() -> dict[str, str]:
    """Headers to advertise Maxwell's Defense at the protocol layer.

    Always-on, no signing required. Free distribution + signal to
    attacker tooling that PoW is in front.
    """
    return {PROVIDER_HEADER: PROVIDER_VALUE}


# ---------------------------------------------------------------------------
# Shared verify path (used by both middlewares)
# ---------------------------------------------------------------------------


def _extract_solution_and_challenge(
    headers: _t.Mapping[str, str],
) -> tuple[Challenge, Solution] | None:
    sol_header = headers.get(SOLUTION_HEADER) or headers.get(SOLUTION_HEADER.lower())
    chal_header = headers.get(CHALLENGE_HEADER) or headers.get(CHALLENGE_HEADER.lower())
    if not sol_header or not chal_header:
        return None
    try:
        challenge = Challenge.from_dict(json.loads(chal_header))
        solution = Solution.from_dict(json.loads(sol_header))
    except (ValueError, KeyError, TypeError, OverflowError):
        return None
    return challenge, solution


def _request_context(
    default_context: str,
    remote_addr: str | None,
    method: str,
    path: str,
    context_factory: ContextFactory | None,
    history: FailedAttemptHistory,
) -> tuple[str, dict[str, _t.Any]]:
    signals: dict[str, _t.Any] = {
        "remote_addr": remote_addr,
        "method": method,
        "path": path,
    }
    context_id = (
        context_factory(default_context, MappingProxyType(dict(signals)))
        if context_factory is not None
        else default_context
    )
    if not isinstance(context_id, str) or not context_id:
        raise ValueError("context_factory must return a nonempty string")
    count, saturated = history.snapshot(context_id, remote_addr)
    signals.update(failed_attempts=count, history_saturated=saturated)
    return context_id, signals


def _record_failure(
    history: FailedAttemptHistory, context_id: str, signals: dict[str, _t.Any]
) -> None:
    count, saturated = history.record_failure(context_id, signals["remote_addr"])
    signals.update(failed_attempts=count, history_saturated=saturated)


def _has_solution_headers(headers: _t.Mapping[str, str]) -> bool:
    return any(
        name in headers
        for name in (
            CHALLENGE_HEADER,
            SOLUTION_HEADER,
            CHALLENGE_HEADER.lower(),
            SOLUTION_HEADER.lower(),
        )
    )


# ---------------------------------------------------------------------------
# FastAPI / Starlette
# ---------------------------------------------------------------------------


class FastAPIMaxwellMiddleware:
    """Starlette/FastAPI ASGI middleware.

    Usage::

        from fastapi import FastAPI
        from maxwells_defense.middleware import FastAPIMaxwellMiddleware
        from maxwells_defense.core import StaticDifficultyOracle

        app = FastAPI()
        app.add_middleware(
            FastAPIMaxwellMiddleware,
            server_secret=b"...32+ high entropy bytes...",
            difficulty_oracle=StaticDifficultyOracle(difficulty=18),
            protect_path_prefix="/api/",
        )
    """

    def __init__(
        self,
        app: _t.Callable[..., _t.Awaitable[None]],
        *,
        server_secret: bytes,
        difficulty_oracle: DifficultyOracle | None = None,
        protect_path_prefix: str = "/",
        ttl_seconds: int = 300,
        nonce_store: NonceStore | None = None,
        challenge_status_code: int = 401,
        retry_after_seconds: int = 1,
        context_factory: ContextFactory | None = None,
        failure_history: FailedAttemptHistory | None = None,
    ) -> None:
        if not server_secret:
            raise ValueError("server_secret must be non-empty")
        _warn_if_short_secret(server_secret)
        _validate_http_options(challenge_status_code, retry_after_seconds)
        self.app = app
        self.server_secret = server_secret
        self.difficulty_oracle = difficulty_oracle or StaticDifficultyOracle(18)
        self.protect_path_prefix = protect_path_prefix
        self.ttl_seconds = ttl_seconds
        self.challenge_status_code = challenge_status_code
        self.retry_after_seconds = retry_after_seconds
        self.context_factory = context_factory
        self.failure_history = (
            FailedAttemptHistory() if failure_history is None else failure_history
        )
        self.nonce_store = (
            InMemoryNonceStore(max_ttl_seconds=ttl_seconds)
            if nonce_store is None
            else nonce_store
        )

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        path: str = scope.get("path", "")
        if not path.startswith(self.protect_path_prefix):
            await self.app(scope, receive, send)
            return

        raw_headers = scope.get("headers") or []
        headers: dict[str, str] = {
            k.decode("latin-1"): v.decode("latin-1") for k, v in raw_headers
        }

        client = scope.get("client")
        remote_addr = client[0] if client else None
        context_id, signals = _request_context(
            headers.get("host", "default") + path,
            remote_addr,
            scope.get("method", "GET"),
            path,
            self.context_factory,
            self.failure_history,
        )

        parsed = _extract_solution_and_challenge(headers)
        if parsed is None:
            if _has_solution_headers(headers):
                _record_failure(self.failure_history, context_id, signals)
            await self._send_challenge(send, context_id, signals)
            return

        challenge, solution = parsed
        try:
            verify_solution(
                server_secret=self.server_secret,
                challenge=challenge,
                solution=solution,
                expected_context_id=context_id,
                nonce_store=self.nonce_store,
            )
        except MaxwellError as e:
            if not isinstance(e, NonceStoreUnavailable):
                _record_failure(self.failure_history, context_id, signals)
            error = (
                "maxwell_replayed_solution"
                if isinstance(e, ReplayedSolution)
                else type(e).__name__
            )
            await self._send_challenge(send, context_id, signals, error=error)
            return

        await self.app(scope, receive, send)

    async def _send_challenge(
        self,
        send,
        context_id: str,
        signals: _t.Mapping[str, _t.Any],
        *,
        error: str | None = None,
    ) -> None:
        difficulty = self.difficulty_oracle(context_id, MappingProxyType(dict(signals)))
        challenge = issue_challenge(
            server_secret=self.server_secret,
            context_id=context_id,
            difficulty=difficulty,
            ttl_seconds=self.ttl_seconds,
        )
        body = json.dumps(
            {
                "error": error or "maxwell_challenge_required",
                "challenge": challenge.to_dict(),
                "spec": "https://github.com/viridis-security/maxwells-defense",
            }
        ).encode("utf-8")
        headers = [
            (b"content-type", b"application/json"),
            (PROVIDER_HEADER.lower().encode(), PROVIDER_VALUE.encode()),
            (
                CHALLENGE_HEADER.lower().encode(),
                json.dumps(challenge.to_dict()).encode(),
            ),
            (b"content-length", str(len(body)).encode()),
        ]
        if self.challenge_status_code == 429:
            headers.append((b"retry-after", str(self.retry_after_seconds).encode()))
        await send(
            {
                "type": "http.response.start",
                "status": self.challenge_status_code,
                "headers": headers,
            }
        )
        await send({"type": "http.response.body", "body": body})


# ---------------------------------------------------------------------------
# Generic WSGI
# ---------------------------------------------------------------------------


class WSGIMaxwellMiddleware:
    """WSGI middleware. Same contract as the ASGI version."""

    def __init__(
        self,
        app: _t.Callable,
        *,
        server_secret: bytes,
        difficulty_oracle: DifficultyOracle | None = None,
        protect_path_prefix: str = "/",
        ttl_seconds: int = 300,
        nonce_store: NonceStore | None = None,
        challenge_status_code: int = 401,
        retry_after_seconds: int = 1,
        context_factory: ContextFactory | None = None,
        failure_history: FailedAttemptHistory | None = None,
    ) -> None:
        if not server_secret:
            raise ValueError("server_secret must be non-empty")
        _warn_if_short_secret(server_secret)
        _validate_http_options(challenge_status_code, retry_after_seconds)
        self.app = app
        self.server_secret = server_secret
        self.difficulty_oracle = difficulty_oracle or StaticDifficultyOracle(18)
        self.protect_path_prefix = protect_path_prefix
        self.ttl_seconds = ttl_seconds
        self.challenge_status_code = challenge_status_code
        self.retry_after_seconds = retry_after_seconds
        self.context_factory = context_factory
        self.failure_history = (
            FailedAttemptHistory() if failure_history is None else failure_history
        )
        self.nonce_store = (
            InMemoryNonceStore(max_ttl_seconds=ttl_seconds)
            if nonce_store is None
            else nonce_store
        )

    def __call__(self, environ, start_response):
        path = environ.get("PATH_INFO", "")
        if not path.startswith(self.protect_path_prefix):
            return self.app(environ, start_response)

        headers = {
            k[5:].replace("_", "-").title(): v
            for k, v in environ.items()
            if k.startswith("HTTP_")
        }
        context_id, signals = _request_context(
            environ.get("HTTP_HOST", "default") + path,
            environ.get("REMOTE_ADDR"),
            environ.get("REQUEST_METHOD", "GET"),
            path,
            self.context_factory,
            self.failure_history,
        )

        parsed = _extract_solution_and_challenge(headers)
        if parsed is None:
            if _has_solution_headers(headers):
                _record_failure(self.failure_history, context_id, signals)
            return self._challenge_response(start_response, context_id, signals)
        challenge, solution = parsed
        try:
            verify_solution(
                server_secret=self.server_secret,
                challenge=challenge,
                solution=solution,
                expected_context_id=context_id,
                nonce_store=self.nonce_store,
            )
        except MaxwellError as e:
            if not isinstance(e, NonceStoreUnavailable):
                _record_failure(self.failure_history, context_id, signals)
            error = (
                "maxwell_replayed_solution"
                if isinstance(e, ReplayedSolution)
                else type(e).__name__
            )
            return self._challenge_response(
                start_response, context_id, signals, error=error
            )
        return self.app(environ, start_response)

    def _challenge_response(
        self,
        start_response,
        context_id,
        signals: _t.Mapping[str, _t.Any],
        *,
        error=None,
    ):
        difficulty = self.difficulty_oracle(context_id, MappingProxyType(dict(signals)))
        challenge = issue_challenge(
            server_secret=self.server_secret,
            context_id=context_id,
            difficulty=difficulty,
            ttl_seconds=self.ttl_seconds,
        )
        body = json.dumps(
            {
                "error": error or "maxwell_challenge_required",
                "challenge": challenge.to_dict(),
                "spec": "https://github.com/viridis-security/maxwells-defense",
            }
        ).encode("utf-8")
        headers = [
            ("Content-Type", "application/json"),
            (PROVIDER_HEADER, PROVIDER_VALUE),
            (CHALLENGE_HEADER, json.dumps(challenge.to_dict())),
            ("Content-Length", str(len(body))),
        ]
        if self.challenge_status_code == 429:
            headers.append(("Retry-After", str(self.retry_after_seconds)))
        status = (
            "429 Too Many Requests"
            if self.challenge_status_code == 429
            else "401 Unauthorized"
        )
        start_response(status, headers)
        return [body]
