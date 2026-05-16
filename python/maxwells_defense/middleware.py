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

from .core import (
    Challenge,
    DifficultyOracle,
    Solution,
    StaticDifficultyOracle,
    issue_challenge,
    verify_solution,
)
from .errors import (
    ExpiredChallenge,
    InsufficientWork,
    InvalidSolution,
    MaxwellError,
    SignatureMismatch,
)

SOLUTION_HEADER = "X-Maxwell-Solution"
CHALLENGE_HEADER = "X-Maxwell-Challenge"
PROVIDER_HEADER = "X-Maxwell-Provider"
PROVIDER_VALUE = "viridis-security.com"


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
    chal_header = headers.get(CHALLENGE_HEADER) or headers.get(
        CHALLENGE_HEADER.lower()
    )
    if not sol_header or not chal_header:
        return None
    try:
        challenge = Challenge.from_dict(json.loads(chal_header))
        solution = Solution.from_dict(json.loads(sol_header))
    except (ValueError, KeyError, TypeError):
        return None
    return challenge, solution


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
    ) -> None:
        if not server_secret:
            raise ValueError("server_secret must be non-empty")
        self.app = app
        self.server_secret = server_secret
        self.difficulty_oracle = difficulty_oracle or StaticDifficultyOracle(18)
        self.protect_path_prefix = protect_path_prefix
        self.ttl_seconds = ttl_seconds

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

        context_id = headers.get("host", "default") + path

        parsed = _extract_solution_and_challenge(headers)
        if parsed is None:
            # No solution — issue a challenge.
            await self._send_challenge(send, context_id)
            return

        challenge, solution = parsed
        try:
            verify_solution(
                server_secret=self.server_secret,
                challenge=challenge,
                solution=solution,
                expected_context_id=context_id,
            )
        except MaxwellError as e:
            await self._send_challenge(send, context_id, error=type(e).__name__)
            return

        await self.app(scope, receive, send)

    async def _send_challenge(
        self, send, context_id: str, *, error: str | None = None
    ) -> None:
        difficulty = self.difficulty_oracle(context_id, {})
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
            (b"content-length", str(len(body)).encode()),
        ]
        await send(
            {
                "type": "http.response.start",
                "status": 401,
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
    ) -> None:
        if not server_secret:
            raise ValueError("server_secret must be non-empty")
        self.app = app
        self.server_secret = server_secret
        self.difficulty_oracle = difficulty_oracle or StaticDifficultyOracle(18)
        self.protect_path_prefix = protect_path_prefix
        self.ttl_seconds = ttl_seconds

    def __call__(self, environ, start_response):
        path = environ.get("PATH_INFO", "")
        if not path.startswith(self.protect_path_prefix):
            return self.app(environ, start_response)

        headers = {
            k[5:].replace("_", "-").title(): v
            for k, v in environ.items()
            if k.startswith("HTTP_")
        }
        context_id = environ.get("HTTP_HOST", "default") + path

        parsed = _extract_solution_and_challenge(headers)
        if parsed is None:
            return self._challenge_response(start_response, context_id)
        challenge, solution = parsed
        try:
            verify_solution(
                server_secret=self.server_secret,
                challenge=challenge,
                solution=solution,
                expected_context_id=context_id,
            )
        except MaxwellError as e:
            return self._challenge_response(
                start_response, context_id, error=type(e).__name__
            )
        return self.app(environ, start_response)

    def _challenge_response(self, start_response, context_id, *, error=None):
        difficulty = self.difficulty_oracle(context_id, {})
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
        start_response(
            "401 Unauthorized",
            [
                ("Content-Type", "application/json"),
                (PROVIDER_HEADER, PROVIDER_VALUE),
                ("Content-Length", str(len(body))),
            ],
        )
        return [body]
