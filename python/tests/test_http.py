# SPDX-License-Identifier: Apache-2.0
"""WP-4 HTTP contract: selectable challenge status and response metadata."""

from __future__ import annotations

import asyncio
import json
from typing import Any

import pytest

from maxwells_defense import StaticDifficultyOracle
from maxwells_defense.middleware import (
    FastAPIMaxwellMiddleware,
    WSGIMaxwellMiddleware,
)

SECRET = b"a" * 32


def challenge_response(
    integration: str, request_path: str = "/api", **options: Any
) -> tuple[int, dict[str, str], dict[str, Any]]:
    def app(*args: Any) -> Any:
        raise AssertionError("a request without a solution must not be forwarded")

    if integration == "wsgi":
        captured: dict[str, Any] = {}

        def start_response(status: str, headers: list[tuple[str, str]]) -> None:
            captured["status"] = int(status.split()[0])
            captured["headers"] = {key.lower(): value for key, value in headers}

        middleware = WSGIMaxwellMiddleware(
            app,
            server_secret=SECRET,
            difficulty_oracle=StaticDifficultyOracle(0),
            **options,
        )
        body = b"".join(middleware({"PATH_INFO": request_path}, start_response))
        return captured["status"], captured["headers"], json.loads(body)

    async def invoke() -> tuple[int, dict[str, str], dict[str, Any]]:
        messages: list[dict[str, Any]] = []

        async def send(message: dict[str, Any]) -> None:
            messages.append(message)

        async def receive() -> dict[str, Any]:
            return {"type": "http.request", "body": b""}

        middleware = FastAPIMaxwellMiddleware(
            app,
            server_secret=SECRET,
            difficulty_oracle=StaticDifficultyOracle(0),
            **options,
        )
        await middleware({"type": "http", "path": request_path}, receive, send)
        headers = {
            key.decode(): value.decode() for key, value in messages[0]["headers"]
        }
        return messages[0]["status"], headers, json.loads(messages[1]["body"])

    return asyncio.run(invoke())


@pytest.mark.parametrize("integration", ["asgi", "wsgi"])
def test_default_status_preserves_401_without_retry_after(integration: str) -> None:
    """INV-4.1: compatibility default remains unchanged pending review."""
    status, headers, body = challenge_response(integration)
    assert status == 401
    assert "retry-after" not in headers
    assert body["error"] == "maxwell_challenge_required"


@pytest.mark.parametrize("integration", ["asgi", "wsgi"])
@pytest.mark.parametrize("retry_after", [0, 7])
def test_rate_limit_status_has_configured_retry_after(
    integration: str, retry_after: int
) -> None:
    """INV-4.1: the alternative mode sends delta-seconds Retry-After."""
    status, headers, body = challenge_response(
        integration, challenge_status_code=429, retry_after_seconds=retry_after
    )
    assert status == 429
    assert headers["retry-after"] == str(retry_after)
    assert body["challenge"]["difficulty"] == 0


@pytest.mark.parametrize("integration", ["asgi", "wsgi"])
@pytest.mark.parametrize(
    "options",
    [
        {"challenge_status_code": 403},
        {"challenge_status_code": 401.0},
        {"challenge_status_code": True},
        {"retry_after_seconds": -1},
        {"retry_after_seconds": 1.5},
        {"retry_after_seconds": False},
    ],
)
def test_invalid_response_configuration_is_rejected(
    integration: str, options: dict[str, Any]
) -> None:
    with pytest.raises(ValueError):
        challenge_response(integration, **options)


@pytest.mark.parametrize("integration", ["asgi", "wsgi"])
@pytest.mark.parametrize("status_code", [401, 429])
def test_challenge_header_matches_body_and_is_ascii(
    integration: str, status_code: int
) -> None:
    """INV-4.2: either HTTP mode mirrors the wire challenge in a header."""
    status, headers, body = challenge_response(
        integration, request_path="/café/U0001f331", challenge_status_code=status_code
    )
    assert status == status_code
    serialized = headers["x-maxwell-challenge"]
    assert serialized.isascii()
    assert json.loads(serialized) == body["challenge"]
    assert body["challenge"]["context_id"] == "default/café/U0001f331"
