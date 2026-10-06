# SPDX-License-Identifier: Apache-2.0
"""INV-4.3: short keys warn without exposing key material or breaking callers."""

from __future__ import annotations

import warnings
from typing import Any

import pytest
from maxwells_defense import issue_challenge, solve_challenge, verify_solution
from maxwells_defense.middleware import (
    FastAPIMaxwellMiddleware,
    WSGIMaxwellMiddleware,
)


@pytest.mark.parametrize("size", [1, 31])
def test_short_secret_warns_and_remains_compatible(size: int) -> None:
    secret = b"s" * size
    with pytest.warns(UserWarning, match="shorter than 32 bytes") as recorded:
        challenge = issue_challenge(
            server_secret=secret, context_id="ctx", difficulty=0
        )
    assert secret.hex() not in str(recorded[0].message)
    verify_solution(
        server_secret=secret, challenge=challenge, solution=solve_challenge(challenge)
    )


@pytest.mark.parametrize(
    "middleware", [FastAPIMaxwellMiddleware, WSGIMaxwellMiddleware]
)
def test_short_secret_warns_at_middleware_setup(middleware: type[Any]) -> None:
    with pytest.warns(UserWarning, match="shorter than 32 bytes"):
        middleware(lambda *args: None, server_secret=b"short-fixture")


@pytest.mark.parametrize("size", [32, 64])
def test_recommended_key_lengths_do_not_warn(size: int) -> None:
    with warnings.catch_warnings(record=True) as recorded:
        warnings.simplefilter("always")
        secret = b"s" * size
        issue_challenge(server_secret=secret, context_id="ctx", difficulty=0)
        FastAPIMaxwellMiddleware(lambda *args: None, server_secret=secret)
        WSGIMaxwellMiddleware(lambda *args: None, server_secret=secret)
    assert recorded == []


def test_empty_secret_still_errors_without_disclosing_it() -> None:
    with pytest.raises(ValueError, match="non-empty"):
        issue_challenge(server_secret=b"", context_id="ctx", difficulty=0)
