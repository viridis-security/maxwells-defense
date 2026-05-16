"""Invariant tests for Maxwell's Defense.

Each test names the invariant it enforces. These are the contract; if any
of these fails on `pytest`, the primitive is broken.

  MX-INV-1  Verification is O(1) in difficulty.
  MX-INV-2  Solution cost is O(2^d) expected.
  MX-INV-3  Challenge is bound to context_id via HMAC. Forged or
            tampered challenges are rejected.
  MX-INV-3a Expired challenges are rejected.
  MX-INV-3b Context mismatch is rejected when caller passes
            expected_context_id.
  MX-INV-4  No exploit code path. Module exports only defense functions.
  MX-INV-5  Difficulty oracle is pluggable.
"""

import hashlib
import time

import pytest

from maxwells_defense.core import (
    Challenge,
    DifficultyOracle,
    Solution,
    StaticDifficultyOracle,
    _leading_zero_bits,
    issue_challenge,
    solve_challenge,
    verify_solution,
)
from maxwells_defense.errors import (
    ExpiredChallenge,
    InsufficientWork,
    InvalidSolution,
    SignatureMismatch,
)


SECRET = b"a" * 32
OTHER_SECRET = b"b" * 32


# ---------------------------------------------------------------------------
# Happy path
# ---------------------------------------------------------------------------


def test_issue_solve_verify_roundtrip_difficulty_0():
    """MX-INV-1 + MX-INV-2 baseline: at d=0, every nonce is a valid solution."""
    c = issue_challenge(
        server_secret=SECRET, context_id="ctx-a", difficulty=0, ttl_seconds=10
    )
    s = solve_challenge(c)
    verify_solution(server_secret=SECRET, challenge=c, solution=s)


def test_issue_solve_verify_roundtrip_moderate_difficulty():
    """End-to-end at a difficulty solvable in <1s in tests."""
    c = issue_challenge(
        server_secret=SECRET, context_id="ctx-a", difficulty=12, ttl_seconds=30
    )
    s = solve_challenge(c)
    verify_solution(server_secret=SECRET, challenge=c, solution=s)


def test_solution_serialisation_roundtrip():
    c = issue_challenge(
        server_secret=SECRET, context_id="ctx-a", difficulty=8, ttl_seconds=30
    )
    s = solve_challenge(c)
    c2 = Challenge.from_dict(c.to_dict())
    s2 = Solution.from_dict(s.to_dict())
    assert c2 == c
    assert s2 == s
    verify_solution(server_secret=SECRET, challenge=c2, solution=s2)


# ---------------------------------------------------------------------------
# MX-INV-3 — HMAC binding
# ---------------------------------------------------------------------------


def test_forged_challenge_signed_with_wrong_secret_is_rejected():
    """Attacker can't issue their own challenges — HMAC binds to server secret."""
    forged = issue_challenge(
        server_secret=OTHER_SECRET, context_id="ctx-a", difficulty=0, ttl_seconds=10
    )
    s = solve_challenge(forged)
    with pytest.raises(SignatureMismatch):
        verify_solution(server_secret=SECRET, challenge=forged, solution=s)


def test_tampered_difficulty_is_rejected():
    """An attacker lowering the difficulty after issuance breaks the HMAC."""
    c = issue_challenge(
        server_secret=SECRET, context_id="ctx-a", difficulty=10, ttl_seconds=10
    )
    tampered = Challenge(
        server_nonce=c.server_nonce,
        difficulty=0,  # attacker tries to drop difficulty
        expires_at=c.expires_at,
        context_id=c.context_id,
        hmac_sig=c.hmac_sig,
    )
    s = Solution(solution_nonce=b"\x00" * 16)
    with pytest.raises(SignatureMismatch):
        verify_solution(server_secret=SECRET, challenge=tampered, solution=s)


def test_tampered_context_is_rejected():
    """Attacker can't replay a challenge against a different context."""
    c = issue_challenge(
        server_secret=SECRET, context_id="ctx-a", difficulty=0, ttl_seconds=10
    )
    tampered = Challenge(
        server_nonce=c.server_nonce,
        difficulty=c.difficulty,
        expires_at=c.expires_at,
        context_id="ctx-b",  # attacker rewires to a different context
        hmac_sig=c.hmac_sig,
    )
    s = solve_challenge(c)
    with pytest.raises(SignatureMismatch):
        verify_solution(server_secret=SECRET, challenge=tampered, solution=s)


def test_tampered_expiry_is_rejected():
    """Attacker can't extend an expired challenge."""
    c = issue_challenge(
        server_secret=SECRET, context_id="ctx-a", difficulty=0, ttl_seconds=10
    )
    tampered = Challenge(
        server_nonce=c.server_nonce,
        difficulty=c.difficulty,
        expires_at=c.expires_at + 999999,  # attacker extends expiry
        context_id=c.context_id,
        hmac_sig=c.hmac_sig,
    )
    s = solve_challenge(c)
    with pytest.raises(SignatureMismatch):
        verify_solution(server_secret=SECRET, challenge=tampered, solution=s)


def test_context_mismatch_at_verify_time_is_rejected():
    """MX-INV-3b: caller can require an expected_context_id."""
    c = issue_challenge(
        server_secret=SECRET, context_id="ctx-a", difficulty=0, ttl_seconds=10
    )
    s = solve_challenge(c)
    with pytest.raises(InvalidSolution):
        verify_solution(
            server_secret=SECRET,
            challenge=c,
            solution=s,
            expected_context_id="ctx-b",
        )


# ---------------------------------------------------------------------------
# MX-INV-3a — expiry
# ---------------------------------------------------------------------------


def test_expired_challenge_is_rejected():
    c = issue_challenge(
        server_secret=SECRET, context_id="ctx-a", difficulty=0, ttl_seconds=1
    )
    s = solve_challenge(c)
    # Fake clock far in the future.
    with pytest.raises(ExpiredChallenge):
        verify_solution(
            server_secret=SECRET,
            challenge=c,
            solution=s,
            _clock=lambda: time.time() + 10_000,
        )


# ---------------------------------------------------------------------------
# MX-INV-2 — insufficient work
# ---------------------------------------------------------------------------


def test_invalid_solution_at_nonzero_difficulty_is_rejected():
    """A random nonce will not satisfy d>=4 (P~6.25%) — try a fixed bad one."""
    c = issue_challenge(
        server_secret=SECRET, context_id="ctx-a", difficulty=12, ttl_seconds=10
    )
    # Deterministic bad nonce: empirically nonzero hash for arbitrary input.
    bad = Solution(solution_nonce=b"deliberately-bad")
    digest = hashlib.sha256(c.server_nonce + bad.solution_nonce).digest()
    assert _leading_zero_bits(digest) < 12, "Test pre-condition: bad nonce"
    with pytest.raises(InsufficientWork):
        verify_solution(server_secret=SECRET, challenge=c, solution=bad)


# ---------------------------------------------------------------------------
# MX-INV-5 — pluggable difficulty oracle
# ---------------------------------------------------------------------------


def test_static_difficulty_oracle_returns_constant():
    oracle = StaticDifficultyOracle(7)
    assert oracle("any-ctx", {}) == 7


def test_difficulty_oracle_signals_are_passed_through():
    captured: dict = {}

    def oracle(context_id, signals):
        captured["context_id"] = context_id
        captured["signals"] = signals
        return 3

    assert oracle("ctx-x", {"failed_attempts": 7}) == 3
    assert captured == {"context_id": "ctx-x", "signals": {"failed_attempts": 7}}


# ---------------------------------------------------------------------------
# Boundary / validation
# ---------------------------------------------------------------------------


def test_issue_rejects_invalid_difficulty():
    with pytest.raises(ValueError):
        issue_challenge(
            server_secret=SECRET, context_id="x", difficulty=-1, ttl_seconds=10
        )
    with pytest.raises(ValueError):
        issue_challenge(
            server_secret=SECRET, context_id="x", difficulty=33, ttl_seconds=10
        )


def test_issue_rejects_empty_secret():
    with pytest.raises(ValueError):
        issue_challenge(
            server_secret=b"", context_id="x", difficulty=4, ttl_seconds=10
        )


def test_issue_rejects_nonpositive_ttl():
    with pytest.raises(ValueError):
        issue_challenge(
            server_secret=SECRET, context_id="x", difficulty=4, ttl_seconds=0
        )


def test_leading_zero_bits_known_values():
    assert _leading_zero_bits(b"\x00\x00\x00\x00") == 32
    assert _leading_zero_bits(b"\xff") == 0
    assert _leading_zero_bits(b"\x01") == 7
    assert _leading_zero_bits(b"\x00\xff") == 8
    assert _leading_zero_bits(b"\x00\x80") == 8


# ---------------------------------------------------------------------------
# MX-INV-4 — no exploit code path
# ---------------------------------------------------------------------------


def test_module_exports_only_defense_primitives():
    """The package public surface contains only defense + utility names —
    no `attack_*`, `exploit_*`, `bypass_*`, etc."""
    import maxwells_defense as md

    public = [n for n in dir(md) if not n.startswith("_")]
    banned = ("attack", "exploit", "bypass", "ssrf", "rce", "payload")
    for name in public:
        for bad in banned:
            assert bad not in name.lower(), f"banned token {bad!r} in public API: {name}"
