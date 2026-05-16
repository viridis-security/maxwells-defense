"""Maxwell's Defense — core PoW primitive (challenge / solution / verify).

Design invariants (the formal contract this module commits to — see THEOREMS.md):

  MX-INV-1  Verification cost is O(1) in difficulty: the defender hashes once.
  MX-INV-2  Solution cost is O(2^d) expected for difficulty d (leading zero bits):
            the attacker pays exponential energy.
  MX-INV-3  Challenges are bound to a (client_context, expiry) tuple via HMAC;
            replay across contexts or after expiry is detectably forged.
  MX-INV-4  No exploit code path. This module issues challenges, verifies
            solutions, and solves them as a self-test. Nothing else.
  MX-INV-5  Difficulty oracle is pluggable: the caller decides how to map a
            (client_context) -> difficulty. Defaults are static and explicit.

Hashing primitive: SHA-256. We require N leading zero BITS of
sha256(server_nonce || client_solution_nonce).

License: Apache-2.0
"""

from __future__ import annotations

import dataclasses
import hashlib
import hmac
import os
import secrets
import time
from typing import Any, Callable, Mapping, Protocol


# ---------------------------------------------------------------------------
# Types
# ---------------------------------------------------------------------------


@dataclasses.dataclass(frozen=True)
class Challenge:
    """A PoW challenge issued by the defender.

    Fields:
      server_nonce  random bytes the attacker must extend to find a hash
                    with `difficulty` leading zero bits.
      difficulty    required leading-zero bits in sha256(server_nonce ||
                    solution_nonce).
      expires_at    unix timestamp after which solutions are rejected.
      context_id    arbitrary opaque string identifying the bound context
                    (route, agent id, IP hash, etc.). Bound by HMAC.
      hmac_sig      HMAC-SHA256 of (server_nonce || difficulty ||
                    expires_at || context_id) keyed by the server secret.
    """

    server_nonce: bytes
    difficulty: int
    expires_at: int
    context_id: str
    hmac_sig: bytes

    def to_dict(self) -> dict[str, Any]:
        return {
            "server_nonce": self.server_nonce.hex(),
            "difficulty": self.difficulty,
            "expires_at": self.expires_at,
            "context_id": self.context_id,
            "hmac_sig": self.hmac_sig.hex(),
        }

    @classmethod
    def from_dict(cls, d: Mapping[str, Any]) -> "Challenge":
        return cls(
            server_nonce=bytes.fromhex(d["server_nonce"]),
            difficulty=int(d["difficulty"]),
            expires_at=int(d["expires_at"]),
            context_id=str(d["context_id"]),
            hmac_sig=bytes.fromhex(d["hmac_sig"]),
        )


@dataclasses.dataclass(frozen=True)
class Solution:
    """A PoW solution submitted by the client."""

    solution_nonce: bytes

    def to_dict(self) -> dict[str, Any]:
        return {"solution_nonce": self.solution_nonce.hex()}

    @classmethod
    def from_dict(cls, d: Mapping[str, Any]) -> "Solution":
        return cls(solution_nonce=bytes.fromhex(d["solution_nonce"]))


class DifficultyOracle(Protocol):
    """Pluggable difficulty oracle.

    Given a context_id (route, agent identity, IP hash, etc.) and an
    arbitrary signal mapping, return the difficulty in leading-zero bits.
    """

    def __call__(self, context_id: str, signals: Mapping[str, Any]) -> int: ...


class StaticDifficultyOracle:
    """Returns a constant difficulty regardless of context."""

    def __init__(self, difficulty: int) -> None:
        if difficulty < 0 or difficulty > 32:
            raise ValueError("difficulty must be in [0, 32]")
        self._difficulty = difficulty

    def __call__(
        self, context_id: str, signals: Mapping[str, Any]
    ) -> int:  # noqa: D401
        return self._difficulty


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _hmac_payload(
    server_nonce: bytes, difficulty: int, expires_at: int, context_id: str
) -> bytes:
    return b"|".join(
        [
            server_nonce,
            str(difficulty).encode("ascii"),
            str(expires_at).encode("ascii"),
            context_id.encode("utf-8"),
        ]
    )


def _leading_zero_bits(digest: bytes) -> int:
    """Count leading zero bits of a byte string."""
    n = 0
    for b in digest:
        if b == 0:
            n += 8
            continue
        # Count leading zeros in this nonzero byte.
        for i in range(7, -1, -1):
            if (b >> i) & 1:
                return n
            n += 1
        return n
    return n


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def issue_challenge(
    *,
    server_secret: bytes,
    context_id: str,
    difficulty: int,
    ttl_seconds: int = 300,
    server_nonce_bytes: int = 16,
    _clock: Callable[[], float] = time.time,
) -> Challenge:
    """Issue a fresh challenge bound to context_id.

    Args:
      server_secret: HMAC key. MUST be high-entropy (>=32 bytes) in
                     production. Treated as opaque bytes.
      context_id:    Opaque string. Recommended: a hash of (route, agent
                     id, ip-with-anonymization). Bound by HMAC.
      difficulty:    Leading-zero bits required (0..32). Each +1 doubles
                     attacker expected cost.
      ttl_seconds:   Lifetime of the challenge.
      server_nonce_bytes: Random bytes in server_nonce. Default 16.

    Raises:
      ValueError on invalid difficulty or empty secret.
    """
    if difficulty < 0 or difficulty > 32:
        raise ValueError("difficulty must be in [0, 32]")
    if not server_secret:
        raise ValueError("server_secret must be non-empty")
    if ttl_seconds <= 0:
        raise ValueError("ttl_seconds must be positive")
    if server_nonce_bytes < 8:
        raise ValueError("server_nonce_bytes must be >= 8")

    server_nonce = secrets.token_bytes(server_nonce_bytes)
    expires_at = int(_clock()) + ttl_seconds
    payload = _hmac_payload(server_nonce, difficulty, expires_at, context_id)
    sig = hmac.new(server_secret, payload, hashlib.sha256).digest()
    return Challenge(
        server_nonce=server_nonce,
        difficulty=difficulty,
        expires_at=expires_at,
        context_id=context_id,
        hmac_sig=sig,
    )


def verify_solution(
    *,
    server_secret: bytes,
    challenge: Challenge,
    solution: Solution,
    expected_context_id: str | None = None,
    _clock: Callable[[], float] = time.time,
) -> None:
    """Verify a solution. Raises on any failure; returns None on success.

    Verification is O(1): one HMAC verify, one SHA-256, one bit-count.

    Raises:
      SignatureMismatch:  challenge HMAC does not verify (forged challenge).
      ExpiredChallenge:   now > challenge.expires_at.
      InvalidSolution:    expected_context_id given and does not match.
      InsufficientWork:   sha256(server_nonce||solution_nonce) does not
                          have `difficulty` leading zero bits.
    """
    from .errors import (
        ExpiredChallenge,
        InsufficientWork,
        InvalidSolution,
        SignatureMismatch,
    )

    # 1. Verify HMAC signature on the challenge — defender's own issued
    #    challenges MUST be the only ones we accept.
    payload = _hmac_payload(
        challenge.server_nonce,
        challenge.difficulty,
        challenge.expires_at,
        challenge.context_id,
    )
    expected_sig = hmac.new(server_secret, payload, hashlib.sha256).digest()
    if not hmac.compare_digest(expected_sig, challenge.hmac_sig):
        raise SignatureMismatch("challenge HMAC does not verify")

    # 2. Check context binding if requested.
    if expected_context_id is not None and expected_context_id != challenge.context_id:
        raise InvalidSolution(
            f"context mismatch: challenge bound to {challenge.context_id!r}, "
            f"verifier expected {expected_context_id!r}"
        )

    # 3. Check expiry.
    now = int(_clock())
    if now > challenge.expires_at:
        raise ExpiredChallenge(
            f"challenge expired at {challenge.expires_at} (now={now})"
        )

    # 4. Check work.
    digest = hashlib.sha256(challenge.server_nonce + solution.solution_nonce).digest()
    zb = _leading_zero_bits(digest)
    if zb < challenge.difficulty:
        raise InsufficientWork(
            f"solution provided {zb} leading zero bits, "
            f"challenge required {challenge.difficulty}"
        )


def solve_challenge(challenge: Challenge, *, max_iterations: int | None = None) -> Solution:
    """Self-test helper: solve a challenge by brute force.

    Not used in production by the defender; included so the SDK is
    self-checking and so client-side workers in agent harnesses have a
    reference algorithm to mirror.

    Args:
      max_iterations: stop after this many tries (raises RuntimeError).
                      Default: 4 * 2**difficulty (high confidence of
                      success at moderate difficulties).
    """
    target_bits = challenge.difficulty
    if max_iterations is None:
        max_iterations = max(1024, 32 * (1 << target_bits))

    server_nonce = challenge.server_nonce
    for _ in range(max_iterations):
        cand = os.urandom(16)
        digest = hashlib.sha256(server_nonce + cand).digest()
        if _leading_zero_bits(digest) >= target_bits:
            return Solution(solution_nonce=cand)
    raise RuntimeError(
        f"solve_challenge: exhausted {max_iterations} iterations at "
        f"difficulty={target_bits}"
    )
