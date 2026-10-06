"""Maxwell's Defense — Adaptive proof-of-work defense for AI agents.

Operational implementation of T-IB-09 (Adversarial Dissipation Theorem) from
the Intelligence Bound corpus (Aristotle-verified 2026-05-10, project
f6dd4bcd-b9f2-4818-940f-c6f52fd360c0). At amplification factor M = 2^d, an
attacker capturing N protected bits pays N * M * k_B * T * ln 2 joules; the
defender pays the Landauer floor.

This is a defense primitive only — no exploit code, no offensive use.

License: Apache-2.0
Reference SDK: github.com/viridis-security/mcp-services-sdk/tree/main/services/maxwell/reference
"""

from .core import (
    Challenge,
    DifficultyOracle,
    NonceStore,
    Solution,
    StaticDifficultyOracle,
    issue_challenge,
    solve_challenge,
    verify_solution,
)
from .errors import (
    ExpiredChallenge,
    InsufficientWork,
    InvalidSolution,
    NonceStoreUnavailable,
    ReplayedSolution,
    SignatureMismatch,
)
from .nonce_stores import InMemoryNonceStore, RedisNonceStore

__version__ = "0.1.0"
__all__ = [
    "Challenge",
    "DifficultyOracle",
    "ExpiredChallenge",
    "InMemoryNonceStore",
    "InsufficientWork",
    "InvalidSolution",
    "NonceStore",
    "NonceStoreUnavailable",
    "RedisNonceStore",
    "ReplayedSolution",
    "SignatureMismatch",
    "Solution",
    "StaticDifficultyOracle",
    "__version__",
    "issue_challenge",
    "solve_challenge",
    "verify_solution",
]
