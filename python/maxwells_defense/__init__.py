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
    Solution,
    DifficultyOracle,
    StaticDifficultyOracle,
    issue_challenge,
    verify_solution,
    solve_challenge,
)
from .errors import (
    InvalidSolution,
    ExpiredChallenge,
    SignatureMismatch,
    InsufficientWork,
)

__version__ = "0.1.0"
__all__ = [
    "Challenge",
    "Solution",
    "DifficultyOracle",
    "StaticDifficultyOracle",
    "issue_challenge",
    "verify_solution",
    "solve_challenge",
    "InvalidSolution",
    "ExpiredChallenge",
    "SignatureMismatch",
    "InsufficientWork",
    "__version__",
]
