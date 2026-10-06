"""Maxwell's Defense — Adaptive proof-of-work defense for AI agents.

SHA-256 reference primitive: constant verification work in difficulty and
2^d expected classical search queries under a random-oracle model.
T-IB-09 is a conditional research model with one declared external asymmetry
axiom and explicit dissipation hypotheses. See THEOREMS.md and the source
statement at docs/artifacts/t-ib-09/statement.lean in the repository.
No physical energy bound or economic outcome is established by this library.

This is a defense primitive only — no exploit code, no offensive use.

License: Apache-2.0
Reference SDK:
github.com/viridis-security/mcp-services-sdk/tree/main/services/maxwell/reference
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
