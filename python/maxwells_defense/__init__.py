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
