"""Exception hierarchy for Maxwell's Defense.

All errors derive from MaxwellError so callers can catch broadly or narrowly.
"""


class MaxwellError(Exception):
    """Base class for all Maxwell's Defense errors."""


class InvalidSolution(MaxwellError):
    """Submitted solution is malformed or does not parse."""


class ExpiredChallenge(MaxwellError):
    """Challenge has passed its expiry timestamp."""


class SignatureMismatch(MaxwellError):
    """Challenge HMAC does not verify — challenge was forged or tampered with."""


class InsufficientWork(MaxwellError):
    """Solution does not meet the required difficulty (leading-zero bits)."""


class ReplayedSolution(MaxwellError):
    """A valid solution's server nonce has already been consumed."""


class NonceStoreUnavailable(MaxwellError):
    """Single-use state cannot be safely retained; verification fails closed."""
