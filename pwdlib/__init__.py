"""Modern password hashing for Python"""

__version__ = "0.3.1"

from ._hash import PasswordHash

__all__ = ["PasswordHash"]

try:
    from .hashers.argon2 import (
        Argon2VerificationPolicy,
        PolicyViolationReason,
    )
except ImportError:  # pragma: no cover
    pass
else:
    __all__ += ["Argon2VerificationPolicy", "PolicyViolationReason"]
