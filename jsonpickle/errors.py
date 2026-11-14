"""
Stores custom jsonpickle errors.
"""

from typing import Any


class ClassNotFoundError(BaseException):
    def __init__(*args: Any, **kwargs: Any):
        pass


class SafeDecodeError(Exception):
    """Base class for failures raised while decoding in safe mode.

    Safe-mode errors never include the full payload that triggered them;
    they only carry a short, truncated description of the offending
    reference so that error reports cannot be used to exfiltrate or
    reflect attacker-controlled data.
    """


class DisallowedClassError(SafeDecodeError):
    """A py/object or py/type referenced a class that is not whitelisted."""


class PrivateModuleError(SafeDecodeError):
    """A reference named a private (underscore-prefixed) module or attribute."""


class DisallowedFunctionError(SafeDecodeError):
    """A py/reduce or py/function referenced an unregistered function."""


class DangerousFunctionError(DisallowedFunctionError):
    """A known-dangerous builtin function was referenced."""


class RecursiveReferenceError(SafeDecodeError):
    """A recursive (cyclic) or otherwise invalid py/id reference was found."""


class MaxDepthExceededError(SafeDecodeError):
    """The payload nested deeper than the configured maximum depth."""
