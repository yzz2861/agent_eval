"""Stream audit completeness checks built on ijson public event API.

The package answers two different questions that must not be conflated:

1. A rule field is *missing* when the container that was supposed to hold it
   has already been closed (an ``end_map`` / ``end_array`` event was seen).
   This is a definitive, negative conclusion.
2. A rule field is *not collected* when the byte stream ended first
   (ijson raises ``IncompleteJSONError``). The slot may simply live further
   down the stream, so "missing" cannot be claimed.

Both the synchronous short-read driver and the push/coroutine driver feed the
exact same ijson ``(prefix, event, value)`` tuples into one observer, so both
produce identical observations on identical bytes.
"""

from .rules import CallerRule, Rule, RuleSpec, compile_rules, normalize_rules
from .observer import (
    CompletenessObserver,
    CompletenessResult,
    Finding,
    Truncation,
)
from .drivers import audit_bytes, audit_chunks, audit_stream

__all__ = [
    "CallerRule",
    "Rule",
    "RuleSpec",
    "compile_rules",
    "normalize_rules",
    "CompletenessObserver",
    "CompletenessResult",
    "Finding",
    "Truncation",
    "audit_stream",
    "audit_chunks",
    "audit_bytes",
]
