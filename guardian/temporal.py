"""Time-window helpers for temporary object permissions.

The validity window is deliberately half-open: a grant is active when
``valid_from <= now < valid_until``.  A null ``valid_from`` means the grant
has always been active, while a null ``valid_until`` means it never expires.
The right-open boundary makes expiry deterministic: at exactly
``valid_until`` the grant is already inactive.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, TypeVar

from django.db.models import Q
from django.utils import timezone

UNSET: Any = object()

T = TypeVar("T")


def normalize_datetime(value: datetime | None, field_name: str = "datetime") -> datetime | None:
    """Return an aware datetime suitable for storage under ``USE_TZ``.

    Naive values are interpreted in Django's current timezone.  Converting
    once at the API boundary keeps comparisons in the database independent of
    the process/server timezone.
    """
    if value is None:
        return None
    if timezone.is_naive(value):
        return timezone.make_aware(value, timezone.get_current_timezone())
    return value


def validate_validity_window(valid_from: datetime | None, valid_until: datetime | None) -> None:
    """Validate that a window is not inverted.

    A zero-length window is allowed (it is never active), which makes explicit
    ``valid_from == valid_until`` expiry records harmless.
    """
    if valid_from is not None and valid_until is not None and valid_until < valid_from:
        raise ValueError("valid_until must be greater than or equal to valid_from")


def _field(prefix: str, name: str) -> str:
    return f"{prefix}{name}" if prefix else name


def active_validity_q(at: datetime | None = None, prefix: str = "") -> Q:
    """Q object selecting grants active at ``at`` (left-closed, right-open)."""
    at = timezone.now() if at is None else at
    return (
        Q(**{_field(prefix, "valid_from__isnull"): True}) | Q(**{_field(prefix, "valid_from__lte"): at})
    ) & (
        Q(**{_field(prefix, "valid_until__isnull"): True}) | Q(**{_field(prefix, "valid_until__gt"): at})
    )


def non_expired_q(at: datetime | None = None, prefix: str = "") -> Q:
    """Q object selecting grants that may still become/remain active.

    Future ``valid_from`` values are intentionally kept by this predicate so
    callers that cache results can record the next activation boundary without
    pulling already-expired rows into Python.
    """
    at = timezone.now() if at is None else at
    return Q(**{_field(prefix, "valid_until__isnull"): True}) | Q(**{_field(prefix, "valid_until__gt"): at})


def next_cache_transition(valid_from: datetime | None, valid_until: datetime | None, at: datetime | None = None):
    """Return the next instant at which a cached active/inactive result changes.

    ``valid_until`` is exclusive, and ``valid_from`` is inclusive.  A cached
    result is therefore usable while ``now < transition``.
    """
    at = timezone.now() if at is None else at
    transitions = []
    if valid_from is not None and valid_from > at:
        transitions.append(valid_from)
    if valid_until is not None and valid_until > at:
        transitions.append(valid_until)
    return min(transitions) if transitions else None


def is_active_window(valid_from: datetime | None, valid_until: datetime | None, at: datetime | None = None) -> bool:
    """Python equivalent of :func:`active_validity_q` (same half-open window)."""
    at = timezone.now() if at is None else at
    return (valid_from is None or valid_from <= at) and (valid_until is None or at < valid_until)


# Cache invalidation for mutations performed through guardian managers.  Each
# checker compares this counter, so a revoke/renewal is visible to checkers
# that were already used in the same process instead of waiting for an expiry.
_cache_generation = 0


def get_cache_generation() -> int:
    return _cache_generation


def bump_cache_generation() -> None:
    global _cache_generation
    _cache_generation += 1
