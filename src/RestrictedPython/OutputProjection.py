##############################################################################
#
# Copyright (c) 2026 Zope Foundation and Contributors.
#
# This software is subject to the provisions of the Zope Public License,
# Version 2.1 (ZPL).  A copy of the ZPL should accompany this distribution.
# THIS SOFTWARE IS PROVIDED "AS IS" AND ANY AND ALL EXPRESS OR IMPLIED
# WARRANTIES ARE DISCLAIMED, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
# WARRANTIES OF TITLE, MERCHANTABILITY, AGAINST INFRINGEMENT, AND FITNESS
# FOR A PARTICULAR PURPOSE
#
##############################################################################
"""Host-side output projection for restricted scripts.

A typical host integration lets a restricted script read protected
values (e.g. to compare a submitted token against a stored one) but
may only publish aggregates back to the caller.  This module provides
a small mechanism for that boundary:

* :class:`OutputPolicy` declares which data *shapes* may leave the
  sandbox (scalars and the built-in container types) and records which
  concrete values are protected, together with a label naming their
  source.
* :meth:`OutputPolicy.project` validates a result object before it is
  handed back, walking nested containers and detecting protected
  values by identity, so aliases of the same object are caught at any
  position.
* :func:`guarded_print_collector` adapts the existing
  :class:`~RestrictedPython.PrintCollector.PrintCollector` so the
  ``print`` interface rejects protected values before they reach the
  collected buffer.

Violations raise :class:`OutputProjectionError` whose message names
the output *position* (e.g. ``output['items'][2]``) and the source
label of the protected value, but never the rejected value itself.
"""

import typing

from RestrictedPython.PrintCollector import PrintCollector


class OutputProjectionError(Exception):
    """An output position was not approved for publishing.

    Attributes:
        location: dotted/indexed path of the offending position.
        reason: human readable explanation; never contains the
            rejected value.
    """

    def __init__(self, location: str, reason: str):
        self.location = location
        self.reason = reason
        super().__init__(
            f"output position {location} is not approved: {reason}")


class OutputPolicy:
    """Define publishable data shapes and the source of protected values."""

    #: Scalar shapes which may always be published.
    scalar_types: tuple[type, ...] = (
        str, bytes, int, float, complex, bool, type(None))

    #: Container shapes which may be published if their content may be.
    container_types: tuple[type, ...] = (list, tuple, dict, set, frozenset)

    def __init__(self) -> None:
        #: Maps ``id(value)`` to the source label of a protected value.
        self._protected: dict[int, str] = {}

    def protect(self, value: typing.Any, origin: str) -> typing.Any:
        """Mark *value* as protected and return it unchanged.

        *origin* is a host chosen label (e.g. ``'ledger.token'``)
        naming where the value came from; it is safe to show in
        diagnostics.  The value itself may still be passed into the
        restricted environment for reading and comparison, but the
        very same object (including any alias of it) will be rejected
        by :meth:`project` and :meth:`ensure_printable`.
        """
        self._protected[id(value)] = origin
        return value

    def protected_origin(self, value: typing.Any) -> str | None:
        """Return the source label if *value* is protected, else None."""
        return self._protected.get(id(value))

    def project(self, value: typing.Any, location: str = 'output'
                ) -> typing.Any:
        """Return *value* if it is approved for publishing.

        Raises :class:`OutputProjectionError` naming the first
        unapproved position otherwise.
        """
        self._check(value, location, set(), protected_only=False)
        return value

    def ensure_printable(self, value: typing.Any, location: str) -> None:
        """Reject protected values in *value*.

        Unlike :meth:`project` any shape is allowed, as ``print``
        stringifies its arguments anyway; only protected content must
        not reach the buffer.
        """
        self._check(value, location, set(), protected_only=True)

    def _check(self, value: typing.Any, location: str, seen: set[int],
               protected_only: bool) -> None:
        origin = self._protected.get(id(value))
        if origin is not None:
            raise OutputProjectionError(
                location,
                f"protected value from {origin!r} must not be published")
        if isinstance(value, self.scalar_types):
            return
        if not isinstance(value, self.container_types):
            if protected_only:
                return
            raise OutputProjectionError(
                location,
                f"values of type {type(value).__name__!r} are not an "
                "approved output shape")
        if id(value) in seen:
            return  # already checked container (cycle or shared reference)
        seen.add(id(value))
        if isinstance(value, dict):
            for key, item in value.items():
                self._check(key, f"{location}.keys()", seen, protected_only)
                self._check(
                    item, f"{location}[{key!r}]", seen, protected_only)
        elif isinstance(value, (set, frozenset)):
            for item in value:
                self._check(item, f"{location}{{...}}", seen, protected_only)
        else:
            for index, item in enumerate(value):
                self._check(
                    item, f"{location}[{index}]", seen, protected_only)


def guarded_print_collector(policy: OutputPolicy) -> type[PrintCollector]:
    """Return a PrintCollector class rejecting protected values.

    The returned class follows the ``_print_`` protocol of restricted
    code, so it can be bound as ``_print_`` in the globals of
    ``compile_restricted_exec`` output.  Every ``print`` argument is
    checked against *policy* before anything is written to the buffer.
    """

    class GuardedPrintCollector(PrintCollector):
        """PrintCollector bound to an OutputPolicy."""

        def _call_print(  # type: ignore[no-untyped-def]
                self, *objects, **kwargs):
            for index, obj in enumerate(objects):
                policy.ensure_printable(obj, f"print argument {index}")
            super()._call_print(*objects, **kwargs)

        def write(self, text: str) -> None:
            policy.ensure_printable(text, "print buffer")
            super().write(text)

    return GuardedPrintCollector
