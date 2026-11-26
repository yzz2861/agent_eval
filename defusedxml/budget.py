# defusedxml
#
# Copyright (c) 2013-2020 by Christian Heimes <christian@python.org>
# Licensed to PSF under a Contributor Agreement.
# See https://www.python.org/psf/license/licensing for licensing details.
"""Local security budget for XML parsers.

The budget ledger is shared by the full-tree (:class:`~defusedxml.ElementTree
.BudgetedXMLParser`) and incremental (:class:`~defusedxml.ElementTree
.BudgetedPullParser` interfaces. Both adapters record their byte consumption
against the same approved quota and report whether the document was parsed to
completion or abandoned before the parser reached the end of the stream.

A document is only treated as *accepted* once its parser finishes the whole
stream. Feeding half of a document and stopping early is recorded as a
cancellation instead of silently looking like a successful decision.
"""
from __future__ import print_function, absolute_import

from enum import Enum

from .common import DefusedXmlException


class BudgetError(DefusedXmlException):
    """Base class for security budget related errors."""


class BudgetExceeded(BudgetError):
    """Raised when a parser consumes more than its approved budget."""

    def __init__(self, budget, amount, consumed):
        super().__init__()
        self.budget = budget
        self.amount = amount
        self.consumed = consumed

    def __str__(self):
        return (
            "BudgetExceeded(approved={!r}, consumed={!r}, "
            "requested={!r})".format(
                self.budget.limit, self.consumed, self.amount
            )
        )


class BudgetStateError(BudgetError):
    """Raised when a terminal budget ledger is reused."""


class BudgetState(str, Enum):
    """Lifecycle of a budget ledger."""

    ACTIVE = "active"
    COMPLETED = "completed"
    CANCELLED = "cancelled"
    EXCEEDED = "exceeded"


class SecurityBudget(object):
    """Shared quota ledger for one or more XML parsing adapters.

    A single ledger may be handed to several parsers. Every byte fed into any
    of them counts against the same ``limit`` so that a document cannot be
    parsed for free by switching between a full-tree and a streaming parser.
    """

    def __init__(self, limit):
        if not isinstance(limit, int) or isinstance(limit, bool):
            raise TypeError("budget limit must be an integer")
        if limit < 0:
            raise ValueError("budget limit must not be negative")
        self._limit = limit
        self._consumed = 0
        self._state = BudgetState.ACTIVE

    @property
    def limit(self):
        """Approved number of bytes."""
        return self._limit

    @property
    def consumed(self):
        """Number of bytes recorded so far."""
        return self._consumed

    @property
    def remaining(self):
        """Number of bytes that may still be consumed."""
        return self._limit - self._consumed

    @property
    def state(self):
        """Current :class:`BudgetState` of the ledger."""
        return self._state

    @property
    def is_active(self):
        return self._state is BudgetState.ACTIVE

    @property
    def is_complete(self):
        """True only when a parser consumed and closed the full document."""
        return self._state is BudgetState.COMPLETED

    @property
    def is_cancelled(self):
        """True when a caller stopped before the end of the stream."""
        return self._state is BudgetState.CANCELLED

    @property
    def is_exceeded(self):
        return self._state is BudgetState.EXCEEDED

    @property
    def accepted(self):
        """Whether the document has been fully and successfully parsed."""
        return self._state is BudgetState.COMPLETED

    def charge(self, amount):
        """Record ``amount`` consumed bytes against the quota.

        The ledger moves to ``EXCEEDED`` and :class:`BudgetExceeded` is raised
        when the cumulative consumption crosses the approved limit. Landing on
        exactly the limit is still permitted so that a document may finish on
        an element boundary.
        """
        if not isinstance(amount, int) or isinstance(amount, bool):
            raise TypeError("charged amount must be an integer")
        if amount < 0:
            raise ValueError("charged amount must not be negative")
        if self._state is not BudgetState.ACTIVE:
            raise BudgetStateError(
                "budget is already {}".format(self._state.value)
            )
        if amount == 0:
            return amount
        new_total = self._consumed + amount
        if new_total > self._limit:
            self._state = BudgetState.EXCEEDED
            raise BudgetExceeded(self, amount, new_total)
        self._consumed = new_total
        return amount

    def complete(self):
        """Mark the document as fully parsed and accepted."""
        if self._state is not BudgetState.ACTIVE:
            raise BudgetStateError(
                "budget is already {}".format(self._state.value)
            )
        self._state = BudgetState.COMPLETED

    def cancel(self):
        """Record an early cancellation.

        Idempotent for terminal ledgers, e.g. when a parser is closed twice or
        garbage collected after an explicit cancellation.
        """
        if self._state is BudgetState.ACTIVE:
            self._state = BudgetState.CANCELLED

    def __repr__(self):
        return "{}(limit={!r}, consumed={!r}, state={!r})".format(
            self.__class__.__name__,
            self._limit,
            self._consumed,
            self._state.value,
        )


class BudgetedReader(object):
    """File-like wrapper that charges every ``read()`` to a budget.

    It implements the small interface that :func:`xml.etree.ElementTree
    .iterparse` relies on (``read`` and ``close``) while recording bytes on
    the shared :class:`SecurityBudget`.
    """

    def __init__(self, source, budget, chunk_size=16 * 1024):
        if not hasattr(source, "read"):
            raise TypeError("source must be a file-like object")
        self._source = source
        self._budget = budget
        self._chunk_size = chunk_size
        self._closed = False

    @property
    def budget(self):
        return self._budget

    def read(self, size=-1):
        if self._closed:
            return b""
        if size is None or size < 0 or size > self._chunk_size:
            size = self._chunk_size
        data = self._source.read(size)
        if data:
            self._budget.charge(len(data))
        return data

    def close(self):
        if self._closed:
            return
        self._closed = True
        close = getattr(self._source, "close", None)
        if close is not None:
            close()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        self.close()
