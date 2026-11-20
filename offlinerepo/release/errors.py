# Copyright 2026, the TUF contributors
# SPDX-License-Identifier: MIT OR Apache-2.0
"""Exceptions for the offline release planner and executor.

Every condition that needs a human decision is a subclass of
:class:`ManualInterventionRequired`. Such conditions are raised while planning
or during pre-switch validation, before any pointer is moved, so an existing
client never observes a half-configured repository.
"""

from __future__ import annotations


class ManualInterventionRequired(Exception):
    """Base class for conditions an operator must resolve."""


class PlanValidationError(ManualInterventionRequired):
    """The signed artifacts do not form a valid, self-consistent release."""


class StaleRootPlanError(ManualInterventionRequired):
    """A pointer changed between planning and execution.

    The plan was derived from a root generation that is no longer current.
    Rebuilding the plan from the current root is required; blindly switching
    would silently overwrite a concurrent publication.
    """


class TransientStorageError(Exception):
    """A retryable object-store failure (timeout, partial/rejected write)."""


__all__ = [
    "ManualInterventionRequired",
    "PlanValidationError",
    "StaleRootPlanError",
    "TransientStorageError",
]
