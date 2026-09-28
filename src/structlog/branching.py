# SPDX-License-Identifier: MIT OR Apache-2.0
# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the MIT License.  See the LICENSE file in the root of this
# repository for complete details.

"""
Fan out one log event to multiple isolated processing branches.

Put shared processors (for example merging bound context or stdlib
*extra* fields) into the regular processor chain, then terminate it with
:class:`BranchFanout`. The shared processors run exactly once; afterwards
each :class:`Branch` receives its own isolated deep copy of the event
dict, runs its own processors and renderer, and passes the rendered
result to its own sink.

.. versionadded:: 26.2.0
"""

from __future__ import annotations

import copy

from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from typing import Any, Literal

from .exceptions import DropEvent
from .typing import EventDict, Processor, WrappedLogger


__all__ = [
    "Branch",
    "BranchErrorPolicy",
    "BranchFanout",
]


BranchErrorPolicy = Literal["continue", "raise"]
"""
What :class:`BranchFanout` does when a branch raises an exception.

- `"continue"`: swallow the exception and keep processing the remaining
  branches.
- `"raise"`: re-raise the exception immediately, skipping the remaining
  branches.

.. versionadded:: 26.2.0
"""


@dataclass
class Branch:
    """
    One isolated output path of a :class:`BranchFanout`.

    Args:
        processors:
            Branch-local processors that run on this branch's private copy
            of the event dict.

        renderer:
            The final processor that turns the event dict into the rendered
            output (for example :class:`structlog.processors.JSONRenderer`).
            If `None`, the processed event dict is passed to *sink* as-is.

        sink:
            A callable that receives the rendered output. If `None`, the
            rendered output is discarded (useful for testing).

        name:
            An optional human-readable name, only used in error messages.

    .. versionadded:: 26.2.0
    """

    processors: Sequence[Processor] = field(default_factory=list)
    renderer: Processor | None = None
    sink: Callable[[Any], None] | None = None
    name: str = ""


class BranchFanout:
    """
    A terminal processor that fans the event dict out to multiple
    :class:`Branch`es.

    Each branch receives its own deep copy of the event dict as it was
    left by the shared processors that ran before the fan-out. Therefore
    branches are fully isolated: deleting keys, mutating nested values,
    or raising :exc:`structlog.DropEvent` in one branch never affects the
    others.

    Since all output happens in the branches' sinks, this processor raises
    :exc:`structlog.DropEvent` when it's done, so the wrapped logger is
    never called. It must be the last processor in the chain.

    Args:
        branches: The branches to fan out to, in order.

        on_branch_error:
            What to do when a branch raises an exception (other than
            :exc:`structlog.DropEvent`, which always only drops its own
            branch): `"continue"` swallows it and processes the remaining
            branches, `"raise"` re-raises it immediately.

    .. versionadded:: 26.2.0
    """

    __slots__ = ("_branches", "_on_branch_error")

    def __init__(
        self,
        branches: Sequence[Branch],
        *,
        on_branch_error: BranchErrorPolicy = "continue",
    ) -> None:
        if on_branch_error not in ("continue", "raise"):
            msg = (
                f"on_branch_error must be 'continue' or 'raise', "
                f"not {on_branch_error!r}."
            )
            raise ValueError(msg)

        self._branches = tuple(branches)
        self._on_branch_error = on_branch_error

    def __call__(
        self,
        logger: WrappedLogger,
        method_name: str,
        event_dict: EventDict,
    ) -> EventDict:
        for branch in self._branches:
            self._run_branch(
                branch, logger, method_name, copy.deepcopy(event_dict)
            )

        # All output was handled by the branches' sinks, so stop the
        # regular processor chain from calling the wrapped logger.
        raise DropEvent

    def _run_branch(
        self,
        branch: Branch,
        logger: WrappedLogger,
        method_name: str,
        event_dict: EventDict,
    ) -> None:
        try:
            for processor in branch.processors:
                event_dict = processor(logger, method_name, event_dict)

            if branch.renderer is not None:
                rendered = branch.renderer(logger, method_name, event_dict)
            else:
                rendered = event_dict

            if branch.sink is not None:
                branch.sink(rendered)
        except DropEvent:
            # Dropping is a deliberate, branch-local decision.
            pass
        except Exception:
            if self._on_branch_error == "raise":
                raise
