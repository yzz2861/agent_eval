# This file is a part of Dramatiq.
#
# Copyright (C) 2017,2018,2019,2020 CLEARTYPE SRL <bogdan@cleartype.io>
#
# Dramatiq is free software; you can redistribute it and/or modify it
# under the terms of the GNU Lesser General Public License as published by
# the Free Software Foundation, either version 3 of the License, or (at
# your option) any later version.
#
# Dramatiq is distributed in the hope that it will be useful, but WITHOUT
# ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
# FITNESS FOR A PARTICULAR PURPOSE. See the GNU Lesser General Public
# License for more details.
#
# You should have received a copy of the GNU Lesser General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

from __future__ import annotations

import threading

from .errors import MessageCancelled


class CancellationBackend:
    """ABC for cancellation backends.

    Cancellation backends track which messages have been asked to
    cancel.  They only store cancellation *requests*; the terminal
    state of a message is always decided on the worker thread that
    processes it, so a cancellation request that arrives after a
    message has completed can never overwrite its result.

    The default implementation used by the Cancel middleware is
    LocalCancellationBackend, which keeps state in the current
    process.  To share cancellation state between separate producer
    and worker processes, subclass this and implement the three
    methods on top of a shared store (e.g. Redis).
    """

    def cancel(self, message_id: str) -> None:
        """Request cancellation of a message.  Must be idempotent:
        cancelling the same message multiple times has the same
        effect as cancelling it once.

        Parameters:
          message_id(str): The id of the message to cancel.
        """
        raise NotImplementedError

    def is_cancelled(self, message_id: str) -> bool:
        """Check whether cancellation has been requested for a
        message.

        Parameters:
          message_id(str): The id of the message to check.

        Returns:
          bool: True if the message has been cancelled.
        """
        raise NotImplementedError

    def clear(self, message_id: str) -> None:
        """Forget any cancellation state for a message.  Called by
        the worker once the message has reached a terminal state, so
        backends don't grow unboundedly.

        Parameters:
          message_id(str): The id of the message to forget.
        """
        raise NotImplementedError


class LocalCancellationBackend(CancellationBackend):
    """An in-process, thread-safe cancellation backend.

    Cancellation state is kept in memory, so both producers calling
    "cancel" and the workers that check for cancellation must live in
    the same process.  This is the default backend.
    """

    def __init__(self) -> None:
        self._cancelled: set[str] = set()
        self._lock = threading.Lock()

    def cancel(self, message_id: str) -> None:
        with self._lock:
            self._cancelled.add(message_id)

    def is_cancelled(self, message_id: str) -> bool:
        with self._lock:
            return message_id in self._cancelled

    def clear(self, message_id: str) -> None:
        with self._lock:
            self._cancelled.discard(message_id)


class CancellationToken:
    """A cooperative cancellation token that actors can poll at
    checkpoints.

    Dramatiq never interrupts a running actor from the outside
    (e.g. by injecting exceptions into its thread).  Instead, actors
    that want to be cancellable should periodically call
    :meth:'is_cancelled' or :meth:'raise_if_cancelled' and give up
    their work when cancellation has been requested.

    Tokens are handed out by the Cancel middleware; use
    Cancel.get_current_token inside actor code to get the token for
    the message currently being processed.
    """

    def __init__(self, backend: CancellationBackend, message_id: str) -> None:
        self._backend = backend
        self.message_id = message_id

    def is_cancelled(self) -> bool:
        """Check whether cancellation has been requested for the
        message this token belongs to.
        """
        return self._backend.is_cancelled(self.message_id)

    def raise_if_cancelled(self) -> None:
        """Raise MessageCancelled if cancellation has been requested.
        Call this at checkpoints inside long-running actors to make
        them exit cooperatively.

        Raises:
          MessageCancelled: When the message has been cancelled.
        """
        if self.is_cancelled():
            raise MessageCancelled("Message %s was cancelled." % self.message_id)

