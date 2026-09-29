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

from .errors import MessageCanceled

#: Terminal state recorded when a message is canceled.
CANCELED = "canceled"

#: Terminal state recorded when a message completes successfully.
COMPLETED = "completed"


class CancellationBackend:
    """ABC for cancellation backends.

    Cancellation backends track the terminal state of messages so
    that cancellation requests and completion acknowledgements race
    to a single terminal state: whichever of :meth:`cancel` or
    :meth:`complete` is recorded first wins, atomically.
    """

    def cancel(self, message_id: str) -> bool:
        """Request the cancellation of a message.

        This method is idempotent: canceling a message that is
        already canceled is a no-op.

        Parameters:
          message_id(str): The id of the message to cancel.

        Returns:
          bool: True if the cancellation was recorded, False if the
          message has already completed (in which case the
          cancellation is rejected and the completion stands).
        """
        raise NotImplementedError

    def is_canceled(self, message_id: str) -> bool:
        """Check whether a message has been canceled.

        Parameters:
          message_id(str): The id of the message to check.

        Returns:
          bool: True if the message's terminal state is "canceled".
        """
        raise NotImplementedError

    def complete(self, message_id: str) -> bool:
        """Record the successful completion of a message.

        Parameters:
          message_id(str): The id of the message that completed.

        Returns:
          bool: True if the completion was recorded, False if the
          message has already been canceled (in which case the
          completion is "late" and its result must be discarded).
        """
        raise NotImplementedError

    def clear(self, message_id: str) -> None:
        """Forget any state stored for a message.

        Parameters:
          message_id(str): The id of the message to forget.
        """
        raise NotImplementedError


class LocalCancellationBackend(CancellationBackend):
    """A thread-safe, in-memory cancellation backend.

    This backend is suitable for single-process setups and tests.
    Note that terminal states are kept in memory forever; backends
    meant for production use should expire them (e.g. with a TTL
    slightly longer than the result TTL).
    """

    def __init__(self) -> None:
        self._states: dict[str, str] = {}
        self._lock = threading.Lock()

    def cancel(self, message_id: str) -> bool:
        with self._lock:
            state = self._states.get(message_id)
            if state == COMPLETED:
                return False
            self._states[message_id] = CANCELED
            return True

    def is_canceled(self, message_id: str) -> bool:
        with self._lock:
            return self._states.get(message_id) == CANCELED

    def complete(self, message_id: str) -> bool:
        with self._lock:
            state = self._states.get(message_id)
            if state == CANCELED:
                return False
            self._states[message_id] = COMPLETED
            return True

    def clear(self, message_id: str) -> None:
        with self._lock:
            self._states.pop(message_id, None)


class CancellationToken:
    """A token actors can use to cooperatively check for cancellation
    at checkpoints during long-running work.

    Tokens are handed out by the
    :class:`Cancellation<dramatiq.middleware.Cancellation>` middleware
    while a message is being processed; use
    :meth:`Cancellation.get_current_token<dramatiq.middleware.Cancellation.get_current_token>`
    to retrieve the token for the message currently being processed.
    """

    def __init__(self, backend: CancellationBackend, message_id: str) -> None:
        self._backend = backend
        self._message_id = message_id

    @property
    def message_id(self) -> str:
        """The id of the message this token belongs to."""
        return self._message_id

    @property
    def is_canceled(self) -> bool:
        """Whether cancellation has been requested for this message."""
        return self._backend.is_canceled(self._message_id)

    def check(self) -> None:
        """Raise :class:`MessageCanceled<dramatiq.errors.MessageCanceled>`
        if cancellation has been requested for this message.

        Call this at checkpoints inside long-running actors to exit
        early when the message has been canceled.

        Raises:
          MessageCanceled: If the message has been canceled.
        """
        if self.is_canceled:
            raise MessageCanceled("Message %s was canceled." % self._message_id)
