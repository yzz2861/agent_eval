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

import contextvars
from typing import TYPE_CHECKING, Optional

from ..cancel import CancellationBackend, CancellationToken, LocalCancellationBackend
from ..errors import MessageCancelled
from .middleware import Middleware, SkipMessage

if TYPE_CHECKING:
    from ..broker import Broker, MessageProxy


class Cancel(Middleware):
    """Middleware that adds cooperative cancellation to messages.

    Example:

      >>> import dramatiq
      >>> from dramatiq.middleware import Cancel

      >>> cancel = Cancel()
      >>> broker.add_middleware(cancel)

      >>> @dramatiq.actor
      ... def long_running():
      ...     token = Cancel.get_current_token()
      ...     for item in items:
      ...         token.raise_if_cancelled()
      ...         process(item)

      >>> message = long_running.send()
      >>> cancel.cancel(message.message_id)

    Cancellation is cooperative: actors are never interrupted from
    the outside.  Messages that have not started executing yet are
    skipped outright, while actors that are already running are
    expected to poll their cancellation token at checkpoints and
    exit (by returning or by letting MessageCancelled propagate).

    Cancelled messages are acknowledged, are never retried and do
    not continue pipelines.  They do, however, count towards group
    completion.  Cancellation requests are idempotent and a request
    that arrives after a message has completed has no effect on its
    stored result.

    Parameters:
      backend(CancellationBackend): The backend used to store
        cancellation requests.  Defaults to a local, in-process
        backend.  Provide a shared backend to cancel messages from
        a different process than the worker.
    """

    _TOKEN: contextvars.ContextVar[Optional[CancellationToken]] = contextvars.ContextVar(
        "_dramatiq_cancel_token", default=None
    )

    def __init__(self, backend: Optional[CancellationBackend] = None) -> None:
        self.backend = backend or LocalCancellationBackend()

    def cancel(self, message_id: str) -> None:
        """Request cancellation of a message.  Idempotent: cancelling
        the same message multiple times has the same effect as
        cancelling it once.

        Parameters:
          message_id(str): The id of the message to cancel.
        """
        self.backend.cancel(message_id)

    def is_cancelled(self, message_id: str) -> bool:
        """Check whether cancellation has been requested for a
        message.
        """
        return self.backend.is_cancelled(message_id)

    @classmethod
    def get_current_token(cls) -> Optional[CancellationToken]:
        """Get the cancellation token for the message that is
        currently being processed on this thread.  Returns None when
        called outside of actor code.
        """
        return cls._TOKEN.get()

    def before_process_message(self, broker: Broker, message: MessageProxy) -> None:
        token = CancellationToken(self.backend, message.message_id)
        self._TOKEN.set(token)
        if token.is_cancelled():
            # The message has not started executing yet: skip it
            # outright.  It will be acked, not retried.
            message.cancelled = True
            raise SkipMessage()

    def after_process_message(
        self,
        broker: Broker,
        message: MessageProxy,
        *,
        result=None,
        exception: Optional[BaseException] = None,
    ) -> None:
        self._TOKEN.set(None)
        if isinstance(exception, MessageCancelled):
            message.cancelled = True

    def after_skip_message(self, broker: Broker, message: MessageProxy) -> None:
        self._TOKEN.set(None)

    def after_ack(self, broker: Broker, message: MessageProxy) -> None:
        # The message reached a terminal state; its cancellation
        # state is no longer needed.
        self.backend.clear(message.message_id)

    def after_nack(self, broker: Broker, message: MessageProxy) -> None:
        self.backend.clear(message.message_id)

