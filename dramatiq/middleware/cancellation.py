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
from typing import TYPE_CHECKING, Optional, Union

from ..cancellation import CancellationBackend, CancellationToken, LocalCancellationBackend
from ..errors import MessageCanceled
from ..logging import get_logger
from .middleware import Middleware, SkipMessage

if TYPE_CHECKING:
    from ..broker import Broker, MessageProxy
    from ..message import Message


class Cancellation(Middleware):
    """Middleware that adds cooperative message cancellation.

    Example:
      >>> import dramatiq
      >>> from dramatiq.middleware import Cancellation

      >>> broker = dramatiq.get_broker()
      >>> cancellation = Cancellation()
      >>> broker.add_middleware(cancellation)

      >>> @dramatiq.actor
      ... def long_running():
      ...     token = Cancellation.get_current_token()
      ...     for chunk in work:
      ...         token.check()  # cancellation checkpoint
      ...         process(chunk)

      >>> message = long_running.send()
      >>> broker.cancel(message)

    Cancellation semantics:

    * Messages that have not started processing yet are skipped.
    * Messages that are being processed run until the actor raises
      :class:`MessageCanceled<dramatiq.errors.MessageCanceled>` (e.g.
      via :meth:`CancellationToken.check<dramatiq.cancellation.CancellationToken.check>`)
      or returns.  Canceled messages are acknowledged and are never
      retried.
    * Cancellation is terminal and idempotent: canceling a message
      multiple times has the same effect as canceling it once, and a
      cancellation request that arrives after the message completed
      is rejected, leaving the stored result untouched.
    * Canceling a member of a |pipeline| prevents its successors
      from being enqueued.  Canceled members of a |group| count
      towards the group's completion.

    Note:
      If you use the :class:`Results<dramatiq.results.Results>`
      middleware, add it *before* this middleware so that results of
      messages whose cancellation won the race against a late
      completion are not stored.

    Parameters:
      backend(CancellationBackend): The backend to use to track
        cancellation state.  Defaults to a
        :class:`LocalCancellationBackend<dramatiq.cancellation.LocalCancellationBackend>`.
    """

    _CURRENT_TOKEN: contextvars.ContextVar[Optional[CancellationToken]] = contextvars.ContextVar(
        "_CURRENT_TOKEN", default=None
    )

    def __init__(self, *, backend: Optional[CancellationBackend] = None) -> None:
        self.logger = get_logger(__name__, type(self))
        self.backend = backend or LocalCancellationBackend()

    @classmethod
    def get_current_token(cls) -> Optional[CancellationToken]:
        """Get the cancellation token of the message that is currently
        being processed.  Tokens are thread local so this returns
        ``None`` when called outside of actor code.
        """
        return cls._CURRENT_TOKEN.get()

    def cancel(self, message: Union[Message, MessageProxy, str]) -> bool:
        """Request the cancellation of a message.

        Parameters:
          message(Message|MessageProxy|str): The message (or message
            id) to cancel.

        Returns:
          bool: True if the cancellation was recorded, False if the
          message has already completed.
        """
        message_id = message if isinstance(message, str) else message.message_id
        accepted = self.backend.cancel(message_id)
        if accepted:
            self.logger.info("Cancellation requested for message %r.", message_id)
        else:
            self.logger.info("Message %r already completed; cancellation rejected.", message_id)
        return accepted

    def is_canceled(self, message: Union[Message, MessageProxy, str]) -> bool:
        """Check whether a message has been canceled.

        Parameters:
          message(Message|MessageProxy|str): The message (or message
            id) to check.

        Returns:
          bool: True if the message's terminal state is "canceled".
        """
        message_id = message if isinstance(message, str) else message.message_id
        return self.backend.is_canceled(message_id)

    def before_process_message(self, broker: Broker, message: MessageProxy) -> None:
        if self.backend.is_canceled(message.message_id):
            self.logger.info("Skipping canceled message %r.", message.message_id)
            message.options["canceled"] = True
            raise SkipMessage()

        self._CURRENT_TOKEN.set(CancellationToken(self.backend, message.message_id))

    def after_process_message(
        self,
        broker: Broker,
        message: MessageProxy,
        *,
        result=None,
        exception: Optional[BaseException] = None,
    ) -> None:
        self._CURRENT_TOKEN.set(None)

        if isinstance(exception, MessageCanceled):
            # The actor exited at a cancellation checkpoint.  Record
            # the terminal state in case the actor raised the error
            # without a matching cancellation request.
            self.backend.cancel(message.message_id)
            message.options["canceled"] = True
        elif exception is None and not message.failed:
            if not self.backend.complete(message.message_id):
                # Cancellation won the race against this late
                # completion; its result must be discarded.
                self.logger.info(
                    "Discarding late completion of canceled message %r.",
                    message.message_id,
                )
                message.options["canceled"] = True

    def after_skip_message(self, broker: Broker, message: MessageProxy) -> None:
        self._CURRENT_TOKEN.set(None)
