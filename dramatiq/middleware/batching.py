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

from threading import Condition, Thread
from typing import TYPE_CHECKING, Optional

from ..common import current_millis
from ..errors import BatchResultError, RateLimitExceeded, Retry
from ..logging import get_logger
from .middleware import Middleware, MiddlewareError, SkipMessage

if TYPE_CHECKING:
    from ..actor import Actor
    from ..broker import Broker, MessageProxy
    from ..worker import ConsumerThread, Worker

#: The default maximum amount of time, in milliseconds, a message may
#: spend in a batch buffer before the batch is flushed.
DEFAULT_BATCH_MAX_WAIT_MS = 1000


class _BatchBuffer:
    """Accumulates messages that share an actor and a batch key."""

    __slots__ = ("actor", "messages", "deadline")

    def __init__(self, actor: Actor, deadline: int) -> None:
        self.actor = actor
        self.messages: list[MessageProxy] = []
        self.deadline = deadline


class BatchManager:
    """Buffers messages destined for batch actors and runs their batch
    functions once enough messages have accumulated or the oldest
    message in a buffer has waited long enough.

    Messages are grouped by ``(actor_name, batch_key)`` so that
    messages belonging to different actors or carrying incompatible
    batch keys are never mixed into the same batch.  Buffers are
    capped at the actor's ``max_batch_size``: as soon as a buffer
    fills up it is flushed, so a buffer never holds more messages
    than that.

    Parameters:
      broker(Broker): The broker this manager belongs to.
      consumers(dict[str, ConsumerThread]): The worker's consumers,
        used to ack or nack each message once its batch has run.
    """

    def __init__(self, broker: Broker, consumers: dict[str, ConsumerThread]) -> None:
        self.logger = get_logger(__name__, type(self))
        self.broker = broker
        self.consumers = consumers
        self.buffers: dict[tuple[str, object], _BatchBuffer] = {}
        self.in_flight = 0
        self.stopped = False
        self.condition = Condition()
        self.flusher: Optional[Thread] = None

    @property
    def idle(self) -> bool:
        """Whether all buffers are empty and no batch is running."""
        with self.condition:
            return not self.buffers and not self.in_flight

    def start(self) -> None:
        """Start the background thread that flushes expired buffers."""
        self.flusher = Thread(target=self._flush_loop, name="BatchFlusher", daemon=True)
        self.flusher.start()

    def stop(self) -> None:
        """Stop the flusher thread.  Messages that are still buffered
        afterwards can be recovered with :meth:`drain`.
        """
        with self.condition:
            self.stopped = True
            self.condition.notify_all()
        if self.flusher is not None:
            self.flusher.join()
            self.flusher = None

    def is_batch_actor(self, actor: Actor) -> bool:
        """Whether the given actor processes its messages in batches."""
        return "max_batch_size" in actor.options

    def submit(self, actor: Actor, message: MessageProxy) -> None:
        """Take ownership of a message and buffer it for batched
        processing.  If the message completes a batch, the batch is
        executed immediately on the calling thread.
        """
        batch_key = message.options.get("batch_key", actor.options.get("batch_key"))
        key = (actor.actor_name, batch_key)
        batch = None
        with self.condition:
            if self.stopped:
                batch = [message]
                self.in_flight += 1
            else:
                buffer = self.buffers.get(key)
                if buffer is None:
                    max_wait = actor.options.get("batch_max_wait_ms", DEFAULT_BATCH_MAX_WAIT_MS)
                    buffer = _BatchBuffer(actor, deadline=current_millis() + max_wait)
                    self.buffers[key] = buffer
                buffer.messages.append(message)
                if len(buffer.messages) >= actor.options["max_batch_size"]:
                    batch = buffer.messages
                    del self.buffers[key]
                    self.in_flight += 1
                self.condition.notify_all()

        if batch is not None:
            self._run_batch(actor, batch)

    def drain(self) -> list[MessageProxy]:
        """Remove and return every buffered message.  Called on worker
        shutdown so that messages that never made it into a batch can
        be requeued instead of lost.
        """
        with self.condition:
            messages = [message for buffer in self.buffers.values() for message in buffer.messages]
            self.buffers.clear()
            self.condition.notify_all()
            return messages

    def join(self) -> None:
        """Block until all buffers are empty and no batch is running."""
        with self.condition:
            while self.buffers or self.in_flight:
                self.condition.wait(timeout=0.1)

    def _flush_loop(self) -> None:
        while True:
            with self.condition:
                while not self.stopped:
                    now = current_millis()
                    if any(buffer.deadline <= now for buffer in self.buffers.values()):
                        break
                    deadlines = [buffer.deadline for buffer in self.buffers.values()]
                    timeout = None if not deadlines else max(0.0, (min(deadlines) - now) / 1000)
                    self.condition.wait(timeout=timeout)

                if self.stopped:
                    return

                now = current_millis()
                expired_keys = [key for key, buffer in self.buffers.items() if buffer.deadline <= now]
                expired = [self.buffers.pop(key) for key in expired_keys]
                self.in_flight += len(expired)

            for buffer in expired:
                self._run_batch(buffer.actor, buffer.messages)

    def _run_batch(self, actor: Actor, messages: list[MessageProxy]) -> None:
        try:
            active = []
            for message in messages:
                try:
                    self.broker.emit_before("process_message", message)
                except SkipMessage as e:
                    if message.failed:
                        message.stuff_exception(e)
                    self.logger.warning("Message %s was skipped.", message)
                    self.broker.emit_after("skip_message", message)
                    self._post_process(message)
                else:
                    active.append(message)

            if not active:
                return

            inputs = [(message.args, message.kwargs) for message in active]
            try:
                results = actor.fn(inputs)
            except BaseException as e:
                self.logger.error(
                    "Batch function of actor %r raised an exception. Failing all %d message(s) in the batch.",
                    actor.actor_name,
                    len(active),
                    exc_info=True,
                )
                results = [e] * len(active)
            else:
                if not isinstance(results, (list, tuple)) or len(results) != len(active):
                    returned = len(results) if isinstance(results, (list, tuple)) else "no"
                    error = BatchResultError(
                        "Batch actor %r must return exactly one result per input; "
                        "got %s result(s) for a batch of %d input(s)." % (actor.actor_name, returned, len(active))
                    )
                    self.logger.error("%s", error)
                    results = [error] * len(active)

            for message, result in zip(active, results):
                self._complete_message(actor, message, result)
        finally:
            with self.condition:
                self.in_flight -= 1
                self.condition.notify_all()

    def _complete_message(self, actor: Actor, message: MessageProxy, result: object) -> None:
        """Route a single batch item's outcome back to its message:
        successful items are acknowledged on their own while failed
        items (results that are exceptions) go through the standard
        failure path so that only they are retried.
        """
        try:
            if isinstance(result, BaseException):
                message.stuff_exception(result)

                throws = message.options.get("throws") or actor.options.get("throws")
                if isinstance(result, RateLimitExceeded):
                    self.logger.debug("Rate limit exceeded in message %s: %s.", message, result)
                elif throws and isinstance(result, throws):
                    self.logger.info(
                        "Failed to process message %s with expected exception %s.",
                        message,
                        type(result).__name__,
                    )
                elif not isinstance(result, Retry):
                    self.logger.error(
                        "Failed to process message %s with unhandled exception.",
                        message,
                        exc_info=result,
                    )

                try:
                    raise result
                except BaseException:
                    self.broker.emit_after("process_message", message, exception=result)
            else:
                self.broker.emit_after("process_message", message, result=result)
        finally:
            self._post_process(message)
            message.clear_exception()

    def _post_process(self, message: MessageProxy) -> None:
        self.consumers[message.queue_name].post_process_message(message)


class Batching(Middleware):
    """Middleware that enables batch actors.

    An actor declared with the ``max_batch_size`` option becomes a
    batch actor.  Instead of being called once per message, its
    function is called with a list of ``(args, kwargs)`` inputs and
    must return a list with exactly one result per input.  A result
    that is an exception instance marks only that input as failed, so
    it is retried on its own while the successful inputs are
    acknowledged independently.  Raising an exception from the
    function fails the whole batch, and returning the wrong number of
    results fails the whole batch with :class:`BatchResultError
    <dramatiq.BatchResultError>`.

    Batches are flushed when they reach ``max_batch_size`` messages
    or when the oldest message in the batch has waited
    ``batch_max_wait_ms`` milliseconds, whichever comes first.
    Messages are only ever grouped with messages of the same actor
    that carry the same ``batch_key`` (an actor- or message-level
    option); different actors or incompatible keys are never mixed.
    When the worker shuts down, messages that never completed a batch
    are requeued so they are not lost.

    Example::

        >>> @dramatiq.actor(max_batch_size=100, batch_max_wait_ms=1000)
        ... def record_events(batch):
        ...     response = events_api.bulk_insert([args[0] for args, _ in batch])
        ...     return [None if item.ok else RuntimeError(item.error) for item in response]
    """

    def __init__(self) -> None:
        self.manager: Optional[BatchManager] = None

    @property
    def actor_options(self) -> set[str]:
        return {
            "max_batch_size",
            "batch_max_wait_ms",
            "batch_key",
        }

    def before_declare_actor(self, broker: Broker, actor: Actor) -> None:
        if "max_batch_size" not in actor.options:
            return

        max_batch_size = actor.options["max_batch_size"]
        if not isinstance(max_batch_size, int) or max_batch_size < 1:
            raise MiddlewareError("max_batch_size must be a positive integer.")

        max_wait = actor.options.get("batch_max_wait_ms", DEFAULT_BATCH_MAX_WAIT_MS)
        if not isinstance(max_wait, (int, float)) or max_wait < 0:
            raise MiddlewareError("batch_max_wait_ms must be a non-negative number.")

    def before_worker_boot(self, broker: Broker, worker: Worker) -> None:
        self.manager = BatchManager(broker, worker.consumers)

    def after_worker_boot(self, broker: Broker, worker: Worker) -> None:
        if self.manager is not None:
            self.manager.start()

    def before_worker_shutdown(self, broker: Broker, worker: Worker) -> None:
        if self.manager is not None:
            self.manager.stop()
