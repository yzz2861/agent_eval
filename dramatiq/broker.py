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

import warnings
from typing import TYPE_CHECKING, Any, Iterable, Optional, cast

from .errors import ActorNotFound
from .logging import get_logger
from .middleware import Middleware, MiddlewareError, default_middleware
from .results import ResultBackend, Results

if TYPE_CHECKING:
    from typing_extensions import Self

    from .actor import Actor
    from .message import Message

#: The global broker instance.
global_broker: Optional[Broker] = None

#: The valid values for the broker's message version policies.
#:
#: * ``"default"``: dispatch the message to the default version of
#:   the actor and log a warning.
#: * ``"error"``: raise :class:`ActorNotFound`, causing the message
#:   to be rejected (moved to the dead-letter queue).
MESSAGE_VERSION_POLICIES = frozenset({"default", "error"})


def get_broker() -> Broker:
    """Get the global broker instance.

    If no global broker is set, a RabbitMQ broker will be returned.
    If the RabbitMQ dependencies are not installed, a Redis broker
    will be returned.

    Returns:
      Broker: The default Broker.
    """
    global global_broker
    if global_broker is None:
        # RabbitMQ will be tried first, but its dependencies might not
        # be installed if the user only installed the [redis] extras.
        try:
            from .brokers.rabbitmq import RabbitmqBroker

            set_broker(
                RabbitmqBroker(
                    host="127.0.0.1",
                    port=5672,
                    heartbeat=5,
                    connection_attempts=5,
                    blocked_connection_timeout=30,
                )
            )
        except ImportError:
            # Fall back to the Redis broker.
            from .brokers.redis import RedisBroker

            set_broker(RedisBroker())
    global_broker = cast(Broker, global_broker)
    return global_broker


def set_broker(broker: Broker) -> None:
    """Configure the global broker instance.

    Parameters:
      broker(Broker): The broker instance to use by default.
    """
    global global_broker
    global_broker = broker


class Broker:
    """Base class for broker implementations.

    Parameters:
      middleware(list[Middleware]): The set of middleware that apply
        to this broker.  If you supply this parameter, you are
        expected to declare *all* middleware.  Most of the time,
        you'll want to use :meth:`.add_middleware` instead.
        See :ref:`customizing-middleware` for details.
      unversioned_message_policy(str): How to dispatch messages that
        don't declare an actor version (e.g. messages enqueued by an
        older version of dramatiq) when no unversioned actor is
        registered under that name.  One of ``"default"`` (run the
        default version of the actor and log a warning) or
        ``"error"`` (reject the message).  Defaults to ``"default"``.
      unknown_version_policy(str): How to dispatch messages that
        declare an actor version that isn't registered on this
        broker.  Same values as ``unversioned_message_policy``.
        Defaults to ``"error"``.

    Attributes:
      actor_options(set[str]): The names of all the options actors may
        overwrite when they are declared.
      actors(dict[str, Actor]): Maps actor names to their *default*
        version.  The default version is the one new messages are
        dispatched to when they don't carry an explicit version.
      actor_versions(dict[str, dict[str, Actor]]): Maps actor names
        to all of their registered versions.
    """

    def __init__(
        self,
        middleware: Optional[list[Middleware]] = None,
        *,
        unversioned_message_policy: str = "default",
        unknown_version_policy: str = "error",
    ) -> None:
        self.logger = get_logger(__name__, type(self))
        self.actors: dict[str, Actor] = {}
        self.actor_versions: dict[str, dict[Any, Actor]] = {}
        self.queues: Any = {}  # Subclasses make this a set!
        self.delay_queues: set[str] = set()

        self.actor_options: set[str] = set()
        self.middleware: list[Middleware] = []
        self.unversioned_message_policy = unversioned_message_policy
        self.unknown_version_policy = unknown_version_policy

        if middleware is None:
            middleware = [m() for m in default_middleware]

        for m in middleware:
            self.add_middleware(m)

    @property
    def unversioned_message_policy(self) -> str:
        return self._unversioned_message_policy

    @unversioned_message_policy.setter
    def unversioned_message_policy(self, policy: str) -> None:
        if policy not in MESSAGE_VERSION_POLICIES:
            raise ValueError(
                f"Invalid unversioned_message_policy {policy!r}. "
                f"Expected one of: {', '.join(sorted(MESSAGE_VERSION_POLICIES))}."
            )
        self._unversioned_message_policy = policy

    @property
    def unknown_version_policy(self) -> str:
        return self._unknown_version_policy

    @unknown_version_policy.setter
    def unknown_version_policy(self, policy: str) -> None:
        if policy not in MESSAGE_VERSION_POLICIES:
            raise ValueError(
                f"Invalid unknown_version_policy {policy!r}. "
                f"Expected one of: {', '.join(sorted(MESSAGE_VERSION_POLICIES))}."
            )
        self._unknown_version_policy = policy

    def emit_before(self, signal: str, *args: Any, **kwargs: Any) -> None:
        signal = "before_" + signal
        for middleware in self.middleware:
            try:
                getattr(middleware, signal)(self, *args, **kwargs)
            except MiddlewareError:
                raise
            except Exception:
                self.logger.critical("Unexpected failure in %s of %r.", signal, middleware, exc_info=True)

    def emit_after(self, signal: str, *args: Any, **kwargs: Any) -> None:
        signal = "after_" + signal
        for middleware in reversed(self.middleware):
            try:
                getattr(middleware, signal)(self, *args, **kwargs)
            except Exception:
                self.logger.critical("Unexpected failure in %s of %r.", signal, middleware, exc_info=True)

    def add_middleware(
        self,
        middleware: Middleware,
        *,
        before: Optional[type[Middleware]] = None,
        after: Optional[type[Middleware]] = None,
    ) -> None:
        """Add a middleware object to this broker.  The middleware is
        appended to the end of the middleware list by default.

        You can specify another middleware (by class) as a reference
        point for where the new middleware should be added.

        Duplicates of middleware are allowed.
        If there's already a middleware object of the same class
        added to the broker, the middleware will be added
        for the second time.

        Parameters:
          middleware(Middleware): The middleware.
          before(type): Add this middleware before a specific one.
          after(type): Add this middleware after a specific one.

        Raises:
          ValueError: When either ``before`` or ``after`` refer to a
            middleware that hasn't been registered yet.
        """
        assert not (before and after), "provide either 'before' or 'after', but not both"

        for existing_middleware in self.middleware:
            if isinstance(existing_middleware, type(middleware)):
                self.logger.warning(
                    "You're adding a middleware of the same type twice: %r. It may have unexpected results.",
                    middleware,
                )

        if before or after:
            for i, m in enumerate(self.middleware):  # noqa: B007
                if before and isinstance(m, before):
                    break
                if after and isinstance(m, after):
                    break
            else:
                raise ValueError("Middleware %r not found" % (before or after))

            if before:
                self.middleware.insert(i, middleware)
            else:
                self.middleware.insert(i + 1, middleware)
        else:
            self.middleware.append(middleware)

        self.actor_options |= middleware.actor_options

        for actor in self.actors.values():
            middleware.after_declare_actor(self, actor)

        for queue_name in self.get_declared_queues():
            middleware.after_declare_queue(self, queue_name)

        for queue_name in self.get_declared_delay_queues():
            middleware.after_declare_delay_queue(self, queue_name)

    def close(self) -> None:
        """Close this broker and perform any necessary cleanup actions."""

    def consume(self, queue_name: str, prefetch: int = 1, timeout: int = 30000) -> Consumer:  # pragma: no cover
        """Get an iterator that consumes messages off of the queue.

        Raises:
          QueueNotFound: If the given queue was never declared.

        Parameters:
          queue_name(str): The name of the queue to consume messages off of.
          prefetch(int): The number of messages to prefetch per consumer.
          timeout(int): The amount of time in milliseconds to idle for.

        Returns:
          Consumer: A message iterator.
        """
        raise NotImplementedError

    def declare_actor(self, actor: Actor) -> None:  # pragma: no cover
        """Declare a new actor on this broker.  Multiple actors
        may share a name as long as each one declares a distinct
        ``actor_version``; declaring the same
        name and version twice raises a ``ValueError``.  The first
        version declared under a name becomes its default version.

        Parameters:
          actor(Actor): The actor being declared.
        """
        self.emit_before("declare_actor", actor)
        self.declare_queue(actor.queue_name)
        versions = self.actor_versions.setdefault(actor.actor_name, {})
        if actor.actor_version in versions:
            raise ValueError(
                f"An actor named {actor.actor_name!r} with version {actor.actor_version!r} is already registered."
            )
        versions[actor.actor_version] = actor
        # The first version declared under a name becomes its default
        # version until it is explicitly changed via set_default_actor.
        self.actors.setdefault(actor.actor_name, actor)
        self.emit_after("declare_actor", actor)

    def declare_queue(self, queue_name: str) -> None:  # pragma: no cover
        """Declare a queue on this broker.  This method must be
        idempotent.

        Parameters:
          queue_name(str): The name of the queue being declared.
        """
        raise NotImplementedError

    def enqueue(self, message: Message, *, delay: Optional[int] = None) -> Message:  # pragma: no cover
        """Enqueue a message on this broker.

        Parameters:
          message(Message): The message to enqueue.
          delay(int): The number of milliseconds to delay the message for.

        Returns:
          Message: Either the original message or a copy of it.
        """
        raise NotImplementedError

    def get_actor(self, actor_name: str, actor_version: Any = None) -> Actor:  # pragma: no cover
        """Look up an actor by its name.

        Parameters:
          actor_name(str): The name to look up.
          actor_version: The version to look up.  If not given, the
            default version of the actor is returned.

        Raises:
          ActorNotFound: If the actor was never declared.

        Returns:
          Actor: The actor.
        """
        try:
            if actor_version is None:
                return self.actors[actor_name]
            return self.actor_versions[actor_name][actor_version]
        except KeyError:
            raise ActorNotFound(actor_name) from None

    def set_default_actor(self, actor_name: str, actor_version: Any = None) -> None:
        """Change the default version of an actor.  The default
        version is the one that new messages are dispatched to when
        they don't carry an explicit actor version.  Messages that
        have already been enqueued (including their retries) keep
        executing the version they were sent with.

        Parameters:
          actor_name(str): The name of the actor.
          actor_version: The version to make the default.

        Raises:
          ActorNotFound: If no actor with that name and version was
            declared.
        """
        try:
            self.actors[actor_name] = self.actor_versions[actor_name][actor_version]
        except KeyError:
            raise ActorNotFound(f"{actor_name} (version {actor_version!r})") from None

    def get_actor_for_message(self, message: Message) -> Actor:
        """Look up the actor a message should be dispatched to.

        Messages that carry an explicit actor version are dispatched
        to that exact version.  Messages without a version (e.g. sent
        by an older version of dramatiq) and messages whose version is
        no longer registered are handled according to the broker's
        ``unversioned_message_policy`` and ``unknown_version_policy``
        respectively.

        Parameters:
          message(Message): The message to look up the actor for.

        Raises:
          ActorNotFound: If the actor was never declared, or the
            applicable policy is ``"error"`` and the message's
            version couldn't be resolved.

        Returns:
          Actor: The actor the message should be dispatched to.
        """
        actor_name = message.actor_name
        actor_version = message.actor_version
        versions = self.actor_versions.get(actor_name)
        if versions is None:
            raise ActorNotFound(actor_name)

        if actor_version is None:
            if None in versions:
                # The actor itself is unversioned, so the message
                # can be matched exactly; no policy applies.
                return versions[None]
            if self.unversioned_message_policy == "error":
                raise ActorNotFound(f"{actor_name} (unversioned message)")
            self.logger.warning(
                "Message %r doesn't declare an actor version; dispatching it to the default version of actor %r.",
                message.message_id,
                actor_name,
            )
            return self.actors[actor_name]

        try:
            return versions[actor_version]
        except KeyError:
            if self.unknown_version_policy == "error":
                raise ActorNotFound(f"{actor_name} (version {actor_version!r})") from None
            self.logger.warning(
                "Message %r declares unknown version %r of actor %r; dispatching it to the default version.",
                message.message_id,
                actor_version,
                actor_name,
            )
            return self.actors[actor_name]

    def get_declared_actors(self) -> set[str]:  # pragma: no cover
        """Get all declared actors.

        Returns:
          set[str]: The names of all the actors declared so far on
          this Broker.
        """
        return set(self.actors.keys())

    def get_declared_queues(self) -> set[str]:  # pragma: no cover
        """Get all declared queues.

        Returns:
          set[str]: The names of all the queues declared so far on
          this Broker.
        """
        return set(self.queues.keys())

    def get_declared_delay_queues(self) -> set[str]:  # pragma: no cover
        """Get all declared delay queues.

        Returns:
          set[str]: The names of all the delay queues declared so far
          on this Broker.
        """
        return self.delay_queues.copy()

    def get_results_backend(self) -> ResultBackend:
        """Get the backend of the Results middleware.

        Raises:
          RuntimeError: If the broker doesn't have a results backend.

        Returns:
          ResultBackend: The backend.
        """
        for middleware in self.middleware:
            if isinstance(middleware, Results):
                return middleware.backend
        else:
            raise RuntimeError("The broker doesn't have a results backend.")

    def flush(self, queue_name: str) -> None:  # pragma: no cover
        """Drop all the messages from a queue.

        Parameters:
          queue_name(str): The name of the queue to flush.
        """
        raise NotImplementedError()

    def flush_all(self) -> None:  # pragma: no cover
        """Drop all messages from all declared queues."""
        raise NotImplementedError()

    def join(self, queue_name: str, *, timeout: Optional[int] = None) -> None:  # pragma: no cover
        """Wait for all the messages on the given queue to be
        processed.  This method is only meant to be used in tests to
        wait for all the messages in a queue to be processed.

        Subclasses that implement this function may add parameters.

        Parameters:
          queue_name(str): The queue to wait on.
          timeout(Optional[int]): The max amount of time, in
            milliseconds, to wait on this queue.
        """
        raise NotImplementedError()


class Consumer:
    """Consumers iterate over messages on a queue.

    Consumers and their MessageProxies are *not* thread-safe.
    """

    def __iter__(self) -> Self:  # pragma: no cover
        """Returns this instance as a Message iterator."""
        return self

    def ack(self, message: MessageProxy) -> None:  # pragma: no cover
        """Acknowledge that a message has been processed, removing it
        from the broker.

        Parameters:
          message(MessageProxy): The message to acknowledge.
        """
        raise NotImplementedError

    def nack(self, message: MessageProxy) -> None:  # pragma: no cover
        """Move a message to the dead-letter queue.

        Parameters:
          message(MessageProxy): The message to reject.
        """
        raise NotImplementedError

    def requeue(self, messages: Iterable[MessageProxy]) -> None:  # pragma: no cover
        """Move unacked messages back to their queues.  This is called
        by consumer threads when they fail or are shut down.  The
        default implementation does nothing.

        Parameters:
          messages(Iterable[MessageProxy]): The messages to requeue.
        """

    def __next__(self) -> MessageProxy | None:  # pragma: no cover
        """Retrieve the next message off of the queue.

        This method should block for a limited amount of time
        (typically self.timeout) until a message becomes available.
        After that time is elapsed, return None if no message is available.

        Returns:
          MessageProxy: A transparent proxy around a Message that can
          be used to acknowledge or reject it once it's done being
          processed.
          None: When no message was available.
        """
        raise NotImplementedError

    def close(self) -> None:
        """Close this consumer and perform any necessary cleanup actions."""


class MessageProxy:
    """Base class for messages returned by :meth:`Broker.consume`."""

    # For the purpose of static type checking we duplicate the fields
    # and their respective types of the Message here; at runtime the
    # message's fields are accessed through the __getattr__ method.
    if TYPE_CHECKING:
        queue_name: str
        actor_name: str
        args: tuple[Any, ...]
        kwargs: dict[str, Any]
        options: dict[str, Any]
        message_id: str
        message_timestamp: int
        actor_version: Optional[str]

    def __init__(self, message: Message) -> None:
        self.failed = False
        self._message = message
        self._exception: Optional[BaseException] = None

    def stuff_exception(self, exception: BaseException) -> None:
        """Stuff an exception into this message."""
        self._exception = exception

    def clear_exception(self) -> None:
        """Remove the exception from this message."""
        self._exception = None

    def fail(self) -> None:
        """Mark this message for rejection."""
        self.failed = True

    def __getattr__(self, name: str) -> Any:
        return getattr(self._message, name)

    def __str__(self) -> str:
        return str(self._message)

    def __repr__(self) -> str:
        return f"<{self.__class__.__qualname__} {self._message!r}>"

    def __lt__(self, other) -> bool:
        warnings.warn(
            "Comparing MessageProxy instances by order (>, <, etc) is deprecated and will be removed in dramatiq v3.0.0.",
            category=DeprecationWarning,
            stacklevel=2,
        )
        return True

    def __eq__(self, other) -> bool:
        if isinstance(other, MessageProxy):
            return self._message == other._message
        return self._message == other
