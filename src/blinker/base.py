from __future__ import annotations

import collections.abc as c
import sys
import threading
import typing as t
import weakref
from collections import defaultdict
from contextlib import contextmanager
from functools import cached_property
from inspect import iscoroutinefunction

from ._utilities import make_id
from ._utilities import make_ref
from ._utilities import Symbol

F = t.TypeVar("F", bound=c.Callable[..., t.Any])

ANY = Symbol("ANY")
"""Symbol for "any sender"."""

ANY_ID = 0

_Holder = t.Union[weakref.ref[c.Callable[..., t.Any]], c.Callable[..., t.Any]]
_OnceKey = tuple[c.Hashable, c.Hashable]
_DispatchEntry = tuple[bool, c.Hashable, t.Any]


class Signal:
    """A notification emitter.

    :param doc: The docstring for the signal.
    """

    ANY = ANY
    """An alias for the :data:`~blinker.ANY` sender symbol."""

    set_class: type[set[t.Any]] = set
    """The set class to use for tracking connected receivers and senders.
    Python's ``set`` is unordered. If receivers must be dispatched in the order
    they were connected, an ordered set implementation can be used.

    .. versionadded:: 1.7
    """

    @cached_property
    def receiver_connected(self) -> Signal:
        """Emitted at the end of each :meth:`connect` call.

        The signal sender is the signal instance, and the :meth:`connect`
        arguments are passed through: ``receiver``, ``sender``, ``weak``, and
        ``once``.

        .. versionadded:: 1.2
        """
        return Signal(doc="Emitted after a receiver connects.")

    @cached_property
    def receiver_disconnected(self) -> Signal:
        """Emitted at the end of each :meth:`disconnect` call.

        The sender is the signal instance, and the :meth:`disconnect` arguments
        are passed through: ``receiver`` and ``sender``.

        This signal is emitted **only** when :meth:`disconnect` is called
        explicitly. This signal cannot be emitted by an automatic disconnect
        when a weakly referenced receiver or sender goes out of scope, as the
        instance is no longer be available to be used as the sender for this
        signal.

        An alternative approach is available by subscribing to
        :attr:`receiver_connected` and setting up a custom weakref cleanup
        callback on weak receivers and senders.

        .. versionadded:: 1.2
        """
        return Signal(doc="Emitted after a receiver disconnects.")

    def __init__(self, doc: str | None = None) -> None:
        if doc:
            self.__doc__ = doc

        self.receivers: dict[
            t.Any, weakref.ref[c.Callable[..., t.Any]] | c.Callable[..., t.Any]
        ] = {}
        """The map of connected receivers. Useful to quickly check if any
        receivers are connected to the signal: ``if s.receivers:``. The
        structure and data is not part of the public API, but checking its
        boolean value is.
        """

        self.is_muted: bool = False
        self._lock = threading.RLock()
        self._by_receiver: dict[t.Any, set[t.Any]] = defaultdict(self.set_class)
        self._by_sender: dict[t.Any, set[t.Any]] = defaultdict(self.set_class)
        self._weak_senders: dict[t.Any, weakref.ref[t.Any]] = {}
        self._once_receivers: dict[_OnceKey, _Holder] = {}
        self._once_by_receiver: dict[t.Any, set[_OnceKey]] = defaultdict(self.set_class)
        self._once_by_sender: dict[t.Any, set[_OnceKey]] = defaultdict(self.set_class)

    def connect(
        self,
        receiver: F,
        sender: t.Any = ANY,
        weak: bool = True,
        once: bool = False,
    ) -> F:
        """Connect ``receiver`` to be called when the signal is sent by
        ``sender``.

        :param receiver: The callable to call when :meth:`send` is called with
            the given ``sender``, passing ``sender`` as a positional argument
            along with any extra keyword arguments.
        :param sender: Any object or :data:`ANY`. ``receiver`` will only be
            called when :meth:`send` is called with this sender. If ``ANY``, the
            receiver will be called for any sender. A receiver may be connected
            to multiple senders by calling :meth:`connect` multiple times.
        :param weak: Track the receiver with a :mod:`weakref`. The receiver will
            be automatically disconnected when it is garbage collected. When
            connecting a receiver defined within a function, set to ``False``,
            otherwise it will be disconnected when the function scope ends.
        :param once: Call the receiver only for the next matching send. The
            subscription is removed before the receiver is called, so it is not
            called again due to reentrant or concurrent sends.
        """
        receiver_id = make_id(receiver)
        sender_id = ANY_ID if sender is ANY else make_id(sender)

        with self._lock:
            if once:
                self._connect_once_locked(receiver, receiver_id, sender_id, weak=weak)
            else:
                self._connect_receiver_locked(
                    receiver, receiver_id, sender_id, weak=weak
                )

            self._store_weak_sender_locked(sender, sender_id)

        if "receiver_connected" in self.__dict__ and self.receiver_connected.receivers:
            try:
                self.receiver_connected.send(
                    self,
                    receiver=receiver,
                    sender=sender,
                    weak=weak,
                    once=once,
                )
            except TypeError:
                # TODO no explanation or test for this
                if once:
                    with self._lock:
                        self._remove_once_key_locked(receiver_id, sender_id)
                else:
                    self.disconnect(receiver, sender)

                raise

        return receiver

    def connect_once(self, receiver: F, sender: t.Any = ANY, weak: bool = True) -> F:
        """Connect ``receiver`` to be called only for the next matching send.

        The one-shot subscription is claimed atomically immediately before the
        receiver is called. Reentrant or concurrent sends do not call it again,
        and an exception raised by the receiver still consumes the subscription.
        """
        return self.connect(receiver, sender=sender, weak=weak, once=True)

    def _connect_receiver_locked(
        self,
        receiver: c.Callable[..., t.Any],
        receiver_id: c.Hashable,
        sender_id: c.Hashable,
        weak: bool,
    ) -> None:
        if weak:
            self.receivers[receiver_id] = make_ref(
                receiver, self._make_cleanup_receiver(receiver_id)
            )
        else:
            self.receivers[receiver_id] = receiver

        self._by_sender[sender_id].add(receiver_id)
        self._by_receiver[receiver_id].add(sender_id)

    def _connect_once_locked(
        self,
        receiver: c.Callable[..., t.Any],
        receiver_id: c.Hashable,
        sender_id: c.Hashable,
        weak: bool,
    ) -> None:
        key = (receiver_id, sender_id)

        if key in self._once_receivers:
            return

        if weak:
            holder: _Holder = make_ref(
                receiver,
                self._make_cleanup_once_receiver(receiver_id, sender_id),
            )
        else:
            holder = receiver

        self._once_receivers[key] = holder
        self._once_by_sender[sender_id].add(key)
        self._once_by_receiver[receiver_id].add(key)

        if receiver_id not in self.receivers:
            self.receivers[receiver_id] = holder

    def _store_weak_sender_locked(self, sender: t.Any, sender_id: c.Hashable) -> None:
        if sender is not ANY and sender_id not in self._weak_senders:
            # store a cleanup for weakref-able senders
            try:
                self._weak_senders[sender_id] = make_ref(
                    sender, self._make_cleanup_sender(sender_id)
                )
            except TypeError:
                pass

    def connect_via(
        self, sender: t.Any, weak: bool = False, once: bool = False
    ) -> c.Callable[[F], F]:
        """Connect the decorated function to be called when the signal is sent
        by ``sender``.

        The decorated function will be called when :meth:`send` is called with
        the given ``sender``, passing ``sender`` as a positional argument along
        with any extra keyword arguments.

        :param sender: Any object or :data:`ANY`. ``receiver`` will only be
            called when :meth:`send` is called with this sender. If ``ANY``, the
            receiver will be called for any sender. A receiver may be connected
            to multiple senders by calling :meth:`connect` multiple times.
        :param weak: Track the receiver with a :mod:`weakref`. The receiver will
            be automatically disconnected when it is garbage collected. When
            connecting a receiver defined within a function, set to ``False``,
            otherwise it will be disconnected when the function scope ends.=
        :param once: Call the receiver only for the next matching send.

        .. versionadded:: 1.1
        """

        def decorator(fn: F) -> F:
            self.connect(fn, sender, weak=weak, once=once)
            return fn

        return decorator

    @contextmanager
    def connected_to(
        self, receiver: c.Callable[..., t.Any], sender: t.Any = ANY
    ) -> c.Generator[None, None, None]:
        """A context manager that temporarily connects ``receiver`` to the
        signal while a ``with`` block executes. When the block exits, the
        receiver is disconnected. Useful for tests.

        :param receiver: The callable to call when :meth:`send` is called with
            the given ``sender``, passing ``sender`` as a positional argument
            along with any extra keyword arguments.
        :param sender: Any object or :data:`ANY`. ``receiver`` will only be
            called when :meth:`send` is called with this sender. If ``ANY``, the
            receiver will be called for any sender.

        .. versionadded:: 1.1
        """
        self.connect(receiver, sender=sender, weak=False)

        try:
            yield None
        finally:
            self.disconnect(receiver)

    @contextmanager
    def muted(self) -> c.Generator[None, None, None]:
        """A context manager that temporarily disables the signal. No receivers
        will be called if the signal is sent, until the ``with`` block exits.
        Useful for tests.
        """
        self.is_muted = True

        try:
            yield None
        finally:
            self.is_muted = False

    def send(
        self,
        sender: t.Any | None = None,
        /,
        *,
        _async_wrapper: c.Callable[
            [c.Callable[..., c.Coroutine[t.Any, t.Any, t.Any]]], c.Callable[..., t.Any]
        ]
        | None = None,
        **kwargs: t.Any,
    ) -> list[tuple[c.Callable[..., t.Any], t.Any]]:
        """Call all receivers that are connected to the given ``sender``
        or :data:`ANY`. Each receiver is called with ``sender`` as a positional
        argument along with any extra keyword arguments. Return a list of
        ``(receiver, return value)`` tuples.

        The order receivers are called is undefined, but can be influenced by
        setting :attr:`set_class`.

        If a receiver raises an exception, that exception will propagate up.
        This makes debugging straightforward, with an assumption that correctly
        implemented receivers will not raise.

        :param sender: Call receivers connected to this sender, in addition to
            those connected to :data:`ANY`.
        :param _async_wrapper: Will be called on any receivers that are async
            coroutines to turn them into sync callables. For example, could run
            the receiver with an event loop.
        :param kwargs: Extra keyword arguments to pass to each receiver.

        .. versionchanged:: 1.7
            Added the ``_async_wrapper`` argument.
        """
        if self.is_muted:
            return []

        results = []
        sender_id = make_id(sender)

        with self._lock:
            dispatch = self._dispatch_for_locked(sender_id=sender_id)

        for is_once, receiver_id, receiver_or_keys in dispatch:
            if is_once:
                keys, receiver = receiver_or_keys

                if iscoroutinefunction(receiver) and _async_wrapper is None:
                    raise RuntimeError("Cannot send to a coroutine function.")

                with self._lock:
                    receiver = self._claim_once_locked(receiver_id, keys)

                if receiver is None:
                    continue
            else:
                receiver = receiver_or_keys

            if iscoroutinefunction(receiver) and _async_wrapper is None:
                raise RuntimeError("Cannot send to a coroutine function.")

            if iscoroutinefunction(receiver):
                result = _async_wrapper(receiver)(sender, **kwargs)
            else:
                result = receiver(sender, **kwargs)

            results.append((receiver, result))

        return results

    async def send_async(
        self,
        sender: t.Any | None = None,
        /,
        *,
        _sync_wrapper: c.Callable[
            [c.Callable[..., t.Any]], c.Callable[..., c.Coroutine[t.Any, t.Any, t.Any]]
        ]
        | None = None,
        **kwargs: t.Any,
    ) -> list[tuple[c.Callable[..., t.Any], t.Any]]:
        """Await all receivers that are connected to the given ``sender``
        or :data:`ANY`. Each receiver is called with ``sender`` as a positional
        argument along with any extra keyword arguments. Return a list of
        ``(receiver, return value)`` tuples.

        The order receivers are called is undefined, but can be influenced by
        setting :attr:`set_class`.

        If a receiver raises an exception, that exception will propagate up.
        This makes debugging straightforward, with an assumption that correctly
        implemented receivers will not raise.

        :param sender: Call receivers connected to this sender, in addition to
            those connected to :data:`ANY`.
        :param _sync_wrapper: Will be called on any receivers that are sync
            callables to turn them into async coroutines. For example,
            could call the receiver in a thread.
        :param kwargs: Extra keyword arguments to pass to each receiver.

        .. versionadded:: 1.7
        """
        if self.is_muted:
            return []

        results = []
        sender_id = make_id(sender)

        with self._lock:
            dispatch = self._dispatch_for_locked(sender_id=sender_id)

        for is_once, receiver_id, receiver_or_keys in dispatch:
            if is_once:
                keys, receiver = receiver_or_keys

                if not iscoroutinefunction(receiver) and _sync_wrapper is None:
                    raise RuntimeError("Cannot send to a non-coroutine function.")

                with self._lock:
                    receiver = self._claim_once_locked(receiver_id, keys)

                if receiver is None:
                    continue
            else:
                receiver = receiver_or_keys

            if not iscoroutinefunction(receiver) and _sync_wrapper is None:
                raise RuntimeError("Cannot send to a non-coroutine function.")

            if not iscoroutinefunction(receiver):
                result = await _sync_wrapper(receiver)(sender, **kwargs)
            else:
                result = await receiver(sender, **kwargs)

            results.append((receiver, result))

        return results

    def has_receivers_for(self, sender: t.Any) -> bool:
        """Check if there is at least one receiver that will be called with the
        given ``sender``. A receiver connected to :data:`ANY` will always be
        called, regardless of sender. Does not check if weakly referenced
        receivers are still live. See :meth:`receivers_for` for a stronger
        search.

        :param sender: Check for receivers connected to this sender, in addition
            to those connected to :data:`ANY`.
        """
        sender_id = make_id(sender)

        with self._lock:
            if not self.receivers:
                return False

            if self._by_sender[ANY_ID] or self._once_by_sender.get(ANY_ID):
                return True

            if sender is ANY:
                return False

            return sender_id in self._by_sender or sender_id in self._once_by_sender

    def receivers_for(
        self, sender: t.Any
    ) -> c.Generator[c.Callable[..., t.Any], None, None]:
        """Yield each receiver to be called for ``sender``, in addition to those
        to be called for :data:`ANY`. Weakly referenced receivers that are not
        live will be disconnected and skipped.

        :param sender: Yield receivers connected to this sender, in addition
            to those connected to :data:`ANY`.
        """
        sender_id = make_id(sender)
        with self._lock:
            dispatch = self._dispatch_for_locked(sender_id=sender_id)

        for is_once, _, receiver_or_keys in dispatch:
            if is_once:
                yield receiver_or_keys[1]
            else:
                yield receiver_or_keys

    def _dispatch_for_locked(
        self, sender: t.Any | None = None, sender_id: c.Hashable | None = None
    ) -> list[_DispatchEntry]:
        if not self.receivers:
            return []

        if sender_id is None:
            sender_id = make_id(sender)

        regular_ids = self._by_sender[ANY_ID].copy()
        regular_ids.update(self._by_sender.get(sender_id, ()))
        dispatch: list[_DispatchEntry] = []

        for receiver_id in regular_ids:
            receiver = self._resolve_holder(self.receivers.get(receiver_id))

            if receiver is None:
                self._disconnect_locked(receiver_id, ANY_ID, once=False)
                continue

            dispatch.append((False, receiver_id, receiver))

        once_keys = self.set_class(self._once_by_sender.get(ANY_ID, ()))
        once_keys.update(self._once_by_sender.get(sender_id, ()))
        once_by_receiver: dict[c.Hashable, set[_OnceKey]] = defaultdict(self.set_class)
        once_receivers: dict[c.Hashable, c.Callable[..., t.Any]] = {}

        for key in once_keys:
            receiver_id, key_sender_id = key
            holder = self._once_receivers.get(key)

            receiver = self._resolve_holder(holder)

            if receiver is None:
                self._disconnect_once_locked(receiver_id, key_sender_id)
                continue

            once_by_receiver[receiver_id].add(key)
            once_receivers.setdefault(receiver_id, receiver)

        for receiver_id, keys in once_by_receiver.items():
            dispatch.append((True, receiver_id, (keys, once_receivers[receiver_id])))

        return dispatch

    @staticmethod
    def _resolve_holder(holder: _Holder | None) -> c.Callable[..., t.Any] | None:
        if holder is None:
            return None

        if isinstance(holder, weakref.ref):
            return holder()

        return holder

    def _claim_once_locked(
        self,
        receiver_id: c.Hashable,
        candidate_keys: set[_OnceKey],
    ) -> c.Callable[..., t.Any] | None:
        holder: _Holder | None = None

        for key in candidate_keys:
            key_receiver_id, key_sender_id = key

            if key_receiver_id != receiver_id:
                continue

            current = self._once_receivers.pop(key, None)

            if current is None:
                continue

            self._once_by_sender[key_sender_id].discard(key)
            self._once_by_receiver[receiver_id].discard(key)

            if not self._once_by_sender[key_sender_id]:
                self._once_by_sender.pop(key_sender_id, None)

            if not self._once_by_receiver[receiver_id]:
                self._once_by_receiver.pop(receiver_id, None)

            if holder is None:
                holder = current

        if holder is None:
            return None

        receiver = self._resolve_holder(holder)

        if not self._by_receiver.get(receiver_id):
            self._refresh_receiver_locked(receiver_id)

        return receiver

    def _refresh_receiver_locked(self, receiver_id: c.Hashable) -> None:
        for key in self._once_by_receiver.get(receiver_id, ()):
            holder = self._once_receivers.get(key)

            if self._resolve_holder(holder) is not None:
                self.receivers[receiver_id] = holder  # type: ignore[assignment]
                return

        self.receivers.pop(receiver_id, None)

    def disconnect(self, receiver: c.Callable[..., t.Any], sender: t.Any = ANY) -> None:
        """Disconnect ``receiver`` from being called when the signal is sent by
        ``sender``.

        :param receiver: A connected receiver callable.
        :param sender: Disconnect from only this sender. By default, disconnect
            from all senders.
        """
        receiver_id = make_id(receiver)
        sender_id = ANY_ID if sender is ANY else make_id(sender)

        with self._lock:
            self._disconnect_locked(receiver_id, sender_id, once=False)
            self._disconnect_once_locked(receiver_id, sender_id)

        if (
            "receiver_disconnected" in self.__dict__
            and self.receiver_disconnected.receivers
        ):
            self.receiver_disconnected.send(self, receiver=receiver, sender=sender)

    def _disconnect_locked(
        self,
        receiver_id: c.Hashable,
        sender_id: c.Hashable,
        once: bool,
    ) -> None:
        if sender_id == ANY_ID:
            if self._by_receiver.pop(receiver_id, None) is not None:
                for bucket in self._by_sender.values():
                    bucket.discard(receiver_id)

            if not once and not self._once_by_receiver.get(receiver_id):
                self.receivers.pop(receiver_id, None)
        else:
            self._by_sender[sender_id].discard(receiver_id)
            self._by_receiver[receiver_id].discard(sender_id)

    def _disconnect_once_locked(
        self,
        receiver_id: c.Hashable,
        sender_id: c.Hashable,
    ) -> None:
        if sender_id == ANY_ID:
            keys = list(self._once_by_receiver.pop(receiver_id, ()))

            for _, key_sender_id in keys:
                key = (receiver_id, key_sender_id)
                self._once_receivers.pop(key, None)
                self._once_by_sender[key_sender_id].discard(key)

                if not self._once_by_sender[key_sender_id]:
                    self._once_by_sender.pop(key_sender_id, None)

            if not self._by_receiver.get(receiver_id):
                self._refresh_receiver_locked(receiver_id)
            return

        self._remove_once_key_locked(receiver_id, sender_id)

    def _remove_once_key_locked(
        self,
        receiver_id: c.Hashable,
        sender_id: c.Hashable,
    ) -> bool:
        key = (receiver_id, sender_id)

        if self._once_receivers.pop(key, None) is None:
            return False

        self._once_by_sender[sender_id].discard(key)
        self._once_by_receiver[receiver_id].discard(key)

        if not self._once_by_sender[sender_id]:
            self._once_by_sender.pop(sender_id, None)

        if not self._once_by_receiver[receiver_id]:
            self._once_by_receiver.pop(receiver_id, None)

        if not self._by_receiver.get(receiver_id):
            self._refresh_receiver_locked(receiver_id)

        return True

    def _make_cleanup_receiver(
        self, receiver_id: c.Hashable
    ) -> c.Callable[[weakref.ref[c.Callable[..., t.Any]]], None]:
        """Create a callback function to disconnect a weakly referenced
        receiver when it is garbage collected.
        """

        def cleanup(ref: weakref.ref[c.Callable[..., t.Any]]) -> None:
            # If the interpreter is shutting down, disconnecting can result in a
            # weird ignored exception. Don't call it in that case.
            if not sys.is_finalizing():
                with self._lock:
                    self._disconnect_locked(receiver_id, ANY_ID, once=False)
                    self._disconnect_once_locked(receiver_id, ANY_ID)

        return cleanup

    def _make_cleanup_once_receiver(
        self,
        receiver_id: c.Hashable,
        sender_id: c.Hashable,
    ) -> c.Callable[[weakref.ref[c.Callable[..., t.Any]]], None]:
        def cleanup(ref: weakref.ref[c.Callable[..., t.Any]]) -> None:
            if not sys.is_finalizing():
                with self._lock:
                    self._disconnect_once_locked(receiver_id, sender_id)

        return cleanup

    def _make_cleanup_sender(
        self, sender_id: c.Hashable
    ) -> c.Callable[[weakref.ref[t.Any]], None]:
        """Create a callback function to disconnect all receivers for a weakly
        referenced sender when it is garbage collected.
        """
        assert sender_id != ANY_ID

        def cleanup(ref: weakref.ref[t.Any]) -> None:
            with self._lock:
                self._weak_senders.pop(sender_id, None)

                for receiver_id in self._by_sender.pop(sender_id, ()):
                    self._by_receiver[receiver_id].discard(sender_id)

                once_keys = list(self._once_by_sender.pop(sender_id, ()))

                for receiver_id, _ in once_keys:
                    key = (receiver_id, sender_id)
                    self._once_receivers.pop(key, None)
                    self._once_by_receiver[receiver_id].discard(key)

                    if not self._once_by_receiver[receiver_id]:
                        self._once_by_receiver.pop(receiver_id, None)

                    if not self._by_receiver[receiver_id]:
                        self._refresh_receiver_locked(receiver_id)

        return cleanup

    def _cleanup_bookkeeping(self) -> None:
        """Prune unused sender/receiver bookkeeping. Not threadsafe.

        Connecting & disconnecting leaves behind a small amount of bookkeeping
        data. Typical workloads using Blinker, for example in most web apps,
        Flask, CLI scripts, etc., are not adversely affected by this
        bookkeeping.

        With a long-running process performing dynamic signal routing with high
        volume, e.g. connecting to function closures, senders are all unique
        object instances. Doing all of this over and over may cause memory usage
        to grow due to extraneous bookkeeping. (An empty ``set`` for each stale
        sender/receiver pair.)

        This method will prune that bookkeeping away, with the caveat that such
        pruning is not threadsafe. The risk is that cleanup of a fully
        disconnected receiver/sender pair occurs while another thread is
        connecting that same pair. If you are in the highly dynamic, unique
        receiver/sender situation that has lead you to this method, that failure
        mode is perhaps not a big deal for you.
        """
        mappings = (
            self._by_sender,
            self._by_receiver,
            self._once_by_sender,
            self._once_by_receiver,
        )

        for mapping in mappings:
            for ident, bucket in list(mapping.items()):
                if not bucket:
                    mapping.pop(ident, None)

    def _clear_state(self) -> None:
        """Disconnect all receivers and senders. Useful for tests."""
        self._weak_senders.clear()
        self.receivers.clear()
        self._by_sender.clear()
        self._by_receiver.clear()
        self._once_receivers.clear()
        self._once_by_sender.clear()
        self._once_by_receiver.clear()


class NamedSignal(Signal):
    """A named generic notification emitter. The name is not used by the signal
    itself, but matches the key in the :class:`Namespace` that it belongs to.

    :param name: The name of the signal within the namespace.
    :param doc: The docstring for the signal.
    """

    def __init__(self, name: str, doc: str | None = None) -> None:
        super().__init__(doc)

        #: The name of this signal.
        self.name: str = name

    def __repr__(self) -> str:
        base = super().__repr__()
        return f"{base[:-1]}; {self.name!r}>"  # noqa: E702


class Namespace(dict[str, NamedSignal]):
    """A dict mapping names to signals."""

    def signal(self, name: str, doc: str | None = None) -> NamedSignal:
        """Return the :class:`NamedSignal` for the given ``name``, creating it
        if required. Repeated calls with the same name return the same signal.

        :param name: The name of the signal.
        :param doc: The docstring of the signal.
        """
        if name not in self:
            self[name] = NamedSignal(name, doc)

        return self[name]


class _PNamespaceSignal(t.Protocol):
    def __call__(self, name: str, doc: str | None = None) -> NamedSignal: ...


default_namespace: Namespace = Namespace()
"""A default :class:`Namespace` for creating named signals. :func:`signal`
creates a :class:`NamedSignal` in this namespace.
"""

signal: _PNamespaceSignal = default_namespace.signal
"""Return a :class:`NamedSignal` in :data:`default_namespace` with the given
``name``, creating it if required. Repeated calls with the same name return the
same signal.
"""
