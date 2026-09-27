from __future__ import annotations

import math
from typing import Literal, TypeVar
from warnings import warn

from ..streams.broadcast import BroadcastSendStream, _BroadcastStreamState
from ..streams.memory import (
    MemoryObjectReceiveStream,
    MemoryObjectSendStream,
    _MemoryObjectStreamState,
)

T_Item = TypeVar("T_Item")


class create_broadcast_stream(BroadcastSendStream[T_Item]):
    """
    Create a broadcast stream.

    A broadcast stream delivers every sent item to every current subscriber,
    unlike a memory object stream where each item is received by a single
    recipient. Subscriptions are created by calling
    :meth:`~anyio.streams.broadcast.BroadcastSendStream.subscribe` on the returned
    send stream.

    The stream's item type can be annotated like
    :func:`create_broadcast_stream[T_Item]`.

    :param max_buffer_size: number of items held in each subscriber's buffer until
        ``send()`` starts blocking (with the ``"wait"`` overflow policy) or the
        subscriber is disconnected (with the ``"close"`` overflow policy)
    :param overflow_policy: the policy applied when a subscriber's buffer is full:
        ``"wait"`` (the default) makes senders wait until every subscriber has
        room in its buffer, while ``"close"`` disconnects the lagging subscriber,
        which will then raise :exc:`~anyio.SubscriberOverflowError` once it has
        drained its buffer
    :return: the send stream of the broadcast stream

    .. versionadded:: 4.16

    """

    def __new__(  # type: ignore[misc]
        cls,
        max_buffer_size: int = 0,
        *,
        overflow_policy: Literal["wait", "close"] = "wait",
    ) -> BroadcastSendStream[T_Item]:
        if not isinstance(max_buffer_size, int):
            raise ValueError("max_buffer_size must be an integer")
        if max_buffer_size < 0:
            raise ValueError("max_buffer_size cannot be negative")
        if overflow_policy not in ("wait", "close"):
            raise ValueError('overflow_policy must be either "wait" or "close"')

        state = _BroadcastStreamState[T_Item](max_buffer_size, overflow_policy)
        return BroadcastSendStream(state)


class create_memory_object_stream(
    tuple[MemoryObjectSendStream[T_Item], MemoryObjectReceiveStream[T_Item]],
):
    """
    Create a memory object stream.

    The stream's item type can be annotated like
    :func:`create_memory_object_stream[T_Item]`.

    :param max_buffer_size: number of items held in the buffer until ``send()`` starts
        blocking
    :param item_type: old way of marking the streams with the right generic type for
        static typing (does nothing on AnyIO 4)

        .. deprecated:: 4.0
          Use ``create_memory_object_stream[YourItemType](...)`` instead.
    :return: a tuple of (send stream, receive stream)

    """

    def __new__(  # type: ignore[misc]
        cls, max_buffer_size: float = 0, item_type: object = None
    ) -> tuple[MemoryObjectSendStream[T_Item], MemoryObjectReceiveStream[T_Item]]:
        if max_buffer_size != math.inf and not isinstance(max_buffer_size, int):
            raise ValueError("max_buffer_size must be either an integer or math.inf")
        if max_buffer_size < 0:
            raise ValueError("max_buffer_size cannot be negative")
        if item_type is not None:
            warn(
                "The item_type argument has been deprecated in AnyIO 4.0. "
                "Use create_memory_object_stream[YourItemType](...) instead.",
                DeprecationWarning,
                stacklevel=2,
            )

        state = _MemoryObjectStreamState[T_Item](max_buffer_size)
        return (MemoryObjectSendStream(state), MemoryObjectReceiveStream(state))
