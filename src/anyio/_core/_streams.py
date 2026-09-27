from __future__ import annotations

import math
from collections.abc import Callable
from typing import TypeVar
from warnings import warn

from ..streams.memory import (
    MemoryObjectReceiveStream,
    MemoryObjectSendStream,
    _MemoryObjectStreamState,
)

T_Item = TypeVar("T_Item")


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
    :param max_buffer_weight: maximum total weight of the items held in the buffer
        until ``send()`` starts blocking (or ``None`` for no limit); the weight of
        each item is computed with ``item_weight``
    :param item_weight: a callable that computes the weight of an item; the weight is
        computed exactly once, when the item is sent, so mutating the item
        afterwards does not change the accounted weight; if not given, every item
        has a weight of 1
    :return: a tuple of (send stream, receive stream)

    Both the item count limit (``max_buffer_size``) and the weight limit
    (``max_buffer_weight``) must be satisfied for an item to be buffered. An item
    whose weight alone exceeds ``max_buffer_weight`` is rejected immediately with
    a :class:`ValueError` instead of blocking forever. The weight limit only
    applies to items stored in the buffer; items handed directly to a waiting
    receiver are not weighed against it. Items are always delivered in the order
    their send operations started: an item waiting for buffer capacity is never
    overtaken by an item sent later, even if the later item would fit.

    .. versionadded:: 4.16.0
       The ``max_buffer_weight`` and ``item_weight`` parameters.

    """

    def __new__(  # type: ignore[misc]
        cls,
        max_buffer_size: float = 0,
        item_type: object = None,
        *,
        max_buffer_weight: float | None = None,
        item_weight: Callable[[T_Item], float] | None = None,
    ) -> tuple[MemoryObjectSendStream[T_Item], MemoryObjectReceiveStream[T_Item]]:
        if max_buffer_size != math.inf and not isinstance(max_buffer_size, int):
            raise ValueError("max_buffer_size must be either an integer or math.inf")
        if max_buffer_size < 0:
            raise ValueError("max_buffer_size cannot be negative")
        if max_buffer_weight is not None:
            if math.isnan(max_buffer_weight):
                raise ValueError("max_buffer_weight cannot be NaN")
            if max_buffer_weight < 0:
                raise ValueError("max_buffer_weight cannot be negative")

        if item_type is not None:
            warn(
                "The item_type argument has been deprecated in AnyIO 4.0. "
                "Use create_memory_object_stream[YourItemType](...) instead.",
                DeprecationWarning,
                stacklevel=2,
            )

        state = _MemoryObjectStreamState[T_Item](
            max_buffer_size,
            math.inf if max_buffer_weight is None else max_buffer_weight,
            item_weight,
        )
        return (MemoryObjectSendStream(state), MemoryObjectReceiveStream(state))
