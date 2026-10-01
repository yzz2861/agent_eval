"""Utility methods for marshmallow."""

from __future__ import annotations

import asyncio
import datetime as dt
import functools
import inspect
import typing
from collections.abc import Mapping, Sequence

from marshmallow.constants import missing


def is_generator(obj) -> typing.TypeGuard[typing.Generator]:
    """Return True if ``obj`` is a generator."""
    return inspect.isgeneratorfunction(obj) or inspect.isgenerator(obj)


def is_iterable_but_not_string(obj) -> typing.TypeGuard[typing.Iterable]:
    """Return True if ``obj`` is an iterable object that isn't a string."""
    return (hasattr(obj, "__iter__") and not hasattr(obj, "strip")) or is_generator(obj)


def is_sequence_but_not_string(obj) -> typing.TypeGuard[Sequence]:
    """Return True if ``obj`` is a sequence that isn't a string."""
    return isinstance(obj, Sequence) and not isinstance(obj, (str, bytes))


def is_collection(obj) -> typing.TypeGuard[typing.Iterable]:
    """Return True if ``obj`` is a collection type, e.g. list, tuple, queryset."""
    return is_iterable_but_not_string(obj) and not isinstance(obj, Mapping)


def is_async_callable(func) -> bool:
    """Return True if ``func`` is an asynchronous callable, i.e. calling it
    returns an awaitable that must be awaited.
    """
    while isinstance(func, functools.partial):
        func = func.func
    if inspect.iscoroutinefunction(func):
        return True
    # Check for callable instances defining an async __call__
    call = getattr(func, "__call__", None)  # noqa: B004
    return call is not None and inspect.iscoroutinefunction(call)


async def maybe_await(value):
    """Await ``value`` if it is awaitable, otherwise return it unchanged."""
    if inspect.isawaitable(value):
        return await value
    return value


async def gather_limited(coroutines, limit: int) -> list:
    """Run ``coroutines`` concurrently, with at most ``limit`` running at once.

    Results are returned in the same order as the input coroutines. If any
    coroutine fails or the surrounding task is cancelled, the remaining
    coroutines are cancelled and awaited so no background tasks are left
    running.
    """
    semaphore = asyncio.Semaphore(limit)

    async def runner(coro):
        async with semaphore:
            return await coro

    tasks = [asyncio.ensure_future(runner(coro)) for coro in coroutines]
    try:
        return await asyncio.gather(*tasks)
    except BaseException:
        for task in tasks:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
        raise


# https://stackoverflow.com/a/27596917
def is_aware(datetime: dt.datetime) -> bool:
    return (
        datetime.tzinfo is not None and datetime.tzinfo.utcoffset(datetime) is not None
    )


def from_timestamp(value: typing.Any) -> dt.datetime:
    if value is True or value is False:
        raise ValueError("Not a valid POSIX timestamp")
    value = float(value)
    if value < 0:
        raise ValueError("Not a valid POSIX timestamp")

    # Load a timestamp with utc as timezone to prevent using system timezone.
    # Then set timezone to None, to let the Field handle adding timezone info.
    try:
        return dt.datetime.fromtimestamp(value, tz=dt.timezone.utc).replace(tzinfo=None)
    except OverflowError as exc:
        raise ValueError("Timestamp is too large") from exc
    except OSError as exc:
        raise ValueError("Error converting value to datetime") from exc


def from_timestamp_ms(value: typing.Any) -> dt.datetime:
    if value is True or value is False:
        raise ValueError("Not a valid POSIX timestamp")
    value = float(value)
    return from_timestamp(value / 1000)


def timestamp(
    value: dt.datetime,
) -> float:
    if not is_aware(value):
        # When a date is naive, use UTC as zone info to prevent using system timezone.
        value = value.replace(tzinfo=dt.timezone.utc)
    return value.timestamp()


def timestamp_ms(value: dt.datetime) -> float:
    return timestamp(value) * 1000


def ensure_text_type(val: str | bytes) -> str:
    if isinstance(val, bytes):
        val = val.decode("utf-8")
    return str(val)


def pluck(dictlist: list[dict[str, typing.Any]], key: str):
    """Extracts a list of dictionary values from a list of dictionaries.
    ::

        >>> dlist = [{'id': 1, 'name': 'foo'}, {'id': 2, 'name': 'bar'}]
        >>> pluck(dlist, 'id')
        [1, 2]
    """
    return [d[key] for d in dictlist]


# Various utilities for pulling keyed values from objects


def get_value(obj, key: str, default=missing):
    """Helper for pulling a keyed value off various types of objects. Fields use
    this method by default to access attributes of the source object. For object `x`
    and attribute `i`, this method first tries to access `x[i]`, and then falls back to
    `x.i` if an exception is raised.

    .. warning::
        If an object `x` does not raise an exception when `x[i]` does not exist,
        `get_value` will never check the value `x.i`. Consider overriding
        `marshmallow.fields.Field.get_value` in this case.
    """
    if "." in key:
        for k in key.split("."):
            obj = _get_value_for_key(obj, k, default)
    else:
        obj = _get_value_for_key(obj, key, default)
    return obj


def _get_value_for_key(obj, key, default):
    if not hasattr(obj, "__getitem__"):
        return getattr(obj, key, default)

    try:
        return obj[key]
    except (KeyError, IndexError, TypeError, AttributeError):
        return getattr(obj, key, default)


def set_value(dct: dict[str, typing.Any], key: str, value: typing.Any):
    """Set a value in a dict. If `key` contains a '.', it is assumed
    to be a path (i.e. dot-delimited string) to the value's location.

    ::

        >>> d = {}
        >>> set_value(d, 'foo.bar', 42)
        >>> d
        {'foo': {'bar': 42}}
    """
    if "." in key:
        head, rest = key.split(".", 1)
        target = dct.setdefault(head, {})
        if not isinstance(target, dict):
            raise ValueError(
                f"Cannot set {key} in {head} due to existing value: {target}"
            )
        set_value(target, rest, value)
    else:
        dct[key] = value


def callable_or_raise(obj):
    """Check that an object is callable, else raise a :exc:`TypeError`."""
    if not callable(obj):
        raise TypeError(f"Object {obj!r} is not callable.")
    return obj


def timedelta_to_microseconds(value: dt.timedelta) -> int:
    """Compute the total microseconds of a timedelta.

    https://github.com/python/cpython/blob/v3.13.1/Lib/_pydatetime.py#L805-L807
    """
    return (value.days * (24 * 3600) + value.seconds) * 1000000 + value.microseconds
