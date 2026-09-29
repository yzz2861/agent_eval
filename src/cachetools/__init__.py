"""Extensible memoizing collections and decorators."""

__all__ = (
    "Cache",
    "FIFOCache",
    "LFUCache",
    "LRUCache",
    "RemovalEvent",
    "RemovalReason",
    "RRCache",
    "TLRUCache",
    "TTLCache",
    "cached",
    "cachedmethod",
)

__version__ = "7.2.0"

import collections
import collections.abc
import contextlib
import enum
import functools
import heapq
import random
import time

from . import keys


class RemovalReason(enum.Enum):
    """The reason why an item was removed from a cache."""

    EXPIRED = "expired"
    EVICTED = "evicted"
    REPLACED = "replaced"
    DELETED = "deleted"
    CLEARED = "cleared"


class RemovalEvent(
    collections.namedtuple("RemovalEvent", ["key", "value", "reason", "sequence"])
):
    """Information about a single cache item removal.

    `key` and `value` are the removed item's key and (old) value,
    `reason` is a `RemovalReason` member, and `sequence` is a
    monotonically increasing per-cache sequence number, starting at 1
    for the first notified removal.  Sequence numbers are only consumed
    by actual removals; reading from the cache never affects them.

    """

    __slots__ = ()


class _RemovalBoundary:
    """Reusable context manager delimiting a mutating cache operation.

    Removal notifications are deferred until the outermost boundary
    exits, so listeners always observe the cache after the operation
    (including any subclass bookkeeping) has fully completed.

    """

    __slots__ = ("_cache",)

    def __init__(self, cache):
        self._cache = cache

    def __enter__(self):
        self._cache._notify_enter()

    def __exit__(self, *exc_info):
        self._cache._notify_exit()


class _DefaultSize:
    """A minimal "fake" dict that returns a constant size 1 for any key."""

    __slots__ = ()

    def __getitem__(self, _key):
        return 1

    def __setitem__(self, _key, _value):
        pass

    def pop(self, _key):
        return 1

    def clear(self):
        pass


class Cache(collections.abc.MutableMapping):
    """Mutable mapping to serve as a simple cache or cache base class."""

    __marker = object()

    __size = _DefaultSize()

    def __init__(
        self, maxsize, getsizeof=None, on_remove=None, on_remove_error="ignore"
    ):
        if maxsize < 0:
            raise ValueError("maxsize must be non-negative")
        if getsizeof:
            self.getsizeof = getsizeof
        if self.getsizeof is not Cache.getsizeof:
            self.__size = {}
        self.__data = {}
        self.__currsize = 0
        self.__maxsize = maxsize
        self.__removal_seq = 0
        self.__pending_removals = []
        self.__notify_depth = 0
        self.__flushing = False
        self.__removal_reason = None
        self.__on_remove = None
        self.__on_remove_error = "ignore"
        # use the property setters for validation
        self.on_remove = on_remove
        self.on_remove_error = on_remove_error

    def __repr__(self):
        return "%s(%s, maxsize=%r, currsize=%r)" % (
            type(self).__name__,
            repr(self.__data),
            self.__maxsize,
            self.__currsize,
        )

    def __getitem__(self, key):
        try:
            return self.__data[key]
        except KeyError:
            return self.__missing__(key)

    def __setitem__(self, key, value):
        maxsize = self.__maxsize
        size = self.getsizeof(value)
        if size < 0:
            raise ValueError("value size must be non-negative")
        if size > maxsize:
            raise ValueError("value too large")
        with self._notify_boundary():
            if key not in self.__data:
                diffsize = size
                with self._removal_reason(RemovalReason.EVICTED):
                    while self.__currsize + diffsize > maxsize:
                        self.popitem()
            else:
                diffsize = size - self.__size[key]
                with self._removal_reason(RemovalReason.EVICTED):
                    while self.__currsize + diffsize > maxsize:
                        self.popitem()
                        if key not in self.__data:
                            diffsize = size
            replaced = self.__data.get(key, self.__marker)
            self.__data[key] = value
            self.__size[key] = size
            self.__currsize += diffsize
            if replaced is not self.__marker:
                self._record_removal(key, replaced, RemovalReason.REPLACED)

    def __delitem__(self, key):
        with self._notify_boundary():
            size = self.__size.pop(key)
            value = self.__data.pop(key)
            self.__currsize -= size
            reason = self.__removal_reason
            if reason is None:
                reason = RemovalReason.DELETED
            self._record_removal(key, value, reason)

    def __contains__(self, key):
        return key in self.__data

    def __missing__(self, key):
        raise KeyError(key)

    def __iter__(self):
        return iter(self.__data)

    def __len__(self):
        return len(self.__data)

    # Note that we cannot simply inherit get(), pop() and setdefault()
    # from MutableMapping, since these rely on __getitem__ throwing a
    # KeyError on cache miss.  This is not the case if __missing__ is
    # implemented for a Cache subclass, so we have to roll our own,
    # somewhat less elegant versions.

    def get(self, key, default=None):
        if key in self:
            return self[key]
        else:
            return default

    def pop(self, key, default=__marker):
        if key in self:
            value = self[key]
            del self[key]
        elif default is self.__marker:
            raise KeyError(key)
        else:
            value = default
        return value

    def setdefault(self, key, default=None):
        if key in self:
            value = self[key]
        else:
            self[key] = value = default
        return value

    def popitem(self):
        """Remove and return an arbitrary `(key, value)` pair."""
        try:
            key = next(iter(self))
        except StopIteration:
            raise KeyError("%s is empty" % type(self).__name__) from None
        with self._removal_reason(RemovalReason.EVICTED):
            value = self[key]
            del self[key]
        return (key, value)

    # Although the MutableMapping.clear() default implementation works
    # perfectly well, it calls popitem() in a loop until the cache is
    # empty, resulting in O(n) complexity.  For large caches, this
    # becomes a significant performance bottleneck, so we provide an
    # optimized version for each Cache subclass.

    def clear(self):
        with self._notify_boundary():
            if self.__on_remove is not None:
                items = list(self.__data.items())
            else:
                items = ()
            self.__data.clear()
            self.__size.clear()
            self.__currsize = 0
            for key, value in items:
                self._record_removal(key, value, RemovalReason.CLEARED)

    @property
    def maxsize(self):
        """The maximum size of the cache."""
        return self.__maxsize

    @property
    def currsize(self):
        """The current size of the cache."""
        return self.__currsize

    @staticmethod
    def getsizeof(value):
        """Return the size of a cache element's value."""
        return 1

    @property
    def on_remove(self):
        """The removal listener called with a `RemovalEvent` for each
        item removed from the cache, or `None` if no listener is set.

        The listener is called after the removal has been fully applied,
        so it observes the cache without the removed item.  It may
        safely perform further cache operations; removals caused by
        these are reported by subsequent notifications.

        """
        return self.__on_remove

    @on_remove.setter
    def on_remove(self, callback):
        if callback is not None and not callable(callback):
            raise TypeError("on_remove must be callable or None")
        self.__on_remove = callback

    @property
    def on_remove_error(self):
        """The policy for handling exceptions raised by the `on_remove`
        listener.

        Either "ignore" to silently ignore listener exceptions (the
        default), "raise" to propagate them to the caller of the cache
        operation, or a callable taking the exception and the
        `RemovalEvent` being reported.  Note that listener exceptions
        never affect the cache contents: a removed item stays removed.

        """
        return self.__on_remove_error

    @on_remove_error.setter
    def on_remove_error(self, policy):
        if policy != "ignore" and policy != "raise" and not callable(policy):
            raise ValueError(
                'on_remove_error must be "ignore", "raise" or a callable'
            )
        self.__on_remove_error = policy

    def _record_removal(self, key, value, reason):
        if self.__on_remove is None:
            return
        self.__removal_seq += 1
        event = RemovalEvent(key, value, reason, self.__removal_seq)
        self.__pending_removals.append(event)

    @contextlib.contextmanager
    def _removal_reason(self, reason):
        previous = self.__removal_reason
        self.__removal_reason = reason
        try:
            yield
        finally:
            self.__removal_reason = previous

    def _notify_enter(self):
        self.__notify_depth += 1

    def _notify_boundary(self):
        return _RemovalBoundary(self)

    def _notify_exit(self):
        self.__notify_depth -= 1
        if self.__notify_depth == 0:
            self.__flush_removals()

    def __flush_removals(self):
        # Reentrant calls (from cache operations performed by the
        # listener) simply leave their events queued; the outermost
        # flush loop will pick them up in order.
        if self.__flushing:
            return
        pending = self.__pending_removals
        if not pending:
            return
        self.__flushing = True
        try:
            while pending:
                callback = self.__on_remove
                if callback is None:
                    del pending[:]
                    break
                event = pending.pop(0)
                try:
                    callback(event)
                except Exception as exc:
                    self.__handle_listener_error(exc, event)
        finally:
            self.__flushing = False

    def __handle_listener_error(self, exc, event):
        policy = self.__on_remove_error
        if policy == "raise":
            raise exc
        elif policy == "ignore":
            return
        else:
            policy(exc, event)


class FIFOCache(Cache):
    """First In First Out (FIFO) cache implementation."""

    def __init__(
        self, maxsize, getsizeof=None, on_remove=None, on_remove_error="ignore"
    ):
        Cache.__init__(self, maxsize, getsizeof, on_remove, on_remove_error)
        self.__order = collections.OrderedDict()

    def __setitem__(self, key, value, cache_setitem=Cache.__setitem__):
        with self._notify_boundary():
            cache_setitem(self, key, value)
            if key in self.__order:
                self.__order.move_to_end(key)
            else:
                self.__order[key] = None

    def __delitem__(self, key, cache_delitem=Cache.__delitem__):
        with self._notify_boundary():
            cache_delitem(self, key)
            del self.__order[key]

    def popitem(self):
        """Remove and return the `(key, value)` pair first inserted."""
        try:
            key = next(iter(self.__order))
        except StopIteration:
            raise KeyError("%s is empty" % type(self).__name__) from None
        with self._removal_reason(RemovalReason.EVICTED):
            return (key, self.pop(key))

    def clear(self):
        self.__order.clear()
        Cache.clear(self)


class LFUCache(Cache):
    """Least Frequently Used (LFU) cache implementation."""

    class _Link:
        __slots__ = ("count", "keys", "next", "prev")

        def __init__(self, count):
            self.count = count
            self.keys = set()

        def unlink(self):
            next = self.next
            prev = self.prev
            prev.next = next
            next.prev = prev

    def __init__(
        self, maxsize, getsizeof=None, on_remove=None, on_remove_error="ignore"
    ):
        Cache.__init__(self, maxsize, getsizeof, on_remove, on_remove_error)
        self.__root = root = LFUCache._Link(0)  # sentinel
        root.prev = root.next = root
        self.__links = {}

    def __getitem__(self, key, cache_getitem=Cache.__getitem__):
        value = cache_getitem(self, key)
        if key in self:  # __missing__ may not store item
            self.__touch(key)
        return value

    def __setitem__(self, key, value, cache_setitem=Cache.__setitem__):
        with self._notify_boundary():
            cache_setitem(self, key, value)
            if key in self.__links:
                self.__touch(key)
                return
            root = self.__root
            link = root.next
            if link.count != 1:
                link = LFUCache._Link(1)
                link.next = root.next
                root.next = link.next.prev = link
                link.prev = root
            link.keys.add(key)
            self.__links[key] = link

    def __delitem__(self, key, cache_delitem=Cache.__delitem__):
        with self._notify_boundary():
            cache_delitem(self, key)
            link = self.__links.pop(key)
            link.keys.remove(key)
            if not link.keys:
                link.unlink()

    def popitem(self):
        """Remove and return the `(key, value)` pair least frequently used."""
        root = self.__root
        curr = root.next
        if curr is root:
            raise KeyError("%s is empty" % type(self).__name__) from None
        key = next(iter(curr.keys))  # remove an arbitrary element
        with self._removal_reason(RemovalReason.EVICTED):
            return (key, self.pop(key))

    def clear(self):
        root = self.__root
        root.prev = root.next = root
        self.__links.clear()
        Cache.clear(self)

    def __touch(self, key):
        """Increment use count"""
        link = self.__links[key]
        curr = link.next
        if curr.count != link.count + 1:
            if len(link.keys) == 1:
                link.count += 1
                return
            curr = LFUCache._Link(link.count + 1)
            curr.next = link.next
            link.next = curr.next.prev = curr
            curr.prev = link
        curr.keys.add(key)
        link.keys.remove(key)
        if not link.keys:
            link.unlink()
        self.__links[key] = curr


class LRUCache(Cache):
    """Least Recently Used (LRU) cache implementation."""

    def __init__(
        self, maxsize, getsizeof=None, on_remove=None, on_remove_error="ignore"
    ):
        Cache.__init__(self, maxsize, getsizeof, on_remove, on_remove_error)
        self.__order = collections.OrderedDict()

    def __getitem__(self, key, cache_getitem=Cache.__getitem__):
        value = cache_getitem(self, key)
        if key in self:  # __missing__ may not store item
            self.__touch(key)
        return value

    def __setitem__(self, key, value, cache_setitem=Cache.__setitem__):
        with self._notify_boundary():
            cache_setitem(self, key, value)
            self.__touch(key)

    def __delitem__(self, key, cache_delitem=Cache.__delitem__):
        with self._notify_boundary():
            cache_delitem(self, key)
            del self.__order[key]

    def popitem(self):
        """Remove and return the `(key, value)` pair least recently used."""
        try:
            key = next(iter(self.__order))
        except StopIteration:
            raise KeyError("%s is empty" % type(self).__name__) from None
        with self._removal_reason(RemovalReason.EVICTED):
            return (key, self.pop(key))

    def clear(self):
        self.__order.clear()
        Cache.clear(self)

    def __touch(self, key):
        """Mark as recently used"""
        try:
            self.__order.move_to_end(key)
        except KeyError:
            self.__order[key] = None


class RRCache(Cache):
    """Random Replacement (RR) cache implementation."""

    def __init__(self, maxsize, choice=random.choice, getsizeof=None,
                 on_remove=None, on_remove_error="ignore"):
        Cache.__init__(self, maxsize, getsizeof, on_remove, on_remove_error)
        self.__choice = choice
        self.__index = {}
        self.__keys = []

    @property
    def choice(self):
        """The `choice` function used by the cache."""
        return self.__choice

    def __setitem__(self, key, value, cache_setitem=Cache.__setitem__):
        with self._notify_boundary():
            cache_setitem(self, key, value)
            if key not in self.__index:
                self.__index[key] = len(self.__keys)
                self.__keys.append(key)

    def __delitem__(self, key, cache_delitem=Cache.__delitem__):
        with self._notify_boundary():
            cache_delitem(self, key)
            index = self.__index.pop(key)
            if index != len(self.__keys) - 1:
                last = self.__keys[-1]
                self.__keys[index] = last
                self.__index[last] = index
            self.__keys.pop()

    def popitem(self):
        """Remove and return a random `(key, value)` pair."""
        try:
            key = self.__choice(self.__keys)
        except IndexError:
            raise KeyError("%s is empty" % type(self).__name__) from None
        with self._removal_reason(RemovalReason.EVICTED):
            return (key, self.pop(key))

    def clear(self):
        self.__index.clear()
        del self.__keys[:]
        Cache.clear(self)


class _TimedCache(Cache):
    """Base class for time aware cache implementations."""

    class _Timer:
        def __init__(self, timer):
            self.__timer = timer
            self.__nesting = 0

        def __call__(self):
            if self.__nesting == 0:
                return self.__timer()
            else:
                return self.__time

        def __enter__(self):
            if self.__nesting == 0:
                self.__time = time = self.__timer()
            else:
                time = self.__time
            self.__nesting += 1
            return time

        def __exit__(self, *exc):
            self.__nesting -= 1

        def __reduce__(self):
            return _TimedCache._Timer, (self.__timer,)

        def __getattr__(self, name):
            return getattr(self.__timer, name)

    def __init__(self, maxsize, timer, getsizeof=None, on_remove=None,
                 on_remove_error="ignore"):
        Cache.__init__(self, maxsize, getsizeof, on_remove, on_remove_error)
        self.__timer = _TimedCache._Timer(timer)

    def __repr__(self, cache_repr=Cache.__repr__):
        with self.__timer as time:
            self.expire(time)
            return cache_repr(self)

    def __len__(self, cache_len=Cache.__len__):
        with self.__timer as time:
            self.expire(time)
            return cache_len(self)

    @property
    def currsize(self):
        with self.__timer as time:
            self.expire(time)
            return super().currsize

    @property
    def timer(self):
        """The timer function used by the cache."""
        return self.__timer

    def get(self, *args, **kwargs):
        with self.__timer:
            return Cache.get(self, *args, **kwargs)

    def pop(self, *args, **kwargs):
        with self.__timer:
            return Cache.pop(self, *args, **kwargs)

    def setdefault(self, *args, **kwargs):
        with self.__timer:
            return Cache.setdefault(self, *args, **kwargs)

    def clear(self):
        # Subclasses must override to also reset their own time-tracking
        # structures; we do not call expire() here since clear() should
        # be O(1) regardless of cache contents.
        Cache.clear(self)

    def expire(self, time=None):  # pragma: no cover
        raise NotImplementedError


class TTLCache(_TimedCache):
    """LRU Cache implementation with per-item time-to-live (TTL) value."""

    class _Link:
        __slots__ = ("expires", "key", "next", "prev")

        def __init__(self, key=None, expires=None):
            self.key = key
            self.expires = expires

        def __reduce__(self):
            return TTLCache._Link, (self.key, self.expires)

        def unlink(self):
            next = self.next
            prev = self.prev
            prev.next = next
            next.prev = prev

    def __init__(self, maxsize, ttl, timer=time.monotonic, getsizeof=None,
                 on_remove=None, on_remove_error="ignore"):
        _TimedCache.__init__(self, maxsize, timer, getsizeof, on_remove,
                             on_remove_error)
        self.__root = root = TTLCache._Link()
        root.prev = root.next = root
        self.__links = collections.OrderedDict()
        self.__ttl = ttl

    def __contains__(self, key):
        try:
            link = self.__links[key]  # no reordering
        except KeyError:
            return False
        else:
            return self.timer() < link.expires

    def __getitem__(self, key, cache_getitem=Cache.__getitem__):
        try:
            link = self.__getlink(key)
        except KeyError:
            expired = False
        else:
            expired = not (self.timer() < link.expires)
        if expired:
            return self.__missing__(key)
        else:
            return cache_getitem(self, key)

    def __setitem__(self, key, value, cache_setitem=Cache.__setitem__):
        with self._notify_boundary():
            with self.timer as time:
                self.expire(time)
                cache_setitem(self, key, value)
            try:
                link = self.__getlink(key)
            except KeyError:
                self.__links[key] = link = TTLCache._Link(key)
            else:
                link.unlink()
            link.expires = time + self.__ttl
            link.next = root = self.__root
            link.prev = prev = root.prev
            prev.next = root.prev = link

    def __delitem__(self, key, cache_delitem=Cache.__delitem__):
        with self._notify_boundary():
            cache_delitem(self, key)
            link = self.__links.pop(key)
            link.unlink()
            if not (self.timer() < link.expires):
                raise KeyError(key)

    def __iter__(self):
        root = self.__root
        curr = root.next
        while curr is not root:
            # "freeze" time for iterator access
            with self.timer as time:
                if time < curr.expires:
                    yield curr.key
            curr = curr.next

    def __setstate__(self, state):
        self.__dict__.update(state)
        root = self.__root
        root.prev = root.next = root
        for link in sorted(self.__links.values(), key=lambda obj: obj.expires):
            link.next = root
            link.prev = prev = root.prev
            prev.next = root.prev = link
        self.expire(self.timer())

    @property
    def ttl(self):
        """The time-to-live value of the cache's items."""
        return self.__ttl

    def expire(self, time=None):
        """Remove expired items from the cache and return an iterable of the
        expired `(key, value)` pairs.

        """
        if time is None:
            time = self.timer()
        with self._notify_boundary(), self._removal_reason(RemovalReason.EXPIRED):
            root = self.__root
            curr = root.next
            links = self.__links
            expired = []
            cache_delitem = Cache.__delitem__
            cache_getitem = Cache.__getitem__
            while curr is not root and not (time < curr.expires):
                expired.append((curr.key, cache_getitem(self, curr.key)))
                cache_delitem(self, curr.key)
                del links[curr.key]
                next = curr.next
                curr.unlink()
                curr = next
            return expired

    def popitem(self):
        """Remove and return the `(key, value)` pair least recently used that
        has not already expired.

        """
        with self.timer as time:
            self.expire(time)
            try:
                key = next(iter(self.__links))
            except StopIteration:
                raise KeyError("%s is empty" % type(self).__name__) from None
            with self._removal_reason(RemovalReason.EVICTED):
                return (key, self.pop(key))

    def clear(self):
        root = self.__root
        root.prev = root.next = root
        self.__links.clear()
        _TimedCache.clear(self)

    def __getlink(self, key):
        value = self.__links[key]
        self.__links.move_to_end(key)
        return value


class TLRUCache(_TimedCache):
    """Time aware Least Recently Used (TLRU) cache implementation."""

    __HEAP_CLEANUP_FACTOR = 2  # clean up the heap if size > N * len(items)

    @functools.total_ordering
    class _Item:
        __slots__ = ("expires", "key", "removed")

        def __init__(self, key=None, expires=None):
            self.key = key
            self.expires = expires
            self.removed = False

        def __lt__(self, other):
            return self.expires < other.expires

    def __init__(self, maxsize, ttu, timer=time.monotonic, getsizeof=None,
                 on_remove=None, on_remove_error="ignore"):
        _TimedCache.__init__(self, maxsize, timer, getsizeof, on_remove,
                             on_remove_error)
        self.__items = collections.OrderedDict()
        self.__order = []
        self.__ttu = ttu

    def __contains__(self, key):
        try:
            item = self.__items[key]  # no reordering
        except KeyError:
            return False
        else:
            return self.timer() < item.expires

    def __getitem__(self, key, cache_getitem=Cache.__getitem__):
        try:
            item = self.__getitem(key)
        except KeyError:
            expired = False
        else:
            expired = not (self.timer() < item.expires)
        if expired:
            return self.__missing__(key)
        else:
            return cache_getitem(self, key)

    def __setitem__(self, key, value, cache_setitem=Cache.__setitem__):
        with self._notify_boundary():
            with self.timer as time:
                self.expire(time)
                expires = self.__ttu(key, value, time)
                if not (time < expires):
                    # updating an existing item with an already expired
                    # one should remove the existing item
                    with self._removal_reason(RemovalReason.REPLACED):
                        return self.__delitem(key)
                cache_setitem(self, key, value)
            # removing an existing item would break the heap structure, so
            # only mark it as removed for now
            try:
                self.__getitem(key).removed = True
            except KeyError:
                pass
            self.__items[key] = item = TLRUCache._Item(key, expires)
            heapq.heappush(self.__order, item)

    def __delitem__(self, key, cache_delitem=Cache.__delitem__):
        with self._notify_boundary():
            with self.timer as time:
                # no self.expire() for performance reasons, e.g. self.clear() [#67]
                cache_delitem(self, key)
            item = self.__items.pop(key)
            item.removed = True
            if not (time < item.expires):
                raise KeyError(key)

    def __iter__(self):
        for curr in self.__order:
            # "freeze" time for iterator access
            with self.timer as time:
                if time < curr.expires and not curr.removed:
                    yield curr.key

    @property
    def ttu(self):
        """The local time-to-use function used by the cache."""
        return self.__ttu

    def expire(self, time=None):
        """Remove expired items from the cache and return an iterable of the
        expired `(key, value)` pairs.

        """
        if time is None:
            time = self.timer()
        with self._notify_boundary(), self._removal_reason(RemovalReason.EXPIRED):
            items = self.__items
            order = self.__order
            # clean up the heap if too many items are marked as removed
            if len(order) > len(items) * self.__HEAP_CLEANUP_FACTOR:
                self.__order = order = [item for item in order if not item.removed]
                heapq.heapify(order)
            expired = []
            cache_delitem = Cache.__delitem__
            cache_getitem = Cache.__getitem__
            while order and (order[0].removed or not (time < order[0].expires)):
                item = heapq.heappop(order)
                if not item.removed:
                    expired.append((item.key, cache_getitem(self, item.key)))
                    cache_delitem(self, item.key)
                    del items[item.key]
            return expired

    def popitem(self):
        """Remove and return the `(key, value)` pair least recently used that
        has not already expired.

        """
        with self.timer as time:
            self.expire(time)
            try:
                key = next(iter(self.__items))
            except StopIteration:
                raise KeyError("%s is empty" % type(self).__name__) from None
            with self._removal_reason(RemovalReason.EVICTED):
                return (key, self.pop(key))

    def clear(self):
        self.__items.clear()
        del self.__order[:]
        _TimedCache.clear(self)

    def __getitem(self, key):
        value = self.__items[key]
        self.__items.move_to_end(key)
        return value

    def __delitem(self, key, cache_delitem=Cache.__delitem__):
        with self._notify_boundary():
            try:
                self.__items.pop(key).removed = True
            except KeyError:
                pass
            else:
                cache_delitem(self, key)


# note that the runtime __name__ is "CacheInfo", as in stdlib:
# https://github.com/python/cpython/blob/3.14/Lib/functools.py#L520
_CacheInfo = collections.namedtuple(
    "CacheInfo", ["hits", "misses", "maxsize", "currsize"]
)


def cached(cache, key=keys.hashkey, lock=None, condition=None, info=False):
    """Decorator to wrap a function with a memoizing callable that saves
    results in a cache.

    """
    from ._cached import _wrapper

    def decorator(func):
        if info:
            if isinstance(cache, Cache):

                def make_info(hits, misses):
                    return _CacheInfo(hits, misses, cache.maxsize, cache.currsize)

            elif isinstance(cache, collections.abc.Mapping):

                def make_info(hits, misses):
                    return _CacheInfo(hits, misses, None, len(cache))

            else:

                def make_info(hits, misses):
                    return _CacheInfo(hits, misses, 0, 0)

            return _wrapper(func, cache, key, lock, condition, info=make_info)
        else:
            return _wrapper(func, cache, key, lock, condition)

    return decorator


def cachedmethod(cache, key=keys.methodkey, lock=None, condition=None, info=False):
    """Decorator to wrap a method with a memoizing callable that saves
    results in a cache.

    """
    from ._cachedmethod import _wrapper

    def decorator(method):
        if info:

            def make_info(cache, hits, misses):
                if isinstance(cache, Cache):
                    return _CacheInfo(hits, misses, cache.maxsize, cache.currsize)
                elif isinstance(cache, collections.abc.Mapping):
                    return _CacheInfo(hits, misses, None, len(cache))
                else:
                    raise TypeError("cache(self) must return a mutable mapping")

            return _wrapper(method, cache, key, lock, condition, info=make_info)
        else:
            return _wrapper(method, cache, key, lock, condition)

    return decorator
