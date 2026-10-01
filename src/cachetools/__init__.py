"""Extensible memoizing collections and decorators."""

__all__ = (
    "Cache",
    "FIFOCache",
    "LFUCache",
    "LRUCache",
    "RRCache",
    "TLRUCache",
    "TTLCache",
    "cached",
    "cachedmethod",
)

__version__ = "7.2.0"

import collections
import collections.abc
import functools
import heapq
import math
import random
import time

from . import keys


_SNAPSHOT_VERSION = 1


def _snapshot_entries(snapshot, cache):
    if not isinstance(snapshot, dict):
        raise ValueError("invalid snapshot: expected a dict")
    if type(snapshot.get("version")) is not int:
        raise ValueError("invalid snapshot: missing version")
    if snapshot["version"] != _SNAPSHOT_VERSION:
        raise ValueError("unsupported snapshot version")
    if snapshot.get("cache") != cache:
        raise ValueError("invalid snapshot: cache type mismatch")
    entries = snapshot.get("entries")
    if not isinstance(entries, list):
        raise ValueError("invalid snapshot: entries must be a list")
    for entry in entries:
        if not isinstance(entry, dict):
            raise ValueError("invalid snapshot: entry must be a dict")
        if "key" not in entry or "value" not in entry:
            raise ValueError("invalid snapshot: missing key or value")
    return entries


def _timed_snapshot_entries(snapshot, cache):
    entries = _snapshot_entries(snapshot, cache)
    if "exported_at" not in snapshot:
        raise ValueError("invalid snapshot: missing exported_at")
    if isinstance(snapshot["exported_at"], bool):
        raise ValueError("invalid snapshot: incompatible export time")
    expiry_order = snapshot.get("expiry_order")
    if not isinstance(expiry_order, list):
        raise ValueError("invalid snapshot: expiry order must be a list")
    if len(expiry_order) != len(entries):
        raise ValueError("invalid snapshot: expiry order length mismatch")
    seen_positions = set()
    for position in expiry_order:
        if type(position) is not int or not 0 <= position < len(entries):
            raise ValueError("invalid snapshot: invalid expiry order position")
        if position in seen_positions:
            raise ValueError("invalid snapshot: duplicate expiry order position")
        seen_positions.add(position)
    for entry in entries:
        if "remaining" not in entry:
            raise ValueError("invalid snapshot: missing remaining lifetime")
        remaining = entry["remaining"]
        if isinstance(remaining, bool) or (
            isinstance(remaining, float) and math.isnan(remaining)
        ):
            raise ValueError("invalid snapshot: remaining lifetime must be positive")
        try:
            if remaining <= 0:
                raise ValueError(
                    "invalid snapshot: remaining lifetime must be positive"
                )
        except TypeError:
            raise ValueError(
                "invalid snapshot: incompatible remaining lifetime"
            ) from None
    return entries, snapshot["exported_at"]


def _restore_timed_entries(
    cache, snapshot, kind, restored_at, decode_key, decode_value
):
    raw_entries, exported_at = _timed_snapshot_entries(snapshot, kind)
    cache_time = cache.timer()
    if isinstance(restored_at, bool):
        raise ValueError("invalid snapshot: incompatible export time")
    try:
        downtime = restored_at - exported_at
        if isinstance(downtime, float) and math.isnan(downtime):
            raise ValueError("invalid snapshot: incompatible export time")
        if downtime < 0:
            raise ValueError("invalid snapshot: restore time is before export time")
    except TypeError:
        raise ValueError("invalid snapshot: incompatible export time") from None

    decoded = []
    seen = set()
    sizes = {}
    maxsize = cache.maxsize
    expiry_rank_by_position = {
        expiry_position: position
        for position, expiry_position in enumerate(snapshot["expiry_order"])
    }
    for position, entry in enumerate(raw_entries):
        key = decode_key(entry["key"])
        value = decode_value(entry["value"])
        if key in seen:
            raise ValueError("invalid snapshot: duplicate key")
        seen.add(key)
        try:
            expires = cache_time + (entry["remaining"] - downtime)
        except TypeError:
            raise ValueError(
                "invalid snapshot: incompatible remaining lifetime"
            ) from None
        expiry_rank = expiry_rank_by_position[position]
        decoded.append((key, value, expires, expiry_rank))

    active = collections.deque()
    for decoded_item in decoded:
        key, value, expires, expiry_rank = decoded_item
        if expires > cache_time:
            size = cache.getsizeof(value)
            if size < 0:
                raise ValueError("value size must be non-negative")
            if size > maxsize:
                raise ValueError("value too large")
            sizes[key] = size
            active.append((key, value, expires, size, expiry_rank))
    currsize = sum(size for _key, _value, _expires, size, _rank in active)
    while currsize > maxsize:
        key, _value, _expires, size, _rank = active.popleft()
        sizes.pop(key)
        currsize -= size
    active = list(active)
    return active, sizes, currsize


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

    def __init__(self, maxsize, getsizeof=None):
        if maxsize < 0:
            raise ValueError("maxsize must be non-negative")
        if getsizeof:
            self.getsizeof = getsizeof
        if self.getsizeof is not Cache.getsizeof:
            self.__size = {}
        self.__data = {}
        self.__currsize = 0
        self.__maxsize = maxsize

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
        if key not in self.__data:
            diffsize = size
            while self.__currsize + diffsize > maxsize:
                self.popitem()
        else:
            diffsize = size - self.__size[key]
            while self.__currsize + diffsize > maxsize:
                self.popitem()
                if key not in self.__data:
                    diffsize = size
        self.__data[key] = value
        self.__size[key] = size
        self.__currsize += diffsize

    def __delitem__(self, key):
        size = self.__size.pop(key)
        del self.__data[key]
        self.__currsize -= size

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

    # Although the MutableMapping.clear() default implementation works
    # perfectly well, it calls popitem() in a loop until the cache is
    # empty, resulting in O(n) complexity.  For large caches, this
    # becomes a significant performance bottleneck, so we provide an
    # optimized version for each Cache subclass.

    def clear(self):
        self.__data.clear()
        self.__size.clear()
        self.__currsize = 0

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


class FIFOCache(Cache):
    """First In First Out (FIFO) cache implementation."""

    def __init__(self, maxsize, getsizeof=None):
        Cache.__init__(self, maxsize, getsizeof)
        self.__order = collections.OrderedDict()

    def __setitem__(self, key, value, cache_setitem=Cache.__setitem__):
        cache_setitem(self, key, value)
        if key in self.__order:
            self.__order.move_to_end(key)
        else:
            self.__order[key] = None

    def __delitem__(self, key, cache_delitem=Cache.__delitem__):
        cache_delitem(self, key)
        del self.__order[key]

    def popitem(self):
        """Remove and return the `(key, value)` pair first inserted."""
        try:
            key = next(iter(self.__order))
        except StopIteration:
            raise KeyError("%s is empty" % type(self).__name__) from None
        else:
            return (key, self.pop(key))

    def clear(self):
        Cache.clear(self)
        self.__order.clear()


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

    def __init__(self, maxsize, getsizeof=None):
        Cache.__init__(self, maxsize, getsizeof)
        self.__root = root = LFUCache._Link(0)  # sentinel
        root.prev = root.next = root
        self.__links = {}

    def __getitem__(self, key, cache_getitem=Cache.__getitem__):
        value = cache_getitem(self, key)
        if key in self:  # __missing__ may not store item
            self.__touch(key)
        return value

    def __setitem__(self, key, value, cache_setitem=Cache.__setitem__):
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
        return (key, self.pop(key))

    def clear(self):
        Cache.clear(self)
        root = self.__root
        root.prev = root.next = root
        self.__links.clear()

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

    def __init__(self, maxsize, getsizeof=None):
        Cache.__init__(self, maxsize, getsizeof)
        self.__order = collections.OrderedDict()

    def __getitem__(self, key, cache_getitem=Cache.__getitem__):
        value = cache_getitem(self, key)
        if key in self:  # __missing__ may not store item
            self.__touch(key)
        return value

    def __setitem__(self, key, value, cache_setitem=Cache.__setitem__):
        cache_setitem(self, key, value)
        self.__touch(key)

    def __delitem__(self, key, cache_delitem=Cache.__delitem__):
        cache_delitem(self, key)
        del self.__order[key]

    def popitem(self):
        """Remove and return the `(key, value)` pair least recently used."""
        try:
            key = next(iter(self.__order))
        except StopIteration:
            raise KeyError("%s is empty" % type(self).__name__) from None
        else:
            return (key, self.pop(key))

    def clear(self):
        Cache.clear(self)
        self.__order.clear()

    def export(self, encode_key, encode_value):
        """Return a portable snapshot with entries in LRU order."""
        data = self._Cache__data
        entries = [
            {
                "key": encode_key(key),
                "value": encode_value(data[key]),
            }
            for key in self.__order
        ]
        return {
            "version": _SNAPSHOT_VERSION,
            "cache": "LRUCache",
            "entries": entries,
        }

    def restore(self, snapshot, decode_key, decode_value):
        """Replace the cache contents with a portable LRU snapshot."""
        raw_entries = _snapshot_entries(snapshot, "LRUCache")
        entries = collections.deque()
        seen = set()
        sizes = {}
        currsize = 0
        maxsize = self.maxsize

        for entry in raw_entries:
            key = decode_key(entry["key"])
            value = decode_value(entry["value"])
            if key in seen:
                raise ValueError("invalid snapshot: duplicate key")
            seen.add(key)
            size = self.getsizeof(value)
            if size < 0:
                raise ValueError("value size must be non-negative")
            if size > maxsize:
                raise ValueError("value too large")
            entries.append((key, value))
            sizes[key] = size
            currsize += size

        while entries and currsize > maxsize:
            key, _value = entries.popleft()
            currsize -= sizes.pop(key)

        data = {}
        order = collections.OrderedDict()
        for key, value in entries:
            data[key] = value
            order[key] = None

        self._Cache__data = data
        self._Cache__size = sizes
        self._Cache__currsize = currsize
        self.__order = order

    def __touch(self, key):
        """Mark as recently used"""
        try:
            self.__order.move_to_end(key)
        except KeyError:
            self.__order[key] = None


class RRCache(Cache):
    """Random Replacement (RR) cache implementation."""

    def __init__(self, maxsize, choice=random.choice, getsizeof=None):
        Cache.__init__(self, maxsize, getsizeof)
        self.__choice = choice
        self.__index = {}
        self.__keys = []

    @property
    def choice(self):
        """The `choice` function used by the cache."""
        return self.__choice

    def __setitem__(self, key, value, cache_setitem=Cache.__setitem__):
        cache_setitem(self, key, value)
        if key not in self.__index:
            self.__index[key] = len(self.__keys)
            self.__keys.append(key)

    def __delitem__(self, key, cache_delitem=Cache.__delitem__):
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
        else:
            return (key, self.pop(key))

    def clear(self):
        Cache.clear(self)
        self.__index.clear()
        del self.__keys[:]


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

    def __init__(self, maxsize, timer, getsizeof=None):
        Cache.__init__(self, maxsize, getsizeof)
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

    def __init__(self, maxsize, ttl, timer=time.monotonic, getsizeof=None):
        _TimedCache.__init__(self, maxsize, timer, getsizeof)
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
            else:
                return (key, self.pop(key))

    def clear(self):
        _TimedCache.clear(self)
        root = self.__root
        root.prev = root.next = root
        self.__links.clear()

    def export(self, encode_key, encode_value, clock=time.time):
        """Return a portable snapshot with LRU order and remaining TTL."""
        with self.timer as cache_time:
            self.expire(cache_time)
            portable_time = clock()
            expiry_order = []
            entry_positions = {}
            entries = [
                {
                    "key": encode_key(key),
                    "value": encode_value(Cache.__getitem__(self, key)),
                    "remaining": link.expires - cache_time,
                }
                for key, link in self.__links.items()
            ]
            for position, key in enumerate(self.__links):
                entry_positions[key] = position
            curr = self.__root.next
            while curr is not self.__root:
                expiry_order.append(entry_positions[curr.key])
                curr = curr.next
        return {
            "version": _SNAPSHOT_VERSION,
            "cache": "TTLCache",
            "exported_at": portable_time,
            "expiry_order": expiry_order,
            "entries": entries,
        }

    def restore(self, snapshot, decode_key, decode_value, clock=time.time):
        """Replace the cache contents with a portable TTL snapshot."""
        restored_at = clock()
        active, sizes, currsize = _restore_timed_entries(
            self,
            snapshot,
            "TTLCache",
            restored_at,
            decode_key,
            decode_value,
        )

        data = {}
        links = collections.OrderedDict()
        root = TTLCache._Link()
        root.prev = root.next = root
        for key, value, _expires, _size, _rank in active:
            data[key] = value
            links[key] = TTLCache._Link(key)

        for expiry_position in sorted(
            range(len(active)), key=lambda index: active[index][4]
        ):
            key, _value, expires, _size, _rank = active[expiry_position]
            link = links[key]
            link.expires = expires
            link.next = root
            link.prev = prev = root.prev
            prev.next = root.prev = link

        self._Cache__data = data
        self._Cache__size = sizes
        self._Cache__currsize = currsize
        self.__root = root
        self.__links = links

    def __getlink(self, key):
        value = self.__links[key]
        self.__links.move_to_end(key)
        return value


class TLRUCache(_TimedCache):
    """Time aware Least Recently Used (TLRU) cache implementation."""

    __HEAP_CLEANUP_FACTOR = 2  # clean up the heap if size > N * len(items)

    @functools.total_ordering
    class _Item:
        __slots__ = ("expires", "key", "order", "removed")

        def __init__(self, key=None, expires=None, order=0):
            self.key = key
            self.expires = expires
            self.order = order
            self.removed = False

        def __lt__(self, other):
            if self.expires < other.expires:
                return True
            if other.expires < self.expires:
                return False
            return self.order < other.order

    def __init__(self, maxsize, ttu, timer=time.monotonic, getsizeof=None):
        _TimedCache.__init__(self, maxsize, timer, getsizeof)
        self.__items = collections.OrderedDict()
        self.__order = []
        self.__sequence = 0
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
        with self.timer as time:
            self.expire(time)
            expires = self.__ttu(key, value, time)
            if not (time < expires):
                # updating an existing item with an already expired
                # one should remove the existing item
                return self.__delitem(key)
            cache_setitem(self, key, value)
        # removing an existing item would break the heap structure, so
        # only mark it as removed for now
        try:
            self.__getitem(key).removed = True
        except KeyError:
            pass
        item = TLRUCache._Item(key, expires, self.__sequence)
        self.__sequence += 1
        self.__items[key] = item
        heapq.heappush(self.__order, item)

    def __delitem__(self, key, cache_delitem=Cache.__delitem__):
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

    def __setstate__(self, state):
        self.__dict__.update(state)
        if "_TLRUCache__sequence" not in self.__dict__:
            self.__sequence = len(self.__items)
        for item in self.__order:
            if not hasattr(item, "order"):
                item.order = 0

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
            else:
                return (key, self.pop(key))

    def clear(self):
        _TimedCache.clear(self)
        self.__items.clear()
        del self.__order[:]

    def export(self, encode_key, encode_value, clock=time.time):
        """Return a portable snapshot with LRU order and remaining lifetimes."""
        with self.timer as cache_time:
            self.expire(cache_time)
            portable_time = clock()
            expiry_order = []
            entry_positions = {}
            entries = [
                {
                    "key": encode_key(key),
                    "value": encode_value(Cache.__getitem__(self, key)),
                    "remaining": item.expires - cache_time,
                }
                for key, item in self.__items.items()
            ]
            for position, key in enumerate(self.__items):
                entry_positions[key] = position
            expiry_heap = [item for item in self.__order]
            expiry_order = []
            while expiry_heap:
                item = heapq.heappop(expiry_heap)
                if not item.removed:
                    expiry_order.append(entry_positions[item.key])
        return {
            "version": _SNAPSHOT_VERSION,
            "cache": "TLRUCache",
            "exported_at": portable_time,
            "expiry_order": expiry_order,
            "entries": entries,
        }

    def restore(self, snapshot, decode_key, decode_value, clock=time.time):
        """Replace the cache contents with a portable TLRU snapshot."""
        restored_at = clock()
        active, sizes, currsize = _restore_timed_entries(
            self,
            snapshot,
            "TLRUCache",
            restored_at,
            decode_key,
            decode_value,
        )

        data = {}
        items = collections.OrderedDict()
        sequence = 0
        for key, value, expires, _size, _rank in active:
            data[key] = value
            items[key] = TLRUCache._Item(key, expires, _rank)
            sequence = max(sequence, _rank + 1)
        order = []
        for expiry_position in sorted(
            range(len(active)), key=lambda index: active[index][4]
        ):
            key = active[expiry_position][0]
            order.append(items[key])
        heapq.heapify(order)

        self._Cache__data = data
        self._Cache__size = sizes
        self._Cache__currsize = currsize
        self.__items = items
        self.__order = order
        self.__sequence = sequence

    def __getitem(self, key):
        value = self.__items[key]
        self.__items.move_to_end(key)
        return value

    def __delitem(self, key, cache_delitem=Cache.__delitem__):
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
