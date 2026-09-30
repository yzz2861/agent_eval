"""Extensible memoizing collections and decorators."""

__all__ = (
    "Cache",
    "FIFOCache",
    "LFUCache",
    "LRUCache",
    "PartitionedCache",
    "PartitionStats",
    "PartitionedLRUCache",
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
import random
import time

from . import keys


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

    def __touch(self, key):
        """Mark as recently used"""
        try:
            self.__order.move_to_end(key)
        except KeyError:
            self.__order[key] = None


PartitionStats = collections.namedtuple("PartitionStats", ("currsize", "quota"))


class _PartitionState:
    __slots__ = ("key", "quota", "data", "order", "currsize")

    def __init__(self, key, quota):
        self.key = key
        self.quota = quota
        self.data = {}
        self.order = collections.OrderedDict()
        self.currsize = 0


class _PartitionView(collections.abc.MutableMapping):
    __slots__ = ("_cache", "_partition")

    def __init__(self, cache, partition):
        self._cache = cache
        self._partition = partition

    @property
    def _state(self):
        return self._cache._partition_state(self._partition)

    def __repr__(self):
        return "Partition(%r, %r, quota=%r, currsize=%r)" % (
            self._state.key,
            self._state.data,
            self._state.quota,
            self._state.currsize,
        )

    def __getitem__(self, key):
        try:
            value = self._state.data[key]
        except KeyError:
            raise KeyError(key) from None
        self._state.order.move_to_end(key)
        return value

    def __setitem__(self, key, value):
        self._cache._setitem(self._state, key, value)

    def __delitem__(self, key):
        self._cache._remove_item(self._state, key)

    def __iter__(self):
        return iter(self._state.order)

    def __len__(self):
        return len(self._state.order)

    def __contains__(self, key):
        return key in self._state.data

    def popitem(self):
        """Remove and return the least recently used `(key, value)` pair."""
        try:
            key = next(iter(self._state.order))
        except StopIteration:
            raise KeyError("partition is empty") from None
        return (key, self.pop(key))

    def clear(self):
        self._cache._clear_partition(self._state)

    @property
    def quota(self):
        """The partition's reserved size."""
        return self._state.quota

    @property
    def currsize(self):
        """The partition's current size."""
        return self._state.currsize


class PartitionedCache(collections.abc.MutableMapping):
    """LRU cache with size reservations for named partitions.

    Partitions are accessed with :meth:`partition`, while individual
    entries are also available through ``(partition, key)`` tuple keys.
    """

    def __init__(self, maxsize, quotas=(), getsizeof=None):
        if maxsize < 0:
            raise ValueError("maxsize must be non-negative")
        if getsizeof:
            self.getsizeof = getsizeof
        self.__size = (
            {}
            if self.getsizeof is not PartitionedLRUCache.getsizeof
            else _DefaultSize()
        )
        self.__maxsize = maxsize
        self.__currsize = 0
        self.__partitions = {}

        quotas = dict(quotas)
        total_quota = 0
        for key, quota in quotas.items():
            self._check_size(quota, "quota")
            total_quota += quota
            if total_quota > maxsize:
                raise ValueError("partition quotas exceed maxsize")
        self.__partitions = {
            key: _PartitionState(key, quota) for key, quota in quotas.items()
        }

    def __repr__(self):
        return "%s(maxsize=%r, currsize=%r, quotas=%r)" % (
            type(self).__name__,
            self.__maxsize,
            self.__currsize,
            self.quotas,
        )

    def __getitem__(self, key):
        if isinstance(key, tuple) and len(key) == 2:
            partition, item_key = key
            state = self._partition_state(partition)
            try:
                value = state.data[item_key]
            except KeyError:
                raise KeyError(key) from None
            state.order.move_to_end(item_key)
            return value
        partition = key
        self._partition_state(partition)
        return _PartitionView(self, partition)

    def __setitem__(self, key, value):
        if not (isinstance(key, tuple) and len(key) == 2):
            raise TypeError(
                "partitions cannot be replaced; use cache[partition][key] = value"
            )
        partition, item_key = key
        self._setitem(self._partition_state(partition), item_key, value)

    def __delitem__(self, key):
        if not (isinstance(key, tuple) and len(key) == 2):
            raise KeyError(key)
        partition, item_key = key
        self._remove_item(self._partition_state(partition), item_key)

    def __iter__(self):
        for partition, state in self.__partitions.items():
            for item_key in state.order:
                yield partition, item_key

    def __len__(self):
        return sum(len(state.order) for state in self.__partitions.values())

    def __contains__(self, key):
        if isinstance(key, tuple) and len(key) == 2:
            partition, item_key = key
            return item_key in self._partition_state(partition).data
        return key in self.__partitions

    def clear(self):
        """Remove all entries while retaining partitions and quotas."""
        for state in self.__partitions.values():
            self._clear_partition(state)

    def partition(self, partition):
        """Return the LRU mapping for a named partition."""
        self._partition_state(partition)
        return _PartitionView(self, partition)

    @property
    def partitions(self):
        """The keys of all configured partitions."""
        return self.__partitions.keys()

    def remove_partition(self, partition):
        """Remove a partition and all of its entries."""
        state = self.__partitions.pop(partition)
        self._clear_partition(state)

    def _partition_state(self, partition):
        try:
            return self.__partitions[partition]
        except KeyError:
            raise KeyError(partition) from None

    def set_quota(self, partition, quota):
        """Set a partition's reserved quota, adding an empty partition if needed."""
        self._check_size(quota, "quota")
        total_quota = quota
        for key, state in self.__partitions.items():
            if key != partition:
                total_quota += state.quota
        if total_quota > self.__maxsize:
            raise ValueError("partition quotas exceed maxsize")
        try:
            state = self.__partitions[partition]
        except KeyError:
            state = _PartitionState(partition, quota)
            self.__partitions[partition] = state
        else:
            state.quota = quota

    def resize(self, maxsize=None, quotas=None):
        """Atomically set the total size and update selected quotas.

        Quotas not present in ``quotas`` keep their current value.
        """
        if maxsize is None:
            maxsize = self.__maxsize
        if maxsize < 0:
            raise ValueError("maxsize must be non-negative")

        updated_quotas = dict(quotas) if quotas is not None else None
        total_quota = 0
        for partition, state in self.__partitions.items():
            quota = (
                updated_quotas[partition]
                if updated_quotas is not None and partition in updated_quotas
                else state.quota
            )
            self._check_size(quota, "quota")
            total_quota += quota
        new_quotas = {
            partition: quota
            for partition, quota in (updated_quotas or {}).items()
            if partition not in self.__partitions
        }
        for partition, quota in new_quotas.items():
            self._check_size(quota, "quota")
            total_quota += quota
        if total_quota > maxsize:
            raise ValueError("partition quotas exceed maxsize")

        for partition, quota in new_quotas.items():
            self.__partitions[partition] = _PartitionState(partition, quota)
        if updated_quotas is not None:
            for partition, state in self.__partitions.items():
                if partition in updated_quotas:
                    state.quota = updated_quotas[partition]
        self.__maxsize = maxsize
        self.__shrink_to_maxsize()

    def set_maxsize(self, maxsize):
        """Set the shared maximum size and evict borrowed entries if needed."""
        if maxsize < 0:
            raise ValueError("maxsize must be non-negative")
        total_quota = 0
        for state in self.__partitions.values():
            total_quota += state.quota
        if total_quota > maxsize:
            raise ValueError("partition quotas exceed maxsize")
        self.__maxsize = maxsize
        self.__shrink_to_maxsize()

    @property
    def maxsize(self):
        """The maximum total size of all partitions."""
        return self.__maxsize

    @property
    def currsize(self):
        """The current total size of all partitions."""
        return self.__currsize

    @property
    def quotas(self):
        """A copy of the current partition quotas."""
        return {
            partition: state.quota for partition, state in self.__partitions.items()
        }

    def stats(self):
        """Return current size and quota statistics for all partitions."""
        return {
            partition: PartitionStats(state.currsize, state.quota)
            for partition, state in self.__partitions.items()
        }

    @staticmethod
    def getsizeof(value):
        """Return the size of a cache element's value."""
        return 1

    def _setitem(self, target, key, value):
        size = self.getsizeof(value)
        self._check_size(size, "value size")

        other_minimum = 0
        for state in self.__partitions.values():
            if state is not target:
                other_minimum += min(state.currsize, state.quota)
        if other_minimum + size > self.__maxsize:
            raise ValueError("value too large")

        if key in target.data:
            self._remove_item(target, key)

        while self.__currsize + size > self.__maxsize:
            if target.currsize > target.quota:
                candidate = target
            else:
                candidate = self._partition_over_quota()
            if candidate is None:
                if target.currsize:
                    candidate = target
                else:
                    raise ValueError("value too large")
            self._pop_partition_item(candidate)

        target.data[key] = value
        target.order[key] = None
        self.__size[(target.key, key)] = size
        target.currsize += size
        self.__currsize += size

    def _remove_item(self, state, key):
        try:
            del state.data[key]
        except KeyError:
            raise KeyError(key) from None
        del state.order[key]
        size = self.__size.pop((state.key, key))
        state.currsize -= size
        self.__currsize -= size

    def _pop_partition_item(self, state):
        key = next(iter(state.order))
        value = state.data[key]
        self._remove_item(state, key)
        return key, value

    def _clear_partition(self, state):
        for key in tuple(state.order):
            self.__size.pop((state.key, key))
        self.__currsize -= state.currsize
        state.currsize = 0
        state.data.clear()
        state.order.clear()

    def _partition_over_quota(self):
        best = None
        largest_overage = 0
        for state in self.__partitions.values():
            overage = state.currsize - state.quota
            if overage > largest_overage:
                best = state
                largest_overage = overage
        return best

    def __shrink_to_maxsize(self):
        while self.__currsize > self.__maxsize:
            state = self._partition_over_quota()
            if state is None:
                raise ValueError("partition quotas exceed maxsize")
            self._pop_partition_item(state)

    @staticmethod
    def _check_size(size, name):
        if size < 0:
            raise ValueError("%s must be non-negative" % name)


PartitionedLRUCache = PartitionedCache


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

    def __init__(self, maxsize, ttu, timer=time.monotonic, getsizeof=None):
        _TimedCache.__init__(self, maxsize, timer, getsizeof)
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
        self.__items[key] = item = TLRUCache._Item(key, expires)
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
