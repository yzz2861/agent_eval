import math
import unittest

import cachetools
from cachetools import RemovalEvent, RemovalReason


class Timer:
    def __init__(self, auto=False):
        self.auto = auto
        self.time = 0

    def __call__(self):
        if self.auto:
            self.time += 1
        return self.time

    def tick(self):
        self.time += 1


def default_ttu(_key, _value, _time):
    return math.inf


class TTLTestCache(cachetools.TTLCache):
    def __init__(self, maxsize, ttl=math.inf, **kwargs):
        super().__init__(maxsize, ttl=ttl, timer=Timer(), **kwargs)


class TLRUTestCache(cachetools.TLRUCache):
    def __init__(self, maxsize, ttu=default_ttu, **kwargs):
        super().__init__(maxsize, ttu, timer=Timer(), **kwargs)


class RemovalListenerTestMixin:
    Cache = None

    def cache(self, maxsize, events, **kwargs):
        return self.Cache(maxsize, on_remove=events.append, **kwargs)

    def test_deleted_event(self):
        events = []
        cache = self.cache(2, events)
        cache[1] = "a"
        cache[2] = "b"
        del cache[1]
        self.assertEqual(events, [RemovalEvent(1, "a", RemovalReason.DELETED, 1)])

    def test_pop_event(self):
        events = []
        cache = self.cache(2, events)
        cache[1] = "a"
        self.assertEqual(cache.pop(1), "a")
        self.assertEqual(events, [RemovalEvent(1, "a", RemovalReason.DELETED, 1)])

    def test_popitem_event(self):
        events = []
        cache = self.cache(2, events)
        cache[1] = "a"
        key, value = cache.popitem()
        self.assertEqual(events, [RemovalEvent(key, value, RemovalReason.DELETED, 1)])

    def test_missing_delete_no_event(self):
        events = []
        cache = self.cache(2, events)
        with self.assertRaises(KeyError):
            del cache[1]
        with self.assertRaises(KeyError):
            cache.pop(1)
        self.assertEqual(cache.pop(1, None), None)
        self.assertEqual(events, [])

    def test_evicted_event(self):
        events = []
        cache = self.cache(2, events)
        cache[1] = "a"
        cache[2] = "b"
        cache[3] = "c"
        self.assertEqual(len(events), 1)
        event = events[0]
        self.assertEqual(event.reason, RemovalReason.EVICTED)
        self.assertEqual(event.sequence, 1)
        self.assertIn(event.key, (1, 2))
        self.assertEqual(event.value, {1: "a", 2: "b"}[event.key])
        self.assertNotIn(event.key, cache)

    def test_replaced_event(self):
        events = []
        cache = self.cache(2, events)
        cache[1] = "a"
        cache[1] = "b"
        self.assertEqual(events, [RemovalEvent(1, "a", RemovalReason.REPLACED, 1)])
        self.assertEqual(cache[1], "b")

    def test_clear_event(self):
        events = []
        cache = self.cache(3, events)
        cache[1] = "a"
        cache[2] = "b"
        cache.clear()
        self.assertEqual(len(events), 2)
        reasons = {RemovalReason.CLEARED}
        self.assertEqual({e.reason for e in events}, reasons)
        self.assertEqual({e.key for e in events}, {1, 2})
        self.assertEqual({e.value for e in events}, {"a", "b"})
        self.assertEqual([e.sequence for e in events], [1, 2])

    def test_notify_only_once(self):
        events = []
        cache = self.cache(2, events)
        cache[1] = "a"
        del cache[1]
        self.assertEqual(len(events), 1)
        # a failed removal must not notify again
        with self.assertRaises(KeyError):
            del cache[1]
        self.assertEqual(len(events), 1)

    def test_reads_do_not_affect_sequence(self):
        events = []
        cache = self.cache(2, events)
        cache[1] = "a"
        cache[1]
        cache.get(1)
        1 in cache
        len(cache)
        list(cache)
        cache.setdefault(1, "x")
        self.assertEqual(events, [])
        del cache[1]
        self.assertEqual([e.sequence for e in events], [1])

    def test_sequence_numbers(self):
        events = []
        cache = self.cache(2, events)
        cache[1] = "a"
        cache[2] = "b"
        cache[1] = "c"  # replaced
        cache[3] = "d"  # evicts something
        del cache[3]
        cache.clear()
        self.assertEqual([e.sequence for e in events], [1, 2, 3, 4])

    def test_listener_sees_completed_cache(self):
        seen = []

        def listener(event):
            seen.append((event, event.key not in cache, len(cache)))

        cache = self.Cache(2, on_remove=listener)
        cache[1] = "a"
        cache[2] = "b"
        cache[3] = "c"  # evicts one item
        self.assertEqual(len(seen), 1)
        event, absent, size = seen[0]
        self.assertTrue(absent)
        self.assertEqual(size, 2)
        self.assertIn(3, cache)

    def test_listener_may_operate_on_cache(self):
        events = []

        def listener(event):
            events.append(event)
            if event.key == 1:
                # nested removal and insertion must not break anything
                del cache[2]
                cache[4] = "d"
                list(cache)

        cache = self.Cache(3, on_remove=listener)
        cache[1] = "a"
        cache[2] = "b"
        cache[3] = "c"
        del cache[1]
        self.assertEqual([e.key for e in events], [1, 2])
        self.assertEqual([e.sequence for e in events], [1, 2])
        self.assertEqual(set(cache), {3, 4})

    def test_multiple_listeners(self):
        events1, events2 = [], []
        cache = self.Cache(2, on_remove=[events1.append, events2.append])
        cache[1] = "a"
        del cache[1]
        self.assertEqual(events1, events2)
        self.assertEqual(len(events1), 1)

    def test_error_raise_keeps_removal(self):
        def listener(_event):
            raise RuntimeError("boom")

        cache = self.Cache(2, on_remove=listener)
        cache[1] = "a"
        with self.assertRaises(RuntimeError):
            del cache[1]
        # the removal is not undone by the listener exception
        self.assertNotIn(1, cache)
        self.assertEqual(len(cache), 0)

    def test_error_ignore(self):
        def listener(_event):
            raise RuntimeError("boom")

        cache = self.Cache(2, on_remove=listener, on_remove_error="ignore")
        cache[1] = "a"
        del cache[1]
        self.assertNotIn(1, cache)

    def test_error_callable(self):
        errors = []

        def listener(_event):
            raise RuntimeError("boom")

        def handler(exc, event):
            errors.append((exc, event))

        cache = self.Cache(2, on_remove=listener, on_remove_error=handler)
        cache[1] = "a"
        del cache[1]
        self.assertEqual(len(errors), 1)
        exc, event = errors[0]
        self.assertIsInstance(exc, RuntimeError)
        self.assertEqual(event.key, 1)
        self.assertEqual(event.reason, RemovalReason.DELETED)

    def test_invalid_error_policy(self):
        with self.assertRaises(ValueError):
            self.Cache(2, on_remove=lambda e: None, on_remove_error="bogus")


class ExpirationListenerTestMixin:
    Cache = None

    def test_expired_event(self):
        events = []
        cache = self.Cache(10, on_remove=events.append)
        cache[1] = "a"
        cache[2] = "b"
        cache.timer.tick()
        cache.timer.tick()
        # expired items are lazily removed; no event yet
        self.assertNotIn(1, cache)
        self.assertEqual(events, [])
        # triggering expiration notifies exactly once per item
        expired = cache.expire()
        self.assertEqual(len(expired), 2)
        self.assertEqual(
            events,
            [
                RemovalEvent(1, "a", RemovalReason.EXPIRED, 1),
                RemovalEvent(2, "b", RemovalReason.EXPIRED, 2),
            ],
        )
        # expiring again must not notify again
        self.assertEqual(cache.expire(), [])
        self.assertEqual(len(events), 2)

    def test_expired_event_on_len(self):
        events = []
        cache = self.Cache(10, on_remove=events.append)
        cache[1] = "a"
        cache.timer.tick()
        cache.timer.tick()
        self.assertEqual(len(cache), 0)
        self.assertEqual(events, [RemovalEvent(1, "a", RemovalReason.EXPIRED, 1)])

    def test_expired_before_evicted(self):
        events = []
        cache = self.Cache(3, on_remove=events.append)
        cache[1] = "a"
        cache.timer.tick()
        cache.timer.tick()
        cache[2] = "b"
        cache[3] = "c"
        self.assertEqual(
            [e.reason for e in events],
            [RemovalReason.EXPIRED],
        )
        self.assertEqual(events[0].key, 1)


class CacheRemovalTest(unittest.TestCase, RemovalListenerTestMixin):
    Cache = cachetools.Cache


class FIFORemovalTest(unittest.TestCase, RemovalListenerTestMixin):
    Cache = cachetools.FIFOCache


class LFURemovalTest(unittest.TestCase, RemovalListenerTestMixin):
    Cache = cachetools.LFUCache


class LRURemovalTest(unittest.TestCase, RemovalListenerTestMixin):
    Cache = cachetools.LRUCache


class RRRemovalTest(unittest.TestCase, RemovalListenerTestMixin):
    Cache = cachetools.RRCache


class TTLRemovalTest(
    unittest.TestCase, RemovalListenerTestMixin, ExpirationListenerTestMixin
):
    class Cache(TTLTestCache):
        def __init__(self, maxsize, **kwargs):
            super().__init__(maxsize, ttl=2, **kwargs)


class TLRURemovalTest(
    unittest.TestCase, RemovalListenerTestMixin, ExpirationListenerTestMixin
):
    class Cache(TLRUTestCache):
        def __init__(self, maxsize, **kwargs):
            super().__init__(maxsize, ttu=lambda k, v, t: t + 2, **kwargs)


if __name__ == "__main__":
    unittest.main()
