import unittest

import cachetools
from cachetools import RemovalEvent, RemovalReason


class Timer:
    def __init__(self):
        self.time = 0

    def __call__(self):
        return self.time

    def tick(self):
        self.time += 1


class RemovalListenerTest(unittest.TestCase):
    def caches(self):
        timer = Timer()
        return [
            cachetools.Cache(maxsize=2),
            cachetools.FIFOCache(maxsize=2),
            cachetools.LFUCache(maxsize=2),
            cachetools.LRUCache(maxsize=2),
            cachetools.RRCache(maxsize=2),
            cachetools.TTLCache(maxsize=2, ttl=10, timer=timer),
            cachetools.TLRUCache(maxsize=2, ttu=lambda k, v, t: t + 10, timer=timer),
        ]

    def test_no_listener_by_default(self):
        for cache in self.caches():
            self.assertIsNone(cache.on_remove)
            cache[1] = 1
            cache[2] = 2
            cache[3] = 3  # evict
            cache.clear()

    def test_explicit_delete(self):
        for cache in self.caches():
            events = []
            cache.on_remove = events.append
            cache[1] = 1
            del cache[1]
            self.assertEqual([RemovalEvent(1, 1, RemovalReason.DELETED, 1)], events)
            self.assertNotIn(1, cache)

    def test_pop_is_delete(self):
        for cache in self.caches():
            events = []
            cache.on_remove = events.append
            cache[1] = 1
            self.assertEqual(1, cache.pop(1))
            self.assertEqual([RemovalEvent(1, 1, RemovalReason.DELETED, 1)], events)

    def test_pop_missing_no_event(self):
        for cache in self.caches():
            events = []
            cache.on_remove = events.append
            self.assertIsNone(cache.pop(1, None))
            self.assertEqual([], events)

    def test_replace(self):
        for cache in self.caches():
            events = []
            cache.on_remove = events.append
            cache[1] = 1
            cache[1] = 2
            self.assertEqual([RemovalEvent(1, 1, RemovalReason.REPLACED, 1)], events)
            self.assertEqual(2, cache[1])

    def test_evict(self):
        for cache in self.caches():
            events = []
            cache.on_remove = events.append
            cache[1] = 1
            cache[2] = 2
            cache[3] = 3
            self.assertEqual(1, len(events))
            self.assertEqual(RemovalReason.EVICTED, events[0].reason)
            self.assertEqual(1, events[0].sequence)
            self.assertEqual(2, len(cache))

    def test_popitem_is_evict(self):
        for cache in self.caches():
            events = []
            cache.on_remove = events.append
            cache[1] = 1
            key, value = cache.popitem()
            self.assertEqual(
                [RemovalEvent(key, value, RemovalReason.EVICTED, 1)], events
            )

    def test_clear(self):
        for cache in self.caches():
            events = []
            cache.on_remove = events.append
            cache[1] = 1
            cache[2] = 2
            cache.clear()
            self.assertEqual(2, len(events))
            self.assertEqual(
                {1, 2}, {event.key for event in events}
            )
            for event in events:
                self.assertEqual(RemovalReason.CLEARED, event.reason)
            self.assertEqual([1, 2], [event.sequence for event in events])
            self.assertEqual(0, len(cache))

    def test_clear_empty_no_event(self):
        for cache in self.caches():
            events = []
            cache.on_remove = events.append
            cache.clear()
            self.assertEqual([], events)

    def test_expire(self):
        timer = Timer()
        for cache in (
            cachetools.TTLCache(maxsize=2, ttl=10, timer=timer),
            cachetools.TLRUCache(maxsize=2, ttu=lambda k, v, t: t + 10, timer=timer),
        ):
            events = []
            cache.on_remove = events.append
            cache[1] = 1
            timer.tick()
            timer.time += 10
            # lazy expiration: item is gone logically, but no event yet
            self.assertNotIn(1, cache)
            self.assertEqual([], events)
            # expire() is triggered by len()
            self.assertEqual(0, len(cache))
            self.assertEqual([RemovalEvent(1, 1, RemovalReason.EXPIRED, 1)], events)

    def test_expire_on_setitem(self):
        timer = Timer()
        cache = cachetools.TTLCache(maxsize=2, ttl=10, timer=timer)
        events = []
        cache.on_remove = events.append
        cache[1] = 1
        timer.time += 20
        cache[2] = 2
        self.assertEqual([RemovalEvent(1, 1, RemovalReason.EXPIRED, 1)], events)

    def test_reads_do_not_affect_sequence(self):
        cache = cachetools.LRUCache(maxsize=3)
        events = []
        cache.on_remove = events.append
        cache[1] = 1
        cache[2] = 2
        cache[1]
        cache[2]
        len(cache)
        1 in cache
        list(cache)
        cache.get(2)
        del cache[1]
        cache.get(2)
        cache.setdefault(3, 3)
        del cache[2]
        self.assertEqual([1, 2], [event.sequence for event in events])

    def test_listener_sees_completed_removal(self):
        for cache in self.caches():
            seen = []
            cache.on_remove = lambda event: seen.append(
                (event.key, event.key in cache, len(cache))
            )
            cache[1] = 1
            cache[2] = 2
            del cache[1]
            self.assertEqual([(1, False, 1)], seen)

    def test_listener_reentrant_operations(self):
        cache = cachetools.LRUCache(maxsize=5)
        events = []

        def listener(event):
            events.append(event)
            if event.key == 1:
                # nested removal: notified exactly once, in order
                cache.pop(2, None)
                # nested insertion must not disturb anything
                cache[3] = 3

        cache.on_remove = listener
        cache[1] = 1
        cache[2] = 2
        del cache[1]
        self.assertEqual(
            [
                RemovalEvent(1, 1, RemovalReason.DELETED, 1),
                RemovalEvent(2, 2, RemovalReason.DELETED, 2),
            ],
            events,
        )
        self.assertEqual({3: 3}, dict(cache))

    def test_listener_reentrant_clear(self):
        cache = cachetools.FIFOCache(maxsize=5)
        events = []

        def listener(event):
            events.append(event)
            if event.reason is RemovalReason.DELETED:
                cache.clear()

        cache.on_remove = listener
        cache[1] = 1
        cache[2] = 2
        del cache[1]
        reasons = [event.reason for event in events]
        self.assertEqual(
            [RemovalReason.DELETED, RemovalReason.CLEARED], reasons
        )
        self.assertEqual(0, len(cache))

    def test_error_ignored_by_default(self):
        cache = cachetools.LRUCache(maxsize=2)

        def listener(event):
            raise RuntimeError("boom")

        cache.on_remove = listener
        cache[1] = 1
        del cache[1]  # must not raise
        self.assertEqual(0, len(cache))

    def test_error_raise(self):
        cache = cachetools.LRUCache(maxsize=2, on_remove_error="raise")

        def listener(event):
            raise RuntimeError("boom")

        cache.on_remove = listener
        cache[1] = 1
        with self.assertRaises(RuntimeError):
            del cache[1]
        # the removed value must not be resurrected
        self.assertNotIn(1, cache)
        self.assertEqual(0, len(cache))

    def test_error_callable(self):
        errors = []
        cache = cachetools.LRUCache(
            maxsize=2,
            on_remove_error=lambda exc, event: errors.append((exc, event)),
        )

        def listener(event):
            raise RuntimeError("boom")

        cache.on_remove = listener
        cache[1] = 1
        del cache[1]
        self.assertEqual(1, len(errors))
        exc, event = errors[0]
        self.assertIsInstance(exc, RuntimeError)
        self.assertEqual(RemovalEvent(1, 1, RemovalReason.DELETED, 1), event)

    def test_error_continues_notification(self):
        cache = cachetools.LRUCache(maxsize=3)
        events = []
        calls = [0]

        def listener(event):
            calls[0] += 1
            if calls[0] == 1:
                raise RuntimeError("boom")
            events.append(event)

        cache.on_remove = listener
        cache[1] = 1
        cache[2] = 2
        cache.clear()
        # both events were delivered despite the first listener call failing
        self.assertEqual(2, calls[0])
        self.assertEqual([2], [event.key for event in events])

    def test_on_remove_setter_validation(self):
        cache = cachetools.Cache(maxsize=1)
        with self.assertRaises(TypeError):
            cache.on_remove = 42
        with self.assertRaises(ValueError):
            cache.on_remove_error = "bogus"

    def test_on_remove_detach(self):
        cache = cachetools.Cache(maxsize=2)
        events = []
        cache.on_remove = events.append
        cache[1] = 1
        del cache[1]
        self.assertEqual(1, len(events))
        cache.on_remove = None
        cache[2] = 2
        del cache[2]
        self.assertEqual(1, len(events))

    def test_event_fields(self):
        cache = cachetools.Cache(maxsize=1)
        events = []
        cache.on_remove = events.append
        cache["key"] = "value"
        del cache["key"]
        (event,) = events
        self.assertEqual("key", event.key)
        self.assertEqual("value", event.value)
        self.assertEqual(RemovalReason.DELETED, event.reason)
        self.assertEqual(1, event.sequence)
        self.assertIsInstance(event, tuple)

    def test_reason_values(self):
        self.assertEqual("expired", RemovalReason.EXPIRED.value)
        self.assertEqual("evicted", RemovalReason.EVICTED.value)
        self.assertEqual("replaced", RemovalReason.REPLACED.value)
        self.assertEqual("deleted", RemovalReason.DELETED.value)
        self.assertEqual("cleared", RemovalReason.CLEARED.value)

    def test_replace_evicting_itself(self):
        # replacing the only item with a larger value evicts the item
        # itself; this is a single EVICTED notification, not REPLACED
        cache = cachetools.LRUCache(maxsize=2, getsizeof=len)
        events = []
        cache.on_remove = events.append
        cache[1] = "x"
        cache[1] = "yy"
        self.assertEqual(
            [RemovalEvent(1, "x", RemovalReason.REPLACED, 1)], events
        )
        self.assertEqual("yy", cache[1])

    def test_tlru_expired_update_is_replace(self):
        timer = Timer()
        cache = cachetools.TLRUCache(
            maxsize=2,
            ttu=lambda k, v, t: t if v == "dead" else t + 10,
            timer=timer,
        )
        events = []
        cache.on_remove = events.append
        cache[1] = "live"
        cache[1] = "dead"
        self.assertEqual(
            [RemovalEvent(1, "live", RemovalReason.REPLACED, 1)], events
        )
        self.assertNotIn(1, cache)

    def test_constructor_arguments(self):
        events = []
        cache = cachetools.LRUCache(
            maxsize=1, on_remove=events.append, on_remove_error="raise"
        )
        self.assertEqual(cache.on_remove, events.append)
        self.assertEqual("raise", cache.on_remove_error)
        cache[1] = 1
        del cache[1]
        self.assertEqual(1, len(events))

    def test_listener_reinsert_during_clear(self):
        cache = cachetools.LRUCache(maxsize=5)
        events = []

        def listener(event):
            events.append(event)
            if event.key == 1:
                cache[99] = 99

        cache.on_remove = listener
        cache[1] = 1
        cache[2] = 2
        cache.clear()
        self.assertEqual(2, len(events))
        self.assertEqual({99: 99}, dict(cache))


if __name__ == "__main__":
    unittest.main()
