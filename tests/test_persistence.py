import json
import unittest
from datetime import datetime, timedelta

from cachetools import LRUCache, TLRUCache, TTLCache


class Timer:
    def __init__(self, time=0):
        self.time = time

    def __call__(self):
        return self.time

    def tick(self, amount=1):
        self.time += amount


def dumps(snapshot):
    return json.dumps(snapshot)


def loads(data):
    return json.loads(data)


class PersistenceTest(unittest.TestCase):
    def test_lru_export_preserves_order(self):
        cache = LRUCache[int, int](maxsize=4)
        cache[1] = 1
        cache[2] = 2
        cache[3] = 3
        cache[1]

        snapshot = cache.export(str, str)

        self.assertEqual(1, snapshot["version"])
        self.assertEqual("LRUCache", snapshot["type"])
        self.assertEqual(
            [("2", "2"), ("3", "3"), ("1", "1")],
            [(item["key"], item["value"]) for item in snapshot["items"]],
        )

    def test_lru_restore_preserves_eviction_order(self):
        cache = LRUCache[int, int](maxsize=3)
        cache[1] = 1
        cache[2] = 2
        cache[3] = 3
        cache[1]
        snapshot = dumps(cache.export(str, str))

        restored = LRUCache[int, int](maxsize=3)
        restored.restore(loads(snapshot), int, int)

        self.assertEqual(2, restored.popitem()[0])
        restored[4] = 4
        self.assertEqual(3, restored.popitem()[0])

    def test_lru_restore_shrinks_by_lru_order(self):
        cache = LRUCache[int, int](maxsize=3)
        cache[1] = 1
        cache[2] = 2
        cache[3] = 3
        cache[1]
        snapshot = dumps(cache.export(str, str))

        restored = LRUCache[int, int](maxsize=2)
        restored.restore(loads(snapshot), int, int)

        self.assertEqual({1, 3}, set(restored))
        self.assertEqual(2, restored.currsize)
        self.assertEqual(3, restored.popitem()[0])

    def test_lru_restore_shrinks_weighted_items(self):
        cache = LRUCache[int, int](maxsize=6, getsizeof=lambda value: value)
        cache[1] = 1
        cache[2] = 2
        cache[3] = 3
        snapshot = dumps(cache.export(str, str))

        restored = LRUCache[int, int](maxsize=4, getsizeof=lambda value: value)
        restored.restore(loads(snapshot), int, int)

        self.assertEqual({3}, set(restored))
        self.assertEqual(3, restored.currsize)

    def test_lru_restore_rejects_item_larger_than_new_maxsize(self):
        cache = LRUCache[int, int](maxsize=4, getsizeof=lambda value: value)
        cache[1] = 1
        cache[3] = 3
        snapshot = cache.export(str, str)

        restored = LRUCache[int, int](maxsize=2, getsizeof=lambda value: value)
        restored[1] = 1

        with self.assertRaises(ValueError):
            restored.restore(snapshot, int, int)

        self.assertEqual({1: 1}, dict(restored))
        self.assertEqual(1, restored.currsize)

    def test_lru_restore_matches_continued_cache_eviction(self):
        source = LRUCache[int, int](maxsize=3)
        source[1] = 1
        source[2] = 2
        source[3] = 3
        source[1]
        snapshot = source.export(str, str)

        source._Cache__maxsize = 2
        source[4] = 4

        restored = LRUCache[int, int](maxsize=2)
        restored.restore(snapshot, int, int)
        restored[4] = 4

        self.assertEqual(source.popitem()[0], restored.popitem()[0])

    def test_ttl_restore_subtracts_downtime(self):
        old_timer = Timer()
        cache = TTLCache[int, int, int](maxsize=3, ttl=5, timer=old_timer)
        cache[1] = 1
        old_timer.tick()
        cache[2] = 2
        old_timer.tick()
        cache[3] = 3
        cache[2]
        snapshot = dumps(cache.export(str, str))

        new_timer = Timer(100)
        restored = TTLCache[int, int, int](maxsize=3, ttl=5, timer=new_timer)
        restored.restore(loads(snapshot), int, int, downtime=3)

        self.assertEqual({2, 3}, set(restored))

        new_timer.tick(1)
        self.assertNotIn(2, restored)
        self.assertIn(3, restored)
        self.assertEqual(3, restored.popitem()[0])
        new_timer.tick(1)
        self.assertNotIn(3, restored)

    def test_ttl_restore_shrinks_after_expiry(self):
        old_timer = Timer()
        cache = TTLCache[int, int, int](maxsize=3, ttl=10, timer=old_timer)
        cache[1] = 1
        old_timer.tick()
        cache[2] = 2
        old_timer.tick()
        cache[3] = 3
        cache[1]
        snapshot = dumps(cache.export(str, str))

        new_timer = Timer(20)
        restored = TTLCache[int, int, int](maxsize=1, ttl=10, timer=new_timer)
        restored.restore(loads(snapshot), int, int, downtime=1)

        self.assertEqual({1}, set(restored))
        self.assertEqual(1, restored.popitem()[0])

    def test_ttl_restore_timedelta(self):
        old_time = datetime(2026, 1, 1, 0, 0, 0)
        cache = TTLCache[int, int, datetime](
            maxsize=1,
            ttl=timedelta(hours=2),
            timer=lambda: old_time,
        )
        cache[1] = 1
        old_time += timedelta(hours=1)
        snapshot = cache.export(str, str)

        new_time = datetime(2026, 1, 2, 0, 0, 0)
        restored = TTLCache[int, int, datetime](
            maxsize=1,
            ttl=timedelta(hours=2),
            timer=lambda: new_time,
        )
        restored.restore(snapshot, int, int, downtime=timedelta(minutes=30))

        self.assertIn(1, restored)
        self.assertEqual(
            datetime(2026, 1, 2, 0, 30, 0),
            restored._TTLCache__links[1].expires,
        )

    def test_ttl_restore_chain_expires_all_due_items(self):
        snapshot = {
            "version": 1,
            "type": "TTLCache",
            "items": [
                {"key": "1", "value": 1, "ttl": 10},
                {"key": "2", "value": 2, "ttl": 1},
            ],
        }
        timer = Timer()
        restored = TTLCache[int, int, int](maxsize=2, ttl=10, timer=timer)

        restored.restore(snapshot, int, int)
        timer.tick(2)

        self.assertEqual({1}, set(restored))
        restored[3] = 3
        self.assertEqual({1, 3}, set(restored))

    def test_ttl_restore_matches_continued_cache_eviction(self):
        export_timer = Timer()
        source = TTLCache[int, int, int](maxsize=3, ttl=10, timer=export_timer)
        source[1] = 1
        export_timer.tick()
        source[2] = 2
        export_timer.tick()
        source[3] = 3
        source[2]
        snapshot = source.export(str, str)
        export_timer.tick(3)
        source.expire()
        source._Cache__maxsize = 2
        source[4] = 4

        restore_timer = Timer(5)
        restored = TTLCache[int, int, int](maxsize=2, ttl=10, timer=restore_timer)
        restored.restore(snapshot, int, int, downtime=3)
        restored[4] = 4

        self.assertEqual(source.popitem()[0], restored.popitem()[0])

    def test_tlru_restore_preserves_per_item_ttl(self):
        old_timer = Timer()
        cache = TLRUCache[int, int, int](
            maxsize=4,
            ttu=lambda _key, value, now: now + value + 1,
            timer=old_timer,
        )
        cache[1] = 10
        old_timer.tick()
        cache[2] = 2
        old_timer.tick()
        cache[3] = 3
        cache[2]
        snapshot = dumps(cache.export(str, str))

        new_timer = Timer(100)
        restored = TLRUCache[int, int, int](
            maxsize=2,
            ttu=lambda *args: self.fail("ttu must not be called on restore"),
            timer=new_timer,
        )
        restored.restore(loads(snapshot), int, int, downtime=1)

        self.assertEqual({2, 3}, set(restored))
        self.assertEqual(3, restored.popitem()[0])

        new_timer.tick()
        self.assertNotIn(2, restored)

    def test_tlru_restore_matches_continued_cache_eviction(self):
        export_timer = Timer()
        source = TLRUCache[int, int, int](
            maxsize=3,
            ttu=lambda _key, value, now: now + value + 1,
            timer=export_timer,
        )
        source[1] = 10
        export_timer.tick()
        source[2] = 2
        export_timer.tick()
        source[3] = 3
        source[2]
        snapshot = source.export(str, str)
        export_timer.tick(3)
        source.expire()
        source._Cache__maxsize = 2
        source[4] = 4

        restore_timer = Timer(5)
        restored = TLRUCache[int, int, int](
            maxsize=2,
            ttu=lambda _key, value, now: now + value + 1,
            timer=restore_timer,
        )
        restored.restore(snapshot, int, int, downtime=3)
        restored[4] = 4

        self.assertEqual(source.popitem()[0], restored.popitem()[0])

    def test_restore_rejects_duplicate_decoded_key_without_mutation(self):
        cache = LRUCache[str, str](maxsize=2)
        cache["old"] = "value"
        snapshot = {
            "version": 1,
            "type": "LRUCache",
            "items": [
                {"key": "1", "value": "a"},
                {"key": "01", "value": "b"},
            ],
        }

        with self.assertRaises(ValueError):
            cache.restore(snapshot, int, str)

        self.assertEqual({"old": "value"}, dict(cache))

    def test_restore_rejects_decode_failure_without_mutation(self):
        cache = LRUCache[int, int](maxsize=2)
        cache[9] = 9
        snapshot = {
            "version": 1,
            "type": "LRUCache",
            "items": [{"key": "1", "value": "bad"}],
        }

        with self.assertRaises(ValueError):
            cache.restore(snapshot, int, int)

        self.assertEqual({9: 9}, dict(cache))

    def test_restore_rejects_corrupt_metadata_without_mutation(self):
        cache = TTLCache[int, int, int](maxsize=2, ttl=5, timer=Timer())
        cache[9] = 9
        snapshots = (
            {},
            {"version": 2, "type": "TTLCache", "items": []},
            {"version": 1, "type": "LRUCache", "items": []},
            {"version": 1, "type": "TTLCache", "items": {}},
            {
                "version": 1,
                "type": "TTLCache",
                "items": [{"key": 1, "value": 1}],
            },
            {
                "version": 1,
                "type": "TTLCache",
                "items": [{"key": 1, "value": 1, "ttl": 0}],
            },
        )

        for snapshot in snapshots:
            with self.subTest(snapshot=snapshot):
                with self.assertRaises(ValueError):
                    cache.restore(snapshot, str, str)
                self.assertEqual({9: 9}, dict(cache))

    def test_restore_rejects_invalid_downtime_without_mutation(self):
        cache = TLRUCache[int, int, int](maxsize=1, ttu=lambda *args: 10, timer=Timer())
        cache[1] = 1
        snapshot = {
            "version": 1,
            "type": "TLRUCache",
            "items": [{"key": 1, "value": 1, "ttl": 2}],
        }

        with self.assertRaises(ValueError):
            cache.restore(snapshot, int, int, downtime=-1)
        with self.assertRaises(ValueError):
            cache.restore(snapshot, int, int, downtime=True)

        self.assertEqual({1: 1}, dict(cache))
