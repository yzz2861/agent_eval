import unittest
import json

from cachetools import LRUCache, TLRUCache, TTLCache


class Clock:
    def __init__(self, value=0):
        self.value = value

    def __call__(self):
        return self.value

    def tick(self, amount=1):
        self.value += amount


def encode_key(key):
    return str(key)


def decode_key(key):
    return int(key)


def identity(value):
    return value


class LRUCacheSnapshotTest(unittest.TestCase):
    def test_json_roundtrip(self):
        cache = LRUCache(maxsize=3)
        cache[1] = "one"
        data = json.dumps(cache.export(str, identity))

        restored = LRUCache(maxsize=3)
        restored.restore(json.loads(data), int, identity)

        self.assertEqual({1: "one"}, dict(restored))

    def test_export_restores_lru_order(self):
        cache = LRUCache(maxsize=3)
        cache[1] = 1
        cache[2] = 2
        cache[3] = 3
        cache[1]

        snapshot = cache.export(encode_key, identity)
        restored = LRUCache(maxsize=3)
        restored.restore(snapshot, decode_key, identity)

        restored[4] = 4
        self.assertEqual({1, 3, 4}, set(restored))

    def test_capacity_shrink_evicts_original_lru_order(self):
        cache = LRUCache(maxsize=3)
        cache[1] = 1
        cache[2] = 2
        cache[3] = 3
        cache[1]

        restored = LRUCache(maxsize=1)
        restored.restore(cache.export(encode_key, identity), decode_key, identity)

        self.assertEqual({1}, set(restored))

    def test_duplicate_key_failure_is_atomic(self):
        cache = LRUCache(maxsize=2)
        cache[1] = 1

        with self.assertRaises(ValueError):
            cache.restore(
                {
                    "version": 1,
                    "cache": "LRUCache",
                    "entries": [
                        {"key": "2", "value": 2},
                        {"key": "2", "value": 3},
                    ],
                },
                decode_key,
                identity,
            )

        self.assertEqual({1: 1}, dict(cache))

    def test_decode_failure_is_atomic(self):
        cache = LRUCache(maxsize=2)
        cache[1] = 1

        def decode_value(value):
            if value == 3:
                raise RuntimeError("bad value")
            return value

        with self.assertRaisesRegex(RuntimeError, "bad value"):
            cache.restore(
                {
                    "version": 1,
                    "cache": "LRUCache",
                    "entries": [
                        {"key": "2", "value": 2},
                        {"key": "3", "value": 3},
                    ],
                },
                decode_key,
                decode_value,
            )

        self.assertEqual({1: 1}, dict(cache))

    def test_corrupt_metadata_failure_is_atomic(self):
        cache = LRUCache(maxsize=2)
        cache[1] = 1

        with self.assertRaises(ValueError):
            cache.restore(
                {
                    "version": 1,
                    "cache": "TTLCache",
                    "entries": [{"key": "2", "value": 2}],
                },
                decode_key,
                identity,
            )

        self.assertEqual({1: 1}, dict(cache))


class TTLCacheSnapshotTest(unittest.TestCase):
    def test_json_roundtrip(self):
        wall_clock = Clock()
        cache = TTLCache(maxsize=2, ttl=10, timer=Clock())
        cache[1] = "one"
        data = json.dumps(cache.export(str, identity, clock=wall_clock))

        restored = TTLCache(maxsize=2, ttl=10, timer=Clock(100))
        restored.restore(json.loads(data), int, identity, clock=wall_clock)

        self.assertEqual({1: "one"}, dict(restored))

    def test_equal_expiry_order_is_preserved(self):
        timer = Clock(100)
        wall_clock = Clock()
        cache = TTLCache(maxsize=4, ttl=5, timer=timer)
        cache[1] = 1
        cache[2] = 2
        cache[3] = 3
        cache[1]
        timer.tick(4)
        cache[4] = 4

        snapshot = cache.export(encode_key, identity, clock=wall_clock)
        self.assertEqual([2, 0, 1, 3], snapshot["expiry_order"])

        restored = TTLCache(maxsize=4, ttl=5, timer=Clock(199))
        restored.restore(snapshot, decode_key, identity, clock=wall_clock)

        self.assertEqual([1, 2, 3], [key for key, _value in restored.expire(200)])
        self.assertEqual({4}, set(restored))

    def test_downtime_is_deducted_from_remaining_ttl(self):
        timer = Clock()
        wall_clock = Clock()
        cache = TTLCache(maxsize=3, ttl=10, timer=timer)

        timer.value = 100
        cache[1] = 1
        timer.value = 103
        cache[2] = 2
        cache[1]

        snapshot = cache.export(encode_key, identity, clock=wall_clock)
        self.assertEqual(0, snapshot["exported_at"])
        remaining = {entry["key"]: entry["remaining"] for entry in snapshot["entries"]}
        self.assertEqual(7, remaining["1"])
        self.assertEqual(10, remaining["2"])

        wall_clock.tick(5)
        timer.value = 900
        restored = TTLCache(maxsize=3, ttl=10, timer=timer)
        restored.restore(snapshot, decode_key, identity, clock=wall_clock)

        restored[3] = 3
        self.assertEqual({1, 2, 3}, set(restored))

        timer.value = 901
        restored[4] = 4
        self.assertEqual({1, 3, 4}, set(restored))

        timer.value = 903
        self.assertNotIn(1, restored)
        self.assertEqual(4, restored[4])

    def test_expired_items_are_not_restored(self):
        timer = Clock()
        wall_clock = Clock()
        cache = TTLCache(maxsize=3, ttl=4, timer=timer)
        cache[1] = 1
        timer.tick(2)
        cache[2] = 2

        snapshot = cache.export(encode_key, identity, clock=wall_clock)
        wall_clock.tick(3)
        timer.tick(100)
        restored = TTLCache(maxsize=3, ttl=4, timer=timer)
        restored.restore(snapshot, decode_key, identity, clock=wall_clock)

        self.assertEqual({2}, set(restored))

    def test_capacity_shrink_uses_lru_policy(self):
        timer = Clock()
        wall_clock = Clock()
        cache = TTLCache(maxsize=3, ttl=10, timer=timer)
        cache[1] = 1
        cache[2] = 2
        cache[3] = 3
        cache[1]

        snapshot = cache.export(encode_key, identity, clock=wall_clock)
        wall_clock.tick(1)
        restored = TTLCache(maxsize=1, ttl=10, timer=Clock(50))
        restored.restore(snapshot, decode_key, identity, clock=wall_clock)

        self.assertEqual({1}, set(restored))

    def test_corrupt_lifetime_failure_is_atomic(self):
        cache = TTLCache(maxsize=2, ttl=10, timer=Clock())
        cache[1] = 1

        with self.assertRaises(ValueError):
            cache.restore(
                {
                    "version": 1,
                    "cache": "TTLCache",
                    "exported_at": 0,
                    "entries": [
                        {"key": "2", "value": 2, "remaining": 0},
                    ],
                },
                decode_key,
                identity,
                clock=Clock(),
            )

        self.assertEqual({1: 1}, dict(cache))

    def test_corrupt_expiry_order_failure_is_atomic(self):
        cache = TTLCache(maxsize=2, ttl=10, timer=Clock())
        cache[1] = 1
        snapshot = cache.export(encode_key, identity, clock=Clock())
        snapshot["expiry_order"] = [0, 0]

        with self.assertRaises(ValueError):
            cache.restore(
                snapshot,
                decode_key,
                identity,
                clock=Clock(),
            )

        self.assertEqual({1: 1}, dict(cache))

    def test_clock_going_backwards_failure_is_atomic(self):
        export_clock = Clock(10)
        cache = TTLCache(maxsize=2, ttl=10, timer=Clock())
        cache[1] = 1
        snapshot = cache.export(encode_key, identity, clock=export_clock)

        with self.assertRaises(ValueError):
            cache.restore(
                snapshot,
                decode_key,
                identity,
                clock=Clock(9),
            )

        self.assertEqual({1: 1}, dict(cache))

    def test_nan_export_time_failure_is_atomic(self):
        cache = TTLCache(maxsize=2, ttl=10, timer=Clock())
        cache[1] = 1
        snapshot = {
            "version": 1,
            "cache": "TTLCache",
            "exported_at": float("nan"),
            "expiry_order": [0],
            "entries": [
                {"key": "2", "value": 2, "remaining": 10},
            ],
        }

        with self.assertRaises(ValueError):
            cache.restore(snapshot, decode_key, identity, clock=Clock())

        self.assertEqual({1: 1}, dict(cache))

    def test_oversized_value_failure_is_atomic(self):
        snapshot = {
            "version": 1,
            "cache": "TTLCache",
            "exported_at": 0,
            "expiry_order": [0],
            "entries": [
                {"key": "2", "value": 2, "remaining": 10},
            ],
        }
        restored = TTLCache(
            maxsize=1,
            ttl=10,
            timer=Clock(),
            getsizeof=lambda value: value,
        )

        with self.assertRaises(ValueError):
            restored.restore(snapshot, decode_key, identity, clock=Clock())

        self.assertEqual(0, len(restored))

    def test_expired_oversized_value_is_skipped(self):
        restored = TTLCache(
            maxsize=1,
            ttl=10,
            timer=Clock(10),
            getsizeof=lambda value: value,
        )
        snapshot = {
            "version": 1,
            "cache": "TTLCache",
            "exported_at": 0,
            "expiry_order": [0],
            "entries": [
                {"key": "2", "value": 2, "remaining": 1},
            ],
        }

        restored.restore(snapshot, decode_key, identity, clock=Clock(20))

        self.assertEqual(0, len(restored))


class TLRUCacheSnapshotTest(unittest.TestCase):
    def test_json_roundtrip(self):
        wall_clock = Clock()
        cache = TLRUCache(
            maxsize=2,
            ttu=lambda _key, _value, now: now + 10,
            timer=Clock(),
        )
        cache[1] = "one"
        data = json.dumps(cache.export(str, identity, clock=wall_clock))

        restored = TLRUCache(
            maxsize=2,
            ttu=lambda _key, _value, now: now + 10,
            timer=Clock(100),
        )
        restored.restore(json.loads(data), int, identity, clock=wall_clock)

        self.assertEqual({1: "one"}, dict(restored))

    def test_equal_expiry_heap_order_is_preserved(self):
        timer = Clock(100)
        wall_clock = Clock()
        cache = TLRUCache(
            maxsize=4,
            ttu=lambda _key, value, now: now + (5 if value < 4 else 20),
            timer=timer,
        )
        cache[1] = 1
        cache[2] = 2
        cache[3] = 3
        cache[1]
        timer.tick(4)
        cache[4] = 4

        snapshot = cache.export(encode_key, identity, clock=wall_clock)
        self.assertEqual([2, 0, 1, 3], snapshot["expiry_order"])

        restored = TLRUCache(
            maxsize=4,
            ttu=lambda _key, value, now: now + (5 if value < 4 else 20),
            timer=Clock(199),
        )
        restored.restore(snapshot, decode_key, identity, clock=wall_clock)

        self.assertEqual([1, 2, 3], [key for key, _value in restored.expire(200)])
        self.assertEqual({4}, set(restored))

    def test_downtime_is_deducted_from_remaining_lifetime(self):
        timer = Clock()
        wall_clock = Clock()
        cache = TLRUCache(
            maxsize=3,
            ttu=lambda key, value, now: now + value + 1,
            timer=timer,
        )

        timer.value = 100
        cache[1] = 7
        timer.value = 103
        cache[2] = 3
        cache[1]

        snapshot = cache.export(encode_key, identity, clock=wall_clock)
        remaining = {entry["key"]: entry["remaining"] for entry in snapshot["entries"]}
        self.assertEqual(5, remaining["1"])
        self.assertEqual(4, remaining["2"])

        wall_clock.tick(2)
        timer.value = 900
        restored = TLRUCache(
            maxsize=3,
            ttu=lambda key, value, now: now + value + 1,
            timer=timer,
        )
        restored.restore(snapshot, decode_key, identity, clock=wall_clock)

        timer.value = 901
        self.assertEqual(7, restored[1])
        self.assertEqual(3, restored[2])

        restored[3] = 5
        self.assertEqual({1, 2, 3}, set(restored))

        timer.value = 902
        restored[4] = 5
        self.assertEqual({1, 3, 4}, set(restored))

        timer.value = 903
        self.assertNotIn(1, restored)

    def test_capacity_shrink_uses_lru_policy(self):
        timer = Clock()
        wall_clock = Clock()
        cache = TLRUCache(
            maxsize=3,
            ttu=lambda _key, _value, now: now + 10,
            timer=timer,
        )
        cache[1] = 1
        cache[2] = 2
        cache[3] = 3
        cache[1]

        snapshot = cache.export(encode_key, identity, clock=wall_clock)
        wall_clock.tick(1)
        restored = TLRUCache(
            maxsize=1,
            ttu=lambda _key, _value, now: now + 10,
            timer=Clock(50),
        )
        restored.restore(snapshot, decode_key, identity, clock=wall_clock)

        self.assertEqual({1}, set(restored))

    def test_expired_item_decode_failure_is_atomic(self):
        timer = Clock()
        wall_clock = Clock()
        cache = TLRUCache(
            maxsize=2,
            ttu=lambda _key, _value, now: now + 1,
            timer=timer,
        )
        cache[1] = 1
        cache[2] = 2
        cache[1]

        snapshot = cache.export(encode_key, identity, clock=wall_clock)
        wall_clock.tick(2)

        def decode_value(value):
            if value == 2:
                raise RuntimeError("bad value")
            return value

        with self.assertRaisesRegex(RuntimeError, "bad value"):
            cache.restore(
                snapshot,
                decode_key,
                decode_value,
                clock=wall_clock,
            )

        self.assertEqual({1: 1, 2: 2}, dict(cache))


if __name__ == "__main__":
    unittest.main()
