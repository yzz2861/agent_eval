import unittest

from cachetools import ARCCache, cached

from . import CacheTestMixin


class ARCCacheTest(unittest.TestCase, CacheTestMixin):
    Cache = ARCCache

    def test_getsizeof_param(self):
        with self.assertRaises(TypeError):
            ARCCache(maxsize=3, getsizeof=lambda x: x)

    def test_maxsize_infinite(self):
        with self.assertRaises(TypeError):
            ARCCache(maxsize=float("inf"))

    def test_maxsize_negative(self):
        with self.assertRaises(ValueError):
            ARCCache(maxsize=-1)

    def test_arc_trace(self):
        cache = ARCCache[int, int](maxsize=3)

        # Each state is (T1, T2, B1, B2, p).
        expected_states = [
            ([0], [], [], [], 0),
            ([0, 1], [], [], [], 0),
            ([0, 1, 2], [], [], [], 0),
            ([1, 2], [0], [], [], 0),
            ([2], [0, 1], [], [], 0),
            ([3], [0, 1], [2], [], 0),
            ([4], [0, 1], [2, 3], [], 0),
            ([5], [0, 1], [3, 4], [], 0),
            ([6], [0, 1], [4, 5], [], 0),
            ([6], [1, 4], [5], [0], 1),
            ([6], [4, 5], [], [0, 1], 2),
            ([], [4, 5, 0], [6], [1], 1),
            ([7], [5, 0], [6], [1, 4], 1),
            ([7, 8], [0], [6], [4, 5], 1),
            ([8], [0, 4], [6, 7], [5], 0),
            ([9], [0, 4], [7, 8], [5], 0),
            ([10], [0, 4], [8, 9], [5], 0),
        ]

        trace = [
            ("set", 0),
            ("set", 1),
            ("set", 2),
            ("get", 0),
            ("get", 1),
            ("set", 3),
            ("set", 4),
            ("set", 5),
            ("set", 6),
            ("set", 4),
            ("set", 5),
            ("set", 0),
            ("set", 7),
            ("set", 8),
            ("set", 4),
            ("set", 9),
            ("set", 10),
        ]

        for index, ((operation, key), expected) in enumerate(
            zip(trace, expected_states), start=1
        ):
            with self.subTest(index=index, operation=operation, key=key):
                if operation == "set":
                    cache[key] = key
                else:
                    self.assertEqual(cache[key], key)
                self.assertEqual(self._state(cache), expected)

        self.assertEqual(len(cache), 3)
        self.assertEqual(cache.currsize, 3)
        self.assertEqual(set(cache), {10, 0, 4})
        self.assertEqual(len(cache._ARCCache__b1) + len(cache._ARCCache__b2), 3)

    def test_history_has_no_evicted_values(self):
        cache = ARCCache[str, str](maxsize=2)

        cache["first"] = "first value"
        cache["second"] = "second value"
        cache["first"]
        cache["third"] = "third value"

        self.assertNotIn("second", cache)
        self.assertIn("second", cache._ARCCache__b1)
        self.assertIsNone(cache._ARCCache__b1["second"])
        self.assertEqual({key for key, _ in cache.items()}, {"first", "third"})

    def test_delete_pop_and_clear_reset_strategy_state(self):
        cache = ARCCache[int, int](maxsize=3)
        for key in range(3):
            cache[key] = key
        cache[0]
        cache[3] = 3

        self.assertEqual(self._state(cache), ([2, 3], [0], [1], [], 0))
        del cache[3]
        self.assertEqual(self._state(cache), ([2], [0], [1], [], 0))

        self.assertEqual(cache.pop(2), 2)
        self.assertEqual(self._state(cache), ([], [0], [1], [], 0))

        cache.clear()
        self.assertEqual(self._state(cache), ([], [], [], [], 0))

        cache[0] = 0
        cache[1] = 1
        cache[2] = 2
        self.assertEqual(self._state(cache), ([0, 1, 2], [], [], [], 0))

    def test_history_hit_after_explicit_delete(self):
        cache = ARCCache[int, int](maxsize=3)
        cache[0] = 0
        cache[0]
        cache[1] = 1
        cache[2] = 2
        cache[3] = 3
        del cache[3]

        self.assertEqual(self._state(cache), ([2], [0], [1], [], 0))
        cache[1] = 10
        self.assertEqual(cache.p, 1)
        self.assertEqual(cache[1], 10)
        self.assertEqual(cache[0], 0)
        self.assertEqual(cache[2], 2)
        self.assertNotIn(3, cache)
        self.assertEqual(self._state(cache), ([], [1, 0, 2], [], [], 1))

    def test_popitem_follows_arc(self):
        cache = ARCCache[int, int](maxsize=2)
        cache[0] = 0
        cache[1] = 1
        cache[0]

        self.assertEqual(cache.popitem(), (1, 1))
        self.assertEqual(self._state(cache), ([], [0], [1], [], 0))

    def test_popitem_keeps_history_bounded(self):
        cache = ARCCache[int, int](maxsize=2)
        cache[0] = 0
        cache[1] = 1
        cache[0]
        cache[2] = 2
        cache[1] = 1
        cache[3] = 3
        cache[2] = 2

        self.assertEqual(self._state(cache), ([3], [2], [], [0, 1], 1))
        self.assertEqual(cache.popitem(), (2, 2))
        self.assertEqual(self._state(cache), ([3], [], [], [0, 1], 1))

    def test_cached_decorator(self):
        calls = 0
        cache = ARCCache[int, int](maxsize=2)

        @cached(cache)
        def load(key):
            nonlocal calls
            calls += 1
            return calls

        self.assertEqual(load(0), 1)
        self.assertEqual(load(0), 1)
        self.assertEqual(load(1), 2)
        self.assertEqual(load(2), 3)
        self.assertEqual(load(1), 4)
        self.assertEqual(calls, 4)
        self.assertEqual(set(cache), {(1,), (2,)})

    def test_clear_getsizeof(self):
        self._assert_getsizeof_unsupported(getsizeof=len)

    def test_getsizeof_negative(self):
        self._assert_getsizeof_unsupported(getsizeof=lambda _value: -1)

    def test_getsizeof_replace_grow(self):
        self._assert_getsizeof_unsupported(getsizeof=len)

    def test_getsizeof_replace_same_size(self):
        self._assert_getsizeof_unsupported(getsizeof=len)

    def test_getsizeof_replace_shrink(self):
        self._assert_getsizeof_unsupported(getsizeof=len)

    def test_getsizeof_subclass(self):
        class SizedARCCache(ARCCache):
            @staticmethod
            def getsizeof(value):
                return value

        with self.assertRaises(TypeError):
            SizedARCCache(maxsize=3)

    def test_missing_getsizeof(self):
        self._assert_getsizeof_unsupported(getsizeof=len)

    def _assert_getsizeof_unsupported(self, **kwargs):
        with self.assertRaises(TypeError):
            ARCCache(maxsize=3, **kwargs)

    @staticmethod
    def _state(cache):
        return (
            list(cache._ARCCache__t1),
            list(cache._ARCCache__t2),
            list(cache._ARCCache__b1),
            list(cache._ARCCache__b2),
            cache.p,
        )
