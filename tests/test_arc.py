import unittest

from cachetools import ARCCache, cached

from . import CacheTestMixin


class ARCCacheTest(unittest.TestCase, CacheTestMixin):
    Cache = ARCCache

    # ARCCache accounts capacity per item and does not support a
    # custom getsizeof function, so the mixin's getsizeof tests are
    # overridden to verify that getsizeof is rejected instead.

    def _assert_getsizeof_rejected(self):
        with self.assertRaises(ValueError):
            self.Cache(maxsize=3, getsizeof=lambda x: x)

        class Cache(self.Cache):
            @staticmethod
            def getsizeof(value):
                return value

        with self.assertRaises(ValueError):
            Cache(maxsize=3)

    def test_missing_getsizeof(self):
        self._assert_getsizeof_rejected()

    def test_getsizeof_param(self):
        self._assert_getsizeof_rejected()

    def test_getsizeof_replace_grow(self):
        self._assert_getsizeof_rejected()

    def test_getsizeof_replace_same_size(self):
        self._assert_getsizeof_rejected()

    def test_getsizeof_replace_shrink(self):
        self._assert_getsizeof_rejected()

    def test_getsizeof_negative(self):
        self._assert_getsizeof_rejected()

    def test_getsizeof_subclass(self):
        self._assert_getsizeof_rejected()

    def test_clear_getsizeof(self):
        self._assert_getsizeof_rejected()

    def test_getsizeof_rejected_message(self):
        with self.assertRaisesRegex(ValueError, "getsizeof"):
            ARCCache(maxsize=3, getsizeof=len)


class ARCTraceTest(unittest.TestCase):
    """Step-by-step verification of ARC (Megiddo & Modha, FAST '03)
    against hand-computed access traces.

    Notation: T1/T2 hold resident items (T1: seen once, T2: seen at
    least twice), B1/B2 hold keys of items evicted from T1/T2, and p
    is the adaptation parameter (target size of T1).  Lists are
    written LRU-first.
    """

    def assert_invariants(self, cache):
        t1 = cache._ARCCache__t1
        t2 = cache._ARCCache__t2
        b1 = cache._ARCCache__b1
        b2 = cache._ARCCache__b2
        # resident lists partition the cached keys
        self.assertEqual(set(cache), set(t1) | set(t2))
        self.assertFalse(set(t1) & set(t2))
        # ghost lists hold keys only, disjoint from everything else
        self.assertFalse(set(b1) & set(b2))
        self.assertFalse(set(cache) & set(b1))
        self.assertFalse(set(cache) & set(b2))
        self.assertTrue(all(v is None for v in b1.values()))
        self.assertTrue(all(v is None for v in b2.values()))
        # resident items and history are bounded
        self.assertLessEqual(len(cache), cache.maxsize)
        self.assertLessEqual(len(t1) + len(b1), cache.maxsize)
        self.assertLessEqual(
            len(t1) + len(t2) + len(b1) + len(b2), 2 * cache.maxsize
        )
        self.assertLessEqual(0, cache.p)
        self.assertLessEqual(cache.p, cache.maxsize)

    def test_hit_promotes_t1_to_t2(self):
        # ARC case I: a second reference moves an item from T1 to T2
        cache = ARCCache(maxsize=2)

        cache[1] = 1
        cache[2] = 2
        self.assertEqual(cache.p, 0)
        self.assert_invariants(cache)

        cache[1]  # T1 hit: promote 1 to T2 -> T1=[2], T2=[1]
        cache[3] = 3  # miss: REPLACE evicts T1 LRU 2 -> B1
        self.assertIn(1, cache)
        self.assertIn(3, cache)
        self.assertNotIn(2, cache)
        self.assertEqual(cache.p, 0)
        self.assert_invariants(cache)

        cache[4] = 4  # miss: |T1|+|B1| = 2 = c, B1 trimmed, 3 -> B1
        self.assertIn(1, cache)
        self.assertIn(4, cache)
        self.assertNotIn(3, cache)
        self.assertEqual(cache.p, 0)
        self.assert_invariants(cache)

    def test_full_t1_drops_lru_without_ghost(self):
        # ARC case IV-A: when T1 alone fills the cache, its LRU item
        # is dropped entirely instead of entering B1
        cache = ARCCache(maxsize=2)

        cache[1] = 1
        cache[2] = 2  # T1=[1, 2], T1 alone fills the cache
        cache[3] = 3  # 1 dropped entirely, T1=[2, 3]
        self.assertNotIn(1, cache)
        self.assert_invariants(cache)

        cache[1] = 1  # complete miss again (1 is not in B1): p unchanged
        self.assertEqual(cache.p, 0)
        self.assertIn(1, cache)
        self.assertIn(3, cache)
        self.assertNotIn(2, cache)  # 2 dropped entirely in turn
        self.assert_invariants(cache)

    def test_ghost_hits_adapt_p(self):
        # ARC cases II/III: hits in B1 increase p, hits in B2
        # decrease p, and REPLACE honors the new target
        cache = ARCCache(maxsize=2)

        cache[1] = 1  # T1=[1]
        cache[2] = 2  # T1=[1, 2]
        cache[3] = 3  # 1 dropped (T1 full), T1=[2, 3]
        cache[2]  # T1 hit: T1=[3], T2=[2]
        self.assertEqual(cache.p, 0)

        cache[4] = 4  # miss: REPLACE evicts T1 LRU 3 -> B1, T1=[4]
        self.assertNotIn(3, cache)
        self.assertEqual(set(cache), {2, 4})
        self.assert_invariants(cache)

        cache[3] = 3  # B1 hit: p = 0 + max(|B2|/|B1|, 1) = 1;
        # REPLACE with |T1| = 1 = p evicts T2 LRU 2 -> B2
        self.assertEqual(cache.p, 1)
        self.assertEqual(set(cache), {3, 4})
        self.assertNotIn(2, cache)
        self.assert_invariants(cache)

        cache[5] = 5  # miss: |T1| = 1 = p, REPLACE evicts T2 LRU
        # 3 -> B2, T1=[4, 5]
        self.assertEqual(cache.p, 1)
        self.assertEqual(set(cache), {4, 5})
        self.assertNotIn(3, cache)
        self.assert_invariants(cache)

        cache[2] = 2  # B2 hit: p = 1 - max(|B1|/|B2|, 1) = 0;
        # REPLACE evicts T1 LRU 4 -> B1
        self.assertEqual(cache.p, 0)
        self.assertEqual(set(cache), {2, 5})
        self.assertNotIn(4, cache)
        self.assert_invariants(cache)

    def test_scan_resistance(self):
        # a one-time scan must not evict frequently used items
        cache = ARCCache(maxsize=4)

        for key in (1, 2, 3, 4):
            cache[key] = key
        for key in (1, 2, 3, 4):
            cache[key]  # second reference: all promoted to T2
        self.assertEqual(cache.p, 0)
        self.assert_invariants(cache)

        # scan eight one-shot items through the cache
        for key in range(101, 109):
            cache[key] = key
            self.assert_invariants(cache)

        # LRU would have evicted all of 1..4; ARC keeps 2, 3, 4
        self.assertIn(2, cache)
        self.assertIn(3, cache)
        self.assertIn(4, cache)
        self.assertNotIn(1, cache)  # LRU of T2, displaced by 101
        for key in range(101, 108):
            self.assertNotIn(key, cache)
        self.assertIn(108, cache)
        self.assertEqual(cache.p, 0)

        # re-referencing scanned items (now in B1) adapts p upwards
        cache[105] = 105  # B1 hit: p = 1, evicts T2 LRU 2 -> B2
        self.assertEqual(cache.p, 1)
        self.assertNotIn(2, cache)
        self.assert_invariants(cache)

        cache[106] = 106  # B1 hit: p = 2, evicts T2 LRU 3 -> B2
        self.assertEqual(cache.p, 2)
        self.assertNotIn(3, cache)
        self.assert_invariants(cache)

        cache[107] = 107  # B1 hit: p = min(2 + 3, 4) = 4 (clamped)
        self.assertEqual(cache.p, 4)
        self.assertEqual(set(cache), {105, 106, 107, 108})
        self.assert_invariants(cache)

        # a hit in B2 adapts p downwards again
        cache[1] = 1  # B2 hit: p = 4 - max(0/4, 1) = 3
        self.assertEqual(cache.p, 3)
        self.assertEqual(set(cache), {1, 106, 107, 108})
        self.assertNotIn(105, cache)  # evicted to B2
        self.assert_invariants(cache)

    def test_history_bounded_and_trimmed(self):
        # ARC case IV-B: once T1+T2+B1+B2 reaches 2 * maxsize, the
        # LRU key of B2 is forgotten entirely
        cache = ARCCache(maxsize=4)

        for key in (1, 2, 3, 4):
            cache[key] = key
        for key in (1, 2, 3, 4):
            cache[key]
        for key in range(101, 109):
            cache[key] = key
        cache[105] = 105
        cache[106] = 106
        cache[107] = 107
        cache[1] = 1
        # T1=[108], T2=[106, 107, 1], B1=[], B2=[2, 3, 4, 105], p=3
        self.assertEqual(cache.p, 3)
        self.assert_invariants(cache)

        cache[109] = 109  # total = 2c: B2 LRU 2 forgotten, 106 -> B2
        self.assertEqual(cache.p, 3)
        self.assertEqual(set(cache), {1, 107, 108, 109})
        self.assert_invariants(cache)

        cache[2] = 2  # complete miss (2 no longer in B2): p unchanged
        self.assertEqual(cache.p, 3)
        self.assert_invariants(cache)

    def test_delete_pop_clear_consistency(self):
        cache = ARCCache(maxsize=3)

        cache[1] = 1
        cache[2] = 2
        cache[3] = 3
        cache[1]  # promote 1 to T2
        cache[4] = 4  # evicts T1 LRU 2 -> B1
        self.assertEqual(set(cache), {1, 3, 4})
        self.assert_invariants(cache)

        # explicit deletion removes the item without ghosting it
        del cache[1]
        self.assertEqual(len(cache), 2)
        self.assertEqual(set(cache), {3, 4})
        self.assert_invariants(cache)

        # the freed slot is reused without spurious eviction; the
        # B1 history is trimmed first, forgetting 2 entirely
        cache[5] = 5
        self.assertEqual(set(cache), {3, 4, 5})
        self.assertEqual(cache.p, 0)
        self.assert_invariants(cache)

        self.assertEqual(cache.pop(3), 3)
        self.assertEqual(set(cache), {4, 5})
        self.assert_invariants(cache)

        cache[6] = 6
        self.assertEqual(set(cache), {4, 5, 6})
        self.assert_invariants(cache)

        cache[4]  # promote 4 to T2
        cache[7] = 7  # evicts T1 LRU 5 -> B1
        self.assertEqual(set(cache), {4, 6, 7})
        self.assert_invariants(cache)

        cache[5] = 5  # B1 hit: p = 1, evicts T1 LRU 6 -> B1
        self.assertEqual(cache.p, 1)
        self.assertEqual(set(cache), {4, 5, 7})
        self.assert_invariants(cache)

        # clear() resets the adaptation parameter and all lists
        cache.clear()
        self.assertEqual(len(cache), 0)
        self.assertEqual(cache.currsize, 0)
        self.assertEqual(cache.p, 0)
        self.assert_invariants(cache)

        cache[7] = 7
        cache[8] = 8
        self.assertEqual(set(cache), {7, 8})
        self.assert_invariants(cache)

    def test_popitem_uses_replace(self):
        cache = ARCCache(maxsize=2)

        cache[1] = 1
        cache[2] = 2
        cache[1]  # promote 1 to T2; T1=[2], T2=[1]

        # p = 0 < |T1|: REPLACE selects the LRU item of T1
        self.assertEqual(cache.popitem(), (2, 2))
        self.assertEqual(set(cache), {1})
        self.assert_invariants(cache)

        self.assertEqual(cache.popitem(), (1, 1))
        self.assertEqual(len(cache), 0)
        self.assert_invariants(cache)

        with self.assertRaises(KeyError):
            cache.popitem()

    def test_random_workload_invariants(self):
        import random

        rng = random.Random(42)
        cache = ARCCache(maxsize=10)
        for _ in range(10000):
            key = rng.randrange(50)
            op = rng.random()
            if op < 0.2:
                cache.pop(key, None)
            elif op < 0.5:
                cache[key] = key
            else:
                cache.get(key)
            self.assert_invariants(cache)

    def test_cached_decorator(self):
        calls = []

        @cached(cache=ARCCache(maxsize=2), info=True)
        def func(x):
            calls.append(x)
            return -x

        self.assertEqual(func(1), -1)
        self.assertEqual(func(2), -2)
        self.assertEqual(func(1), -1)  # hit: promote to T2
        self.assertEqual(func(2), -2)  # hit: promote to T2
        self.assertEqual(calls, [1, 2])

        func(3)  # scan: evicts T2 LRU 1
        func(4)  # scan: evicts T1 item 3
        self.assertEqual(calls, [1, 2, 3, 4])

        self.assertEqual(func(2), -2)  # still cached (LRU would miss)
        self.assertEqual(calls, [1, 2, 3, 4])

        info = func.cache_info()
        self.assertEqual((info.hits, info.misses), (3, 4))
        self.assertEqual((info.maxsize, info.currsize), (2, 2))

        func.cache_clear()
        self.assertEqual(len(func.cache), 0)
        self.assertEqual(func.cache.p, 0)
