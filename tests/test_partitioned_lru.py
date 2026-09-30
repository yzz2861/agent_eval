import unittest

from cachetools import PartitionedLRUCache, PartitionStats


class PartitionedLRUCacheTest(unittest.TestCase):
    def test_quotas_cannot_exceed_maxsize(self):
        with self.assertRaises(ValueError):
            PartitionedLRUCache(maxsize=3, quotas={"a": 2, "b": 2})

        with self.assertRaises(ValueError):
            PartitionedLRUCache(maxsize=3, quotas=[("a", 2), ("b", 2)])

        cache = PartitionedLRUCache(maxsize=4, quotas={"a": 2, "b": 2})
        with self.assertRaises(ValueError):
            cache.set_quota("a", 3)

    def test_negative_sizes(self):
        with self.assertRaises(ValueError):
            PartitionedLRUCache(maxsize=-1)

        with self.assertRaises(ValueError):
            PartitionedLRUCache(maxsize=1, quotas={"a": -1})

        cache = PartitionedLRUCache(
            maxsize=1,
            quotas={"a": 0},
            getsizeof=lambda value: -1,
        )
        with self.assertRaises(ValueError):
            cache["a"][1] = 1

    def test_empty_partitions_and_stats(self):
        cache = PartitionedLRUCache(maxsize=4, quotas={"a": 2, "b": 1})

        self.assertEqual(["a", "b"], list(cache.partitions))
        self.assertEqual(0, len(cache))
        self.assertEqual(0, len(cache["a"]))
        self.assertEqual(
            {
                "a": PartitionStats(0, 2),
                "b": PartitionStats(0, 1),
            },
            cache.stats(),
        )
        self.assertEqual(0, cache.currsize)

    def test_missing_partition(self):
        cache = PartitionedLRUCache(maxsize=2)
        with self.assertRaises(KeyError):
            cache["missing"]

    def test_borrow_and_reclaim(self):
        cache = PartitionedLRUCache(maxsize=5, quotas={"a": 2, "b": 2})
        a, b = cache["a"], cache["b"]

        a["a1"] = 1
        a["a2"] = 1
        b["b1"] = 1
        b["b2"] = 1
        b["b3"] = 1

        self.assertEqual(["b1", "b2", "b3"], list(b))
        self.assertEqual(2, a.currsize)
        self.assertEqual(3, b.currsize)
        self.assertEqual(5, cache.currsize)

        a["a3"] = 1
        self.assertEqual(["a1", "a2", "a3"], list(a))
        self.assertEqual(["b2", "b3"], list(b))
        self.assertEqual(3, a.currsize)
        self.assertEqual(2, b.currsize)
        self.assertEqual(5, cache.currsize)

    def test_reclaim_uses_lru_within_other_partition(self):
        cache = PartitionedLRUCache(maxsize=5, quotas={"a": 2, "b": 1})
        a, b = cache["a"], cache["b"]

        a["a1"] = 1
        a["a2"] = 1
        b["b1"] = 1
        b["b2"] = 1
        b["b3"] = 1
        b["b1"]  # make b1 recently used

        a["a3"] = 1

        self.assertEqual(["a1", "a2", "a3"], list(a))
        self.assertEqual(["b3", "b1"], list(b))
        self.assertEqual(5, cache.currsize)

    def test_writing_partition_reclaims_its_own_borrowed_capacity_first(self):
        cache = PartitionedLRUCache(maxsize=5, quotas={"a": 1, "b": 2})
        a, b = cache["a"], cache["b"]

        a["a1"] = 1
        a["a2"] = 1
        a["a3"] = 1
        b["b1"] = 1
        b["b2"] = 1
        a["a4"] = 1

        self.assertEqual(["a2", "a3", "a4"], list(a))
        self.assertEqual(["b1", "b2"], list(b))
        self.assertEqual(5, cache.currsize)

    def test_reservations_are_not_evicted_for_other_partitions(self):
        cache = PartitionedLRUCache(
            maxsize=5,
            quotas={"a": 2, "b": 2},
            getsizeof=lambda value: value,
        )
        a, b = cache["a"], cache["b"]

        b["b1"] = 2
        a["a1"] = 1

        with self.assertRaises(ValueError):
            a["big"] = 4

        self.assertNotIn("big", a)
        self.assertEqual(["a1"], list(a))
        self.assertEqual(["b1"], list(b))
        self.assertEqual(3, cache.currsize)

    def test_oversized_item(self):
        cache = PartitionedLRUCache(
            maxsize=5,
            quotas={"a": 2},
            getsizeof=lambda value: value,
        )

        with self.assertRaises(ValueError):
            cache["a"][1] = 6

        self.assertNotIn(1, cache["a"])
        self.assertEqual(0, cache.currsize)

    def test_lru_touch_does_not_change_size(self):
        cache = PartitionedLRUCache(maxsize=2, quotas={"a": 0, "b": 0})
        a, b = cache["a"], cache["b"]

        a["a1"] = 1
        a["a2"] = 1
        self.assertIn("a1", a)
        self.assertEqual(a["a1"], 1)

        b["b1"] = 1

        self.assertEqual(["a1"], list(a))
        self.assertEqual(["b1"], list(b))
        self.assertEqual(2, cache.currsize)

    def test_getsizeof_overwrite_grow_reclaims_borrowed_capacity(self):
        cache = PartitionedLRUCache(
            maxsize=6, quotas={"a": 2, "b": 2}, getsizeof=lambda value: value
        )
        a, b = cache["a"], cache["b"]

        a[1] = 1
        b[2] = 2
        b[3] = 3

        a[1] = 3

        self.assertEqual(3, a[1])
        self.assertEqual([1], list(a))
        self.assertEqual([3], list(b))
        self.assertEqual(3, a.currsize)
        self.assertEqual(3, b.currsize)
        self.assertEqual(6, cache.currsize)

    def test_getsizeof_overwrite_shrink_updates_stats(self):
        cache = PartitionedLRUCache(
            maxsize=6,
            quotas={"a": 0},
            getsizeof=lambda value: value,
        )
        a = cache["a"]

        a[1] = 5
        self.assertEqual(5, a.currsize)
        self.assertEqual(5, cache.currsize)

        a[1] = 2
        self.assertEqual(2, a.currsize)
        self.assertEqual(2, cache.currsize)
        self.assertEqual([1], list(a))

    def test_getsizeof_overwrite_too_large_keeps_previous_entry(self):
        cache = PartitionedLRUCache(
            maxsize=5,
            quotas={"a": 2, "b": 2},
            getsizeof=lambda value: value,
        )
        a, b = cache["a"], cache["b"]

        a[1] = 2
        b[2] = 2

        with self.assertRaises(ValueError):
            a[1] = 4

        self.assertEqual(2, a[1])
        self.assertEqual(2, b[2])
        self.assertEqual(4, cache.currsize)
        self.assertEqual(2, a.currsize)
        self.assertEqual(2, b.currsize)

    def test_getsizeof_overwrite_negative_keeps_previous_entry(self):
        cache = PartitionedLRUCache(
            maxsize=5,
            quotas={"a": 2},
            getsizeof=lambda value: value,
        )
        a = cache["a"]
        a[1] = 2

        with self.assertRaises(ValueError):
            a[1] = -1

        self.assertEqual(2, a[1])
        self.assertEqual(2, cache.currsize)

    def test_shrink_evicts_largest_borrower(self):
        cache = PartitionedLRUCache(maxsize=6, quotas={"a": 1, "b": 2})
        a, b = cache["a"], cache["b"]

        a["a1"] = 1
        a["a2"] = 1
        a["a3"] = 1
        b["b1"] = 1
        b["b2"] = 1
        b["b3"] = 1

        cache.set_maxsize(4)

        self.assertEqual(["a3"], list(a))
        self.assertEqual(["b1", "b2", "b3"], list(b))
        self.assertEqual(1, a.currsize)
        self.assertEqual(3, b.currsize)
        self.assertEqual(4, cache.currsize)

    def test_shrink_tie_uses_partition_creation_order(self):
        cache = PartitionedLRUCache(maxsize=4, quotas={"a": 1, "b": 1})
        a, b = cache["a"], cache["b"]

        a["a1"] = 1
        a["a2"] = 1
        b["b1"] = 1
        b["b2"] = 1

        cache.set_maxsize(2)

        self.assertEqual(["a2"], list(a))
        self.assertEqual(["b2"], list(b))

    def test_set_quota_and_resize_sequences(self):
        cache = PartitionedLRUCache(maxsize=4, quotas={"a": 2, "b": 2})
        a, b = cache["a"], cache["b"]

        a["a1"] = 1
        a["a2"] = 1
        b["b1"] = 1
        b["b2"] = 1

        cache.set_quota("a", 1)
        self.assertEqual(PartitionStats(2, 1), cache.stats()["a"])
        self.assertEqual(4, cache.currsize)

        b["b3"] = 1
        self.assertEqual(["a2"], list(a))
        self.assertEqual(["b1", "b2", "b3"], list(b))

        cache.resize(maxsize=6, quotas={"a": 2, "b": 2, "c": 2})
        self.assertEqual(
            {"a": 2, "b": 2, "c": 2},
            cache.quotas,
        )
        self.assertEqual([], list(cache["c"]))
        self.assertEqual(4, cache.currsize)

    def test_invalid_resize_is_atomic(self):
        cache = PartitionedLRUCache(maxsize=4, quotas={"a": 2, "b": 2})
        a, b = cache["a"], cache["b"]
        a["a1"] = 1
        b["b1"] = 1

        with self.assertRaises(ValueError):
            cache.resize(maxsize=3, quotas={"a": 3})

        self.assertEqual(4, cache.maxsize)
        self.assertEqual({"a": 2, "b": 2}, cache.quotas)
        self.assertEqual(["a1"], list(a))
        self.assertEqual(["b1"], list(b))
        self.assertEqual(2, cache.currsize)

    def test_clear_retains_empty_partitions_and_quotas(self):
        cache = PartitionedLRUCache(maxsize=4, quotas={"a": 2, "b": 1})
        cache["a"][1] = 1
        cache["b"][2] = 2

        cache.clear()

        self.assertEqual(["a", "b"], list(cache.partitions))
        self.assertEqual([], list(cache["a"]))
        self.assertEqual([], list(cache["b"]))
        self.assertEqual({"a": 2, "b": 1}, cache.quotas)
        self.assertEqual(0, cache.currsize)
        self.assertEqual(0, len(cache))

    def test_delete_partition_and_recreate_view(self):
        cache = PartitionedLRUCache(maxsize=4, quotas={"a": 2})
        a = cache["a"]
        a["a1"] = 1

        cache.remove_partition("a")
        self.assertNotIn("a", cache)
        self.assertEqual(0, cache.currsize)

        cache.set_quota("a", 1)
        self.assertEqual([], list(a))
        self.assertEqual(1, a.quota)

    def test_partition_size_sums_stay_consistent(self):
        cache = PartitionedLRUCache(
            maxsize=7, quotas={"a": 2, "b": 2}, getsizeof=lambda value: value
        )
        a, b = cache["a"], cache["b"]

        a[1] = 1
        a[2] = 2
        b[3] = 3

        self.assertEqual(3, a.currsize)
        self.assertEqual(3, b.currsize)
        self.assertEqual(6, cache.currsize)
        self.assertEqual(
            cache.currsize,
            sum(stat.currsize for stat in cache.stats().values()),
        )

        a.pop(1)
        self.assertEqual(2, a.currsize)
        self.assertEqual(5, cache.currsize)
        self.assertEqual(
            cache.currsize,
            sum(stat.currsize for stat in cache.stats().values()),
        )

        b.popitem()
        self.assertEqual(0, b.currsize)
        self.assertEqual(2, cache.currsize)
        self.assertEqual(
            cache.currsize,
            sum(stat.currsize for stat in cache.stats().values()),
        )

    def test_flat_tuple_keys_share_partition_state(self):
        cache = PartitionedLRUCache(maxsize=4, quotas={"a": 2, "b": 1})

        cache[("a", 1)] = "one"
        self.assertEqual("one", cache["a"][1])
        self.assertEqual("one", cache[("a", 1)])
        self.assertEqual([("a", 1)], list(cache))
        self.assertEqual(1, len(cache))

        del cache[("a", 1)]
        self.assertNotIn(("a", 1), cache)
        self.assertEqual(0, cache.currsize)


if __name__ == "__main__":
    unittest.main()
