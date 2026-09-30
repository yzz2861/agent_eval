import unittest

from cachetools import PartitionedLRUCache


class PartitionedLRUCacheTest(unittest.TestCase):
    def assert_consistent(self, cache):
        total = 0
        count = 0
        for partition in cache.partitions:
            partition_size = 0
            partition_count = 0
            for item_partition, item_key in cache:
                if item_partition == partition:
                    partition_size += cache.getsizeof(cache[(partition, item_key)])
                    partition_count += 1
            self.assertEqual(partition_size, cache.partition_currsize(partition))
            total += partition_size
            count += partition_count
        self.assertEqual(total, cache.currsize)
        self.assertEqual(count, len(cache))

    def test_borrow_and_reclaim_idle_capacity(self):
        cache = PartitionedLRUCache(
            maxsize=6,
            partitions={"a": 2, "b": 2},
            getsizeof=len,
        )

        cache[("a", 1)] = "a"
        cache[("a", 2)] = "a"
        cache[("a", 3)] = "a"

        self.assertEqual(1, cache.partition_borrowed("a"))
        self.assertEqual(0, cache.partition_currsize("b"))

        cache[("b", 1)] = "b"
        cache[("b", 2)] = "b"
        cache[("b", 3)] = "b"
        cache[("b", 4)] = "b"

        self.assertNotIn(("a", 1), cache)
        self.assertIn(("a", 2), cache)
        self.assertIn(("a", 3), cache)
        self.assertIn(("b", 1), cache)
        self.assertIn(("b", 2), cache)
        self.assertIn(("b", 3), cache)
        self.assertIn(("b", 4), cache)
        self.assertEqual(6, cache.currsize)
        self.assertEqual(2, cache.partition_currsize("a"))
        self.assertEqual(4, cache.partition_currsize("b"))
        self.assertEqual(0, cache.partition_borrowed("a"))
        self.assertEqual(2, cache.partition_borrowed("b"))
        self.assert_consistent(cache)

    def test_shrink_maxsize_evicts_largest_borrower(self):
        cache = PartitionedLRUCache(
            maxsize=8,
            partitions={"a": 2, "b": 2},
            getsizeof=lambda value: value,
        )

        cache[("a", 1)] = 1
        cache[("a", 2)] = 2
        cache[("b", 3)] = 1
        cache[("b", 4)] = 3

        cache.set_maxsize(6)

        self.assertIn(("a", 1), cache)
        self.assertIn(("a", 2), cache)
        self.assertNotIn(("b", 3), cache)
        self.assertIn(("b", 4), cache)
        self.assertEqual(6, cache.currsize)
        self.assertEqual(3, cache.partition_currsize("a"))
        self.assertEqual(3, cache.partition_currsize("b"))
        self.assert_consistent(cache)

    def test_lru_inside_partition(self):
        cache = PartitionedLRUCache(
            maxsize=6,
            partitions={"a": 2, "b": 2},
            getsizeof=len,
        )

        cache[("a", 1)] = "a"
        cache[("b", 2)] = "b"
        cache[("b", 3)] = "cc"
        cache[("b", 2)]
        cache[("b", 4)] = "dd"
        cache[("c", 5)] = "e"

        self.assertIn(("a", 1), cache)
        self.assertIn(("b", 2), cache)
        self.assertNotIn(("b", 3), cache)
        self.assertIn(("b", 4), cache)
        self.assertIn(("c", 5), cache)
        self.assertEqual(5, cache.currsize)
        self.assert_consistent(cache)

    def test_equal_borrowed_selects_earlier_partition(self):
        cache = PartitionedLRUCache(
            maxsize=6,
            partitions={"a": 2, "b": 2, "c": 2},
            getsizeof=len,
        )

        cache[("a", 1)] = "aaa"
        cache[("b", 2)] = "bbb"
        cache[("c", 3)] = "e"

        self.assertNotIn(("a", 1), cache)
        self.assertIn(("b", 2), cache)
        self.assertIn(("c", 3), cache)
        self.assertEqual(4, cache.currsize)
        self.assert_consistent(cache)

    def test_replace_size_change(self):
        cache = PartitionedLRUCache(
            maxsize=7,
            partitions={"a": 2, "b": 2},
            getsizeof=lambda value: value,
        )

        cache[("a", 1)] = 4
        cache[("b", 2)] = 2
        cache[("a", 1)] = 3

        self.assertEqual(5, cache.currsize)
        self.assertEqual(3, cache.partition_currsize("a"))
        self.assertEqual(2, cache.partition_currsize("b"))

        cache[("a", 1)] = 5

        self.assertEqual(7, cache.currsize)
        self.assertEqual(5, cache.partition_currsize("a"))
        self.assertEqual(2, cache.partition_currsize("b"))

        with self.assertRaises(ValueError):
            cache[("a", 1)] = 6

        self.assertEqual(5, cache[("a", 1)])
        self.assertEqual(7, cache.currsize)
        self.assert_consistent(cache)

    def test_too_large_item_is_atomic(self):
        cache = PartitionedLRUCache(
            maxsize=5,
            partitions={"a": 2, "b": 2},
            getsizeof=lambda value: value,
        )
        cache[("a", 1)] = 2

        with self.assertRaises(ValueError):
            cache[("b", 2)] = 5

        self.assertEqual(("a", "b"), cache.partitions)
        self.assertNotIn(("b", 2), cache)
        self.assertEqual(2, cache.currsize)

        with self.assertRaises(ValueError):
            cache[("a", 1)] = 6

        self.assertEqual(2, cache[("a", 1)])
        self.assertEqual(2, cache.currsize)
        self.assert_consistent(cache)

    def test_adjust_quotas_and_empty_partition(self):
        cache = PartitionedLRUCache(maxsize=8, partitions={"a": 2, "b": 2})

        cache[("a", 1)] = 1
        cache[("b", 2)] = 1
        cache[("c", 3)] = 1
        cache.set_quota("b", 1)
        cache.set_quota("c", 2)

        self.assertEqual(("a", "b", "c"), cache.partitions)
        self.assertEqual(1, cache.partition_currsize("c"))
        self.assertEqual(3, cache.currsize)

        cache.set_quota("a", 1)
        cache.set_quota("b", 1)
        cache.set_quota("c", 1)
        cache.set_maxsize(3)

        self.assertIn(("a", 1), cache)
        self.assertIn(("b", 2), cache)
        self.assertIn(("c", 3), cache)
        self.assertEqual(0, cache.partition_borrowed("a"))
        self.assertEqual(0, cache.partition_borrowed("b"))
        self.assertEqual(0, cache.partition_borrowed("c"))
        self.assertEqual(3, cache.currsize)
        self.assert_consistent(cache)

        cache.clear_partition("c")
        cache.remove_partition("c")
        self.assertEqual(("a", "b"), cache.partitions)

        with self.assertRaises(ValueError):
            cache.remove_partition("a")
