import threading

import pytest

from hpack import InvalidTableIndex
from hpack.table import HeaderTable, table_entry_size


class TestPackageFunctions:
    def test_table_entry_size(self):
        res = table_entry_size(b'TestName', b'TestValue')
        assert res == 49


class TestHeaderTable:
    def test_get_by_index_dynamic_table(self):
        tbl = HeaderTable()
        off = len(HeaderTable.STATIC_TABLE)
        val = (b'TestName', b'TestValue')
        tbl.add(*val)
        res = tbl.get_by_index(off + 1)
        assert res == val

    def test_get_by_index_static_table(self):
        tbl = HeaderTable()
        exp = (b':authority', b'')
        res = tbl.get_by_index(1)
        assert res == exp
        idx = len(HeaderTable.STATIC_TABLE)
        exp = (b'www-authenticate', b'')
        res = tbl.get_by_index(idx)
        assert res == exp

    def test_get_by_index_zero_index(self):
        tbl = HeaderTable()
        with pytest.raises(InvalidTableIndex):
            tbl.get_by_index(0)

    def test_get_by_index_out_of_range(self):
        tbl = HeaderTable()
        off = len(HeaderTable.STATIC_TABLE)
        tbl.add(b'TestName', b'TestValue')
        with pytest.raises(InvalidTableIndex) as e:
            tbl.get_by_index(off + 2)

        assert (
            "Invalid table index %d" % (off + 2) in str(e.value)
        )

    def test_repr(self):
        tbl = HeaderTable()
        tbl.add(b'TestName1', b'TestValue1')
        tbl.add(b'TestName2', b'TestValue2')
        tbl.add(b'TestName2', b'TestValue2')
        exp = (
            "HeaderTable(4096, False, deque(["
            "(b'TestName2', b'TestValue2'), "
            "(b'TestName2', b'TestValue2'), "
            "(b'TestName1', b'TestValue1')"
            "]))"
        )
        res = repr(tbl)
        assert res == exp

    def test_add_to_large(self):
        tbl = HeaderTable()
        # Max size to small to hold the value we specify
        tbl.maxsize = 1
        tbl.add(b'TestName', b'TestValue')
        # Table length should be 0
        assert len(tbl.dynamic_entries) == 0

    def test_search_in_static_full(self):
        tbl = HeaderTable()
        itm = (b':authority', b'')
        exp = (1, itm[0], itm[1])
        res = tbl.search(itm[0], itm[1])
        assert res == exp

    def test_search_in_static_partial(self):
        tbl = HeaderTable()
        exp = (1, b':authority', None)
        res = tbl.search(b':authority', b'NotInTable')
        assert res == exp

    def test_search_in_dynamic_full(self):
        tbl = HeaderTable()
        idx = len(HeaderTable.STATIC_TABLE) + 1
        tbl.add(b'TestName', b'TestValue')
        exp = (idx, b'TestName', b'TestValue')
        res = tbl.search(b'TestName', b'TestValue')
        assert res == exp

    def test_search_in_dynamic_partial(self):
        tbl = HeaderTable()
        idx = len(HeaderTable.STATIC_TABLE) + 1
        tbl.add(b'TestName', b'TestValue')
        exp = (idx, b'TestName', None)
        res = tbl.search(b'TestName', b'NotInTable')
        assert res == exp

    def test_search_no_match(self):
        tbl = HeaderTable()
        tbl.add(b'TestName', b'TestValue')
        res = tbl.search(b'NotInTable', b'NotInTable')
        assert res is None

    def test_maxsize_prop_getter(self):
        tbl = HeaderTable()
        assert tbl.maxsize == HeaderTable.DEFAULT_SIZE

    def test_maxsize_prop_setter(self):
        tbl = HeaderTable()
        exp = int(HeaderTable.DEFAULT_SIZE / 2)
        tbl.maxsize = exp
        assert tbl.resized is True
        assert tbl.maxsize == exp
        tbl.resized = False
        tbl.maxsize = exp
        assert tbl.resized is False
        assert tbl.maxsize == exp

    def test_size(self):
        tbl = HeaderTable()
        for i in range(3):
            tbl.add(b'TestName', b'TestValue')
        res = tbl._current_size
        assert res == 147

    def test_shrink_maxsize_is_zero(self):
        tbl = HeaderTable()
        tbl.add(b'TestName', b'TestValue')
        assert len(tbl.dynamic_entries) == 1
        tbl.maxsize = 0
        assert len(tbl.dynamic_entries) == 0

    def test_shrink_maxsize(self):
        tbl = HeaderTable()
        for i in range(3):
            tbl.add(b'TestName', b'TestValue')

        assert tbl._current_size == 147
        tbl.maxsize = 146
        assert len(tbl.dynamic_entries) == 2
        assert tbl._current_size == 98


def _recomputed_size(tbl: HeaderTable) -> int:
    return sum(
        table_entry_size(name, value)
        for name, value in tbl.dynamic_entries
    )


def _table_invariant_violations(tbl: HeaderTable) -> list[str]:
    violations: list[str] = []
    if tbl._current_size != _recomputed_size(tbl):
        violations.append("tracked size does not match entries")
    if tbl._current_size > tbl.maxsize:
        violations.append("table exceeds maxsize")
    # Every live dynamic index must resolve without error.
    for index in range(
        HeaderTable.STATIC_TABLE_LENGTH + 1,
        HeaderTable.STATIC_TABLE_LENGTH + 1 + len(tbl.dynamic_entries),
    ):
        tbl.get_by_index(index)
    return violations


class TestHeaderTableInvariants:
    def test_tracked_size_matches_entries_after_adds(self):
        tbl = HeaderTable()
        for i in range(5):
            tbl.add(b'name%d' % i, b'value%d' % i)
        assert tbl._current_size == _recomputed_size(tbl)
        assert tbl._current_size <= tbl.maxsize

    def test_oversized_entry_clears_table_and_keeps_size_zero(self):
        tbl = HeaderTable()
        tbl.add(b'name', b'value')
        assert len(tbl.dynamic_entries) == 1

        tbl.maxsize = 1
        tbl.add(b'TestName', b'TestValue')

        assert len(tbl.dynamic_entries) == 0
        assert tbl._current_size == 0
        assert tbl._current_size == _recomputed_size(tbl)

    def test_add_evicts_only_enough_entries_to_fit(self):
        tbl = HeaderTable()
        tbl.maxsize = 100

        tbl.add(b'aa', b'bb')   # size 36
        tbl.add(b'ccc', b'ddd')  # size 38 -> total 74
        tbl.add(b'eeee', b'ffff')  # size 40 -> total 114, evicts oldest

        # The newest two entries survive, the oldest (aa, bb) is evicted.
        assert list(tbl.dynamic_entries) == [
            (b'eeee', b'ffff'),
            (b'ccc', b'ddd'),
        ]
        assert tbl._current_size == 78
        assert tbl._current_size == _recomputed_size(tbl)
        assert tbl._current_size <= tbl.maxsize

    def test_resize_to_zero_clears_entries_and_size(self):
        tbl = HeaderTable()
        for _ in range(3):
            tbl.add(b'TestName', b'TestValue')

        tbl.maxsize = 0

        assert len(tbl.dynamic_entries) == 0
        assert tbl._current_size == 0
        assert tbl.maxsize == 0

    def test_resize_shrinking_is_atomic_and_size_consistent(self):
        tbl = HeaderTable()
        for i in range(6):
            tbl.add(b'name%d' % i, b'value%d' % i)

        original_entries = list(tbl.dynamic_entries)
        tbl.maxsize = 60

        assert tbl._current_size == _recomputed_size(tbl)
        assert tbl._current_size <= 60
        # Surviving entries must be the most recently inserted prefix.
        assert list(tbl.dynamic_entries) == original_entries[:len(tbl.dynamic_entries)]

    def test_resize_growing_preserves_all_entries(self):
        tbl = HeaderTable()
        tbl.maxsize = 60
        tbl.add(b'aa', b'bb')
        tbl.add(b'ccc', b'ddd')
        entries_before = list(tbl.dynamic_entries)
        size_before = tbl._current_size

        tbl.maxsize = 4096

        assert list(tbl.dynamic_entries) == entries_before
        assert tbl._current_size == size_before
        assert tbl._current_size == _recomputed_size(tbl)

    def test_resize_to_same_size_leaves_state_untouched(self):
        tbl = HeaderTable()
        tbl.add(b'aa', b'bb')
        entries_before = list(tbl.dynamic_entries)
        size_before = tbl._current_size

        tbl.maxsize = tbl.maxsize

        assert list(tbl.dynamic_entries) == entries_before
        assert tbl._current_size == size_before
        assert tbl.resized is False

    def test_entry_larger_than_new_maxsize_is_evicted_on_resize(self):
        tbl = HeaderTable()
        tbl.add(b'TestName', b'TestValue')  # size 49
        tbl.maxsize = 10
        assert len(tbl.dynamic_entries) == 0
        assert tbl._current_size == 0

    def test_shrink_helper_evicts_until_table_fits(self):
        tbl = HeaderTable()
        # Build an over-full table directly, then exercise the
        # backward-compatible shrink helper against the live table.
        tbl.maxsize = 100
        tbl.dynamic_entries.clear()
        for i in range(3):
            tbl.dynamic_entries.append((b'TestName', b'TestValue'))
        tbl._current_size = 147
        tbl._shrink()

        assert tbl._current_size == _recomputed_size(tbl)
        assert tbl._current_size <= 100
        assert len(tbl.dynamic_entries) == 2


class TestHeaderTableConcurrency:
    def test_concurrent_add_and_resize_never_break_invariants(self):
        tbl = HeaderTable()
        stop = threading.Event()
        violations: list[str] = []

        def add_entries() -> None:
            for i in range(2000):
                tbl.add(b'name%d' % (i % 20), b'value%d' % i)

        def resize() -> None:
            for size in (4096, 64, 128, 0, 256, 4096):
                tbl.maxsize = size

        def check_invariants() -> None:
            while not stop.is_set():
                violations.extend(_table_invariant_violations(tbl))

        threads = [
            threading.Thread(target=add_entries),
            threading.Thread(target=add_entries),
            threading.Thread(target=resize),
            threading.Thread(target=check_invariants),
        ]
        for thread in threads:
            thread.start()
        for thread in threads[:-1]:
            thread.join()
        stop.set()
        threads[-1].join()

        assert violations == []
        assert tbl._current_size == _recomputed_size(tbl)
        assert tbl._current_size <= tbl.maxsize

    def test_concurrent_reads_never_guess_unknown_index(self):
        tbl = HeaderTable()
        for i in range(10):
            tbl.add(b'name%d' % i, b'value')
        invalid_index = HeaderTable.STATIC_TABLE_LENGTH + len(tbl.dynamic_entries) + 50
        violations: list[str] = []

        def evict() -> None:
            for _ in range(100):
                tbl.maxsize = 0
                for i in range(10):
                    tbl.add(b'name%d' % i, b'value')

        def read_unknown_index() -> None:
            for _ in range(1000):
                try:
                    tbl.get_by_index(invalid_index)
                except InvalidTableIndex:
                    continue
                violations.append("unknown index was not rejected")

        threads = [
            threading.Thread(target=evict),
            threading.Thread(target=read_unknown_index),
        ]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()

        assert violations == []
