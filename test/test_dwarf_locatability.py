#-------------------------------------------------------------------------------
# elftools tests
#
# Read-only semantic queries for the address ranges over which a variable location
# is known. DWARF objects are lightweight stand-ins; the queries only decode
# section data and never touch process memory.
#
# This code is in the public domain
#-------------------------------------------------------------------------------
import os
import unittest
from types import SimpleNamespace

from elftools.elf.elffile import ELFFile

from elftools.common.exceptions import DWARFError
from elftools.dwarf.locationlists import (
    BaseAddressEntry,
    LocationEntry,
)
from elftools.dwarf.locatability import (
    UNPROVABLE_RANGE,
    VariableLocator,
    get_variable_locatable_ranges,
)


def attr(name, form, value):
    return SimpleNamespace(name=name, form=form, value=value)


def make_die(cu, attributes, parent=None, offset=0):
    die = SimpleNamespace(cu=cu, offset=offset, attributes=attributes)
    die.get_parent = lambda: parent
    return die


def make_cu(dwarfinfo, version, top_die, cu_offset=0):
    cu = SimpleNamespace(
        dwarfinfo=dwarfinfo,
        cu_offset=cu_offset,
        header=SimpleNamespace(version=version),
    )
    cu.get_top_DIE = lambda: top_die
    top_die.cu = cu
    return cu


class FakeLocationLists:
    """Returns prebuilt entries per section offset, like LocationLists."""

    def __init__(self, lists):
        self._lists = lists

    def get_location_list_at_offset(self, offset, die=None):
        return list(self._lists[offset])


class FailingLocationLists:
    def get_location_list_at_offset(self, offset, die=None):
        raise DWARFError('missing loclists offset index table')


class FakeRangeLists:
    def __init__(self, entries):
        self._entries = entries

    def get_range_list_at_offset(self, offset, cu=None):
        return list(self._entries[offset])


class FailingRangeLists:
    def get_range_list_at_offset(self, offset, cu=None):
        raise DWARFError('missing rnglists offset index table')


def make_dwarfinfo(loc_lists, range_lists=None):
    return SimpleNamespace(
        location_lists=lambda: loc_lists,
        range_lists=lambda: range_lists,
    )


def loc_attr(offset):
    return attr('DW_AT_location', 'DW_FORM_sec_offset', offset)


class TestSharedLocationList(unittest.TestCase):
    """The same underlying list resolves independently per unit context."""

    def setUp(self):
        self.shared_offset = 0x100
        self.shared_list = [
            BaseAddressEntry(entry_offset=0x100, entry_length=8, base_address=0),
            LocationEntry(entry_offset=0x108, entry_length=10,
                          begin_offset=0x10, end_offset=0x20,
                          loc_expr=[0x91, 0x00], is_absolute=False),
        ]
        self.loc_lists = FakeLocationLists({self.shared_offset: self.shared_list})

    def test_same_list_two_unit_contexts(self):
        dwarfinfo = make_dwarfinfo(self.loc_lists)
        top_a = make_die(None, {'DW_AT_low_pc': attr('DW_AT_low_pc', 'DW_FORM_addr', 0x1000)})
        cu_a = make_cu(dwarfinfo, 4, top_a, cu_offset=0)
        var_a = make_die(cu_a, {'DW_AT_location': loc_attr(self.shared_offset)}, parent=top_a, offset=0x50)
        top_b = make_die(None, {'DW_AT_low_pc': attr('DW_AT_low_pc', 'DW_FORM_addr', 0x8000)})
        cu_b = make_cu(dwarfinfo, 4, top_b, cu_offset=0x400)
        var_b = make_die(cu_b, {'DW_AT_location': loc_attr(self.shared_offset)}, parent=top_b, offset=0x450)

        locator = VariableLocator(dwarfinfo, self.loc_lists)
        ranges_a = locator.get_variable_ranges(var_a)
        ranges_b = locator.get_variable_ranges(var_b)

        self.assertEqual(len(ranges_a), 1)
        self.assertEqual(len(ranges_b), 1)
        # source_offset is the entry's own offset; both units read the same bytes
        self.assertEqual(ranges_a[0].source_offset, 0x108)
        self.assertEqual(ranges_b[0].source_offset, 0x108)
        self.assertEqual(ranges_a[0].begin_address, 0x10)
        self.assertEqual(ranges_b[0].begin_address, 0x10)
        self.assertIsNot(ranges_a, ranges_b)
        self.assertEqual(ranges_a[0].loc_expr, [0x91, 0x00])
        self.assertTrue(ranges_a[0].provable)
        self.assertFalse(ranges_a[0].overlapping)

    def test_unit_base_used_without_base_selection_entry(self):
        # No BaseAddressEntry: relative entries are offsets from the unit
        # base (CU DW_AT_low_pc). The same list yields different ranges.
        rel_list = [
            LocationEntry(entry_offset=0x200, entry_length=10,
                          begin_offset=0x0, end_offset=0x30,
                          loc_expr=[0x91, 0x04], is_absolute=False),
        ]
        loc_lists = FakeLocationLists({0x200: rel_list})
        dwarfinfo = make_dwarfinfo(loc_lists)

        top_a = make_die(None, {'DW_AT_low_pc': attr('DW_AT_low_pc', 'DW_FORM_addr', 0x1000)})
        cu_a = make_cu(dwarfinfo, 3, top_a, cu_offset=0)
        var_a = make_die(cu_a, {'DW_AT_location': loc_attr(0x200)}, parent=top_a)
        top_b = make_die(None, {'DW_AT_low_pc': attr('DW_AT_low_pc', 'DW_FORM_addr', 0x8000)})
        cu_b = make_cu(dwarfinfo, 3, top_b, cu_offset=0x900)
        var_b = make_die(cu_b, {'DW_AT_location': loc_attr(0x200)}, parent=top_b)

        locator = VariableLocator(dwarfinfo, loc_lists)
        ranges_a = locator.get_variable_ranges(var_a)
        ranges_b = locator.get_variable_ranges(var_b)

        self.assertEqual((ranges_a[0].begin_address, ranges_a[0].end_address), (0x1000, 0x1030))
        self.assertEqual((ranges_b[0].begin_address, ranges_b[0].end_address), (0x8000, 0x8030))
        self.assertEqual(ranges_a[0].source_offset, 0x200)

    def test_query_order_does_not_change_results(self):
        dwarfinfo = make_dwarfinfo(self.loc_lists)
        top_a = make_die(None, {'DW_AT_low_pc': attr('DW_AT_low_pc', 'DW_FORM_addr', 0x1000)})
        cu_a = make_cu(dwarfinfo, 4, top_a, 0)
        var_a = make_die(cu_a, {'DW_AT_location': loc_attr(self.shared_offset)}, parent=top_a)
        top_b = make_die(None, {'DW_AT_low_pc': attr('DW_AT_low_pc', 'DW_FORM_addr', 0x8000)})
        cu_b = make_cu(dwarfinfo, 4, top_b, 0x400)
        var_b = make_die(cu_b, {'DW_AT_location': loc_attr(self.shared_offset)}, parent=top_b)

        locator = VariableLocator(dwarfinfo, self.loc_lists)
        first_a = locator.get_variable_ranges(var_a)
        first_b = locator.get_variable_ranges(var_b)
        again_b = locator.get_variable_ranges(var_b)
        again_a = locator.get_variable_ranges(var_a)

        self.assertEqual(first_a, again_a)
        self.assertEqual(first_b, again_b)


class TestDefaultLocationOnly(unittest.TestCase):
    """A list containing only a default location entry stays unprovable."""

    def test_default_entry_retained(self):
        default_only = [
            LocationEntry(entry_offset=0x300, entry_length=6,
                          begin_offset=-1, end_offset=-1,
                          loc_expr=[0x50], is_absolute=True),
        ]
        loc_lists = FakeLocationLists({0x300: default_only})
        dwarfinfo = make_dwarfinfo(loc_lists)
        top = make_die(None, {'DW_AT_low_pc': attr('DW_AT_low_pc', 'DW_FORM_addr', 0x2000)})
        cu = make_cu(dwarfinfo, 5, top)
        var = make_die(cu, {'DW_AT_location': loc_attr(0x300)}, parent=top)

        ranges = VariableLocator(dwarfinfo, loc_lists).get_variable_ranges(var)
        self.assertEqual(len(ranges), 1)
        result = ranges[0]
        self.assertEqual((result.begin_address, result.end_address), UNPROVABLE_RANGE)
        self.assertFalse(result.provable)
        self.assertTrue(result.default_location)
        self.assertEqual(result.loc_expr, [0x50])

    def test_bare_expression_is_unprovable(self):
        # A self-contained DW_FORM_exprloc makes no address claim; it must
        # not be stamped across the whole frame.
        dwarfinfo = make_dwarfinfo(FakeLocationLists({}))
        top = make_die(None, {'DW_AT_low_pc': attr('DW_AT_low_pc', 'DW_FORM_addr', 0x2000)})
        cu = make_cu(dwarfinfo, 5, top)
        expr_attr = attr('DW_AT_location', 'DW_FORM_exprloc', bytes([0x91, 0x08]))
        var = make_die(cu, {"DW_AT_location": expr_attr}, parent=top)

        ranges = VariableLocator(dwarfinfo, dwarfinfo.location_lists()).get_variable_ranges(var)
        self.assertEqual(len(ranges), 1)
        result = ranges[0]
        self.assertFalse(result.provable)
        self.assertTrue(result.default_location)
        self.assertEqual(result.begin_address, -1)
        self.assertEqual(result.loc_expr, bytes([0x91, 0x08]))


class TestMissingIndexTable(unittest.TestCase):
    """A missing loclists/addr index table must degrade, not crash."""

    def test_unresolvable_loclist_is_retained(self):
        loc_lists = FailingLocationLists()
        dwarfinfo = make_dwarfinfo(loc_lists)
        top = make_die(None, {'DW_AT_low_pc': attr('DW_AT_low_pc', 'DW_FORM_addr', 0x3000)})
        cu = make_cu(dwarfinfo, 5, top)
        var = make_die(cu, {'DW_AT_location': loc_attr(0x400)}, parent=top)

        ranges = VariableLocator(dwarfinfo, loc_lists).get_variable_ranges(var)
        self.assertEqual(len(ranges), 1)
        result = ranges[0]
        self.assertFalse(result.provable)
        self.assertTrue(result.default_location)
        self.assertEqual((result.begin_address, result.end_address), UNPROVABLE_RANGE)
        self.assertEqual(result.source_offset, 0x400)

    def test_missing_rnglist_table_does_not_fabricate_scope(self):
        # Location list is fine, but the scope uses DW_AT_ranges whose
        # offset table is missing. Scope is treated as unconstrained.
        good_list = [
            LocationEntry(entry_offset=0x500, entry_length=10,
                          begin_offset=0x40, end_offset=0x80,
                          loc_expr=[0x91], is_absolute=True),
        ]
        loc_lists = FakeLocationLists({0x500: good_list})
        dwarfinfo = make_dwarfinfo(loc_lists, FailingRangeLists())
        top = make_die(None, {'DW_AT_low_pc': attr('DW_AT_low_pc', 'DW_FORM_addr', 0x3000)})
        cu = make_cu(dwarfinfo, 5, top)
        scope_die = make_die(cu, {'DW_AT_ranges': attr('DW_AT_ranges', 'DW_FORM_rnglistx', 0)}, parent=top)
        var = make_die(cu, {'DW_AT_location': loc_attr(0x500)}, parent=scope_die)

        ranges = VariableLocator(dwarfinfo, loc_lists).get_variable_ranges(var)
        self.assertEqual(len(ranges), 1)
        self.assertTrue(ranges[0].provable)
        self.assertEqual((ranges[0].begin_address, ranges[0].end_address), (0x40, 0x80))


class TestOverlappingCandidates(unittest.TestCase):
    """Overlapping entries are all retained and flagged as candidates."""

    def test_overlapping_entries_both_flagged(self):
        entries = [
            LocationEntry(entry_offset=0x600, entry_length=8,
                          begin_offset=0x100, end_offset=0x200,
                          loc_expr=[0x50], is_absolute=True),
            LocationEntry(entry_offset=0x608, entry_length=8,
                          begin_offset=0x180, end_offset=0x300,
                          loc_expr=[0x91, 0x00], is_absolute=True),
        ]
        loc_lists = FakeLocationLists({0x600: entries})
        dwarfinfo = make_dwarfinfo(loc_lists)
        top = make_die(None, {'DW_AT_low_pc': attr('DW_AT_low_pc', 'DW_FORM_addr', 0x100)})
        cu = make_cu(dwarfinfo, 5, top)
        var = make_die(cu, {'DW_AT_location': loc_attr(0x600)}, parent=top)

        ranges = VariableLocator(dwarfinfo, loc_lists).get_variable_ranges(var)
        self.assertEqual(len(ranges), 2)
        self.assertTrue(all(r.overlapping for r in ranges))
        self.assertTrue(all(r.provable for r in ranges))

    def test_disjoint_entries_are_not_overlapping(self):
        entries = [
            LocationEntry(entry_offset=0x700, entry_length=8,
                          begin_offset=0x100, end_offset=0x200,
                          loc_expr=[0x50], is_absolute=True),
            LocationEntry(entry_offset=0x708, entry_length=8,
                          begin_offset=0x200, end_offset=0x300,
                          loc_expr=[0x91], is_absolute=True),
        ]
        loc_lists = FakeLocationLists({0x700: entries})
        dwarfinfo = make_dwarfinfo(loc_lists)
        top = make_die(None, {'DW_AT_low_pc': attr('DW_AT_low_pc', 'DW_FORM_addr', 0x100)})
        cu = make_cu(dwarfinfo, 5, top)
        var = make_die(cu, {'DW_AT_location': loc_attr(0x700)}, parent=top)

        ranges = VariableLocator(dwarfinfo, loc_lists).get_variable_ranges(var)
        self.assertEqual(len(ranges), 2)
        self.assertFalse(any(r.overlapping for r in ranges))
        # Half-open adjacent ranges do not overlap and stay sorted.
        self.assertEqual([r.begin_address for r in ranges], [0x100, 0x200])


class TestScopeIntersection(unittest.TestCase):
    """Location entries are clipped to the lexical scope ranges."""

    def test_clip_to_enclosing_lexical_block(self):
        entries = [
            LocationEntry(entry_offset=0x800, entry_length=8,
                          begin_offset=0x100, end_offset=0x400,
                          loc_expr=[0x50], is_absolute=True),
        ]
        loc_lists = FakeLocationLists({0x800: entries})
        dwarfinfo = make_dwarfinfo(loc_lists)
        top = make_die(None, {'DW_AT_low_pc': attr('DW_AT_low_pc', 'DW_FORM_addr', 0x100)})
        cu = make_cu(dwarfinfo, 5, top)
        block = make_die(cu, {'DW_AT_low_pc': attr('DW_AT_low_pc', 'DW_FORM_addr', 0x200),
                             'DW_AT_high_pc': attr('DW_AT_high_pc', 'DW_FORM_data8', 0x80)},
                      parent=top)
        var = make_die(cu, {'DW_AT_location': loc_attr(0x800)}, parent=block)

        ranges = VariableLocator(dwarfinfo, loc_lists).get_variable_ranges(var)
        self.assertEqual(len(ranges), 1)
        self.assertEqual((ranges[0].begin_address, ranges[0].end_address), (0x200, 0x280))

    def test_clip_to_dw_at_ranges_scope(self):
        from elftools.dwarf.ranges import RangeEntry
        entries = [
            LocationEntry(entry_offset=0x900, entry_length=8,
                          begin_offset=0x100, end_offset=0x500,
                          loc_expr=[0x50], is_absolute=True),
        ]
        loc_lists = FakeLocationLists({0x900: entries})
        scope_entries = [
            RangeEntry(entry_offset=0, entry_length=0, begin_offset=0x200,
                       end_offset=0x300, is_absolute=True),
            RangeEntry(entry_offset=0, entry_length=0, begin_offset=0x400,
                       end_offset=0x480, is_absolute=True),
        ]
        range_lists = FakeRangeLists({0x77: scope_entries})
        dwarfinfo = make_dwarfinfo(loc_lists, range_lists)
        top = make_die(None, {'DW_AT_low_pc': attr('DW_AT_low_pc', 'DW_FORM_addr', 0x100)})
        cu = make_cu(dwarfinfo, 5, top)
        block = make_die(cu, {'DW_AT_ranges': attr('DW_AT_ranges', 'DW_FORM_sec_offset', 0x77)}, parent=top)
        var = make_die(cu, {'DW_AT_location': loc_attr(0x900)}, parent=block)

        ranges = VariableLocator(dwarfinfo, loc_lists).get_variable_ranges(var)
        pieces = sorted((r.begin_address, r.end_address) for r in ranges)
        self.assertEqual(pieces, [(0x200, 0x300), (0x400, 0x480)])

    def test_claim_outside_scope_kept_as_unprovable(self):
        entries = [
            LocationEntry(entry_offset=0xA00, entry_length=8,
                          begin_offset=0x900, end_offset=0xA00,
                          loc_expr=[0x50], is_absolute=True),
        ]
        loc_lists = FakeLocationLists({0xA00: entries})
        dwarfinfo = make_dwarfinfo(loc_lists)
        top = make_die(None, {'DW_AT_low_pc': attr('DW_AT_low_pc', 'DW_FORM_addr', 0x100)})
        cu = make_cu(dwarfinfo, 5, top)
        block = make_die(cu, {'DW_AT_low_pc': attr('DW_AT_low_pc', 'DW_FORM_addr', 0x100),
                             'DW_AT_high_pc': attr('DW_AT_high_pc', 'DW_FORM_data8', 0x10)},
                      parent=top)
        var = make_die(cu, {'DW_AT_location': loc_attr(0xA00)}, parent=block)

        ranges = VariableLocator(dwarfinfo, loc_lists).get_variable_ranges(var)
        self.assertEqual(len(ranges), 1)
        self.assertFalse(ranges[0].provable)
        self.assertEqual((ranges[0].begin_address, ranges[0].end_address), (0x900, 0xA00))


class TestMixedAndOrdering(unittest.TestCase):
    """Default entries coexist with concrete ones; output is deterministic."""

    def test_default_plus_concrete_entries(self):
        entries = [
            LocationEntry(entry_offset=0xB00, entry_length=8,
                          begin_offset=0x100, end_offset=0x200,
                          loc_expr=[0x91, 0x00], is_absolute=True),
            LocationEntry(entry_offset=0xB08, entry_length=6,
                          begin_offset=-1, end_offset=-1,
                          loc_expr=[0x50], is_absolute=True),
        ]
        loc_lists = FakeLocationLists({0xB00: entries})
        dwarfinfo = make_dwarfinfo(loc_lists)
        top = make_die(None, {'DW_AT_low_pc': attr('DW_AT_low_pc', 'DW_FORM_addr', 0x100)})
        cu = make_cu(dwarfinfo, 5, top)
        var = make_die(cu, {'DW_AT_location': loc_attr(0xB00)}, parent=top)

        ranges = VariableLocator(dwarfinfo, loc_lists).get_variable_ranges(var)
        self.assertEqual(len(ranges), 2)
        concrete = [r for r in ranges if r.provable]
        defaults = [r for r in ranges if r.default_location]
        self.assertEqual(len(concrete), 1)
        self.assertEqual(len(defaults), 1)
        self.assertEqual((concrete[0].begin_address, concrete[0].end_address), (0x100, 0x200))
        self.assertEqual((defaults[0].begin_address, defaults[0].end_address), UNPROVABLE_RANGE)
        # Deterministic ordering: concrete first, default last.
        self.assertLess(ranges.index(concrete[0]), ranges.index(defaults[0]))

    def test_convenience_wrapper(self):
        entries = [
            LocationEntry(entry_offset=0xC00, entry_length=8,
                          begin_offset=0x10, end_offset=0x20,
                          loc_expr=[0x50], is_absolute=True),
        ]
        loc_lists = FakeLocationLists({0xC00: entries})
        dwarfinfo = make_dwarfinfo(loc_lists)
        top = make_die(None, {'DW_AT_low_pc': attr('DW_AT_low_pc', 'DW_FORM_addr', 0)})
        cu = make_cu(dwarfinfo, 5, top)
        var = make_die(cu, {'DW_AT_location': loc_attr(0xC00)}, parent=top)

        ranges = get_variable_locatable_ranges(var)
        self.assertEqual(len(ranges), 1)
        self.assertTrue(ranges[0].provable)
        self.assertEqual((ranges[0].begin_address, ranges[0].end_address), (0x10, 0x20))

    def test_no_location_attribute_is_empty(self):
        dwarfinfo = make_dwarfinfo(FakeLocationLists({}))
        top = make_die(None, {'DW_AT_low_pc': attr('DW_AT_low_pc', 'DW_FORM_addr', 0)})
        cu = make_cu(dwarfinfo, 5, top)
        var = make_die(cu, {}, parent=top)
        self.assertEqual(VariableLocator(dwarfinfo).get_variable_ranges(var), [])


if __name__ == '__main__':
    unittest.main()


class TestRealBinaryIntegration(unittest.TestCase):
    """End-to-end, read-only pass over shipped ELF fixtures."""

    def _dwarfinfo(self, name):
        path = os.path.join('test', 'testfiles_for_unittests', name)
        stream = open(path, 'rb')
        self.addCleanup(stream.close)
        return ELFFile(stream).get_dwarf_info()

    def test_llpair_shared_section_two_unit_contexts(self):
        di = self._dwarfinfo('dwarf_llpair.so.elf')
        locator = VariableLocator(di, di.location_lists())
        per_unit = {}
        for cu in di.iter_CUs():
            ranges = [
                r for die in cu.iter_DIEs()
                if 'DW_AT_location' in die.attributes
                for r in locator.get_variable_ranges(die)]
            self.assertTrue(ranges)
            per_unit[cu.cu_offset] = ranges

        # The two CUs (one v5, one v2) share the underlying file-backed
        # location section; each still gets its own decoded range set.
        self.assertEqual(len(per_unit), 2)
        offsets_a = {r.source_offset for r in next(iter(per_unit.values()))}
        offsets_b = {r.source_offset for r in list(per_unit.values())[1]}
        self.assertNotEqual(offsets_a, offsets_b)

    def test_every_range_is_well_formed(self):
        di = self._dwarfinfo('sample_exe64.elf')
        locator = VariableLocator(di, di.location_lists())
        for cu in di.iter_CUs():
            for die in cu.iter_DIEs():
                if 'DW_AT_location' not in die.attributes:
                    continue
                for r in locator.get_variable_ranges(die):
                    if r.provable:
                        self.assertLess(r.begin_address, r.end_address)
                        self.assertFalse(r.default_location)
                    else:
                        self.assertEqual((r.begin_address, r.end_address), UNPROVABLE_RANGE)

    def test_iter_all_sorts_units_and_is_stable(self):
        di = self._dwarfinfo('sample_exe64.elf')
        locator = VariableLocator(di, di.location_lists())
        cus = list(di.iter_CUs())
        forward = list(locator.iter_all_variable_ranges(cus))
        reverse = list(locator.iter_all_variable_ranges(list(reversed(cus))))
        self.assertEqual([d.offset for d, _ in forward], [d.offset for d, _ in reverse])
