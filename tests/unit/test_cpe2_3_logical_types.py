# -*- coding: utf-8 -*-

"""
Tests for the separated type system of logical values (ANY, NA),
wildcards and unassigned/empty states in WFNs of version 2.3 of CPE
specification.
"""

from cpe.cpe2_3_wfn import CPE2_3_WFN
from cpe.cpeset2_3 import CPESet2_3
from cpe.comp.cpecomp_anyvalue import CPEComponentAnyValue
from cpe.comp.cpecomp_empty import CPEComponentEmpty
from cpe.comp.cpecomp_notapplicable import CPEComponentNotApplicable
from cpe.comp.cpecomp_undefined import CPEComponentUndefined

import unittest


class LogicalTypeSystemTest(unittest.TestCase):
    """
    The four logical states form a closed type system with strict
    equality and an explicit containment truth table.
    """

    def test_equality_is_strict_per_type(self):
        """
        ANY, NA, UNDEFINED and EMPTY are only equal to themselves.
        """
        any1 = CPEComponentAnyValue()
        any2 = CPEComponentAnyValue()
        na1 = CPEComponentNotApplicable()
        na2 = CPEComponentNotApplicable()
        undef1 = CPEComponentUndefined()
        undef2 = CPEComponentUndefined()
        empty1 = CPEComponentEmpty()
        empty2 = CPEComponentEmpty()

        self.assertEqual(any1, any2)
        self.assertEqual(na1, na2)
        self.assertEqual(undef1, undef2)
        self.assertEqual(empty1, empty2)

        for first, second in ((any1, na1), (any1, undef1), (any1, empty1),
                           (na1, undef1), (na1, empty1), (undef1, empty1)):
            self.assertNotEqual(first, second)

    def test_containment_truth_table(self):
        """
        Containment truth table: ANY, UNDEFINED and EMPTY contain
        every value; NA contains only NA.
        """
        any = CPEComponentAnyValue()
        na = CPEComponentNotApplicable()
        undef = CPEComponentUndefined()
        empty = CPEComponentEmpty()

        for container in (any, undef, empty):
            for item in (any, na, undef, empty):
                self.assertIn(item, container)

        for item in (any, undef, empty):
            self.assertNotIn(item, na)
        self.assertIn(na, na)

    def test_matches_truth_table(self):
        """
        matches() implements the matching truth table: ANY, UNDEFINED
        and EMPTY match every value; NA matches only NA.
        """
        any = CPEComponentAnyValue()
        na = CPEComponentNotApplicable()
        undef = CPEComponentUndefined()
        empty = CPEComponentEmpty()

        for container in (any, undef, empty):
            for item in (any, na, undef, empty):
                self.assertTrue(container.matches(item))

        self.assertTrue(na.matches(na))
        self.assertFalse(na.matches(any))
        self.assertFalse(na.matches(undef))
        self.assertFalse(na.matches(empty))

    def test_str_representations(self):
        """
        Each logical state has a distinct human-readable form.
        """
        self.assertEqual(str(CPEComponentAnyValue()), "<ANY>")
        self.assertEqual(str(CPEComponentNotApplicable()), "<NA>")
        self.assertEqual(str(CPEComponentUndefined()), "<UNDEFINED>")
        self.assertEqual(str(CPEComponentEmpty()), "<EMPTY>")


class LogicalSetOperationsTest(unittest.TestCase):
    """
    Intersection, union, difference and legacy compatibility follow
    the documented truth tables.
    """

    def test_intersection(self):
        """
        NA intersects to NA; ANY and UNDEFINED are neutral; EMPTY
        intersects to EMPTY.
        """
        any = CPEComponentAnyValue()
        na = CPEComponentNotApplicable()
        undef = CPEComponentUndefined()
        empty = CPEComponentEmpty()

        self.assertEqual(any.intersection(na), na)
        self.assertEqual(any.intersection(undef), undef)
        self.assertEqual(any.intersection(empty), empty)
        self.assertEqual(any.intersection(any), any)

        self.assertEqual(na.intersection(any), na)
        self.assertEqual(undef.intersection(any), undef)
        self.assertEqual(empty.intersection(any), empty)

        self.assertEqual(undef.intersection(empty), undef)
        self.assertEqual(empty.intersection(undef), undef)

    def test_union(self):
        """
        ANY absorbs everything; NA is neutral; UNDEFINED and EMPTY
        unite to ANY.
        """
        any = CPEComponentAnyValue()
        na = CPEComponentNotApplicable()
        undef = CPEComponentUndefined()
        empty = CPEComponentEmpty()

        self.assertEqual(any.union(na), any)
        self.assertEqual(any.union(undef), any)
        self.assertEqual(any.union(empty), any)
        self.assertEqual(any.union(any), any)

        self.assertEqual(na.union(any), any)
        self.assertEqual(na.union(undef), undef)
        self.assertEqual(na.union(empty), empty)
        self.assertEqual(na.union(na), na)

        self.assertEqual(undef.union(any), any)
        self.assertEqual(undef.union(na), undef)
        self.assertEqual(undef.union(empty), any)
        self.assertEqual(undef.union(undef), undef)

        self.assertEqual(empty.union(any), any)
        self.assertEqual(empty.union(na), empty)
        self.assertEqual(empty.union(undef), any)
        self.assertEqual(empty.union(empty), empty)

    def test_difference(self):
        """
        Subtracting ANY leaves NA; subtracting NA leaves self;
        subtracting self leaves NA.
        """
        any = CPEComponentAnyValue()
        na = CPEComponentNotApplicable()
        undef = CPEComponentUndefined()
        empty = CPEComponentEmpty()

        self.assertEqual(any.difference(na), any)
        self.assertEqual(any.difference(undef), any)
        self.assertEqual(any.difference(empty), any)
        self.assertEqual(any.difference(any), na)

        self.assertEqual(na.difference(any), na)
        self.assertEqual(na.difference(undef), na)
        self.assertEqual(na.difference(empty), na)
        self.assertEqual(na.difference(na), na)

        self.assertEqual(undef.difference(any), na)
        self.assertEqual(undef.difference(undef), na)
        self.assertEqual(undef.difference(empty), undef)
        self.assertEqual(undef.difference(na), undef)

        self.assertEqual(empty.difference(any), na)
        self.assertEqual(empty.difference(undef), empty)
        self.assertEqual(empty.difference(empty), na)
        self.assertEqual(empty.difference(na), empty)

    def test_legacy_compatibility(self):
        """
        NA is only compatible with NA; ANY, UNDEFINED and EMPTY are
        mutually compatible.
        """
        any = CPEComponentAnyValue()
        na = CPEComponentNotApplicable()
        undef = CPEComponentUndefined()
        empty = CPEComponentEmpty()

        self.assertTrue(any.is_compatible_with(undef))
        self.assertTrue(any.is_compatible_with(empty))
        self.assertTrue(undef.is_compatible_with(any))
        self.assertTrue(undef.is_compatible_with(empty))
        self.assertTrue(empty.is_compatible_with(any))
        self.assertTrue(empty.is_compatible_with(undef))

        self.assertFalse(na.is_compatible_with(any))
        self.assertFalse(na.is_compatible_with(undef))
        self.assertFalse(na.is_compatible_with(empty))
        self.assertTrue(na.is_compatible_with(na))

    def test_serialization(self):
        """
        Serialization truth table: ANY -> ANY, NA -> NA,
        UNDEFINED -> ANY, EMPTY -> ANY.
        """
        self.assertEqual(CPEComponentAnyValue().as_wfn(), "ANY")
        self.assertEqual(CPEComponentNotApplicable().as_wfn(), "NA")
        self.assertEqual(CPEComponentUndefined().as_wfn(), "ANY")
        self.assertEqual(CPEComponentEmpty().as_wfn(), "ANY")


class WFNParseTest(unittest.TestCase):
    """
    Parsing of WFN strings separates logical values, wildcards and
    unassigned states, and reports errors with component names.
    """

    def test_logical_any_is_typed(self):
        """
        version=ANY parses to a logical AnyValue component.
        """
        wfn = CPE2_3_WFN('wfn:[part="a", vendor="v", version=ANY]')
        comp = wfn.get_attribute_components("version")[0]
        self.assertIsInstance(comp, CPEComponentAnyValue)

    def test_quoted_any_is_string(self):
        """
        Quoted "ANY" stays a plain string, not the logical value.
        """
        wfn = CPE2_3_WFN('wfn:[part="a", vendor="v", version="ANY"]')
        comp = wfn.get_attribute_components("version")[0]
        self.assertNotIsInstance(comp, CPEComponentAnyValue)
        self.assertEqual(comp.get_value(), '"any"')

    def test_undefined_attribute_is_typed(self):
        """
        Attributes omitted from the WFN are typed as UNDEFINED.
        """
        wfn = CPE2_3_WFN('wfn:[part="a", vendor="v"]')
        comp = wfn.get_attribute_components("version")[0]
        self.assertIsInstance(comp, CPEComponentUndefined)

    def test_error_names_attribute(self):
        """
        Parse errors name the offending attribute.
        """
        with self.assertRaises(ValueError) as ctx:
            CPE2_3_WFN('wfn:[version=FOO]')
        self.assertIn("version", str(ctx.exception))

        with self.assertRaises(ValueError) as ctx:
            CPE2_3_WFN('wfn:[part="a", version=ANY, version=NA]')
        self.assertIn("version", str(ctx.exception))

        with self.assertRaises(ValueError) as ctx:
            CPE2_3_WFN('wfn:[part="a", invented="x"]')
        self.assertIn("invented", str(ctx.exception))


class VersionBoundaryTest(unittest.TestCase):
    """
    Comparisons at version boundaries follow the typed truth table.
    """

    def test_version_equality(self):
        """
        Identical versions are equal; different versions are disjoint.
        """
        w1 = CPE2_3_WFN(r'wfn:[part="a", vendor="v", version="1\.0"]')
        w2 = CPE2_3_WFN(r'wfn:[part="a", vendor="v", version="1\.0"]')
        w3 = CPE2_3_WFN(r'wfn:[part="a", vendor="v", version="1\.0\.1"]')

        self.assertTrue(CPESet2_3.cpe_equal(w1, w2))
        self.assertFalse(CPESet2_3.cpe_equal(w1, w3))
        self.assertTrue(CPESet2_3.cpe_disjoint(w1, w3))

    def test_wildcard_boundaries(self):
        """
        Wildcards at version boundaries: "1.0.*" is not a valid WFN
        version; "1.0" vs "1.0.1" are disjoint.
        """
        with self.assertRaises(ValueError) as ctx:
            CPE2_3_WFN(r'wfn:[part="a", vendor="v", version="1.0.*"]')
        self.assertIn("version", str(ctx.exception))


class SetCombinationTest(unittest.TestCase):
    """
    Set operations on WFNs combine per-attribute results.
    """

    def test_equal(self):
        """
        EQUAL requires identical logical states in every attribute.
        """
        w1 = CPE2_3_WFN('wfn:[part="a", vendor="v", version=ANY]')
        w2 = CPE2_3_WFN('wfn:[part="a", vendor="v", version=ANY]')
        w3 = CPE2_3_WFN('wfn:[part="a", vendor="v"]')

        self.assertTrue(CPESet2_3.cpe_equal(w1, w2))
        self.assertFalse(CPESet2_3.cpe_equal(w1, w3))
        self.assertTrue(CPESet2_3.cpe_equal(w3, w3))

    def test_superset_subset(self):
        """
        ANY and UNDEFINED are matching-equivalent (mutual superset)
        but not equal; neither is a subset of the other.
        """
        w_any = CPE2_3_WFN('wfn:[part="a", vendor="v", version=ANY]')
        w_und = CPE2_3_WFN('wfn:[part="a", vendor="v"]')

        self.assertTrue(CPESet2_3.cpe_superset(w_any, w_und))
        self.assertTrue(CPESet2_3.cpe_superset(w_und, w_any))
        self.assertFalse(CPESet2_3.cpe_subset(w_any, w_und))
        self.assertFalse(CPESet2_3.cpe_subset(w_und, w_any))
        self.assertFalse(CPESet2_3.cpe_equal(w_any, w_und))
        self.assertTrue(CPESet2_3.cpe_equal(w_und, w_und))

    def test_disjoint(self):
        """
        NA is disjoint from defined string values; NA is not
        disjoint from ANY or itself.
        """
        w_na = CPE2_3_WFN('wfn:[part="a", vendor="v", version=NA]')
        w_any = CPE2_3_WFN('wfn:[part="a", vendor="v", version=ANY]')
        w_str = CPE2_3_WFN(r'wfn:[part="a", vendor="v", version="1\.0"]')

        self.assertTrue(CPESet2_3.cpe_disjoint(w_na, w_str))
        self.assertTrue(CPESet2_3.cpe_disjoint(w_str, w_na))
        self.assertFalse(CPESet2_3.cpe_disjoint(w_na, w_any))
        self.assertFalse(CPESet2_3.cpe_disjoint(w_any, w_na))
        self.assertFalse(CPESet2_3.cpe_disjoint(w_na, w_na))


if __name__ == '__main__':
    unittest.main()
