# -*- coding: utf-8 -*-
"""Tests for the collector coverage pre-check."""

from __future__ import absolute_import, unicode_literals

import unittest

from cpe.coverage import (
    CollectionChannel,
    CoveragePrecheck,
    precheck_coverage,
    required_observations,
)


ALL_APPS = "cpe:2.3:a:*:*:*:*:*:*:*:*:*:*"
ACME_APPS = "cpe:2.3:a:acme:*:*:*:*:*:*:*:*:*"
OTHER_APPS = "cpe:2.3:a:other:*:*:*:*:*:*:*:*:*"
ACME_WIDGET_ANY = "cpe:2.3:a:acme:widget:*:*:*:*:*:*:*:*"
ACME_WIDGET_10 = "cpe:2.3:a:acme:widget:1.0:*:*:*:*:*:*:*"
ACME_WIDGET_20 = "cpe:2.3:a:acme:widget:2.0:*:*:*:*:*:*:*"
ACME_WIDGET_42 = "cpe:2.3:a:acme:widget:4.2:*:*:*:*:*:*:*"
ANY_WIDGET_42 = "cpe:2.3:a:*:widget:4.2:*:*:*:*:*:*:*"

VENDOR_PRODUCT = ("vendor", "product")
VENDOR_PRODUCT_VERSION = ("vendor", "product", "version")


class RequiredObservationsTest(unittest.TestCase):
    def test_unversioned_range_only_needs_vendor_and_product(self):
        self.assertEqual(
            required_observations(ACME_WIDGET_ANY),
            ("vendor", "product"),
        )

    def test_versioned_range_needs_version(self):
        self.assertEqual(
            required_observations(ACME_WIDGET_42),
            ("vendor", "product", "version"),
        )


class ObservationCapabilityTest(unittest.TestCase):
    def test_vendor_product_collector_asserts_unversioned_but_not_versioned(self):
        report = precheck_coverage(
            advisories=[ACME_WIDGET_ANY, ACME_WIDGET_42],
            channels=[
                CollectionChannel(
                    "inventory",
                    fields=VENDOR_PRODUCT,
                    assets=ALL_APPS,
                )
            ],
        )

        by_range = dict((item.cpe, item) for item in report)
        self.assertEqual(by_range[ACME_WIDGET_ANY].status, "asserted")
        self.assertEqual(by_range[ACME_WIDGET_42].status, "unclear")
        self.assertEqual(
            by_range[ACME_WIDGET_42].missing_observations,
            ("version",),
        )
        self.assertEqual(by_range[ACME_WIDGET_42].reason,
                         "missing_observation")
        self.assertEqual(report.asserted_ranges, (ACME_WIDGET_ANY,))
        self.assertEqual(report.unclear_ranges, (ACME_WIDGET_42,))

    def test_collector_with_version_asserts_versioned_range(self):
        report = precheck_coverage(
            advisories=[ACME_WIDGET_42],
            channels=[
                CollectionChannel(
                    "versioned-inventory",
                    fields=VENDOR_PRODUCT_VERSION,
                    assets=ACME_APPS,
                )
            ],
        )

        self.assertTrue(report.complete)
        self.assertEqual(report.asserted_ranges, (ACME_WIDGET_42,))

    def test_missing_update_is_reported_as_update(self):
        advisory = "cpe:2.3:a:acme:widget:4.2:sp1:*:*:*:*:*:*"
        report = precheck_coverage(
            advisories=[advisory],
            channels=[
                CollectionChannel(
                    "versioned-inventory",
                    fields=VENDOR_PRODUCT_VERSION,
                    assets=ALL_APPS,
                )
            ],
        )

        self.assertEqual(report[0].status, "unclear")
        self.assertEqual(report[0].missing_observations, ("update",))

    def test_missing_asset_scope_is_reported_when_evidence_exists(self):
        report = precheck_coverage(
            advisories=[ANY_WIDGET_42],
            channels=[
                CollectionChannel(
                    "acme-only",
                    fields=VENDOR_PRODUCT_VERSION,
                    assets=ACME_APPS,
                ),
                CollectionChannel(
                    "other-only",
                    fields=VENDOR_PRODUCT_VERSION,
                    assets=OTHER_APPS,
                ),
            ],
        )

        coverage = report[0]
        self.assertEqual(coverage.status, "unclear")
        self.assertTrue(coverage.partial)
        self.assertEqual(coverage.missing_observations, ("asset_scope",))
        self.assertIn(ACME_WIDGET_42, coverage.asserted_ranges)
        self.assertIn(
            "cpe:2.3:a:other:widget:4.2:*:*:*:*:*:*:*",
            coverage.asserted_ranges,
        )


class SameKindCollectorTest(unittest.TestCase):
    """Two small plans where more collectors of the same kind do not help."""

    def test_duplicate_same_scope_collectors_do_not_change_coverage(self):
        seed = [
            CollectionChannel(
                "vendor-product-1",
                fields=VENDOR_PRODUCT,
                assets=ALL_APPS,
            )
        ]
        one = precheck_coverage([ACME_WIDGET_42], seed)[0]
        many = precheck_coverage(
            [ACME_WIDGET_42],
            seed + [
                CollectionChannel(
                    "vendor-product-2",
                    fields=VENDOR_PRODUCT,
                    assets=ALL_APPS,
                ),
                CollectionChannel(
                    "vendor-product-3",
                    fields=VENDOR_PRODUCT,
                    assets=ALL_APPS,
                ),
            ],
        )[0]

        self.assertEqual(one.status, "unclear")
        self.assertEqual(many.status, "unclear")
        self.assertEqual(one.missing_observations, ("version",))
        self.assertEqual(many.missing_observations, ("version",))
        self.assertEqual(one.asserted_ranges, ())
        self.assertEqual(many.asserted_ranges, ())

    def test_same_scope_subranges_and_same_fields_do_not_change_coverage(self):
        seed = [
            CollectionChannel(
                "vendor-product-acme",
                fields=VENDOR_PRODUCT,
                assets=ACME_APPS,
            )
        ]
        one = precheck_coverage([ACME_WIDGET_42], seed)[0]
        many = precheck_coverage(
            [ACME_WIDGET_42],
            seed + [
                CollectionChannel(
                    "vendor-product-widget",
                    fields=VENDOR_PRODUCT,
                    assets=ACME_WIDGET_ANY,
                ),
                CollectionChannel(
                    "vendor-product-version-wildcard",
                    fields=VENDOR_PRODUCT,
                    assets="cpe:2.3:a:acme:widget:*:*:*:*:*:*:*:*",
                ),
            ],
        )[0]

        self.assertEqual(one.status, "unclear")
        self.assertEqual(many.status, "unclear")
        self.assertEqual(one.missing_observations, ("version",))
        self.assertEqual(many.missing_observations, ("version",))
        self.assertEqual(one.asserted_ranges, ())
        self.assertEqual(many.asserted_ranges, ())

    def test_adding_a_version_observation_changes_the_verdict(self):
        report = precheck_coverage(
            [ACME_WIDGET_42],
            [
                CollectionChannel(
                    "vendor-product",
                    fields=VENDOR_PRODUCT,
                    assets=ACME_APPS,
                ),
                CollectionChannel(
                    "version-add-on",
                    fields=("version",),
                    assets=ACME_APPS,
                ),
            ],
        )

        # A channel must prove all required fields itself.  Splitting the
        # evidence across two collectors does not combine into one observation.
        self.assertEqual(report[0].status, "unclear")
        self.assertEqual(report[0].missing_observations, ("version",))

        complete = precheck_coverage(
            [ACME_WIDGET_42],
            [
                CollectionChannel(
                    "versioned-inventory",
                    fields=VENDOR_PRODUCT_VERSION,
                    assets=ACME_APPS,
                )
            ],
        )
        self.assertEqual(complete[0].status, "asserted")


class OverlapAndExclusionTest(unittest.TestCase):
    def test_overlapping_channels_are_merged_without_duplicate_ranges(self):
        report = precheck_coverage(
            [ACME_WIDGET_42],
            [
                CollectionChannel(
                    "acme-apps",
                    fields=VENDOR_PRODUCT_VERSION,
                    assets=ACME_APPS,
                ),
                CollectionChannel(
                    "all-apps",
                    fields=VENDOR_PRODUCT_VERSION,
                    assets=ALL_APPS,
                ),
            ],
        )

        self.assertEqual(report[0].status, "asserted")
        self.assertEqual(report.asserted_ranges, (ACME_WIDGET_42,))

    def test_two_partial_channels_can_jointly_cover_a_range(self):
        report = precheck_coverage(
            [ACME_WIDGET_42],
            [
                CollectionChannel(
                    "widget-inventory",
                    fields=VENDOR_PRODUCT_VERSION,
                    assets=ACME_WIDGET_ANY,
                ),
                CollectionChannel(
                    "acme-inventory",
                    fields=VENDOR_PRODUCT_VERSION,
                    assets=ACME_APPS,
                ),
            ],
        )

        self.assertEqual(report[0].status, "asserted")

    def test_exclusions_are_merged_then_deducted(self):
        plan = CoveragePrecheck(
            advisories=[ACME_WIDGET_ANY],
            channels=[
                CollectionChannel(
                    "vendor-product",
                    fields=VENDOR_PRODUCT,
                    assets=ALL_APPS,
                )
            ],
            exclusions=[
                ACME_WIDGET_10,
                ACME_WIDGET_10,
                ACME_WIDGET_20,
            ],
        )
        report = plan.run()

        self.assertEqual(plan.merged_exclusions,
                         (ACME_WIDGET_10, ACME_WIDGET_20))
        self.assertEqual(report[0].status, "asserted")
        self.assertEqual(
            report[0].excluded_ranges,
            (ACME_WIDGET_10, ACME_WIDGET_20),
        )
        self.assertEqual(report[0].unclear_ranges, ())

    def test_fully_excluded_range_is_not_a_coverage_gap(self):
        report = precheck_coverage(
            [ACME_WIDGET_ANY],
            [
                CollectionChannel(
                    "vendor-product",
                    fields=VENDOR_PRODUCT,
                    assets=ALL_APPS,
                )
            ],
            exclusions=[ACME_WIDGET_ANY],
        )

        self.assertEqual(report[0].status, "excluded")
        self.assertEqual(report[0].missing_observations, ())
        self.assertTrue(report.complete)

    def test_absent_channel_is_an_asset_scope_gap(self):
        report = precheck_coverage(
            [ACME_WIDGET_ANY],
            [],
        )

        self.assertEqual(report[0].status, "unclear")
        self.assertEqual(report[0].missing_observations, ("asset_scope",))
        self.assertEqual(report[0].reason, "no_channel_covers_range")


class ExistingComparisonRegressionTest(unittest.TestCase):
    def test_cpe_equality_across_bindings_is_unchanged(self):
        from cpe import CPE

        uri = CPE("cpe:/a:mozilla:firefox:2.0::osx:es-es")
        fs = CPE("cpe:2.3:a:mozilla:firefox:2.0:*:osx:es-es:*:*:*:*")
        wfn = CPE(
            'wfn:[part="a", vendor="mozilla", product="firefox", '
            'version="2\\.0", edition="osx", language="es\\-es"]'
        )

        self.assertEqual(uri, fs)
        self.assertEqual(fs, wfn)

    def test_cpe_set_superset_and_name_match_are_unchanged(self):
        from cpe.cpe2_3_wfn import CPE2_3_WFN
        from cpe.cpeset2_3 import CPESet2_3

        broad = CPE2_3_WFN(
            'wfn:[part="a", vendor="microsoft", '
            'product="internet_explorer"]'
        )
        narrow = CPE2_3_WFN(
            'wfn:[part="a", vendor="microsoft", '
            'product="internet_explorer", version="8\\.0\\.6"]'
        )
        candidate = CPE2_3_WFN(
            'wfn:[part="a", vendor="microsoft", '
            'product="internet_explorer", version="8\\.0\\.*"]'
        )

        self.assertTrue(CPESet2_3.cpe_superset(broad, narrow))
        self.assertFalse(CPESet2_3.cpe_superset(narrow, broad))
        self.assertFalse(CPESet2_3.cpe_disjoint(broad, narrow))

        known = CPESet2_3()
        known.append(narrow)
        self.assertTrue(known.name_match(candidate))


if __name__ == "__main__":
    unittest.main()
