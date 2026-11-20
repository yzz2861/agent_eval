"""Unit tests for the enterprise alias arbitration layer."""

from datetime import date
import unittest

from cpe.alias import (
    AliasRegistry,
    AliasRelation,
    Disposition,
    EdgeReason,
    EdgeStatus,
    EnterpriseArbitrator,
    ProductCatalog,
    AssetBook,
    Bulletin,
    RelationConflict,
    ScopeViolation,
    scope_allows,
)


SKYLAKE = "cpe:2.3:a:acme:skylake:1.0:*:*:*:*:*:*:*"
CLOUD = "cpe:2.3:a:acme:cloudengine:1.0:*:*:*:*:*:*:*"
DATABUS = "cpe:2.3:a:acme:databus:2.0:*:*:*:*:*:*:*"
EDGE = "cpe:2.3:a:acme:edgeproxy:3.0:*:*:*:*:*:*:*"


def make_relation(**overrides):
    params = {
        "relation_id": "RX",
        "product_from": "skylake",
        "product_to": "cloudengine",
        "source": "product-office",
        "business_scope": ["BU-ALPHA"],
        "valid_from": "2026-01-01",
        "valid_to": None,
    }
    params.update(overrides)
    return AliasRelation.create(**params)


class ScopeTests(unittest.TestCase):
    def test_explicit_unit_and_prefix_wildcard(self):
        self.assertTrue(scope_allows(["BU-ALPHA"], "BU-ALPHA"))
        self.assertTrue(scope_allows(["BU-*"], "BU-BETA"))
        self.assertFalse(scope_allows(["BU-*"], "OTHER-X"))

    def test_bare_wildcard_is_rejected(self):
        with self.assertRaises(ScopeViolation):
            make_relation(relation_id="BARE", business_scope=["*"])

    def test_empty_scope_is_rejected(self):
        with self.assertRaises(ScopeViolation):
            make_relation(relation_id="EMPTY", business_scope=[])


class RelationLifecycleTests(unittest.TestCase):
    def test_validity_window(self):
        relation = make_relation(valid_from="2026-01-01", valid_to="2026-06-30")
        self.assertFalse(relation.is_active_on("2025-12-31"))
        self.assertTrue(relation.is_active_on("2026-01-01"))
        self.assertTrue(relation.is_active_on("2026-06-30"))
        self.assertFalse(relation.is_active_on("2026-07-01"))

    def test_revocation_is_immutable_and_dated(self):
        relation = make_relation()
        revoked = relation.revoke("2026-09-01")
        self.assertEqual(relation.status, EdgeStatus.ACTIVE)
        self.assertEqual(revoked.status, EdgeStatus.REVOKED)
        self.assertTrue(revoked.is_active_on("2026-08-31"))
        self.assertFalse(revoked.is_active_on("2026-09-01"))

    def test_edge_verdict_distinguishes_scope_reasons(self):
        relation = make_relation(business_scope=["BU-*"])
        allowed, reason = relation.edge_verdict("BU-BETA", "2026-02-01")
        self.assertTrue(allowed)
        self.assertEqual(reason, EdgeReason.AUTHORIZED)
        allowed, reason = relation.edge_verdict("OTHER", "2026-02-01")
        self.assertFalse(allowed)
        self.assertEqual(reason, EdgeReason.UNAUTHORIZED_WILDCARD)

        explicit = make_relation(business_scope=["BU-ALPHA"])
        allowed, reason = explicit.edge_verdict("BU-BETA", "2026-02-01")
        self.assertFalse(allowed)
        self.assertEqual(reason, EdgeReason.OUT_OF_SCOPE)


class RegistryConflictTests(unittest.TestCase):
    def test_conflicting_same_pair_sources_raise(self):
        registry = AliasRegistry()
        registry.register(make_relation(relation_id="A", source="s1"))
        with self.assertRaises(RelationConflict):
            registry.register(make_relation(relation_id="B", source="s2"))
        self.assertEqual(registry.conflict_ids_for("skylake", "cloudengine"),
                         ("A", "B"))

    def test_same_source_renewal_is_allowed(self):
        registry = AliasRegistry()
        registry.register(make_relation(
            relation_id="OLD", valid_to="2026-06-30"))
        registry.register(make_relation(
            relation_id="NEW", valid_from="2026-07-01", valid_to=None))
        self.assertEqual(len(registry.relations), 2)


def build_arbitrator():
    catalog = ProductCatalog()
    catalog.register("skylake", SKYLAKE)
    catalog.register("cloudengine", CLOUD)
    catalog.register("databus", DATABUS)
    catalog.register("edgeproxy", EDGE)

    book_a = AssetBook("book-A")
    book_a.add("A1", "BU-ALPHA", "skylake", SKYLAKE)
    book_a.add("A2", "BU-ALPHA", "databus", DATABUS)
    book_b = AssetBook("book-B")
    book_b.add("B1", "BU-BETA", "cloudengine", CLOUD)

    registry = AliasRegistry()
    registry.register(AliasRelation.create(
        relation_id="R1", product_from="skylake", product_to="cloudengine",
        source="product-office", business_scope=["BU-ALPHA", "BU-BETA"],
        valid_from="2025-01-01", valid_to="2026-06-30"))
    registry.register(AliasRelation.create(
        relation_id="R1-NEW", product_from="skylake", product_to="cloudengine",
        source="product-office", business_scope=["BU-ALPHA"],
        valid_from="2026-07-01", valid_to=None))
    registry.register(AliasRelation.create(
        relation_id="R2", product_from="cloudengine", product_to="databus",
        source="m-and-a", business_scope=["BU-ALPHA"],
        valid_from="2026-01-01", valid_to=None))
    registry.register(AliasRelation.create(
        relation_id="R3", product_from="databus", product_to="edgeproxy",
        source="m-and-a", business_scope=["BU-ALPHA"],
        valid_from="2026-01-01", valid_to=None))

    return EnterpriseArbitrator(registry, catalog), registry, (book_a, book_b)


class ArbitrationTests(unittest.TestCase):
    def setUp(self):
        self.arbitrator, self.registry, self.books = build_arbitrator()
        self.cloud_adv = Bulletin("ADV-CLOUD", CLOUD, "cloud")
        self.edge_adv = Bulletin("ADV-EDGE", EDGE, "edge")

    def test_direct_cpe_equivalence_still_wins(self):
        report = self.arbitrator.run_match(self.books, [self.cloud_adv], "2026-08-01")
        result = report.results[0]
        direct = [e for e in result.matches if e.kind == Disposition.DIRECT_MATCH]
        self.assertTrue(any(e.asset_id == "B1" for e in direct))

    def test_alias_match_uses_authorized_chain(self):
        report = self.arbitrator.run_match(self.books, [self.cloud_adv], "2026-08-01")
        alias_ev = [e for e in report.results[0].matches
                    if e.kind == Disposition.ALIAS_MATCH]
        self.assertTrue(alias_ev)
        a1 = next(e for e in alias_ev if e.asset_id == "A1")
        self.assertEqual(a1.chain, ("R1-NEW",))

    def test_cross_source_chain_requires_every_edge(self):
        report = self.arbitrator.run_match(self.books, [self.edge_adv], "2026-05-01")
        result = report.results[0]
        a1 = next(e for e in result.matches if e.asset_id == "A1")
        self.assertEqual(a1.chain, ("R1", "R2", "R3"))
        # BU-BETA is licensed on R1 but not on R2, so its path is blocked.
        blocked_b1 = next(e for e in result.blocked if e.asset_id == "B1")
        self.assertEqual(blocked_b1.kind, Disposition.BLOCKED_SCOPE)
        self.assertIn("R2", blocked_b1.chain)

    def test_revocation_only_withdraws_affected_matches(self):
        before = self.arbitrator.run_match(self.books, [self.edge_adv], "2026-05-01")
        self.assertTrue(before.results[0].matched)
        self.registry.revoke("R3", date(2026, 9, 1))
        after = self.arbitrator.run_match(self.books, [self.edge_adv], "2026-09-15")
        result = after.results[0]
        # No alias match survives for A1/A2 once R3 is gone ...
        self.assertFalse(any(e.asset_id in ("A1", "A2") for e in result.matches))
        revoked = [e for e in result.blocked if e.kind == Disposition.BLOCKED_REVOKED]
        self.assertTrue(any("R3" in e.chain for e in revoked))
        # ... but the direct CPE match on B2-style assets is untouched.
        cloud = self.arbitrator.run_match(self.books, [self.cloud_adv], "2026-09-15")
        self.assertTrue(cloud.results[0].matched)

    def test_audit_replay_before_revocation_restores_chain(self):
        self.registry.revoke("R3", date(2026, 9, 1))
        replayed = self.arbitrator.run_match(self.books, [self.edge_adv], "2026-05-01")
        a1 = next(e for e in replayed.results[0].matches if e.asset_id == "A1")
        self.assertEqual(a1.chain, ("R1", "R2", "R3"))

    def test_renewal_narrows_scope_to_one_unit(self):
        report = self.arbitrator.run_match(self.books, [self.cloud_adv], "2026-08-01")
        # B1 still matches directly by CPE; the alias from A1 is BU-ALPHA only.
        a1 = next(e for e in report.results[0].matches if e.asset_id == "A1")
        self.assertIn("BU-ALPHA", a1.reason)
        self.assertNotIn("BU-BETA", a1.reason)


class EvidenceMergeTests(unittest.TestCase):
    def test_same_normalized_cpe_merges_without_widening_scope(self):
        catalog = ProductCatalog()
        catalog.register("skylake", SKYLAKE)
        catalog.register("cloudengine", CLOUD)
        book = AssetBook("book-X")
        # Two asset records that normalize to the same WFN key.
        book.add("X1", "BU-ALPHA", "skylake", SKYLAKE)
        book.add("X2", "BU-ALPHA", "skylake", SKYLAKE)
        registry = AliasRegistry()
        registry.register(AliasRelation.create(
            relation_id="R1", product_from="skylake", product_to="cloudengine",
            source="product-office", business_scope=["BU-ALPHA"],
            valid_from="2026-01-01", valid_to=None))
        arbitrator = EnterpriseArbitrator(registry, catalog)
        report = arbitrator.run_match((book,), [Bulletin("ADV", CLOUD, "t")], "2026-02-01")
        matches = report.results[0].matches
        self.assertEqual(len(matches), 1)
        self.assertEqual(matches[0].asset_id, ("X1", "X2"))
        self.assertEqual(matches[0].chain, ("R1",))


if __name__ == "__main__":
    unittest.main()
