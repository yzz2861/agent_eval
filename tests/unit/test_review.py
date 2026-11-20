"""
Tests for the offline evidence-driven CPE review layer.
"""

import os
import shutil
import tempfile
import unittest

from cpe.review.fixtures.devices import (
    build_assets,
    build_advisories,
    build_updated_assets,
    ALPHA_FIRMWARE_ALT,
)
from cpe.review.inventory import InventoryStore
from cpe.review.model import (
    Asset,
    AdvisoryEntry,
    REL_SAME,
    REL_CONTAINED,
    REL_SUPPLIED,
    DISPOSITION_ACTIONABLE,
    DISPOSITION_REVIEW,
    DISPOSITION_EXCLUDED,
)
from cpe.review.review import OfflineReview

class OfflineReviewTest(unittest.TestCase):
    def setUp(self):
        self.assets = build_assets()
        self.advisories = build_advisories()
        self.review = OfflineReview(self.assets, self.advisories)
        self.result = self.review.run()

    def _relations(self, kind, asset_id=None):
        return [r for r in self.result.relations
                if r.kind == kind and
                (asset_id is None or r.asset_id == asset_id)]

    def test_three_relation_kinds_collected(self):
        self.assertTrue(self._relations(REL_SAME))
        self.assertTrue(self._relations(REL_CONTAINED))
        self.assertTrue(self._relations(REL_SUPPLIED))

    def test_containment_walks_provable_chain(self):
        contained = self._relations(REL_CONTAINED, "gw-alpha-01")
        targets = {r.object_cpe for r in contained}
        engine = [c for c in self.assets[0].component_cpes
                  if "packet_engine" in c][0]
        self.assertIn(engine, targets)
        for relation in contained:
            self.assertEqual(relation.chain[-1], relation.object_cpe)
            self.assertTrue(relation.chain)
            for evidence in relation.evidence:
                self.assertEqual(evidence.source, "hierarchy")
                self.assertTrue(evidence.detail["edges"])

    def test_only_same_relations_are_folded(self):
        folds = self.review.fold_identities(self.result)
        names = set()
        for group in folds.values():
            names.update(group)
        self.assertIn(ALPHA_FIRMWARE_ALT, names)
        # Containment proofs never produce folded identifiers.
        contained_objects = {r.object_cpe
                              for r in self._relations(REL_CONTAINED)}
        self.assertFalse(contained_objects & names)

        # Every folded name must be an endpoint of a same relation;
        # supplied and contained relations never introduce fold members.
        same_endpoints = set()
        for relation in self._relations(REL_SAME):
            same_endpoints.add(relation.subject_cpe)
            same_endpoints.add(relation.object_cpe)
        self.assertTrue(names.issubset(same_endpoints))

        # The declaration-only device has no same relation, proving its
        # supplier claim cannot trigger folding by itself.
        self.assertEqual(self._relations(REL_SAME, "gw-charlie-03"), [])
        self.assertEqual(
            self._relations(REL_CONTAINED, "gw-charlie-03"), [])

    def test_dispositions_reflect_evidence_quality(self):
        items = self.result.dispositions
        self.assertEqual(items["gw-alpha-01"].disposition,
                         DISPOSITION_ACTIONABLE)
        self.assertEqual(items["gw-bravo-02"].disposition,
                         DISPOSITION_ACTIONABLE)
        self.assertEqual(items["gw-charlie-03"].disposition,
                         DISPOSITION_REVIEW)
        charlie = items["gw-charlie-03"]
        self.assertTrue(
            all(r.kind == REL_SUPPLIED for r in charlie.relations))
        self.assertEqual(len(charlie.relations), 1)

    def test_enclosure_is_rejected_not_actionable(self):
        for asset_id, item in self.result.dispositions.items():
            self.assertTrue(item.rejections)
            for rejection in item.rejections:
                self.assertFalse(rejection.supports)
                self.assertEqual(rejection.detail["type"],
                                 "name_layer_only")
                self.assertIn("enclosure", rejection.detail["enclosure_cpe"])
            enclosure_cpes = set(self.assets[
                [a.asset_id for a in self.assets].index(asset_id)]
                .enclosure_cpes)
            self.assertFalse(enclosure_cpes & set(item.matched_cpe))

    def test_supplied_relation_never_actionable_alone(self):
        charlie = self.result.dispositions["gw-charlie-03"]
        self.assertNotEqual(charlie.disposition,
                            DISPOSITION_ACTIONABLE)
        relation = charlie.relations[0]
        self.assertEqual(relation.evidence[0].source,
                         "supplier-declaration")
        self.assertFalse(
            relation.evidence[0].detail["queryable_record"])

    def test_containment_requires_explicit_parent_links(self):
        device = 'cpe:2.3:h:acme:gx_900:r1:*:*:*:*:*:*:*'
        dist = 'cpe:2.3:a:acme:secure_dist:1.8.0:*:*:*:*:*:*:*'
        component = 'cpe:2.3:a:acme:packet_engine:3.1.4:*:*:*:*:*:*:*'
        asset = Asset('gx-no-links', 'host', device,
                      component_cpes=[dist, component])
        advisory = AdvisoryEntry(
            'A1', 'cpe:2.3:a:acme:secure_dist:*:*:*:*:*:*:*:*')
        result = OfflineReview([asset], [advisory]).run()
        self.assertFalse(
            [r for r in result.relations if r.kind == REL_CONTAINED])
        item = result.dispositions['gx-no-links']
        self.assertNotIn(component, item.matched_cpe)
        self.assertIn(dist, item.matched_cpe)


class InventoryUpdateTest(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.mkdtemp()
        self.store = InventoryStore(os.path.join(self.directory,
                                    "inventory.json"))
        self.assets = build_assets()
        self.advisories = build_advisories()
        self.store.save_snapshot(self.assets, self.advisories)

    def tearDown(self):
        shutil.rmtree(self.directory, ignore_errors=True)

    def test_snapshot_roundtrip(self):
        loaded_assets, loaded_advisories = self.store.load_snapshot()
        self.assertEqual(len(loaded_assets), len(self.assets))
        self.assertEqual(len(loaded_advisories), len(self.advisories))
        alpha = loaded_assets[0]
        self.assertTrue(alpha.identity_aliases)
        self.assertTrue(alpha.parent_links)

    def test_update_explains_disappeared_proofs(self):
        new_assets = build_updated_assets()
        new_result, diff = self.store.update_and_diff(
            new_assets, self.advisories)
        removed = [c for c in diff["proof_changes"]
                   if c["change"] == "proof_removed"]
        kinds = {c["kind"] for c in removed}
        self.assertIn(REL_SAME, kinds)
        self.assertIn(REL_CONTAINED, kinds)
        self.assertIn(REL_SUPPLIED, kinds)
        for change in removed:
            self.assertTrue(change["lost_evidence"])
            self.assertTrue(change["explanation"])
        contained_removed = [c for c in removed
                             if c["kind"] == REL_CONTAINED]
        self.assertTrue(any(c["chain"] for c in contained_removed))
        levels = {c["asset_id"]: c["new_disposition"]
                  for c in diff["disposition_changes"]}
        self.assertEqual(levels["gw-charlie-03"],
                         DISPOSITION_EXCLUDED)
        self.assertEqual(
            new_result.dispositions["gw-alpha-01"].disposition,
            DISPOSITION_ACTIONABLE)

    def test_unchanged_inventory_has_no_diff(self):
        _, diff = self.store.update_and_diff(
            self.assets, self.advisories)
        self.assertEqual(diff["proof_changes"], [])
        self.assertEqual(diff["disposition_changes"], [])


if __name__ == "__main__":
    unittest.main()
