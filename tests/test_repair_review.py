# Copyright New York University and the in-toto contributors
# SPDX-License-Identifier: Apache-2.0

import json
import os
import tempfile
import unittest

from in_toto.models.layout import Layout, Step
from in_toto.models.link import FILENAME_FORMAT, Link
from in_toto.models.metadata import Metablock
from in_toto.repair_review import review_repairs
from tests.common import SignerStore, TmpDirMixin


class _Metadata:
    def __init__(self, payload):
        self._payload = payload

    def get_payload(self):
        return self._payload


class TestRepairReview(unittest.TestCase):
    def setUp(self):
        self.key_a = "a" * 40
        self.key_b = "b" * 40
        self.hash_a = {"sha256": "1" * 64}
        self.hash_b = {"sha256": "2" * 64}

    def test_equal_cost_conflicting_material_chains(self):
        layout = Layout(
            steps=[
                Step(
                    name="build",
                    pubkeys=[self.key_a, self.key_b],
                    threshold=2,
                    expected_materials=[
                        [
                            "MATCH",
                            "source.tar",
                            "WITH",
                            "PRODUCTS",
                            "FROM",
                            "source",
                        ],
                    ],
                    expected_products=[
                        ["ALLOW", "product"],
                        ["DISALLOW", "*"],
                    ],
                )
            ]
        )
        links = {
            "build": {
                self.key_a: _Metadata(
                    Link(
                        name="build",
                        materials={"source.tar": self.hash_a},
                        products={"product": self.hash_a},
                    )
                ),
                self.key_b: _Metadata(
                    Link(
                        name="build",
                        materials={"source.tar": self.hash_b},
                        products={"product": self.hash_a},
                    )
                ),
            },
            "source": {
                self.key_a: _Metadata(
                    Link(products={"source.tar": self.hash_a})
                ),
                self.key_b: _Metadata(
                    Link(products={"source.tar": self.hash_b})
                ),
            },
        }

        options = review_repairs(layout, links)
        json.dumps(options[0].to_dict())

        self.assertEqual([option.cost for option in options], [1, 1])
        self.assertEqual(
            [option.candidate_keyid for option in options],
            [self.key_a, self.key_b],
        )
        for option in options:
            self.assertEqual(option.evidence[0].step_name, "build")
            self.assertEqual(option.evidence[0].action, "resign")
            self.assertEqual(option.evidence[0].threshold, 2)
            self.assertEqual(
                option.evidence[0].artifacts, frozenset(["source.tar"])
            )
            self.assertIn(
                (
                    "build",
                    "materials",
                    2,
                    (
                        "MATCH",
                        "source.tar",
                        "WITH",
                        "PRODUCTS",
                        "FROM",
                        "source",
                    ),
                ),
                option.rules,
            )

    def test_compatible_old_evidence_is_reusable(self):
        layout = Layout(
            steps=[
                Step(
                    name="build",
                    pubkeys=[self.key_a, self.key_b],
                    threshold=2,
                    expected_products=[
                        ["ALLOW", "product"],
                        ["DISALLOW", "*"],
                    ],
                )
            ]
        )
        links = {
            "build": {
                self.key_a: _Metadata(
                    Link(
                        name="build",
                        materials={"source.tar": self.hash_a},
                        products={"product": self.hash_a},
                    )
                ),
                self.key_b: _Metadata(
                    Link(
                        name="build",
                        materials={"source.tar": self.hash_a},
                        products={"product": self.hash_a},
                    )
                ),
            }
        }

        options = review_repairs(layout, links)

        self.assertEqual(len(options), 2)
        self.assertEqual(options[0].cost, 0)
        reusable = {
            (item.step_name, item.keyid, item.action)
            for item in options[0].reusable_evidence
        }
        self.assertEqual(
            reusable,
            {
                ("build", self.key_a, "reuse"),
                ("build", self.key_b, "reuse"),
            },
        )

    def test_require_rule_marks_old_link_for_resign(self):
        layout = Layout(
            steps=[
                Step(
                    name="build",
                    pubkeys=[self.key_a],
                    expected_products=[
                        ["REQUIRE", "missing-product"],
                    ],
                )
            ]
        )
        links = {
            "build": {
                self.key_a: _Metadata(
                    Link(products={"product": self.hash_a})
                )
            }
        }

        options = review_repairs(layout, links)

        self.assertEqual(options[0].cost, 1)
        request = options[0].evidence[0]
        self.assertEqual(request.action, "resign")
        self.assertEqual(request.artifacts, frozenset(["missing-product"]))
        self.assertEqual(request.rule, ("REQUIRE", "missing-product"))

    def test_missing_threshold_requires_new_independent_records(self):
        layout = Layout(
            steps=[
                Step(
                    name="build",
                    pubkeys=[self.key_a, self.key_b],
                    threshold=2,
                )
            ]
        )
        links = {
            "build": {
                self.key_a: _Metadata(
                    Link(products={"product": self.hash_a})
                )
            }
        }

        options = review_repairs(layout, links)

        self.assertEqual(options[0].cost, 1)
        request = options[0].evidence[0]
        self.assertEqual(request.action, "record")
        self.assertEqual(request.keyid, self.key_b)
        self.assertEqual(request.threshold, 2)

    def test_no_existing_chain_returns_one_cold_start_option(self):
        layout = Layout(
            steps=[
                Step(
                    name="build",
                    pubkeys=[self.key_a, self.key_b],
                    threshold=2,
                )
            ]
        )

        options = review_repairs(layout, {})

        self.assertEqual(len(options), 1)
        self.assertEqual(options[0].cost, 2)
        self.assertEqual(
            [item.keyid for item in options[0].evidence],
            [self.key_a, self.key_b],
        )
        self.assertTrue(
            all(item.action == "record" for item in options[0].evidence)
        )

    def test_cross_step_match_does_not_double_count_team_evidence(self):
        product_hash = {"sha256": "9" * 64}
        layout = Layout(
            steps=[
                Step(
                    name="source",
                    pubkeys=[self.key_a, self.key_b],
                    threshold=2,
                    expected_products=[
                        ["ALLOW", "source.tar"],
                        ["DISALLOW", "*"],
                    ],
                ),
                Step(
                    name="build",
                    pubkeys=[self.key_a, self.key_b],
                    threshold=2,
                    expected_materials=[
                        [
                            "MATCH",
                            "source.tar",
                            "WITH",
                            "PRODUCTS",
                            "FROM",
                            "source",
                        ]
                    ],
                    expected_products=[
                        ["ALLOW", "product"],
                        ["DISALLOW", "*"],
                    ],
                ),
            ]
        )
        links = {
            "source": {
                self.key_a: _Metadata(
                    Link(products={"source.tar": self.hash_a})
                ),
                self.key_b: _Metadata(
                    Link(products={"source.tar": self.hash_b})
                ),
            },
            "build": {
                self.key_a: _Metadata(
                    Link(
                        materials={"source.tar": self.hash_a},
                        products={"product": product_hash},
                    )
                ),
                self.key_b: _Metadata(
                    Link(
                        materials={"source.tar": self.hash_b},
                        products={"product": product_hash},
                    )
                ),
            },
        }

        options = review_repairs(layout, links)

        self.assertEqual([option.cost for option in options], [2, 2])
        self.assertEqual(
            [option.candidate_keyid for option in options],
            [self.key_a, self.key_b],
        )
        for option in options:
            steps = {item.step_name for item in option.evidence}
            self.assertEqual(steps, {"source", "build"})
            self.assertTrue(
                all(item.action == "resign" for item in option.evidence)
            )

    def test_prefixed_match_uses_scoped_material_reference(self):
        layout = Layout(
            steps=[
                Step(
                    name="build",
                    pubkeys=[self.key_a],
                    expected_materials=[
                        [
                            "MATCH",
                            "source.tar",
                            "IN",
                            "inputs",
                            "WITH",
                            "PRODUCTS",
                            "IN",
                            "out",
                            "FROM",
                            "source",
                        ]
                    ],
                )
            ]
        )
        links = {
            "build": {
                self.key_a: _Metadata(
                    Link(
                        materials={
                            "inputs/source.tar": self.hash_a,
                            "other/source.tar": self.hash_b,
                        }
                    )
                )
            },
            "source": {
                self.key_a: _Metadata(
                    Link(products={"out/source.tar": self.hash_a})
                )
            },
        }

        options = review_repairs(layout, links)

        self.assertEqual(options[0].cost, 0)

    def test_same_step_match_explains_compatible_threshold_link(self):
        layout = Layout(
            steps=[
                Step(
                    name="build",
                    pubkeys=[self.key_a, self.key_b],
                    threshold=2,
                    expected_materials=[
                        [
                            "MATCH",
                            "source.tar",
                            "WITH",
                            "MATERIALS",
                            "FROM",
                            "build",
                        ]
                    ],
                )
            ]
        )
        links = {
            "build": {
                self.key_a: _Metadata(
                    Link(materials={"source.tar": self.hash_a})
                ),
                self.key_b: _Metadata(
                    Link(materials={"source.tar": self.hash_a})
                ),
            }
        }

        options = review_repairs(layout, links)

        self.assertEqual(options[0].cost, 0)


class TestSublayoutRepairReview(unittest.TestCase, TmpDirMixin):
    def test_sublayout_evidence_uses_namespaced_location(self):
        self.set_up_test_dir()
        try:
            alice = SignerStore.rsa_pub["keyid"]
            bob = SignerStore.ecdsa_pub["keyid"]
            hash_a = {"sha256": "1" * 64}
            hash_b = {"sha256": "2" * 64}

            sublayout = Layout(
                keys={
                    SignerStore.rsa_pub["keyid"]: SignerStore.rsa_pub,
                    SignerStore.ecdsa_pub["keyid"]: SignerStore.ecdsa_pub,
                },
                steps=[
                    Step(
                        name="inner",
                        pubkeys=[alice, bob],
                        threshold=2,
                    )
                ],
            )
            root_layout = Layout(
                steps=[
                    Step(
                        name="delegated",
                        pubkeys=[alice],
                        threshold=1,
                    )
                ]
            )
            sub_metadata = Metablock(signed=sublayout)
            sub_metadata.create_signature(SignerStore.rsa)
            root_links = {"delegated": {alice: sub_metadata}}

            sub_dir = f"delegated.{alice[:8]}"
            os.mkdir(sub_dir)
            for keyid, payload_hash in ((alice, hash_a), (bob, hash_b)):
                link = Metablock(
                    signed=Link(
                        name="inner",
                        products={"product": payload_hash},
                    )
                )
                link.create_signature(SignerStore.rsa)
                link.dump(
                    os.path.join(
                        sub_dir,
                        FILENAME_FORMAT.format(
                            step_name="inner", keyid=keyid
                        ),
                    )
                )

            options = review_repairs(root_layout, root_links, ".")

            self.assertEqual(len(options), 1)
            self.assertEqual(options[0].cost, 1)
            request = options[0].evidence[0]
            self.assertEqual(request.step_name, "inner")
            self.assertEqual(request.keyid, bob)
            self.assertEqual(request.action, "resign")
            self.assertEqual(
                request.location,
                os.path.join(
                    ".",
                    sub_dir,
                    FILENAME_FORMAT.format(step_name="inner", keyid=bob),
                ),
            )
            self.assertEqual(request.threshold, 2)
        finally:
            self.tear_down_test_dir()


if __name__ == "__main__":
    unittest.main()
