# Copyright New York University and the in-toto contributors
# SPDX-License-Identifier: Apache-2.0

"""Tests for dependency-aware re-verification planning."""

import hashlib
import json
import unittest

from in_toto.in_toto_reverify import load_withdrawn_artifacts
from in_toto.models.layout import Layout, Step
from in_toto.models.link import FILENAME_FORMAT, Link
from in_toto.models.metadata import Envelope, Metablock, Metadata
from in_toto.reverification import (
    ACTION_REUSE,
    ACTION_REVERIFY,
    WithdrawnArtifact,
    build_reverification_plan,
    render_plan,
    verify_and_build_plan,
)
from tests.common import SignerStore, TmpDirMixin

KEY = "11" * 32


def _hash(label):
    """Return a valid sha256 hash dictionary for a fixture label."""
    digest = hashlib.sha256(label.encode("utf-8")).hexdigest()
    return {"sha256": digest}


def _step(name, materials=(), products=(), keyid=KEY):
    """Create a single-functionary step with the given rules."""
    return Step(
        name=name,
        pubkeys=[keyid],
        expected_materials=[list(rule) for rule in materials],
        expected_products=[list(rule) for rule in products],
    )


def _five_step_layout(keyid=KEY):
    """Create the five-step fixture with two same-named output branches.

    Both compile-a and compile-b produce ``payload.bin`` but with different
    digests. package-a only depends on compile-a, package-b only on compile-b.
    """
    return Layout(
        steps=[
            _step(
                "fetch",
                products=[["CREATE", "src.tar"]],
                keyid=keyid,
            ),
            _step(
                "compile-a",
                materials=[
                    [
                        "MATCH",
                        "src.tar",
                        "WITH",
                        "PRODUCTS",
                        "FROM",
                        "fetch",
                    ]
                ],
                products=[["CREATE", "payload.bin"]],
                keyid=keyid,
            ),
            _step(
                "compile-b",
                materials=[
                    [
                        "MATCH",
                        "src.tar",
                        "WITH",
                        "PRODUCTS",
                        "FROM",
                        "fetch",
                    ]
                ],
                products=[["CREATE", "payload.bin"]],
                keyid=keyid,
            ),
            _step(
                "package-a",
                materials=[
                    [
                        "MATCH",
                        "payload.bin",
                        "WITH",
                        "PRODUCTS",
                        "FROM",
                        "compile-a",
                    ]
                ],
                products=[["CREATE", "a.pkg"]],
                keyid=keyid,
            ),
            _step(
                "package-b",
                materials=[
                    [
                        "MATCH",
                        "payload.bin",
                        "WITH",
                        "PRODUCTS",
                        "FROM",
                        "compile-b",
                    ]
                ],
                products=[["CREATE", "b.pkg"]],
                keyid=keyid,
            ),
        ],
        keys={keyid: SignerStore.rsa_pub},
    )


def _five_step_links():
    """Return verified link evidence for the five-step fixture."""
    src = _hash("src")
    payload_a = _hash("payload-a")
    payload_b = _hash("payload-b")
    pkg_a = _hash("pkg-a")
    pkg_b = _hash("pkg-b")

    return {
        "fetch": {KEY: Link(name="fetch", products={"src.tar": src})},
        "compile-a": {
            KEY: Link(
                name="compile-a",
                materials={"src.tar": src},
                products={"payload.bin": payload_a},
            )
        },
        "compile-b": {
            KEY: Link(
                name="compile-b",
                materials={"src.tar": src},
                products={"payload.bin": payload_b},
            )
        },
        "package-a": {
            KEY: Link(
                name="package-a",
                materials={"payload.bin": payload_a},
                products={"a.pkg": pkg_a},
            )
        },
        "package-b": {
            KEY: Link(
                name="package-b",
                materials={"payload.bin": payload_b},
                products={"b.pkg": pkg_b},
            )
        },
    }


def _withdraw_branch_a():
    """Explicitly withdraw compile-a's payload product by name and digest."""
    return {
        "step": "compile-a",
        "name": "payload.bin",
        "hashes": _hash("payload-a"),
    }


class TestWithdrawnArtifact(unittest.TestCase):
    """Tests for the withdrawn artifact identity model."""

    def test_wrapper_and_flat_forms(self):
        wrapper = WithdrawnArtifact.from_data(
            {
                "name": "payload.bin",
                "hashes": _hash("payload-a"),
                "step": "compile-a",
            }
        )
        flat = WithdrawnArtifact.from_data(
            {"name": "payload.bin", "sha256": _hash("payload-a")["sha256"]}
        )

        self.assertEqual(wrapper.name, "payload.bin")
        self.assertEqual(wrapper.step, "compile-a")
        self.assertEqual(wrapper.hashes, flat.hashes)

    def test_digest_is_the_identity(self):
        withdrawal = WithdrawnArtifact.from_data(
            {"name": "payload.bin", "hashes": _hash("payload-a")}
        )
        self.assertTrue(
            withdrawal.matches("payload.bin", _hash("payload-a"), "compile-a")
        )
        self.assertFalse(
            withdrawal.matches("payload.bin", _hash("payload-b"), "compile-b")
        )

    def test_step_scopes_withdrawal(self):
        withdrawal = WithdrawnArtifact.from_data(_withdraw_branch_a())
        self.assertTrue(
            withdrawal.matches("payload.bin", _hash("payload-a"), "compile-a")
        )
        self.assertFalse(
            withdrawal.matches("payload.bin", _hash("payload-a"), "compile-b")
        )


class TestBuildReverificationPlan(unittest.TestCase):
    """Tests for dependency-aware plan construction."""

    def test_withdrawal_cuts_only_one_branch(self):
        plan = build_reverification_plan(
            _five_step_layout(),
            _five_step_links(),
            [_withdraw_branch_a()],
            layout_verified=True,
        )

        self.assertEqual(
            plan.retained_steps, ["fetch", "compile-b", "package-b"]
        )
        self.assertEqual(plan.reverify_steps, ["compile-a", "package-a"])
        self.assertEqual(plan.rerun_order, ["compile-a", "package-a"])
        self.assertEqual(plan.get_step("fetch").action, ACTION_REUSE)
        self.assertEqual(plan.get_step("compile-b").action, ACTION_REUSE)
        self.assertEqual(plan.get_step("compile-a").action, ACTION_REVERIFY)
        self.assertEqual(plan.get_step("package-a").action, ACTION_REVERIFY)

    def test_same_name_different_digest_is_not_a_dependency(self):
        plan = build_reverification_plan(
            _five_step_layout(),
            _five_step_links(),
            [_withdraw_branch_a()],
        )

        branch_b = plan.get_step("package-b")
        self.assertEqual(branch_b.action, ACTION_REUSE)
        self.assertTrue(
            any(
                "payload.bin" in dependency.consumer_path
                and dependency.producer == "compile-b"
                for dependency in branch_b.dependencies
            )
        )
        self.assertFalse(
            any(
                dependency.producer == "compile-a"
                for dependency in branch_b.dependencies
            )
        )

    def test_unscoped_withdrawal_matches_digest_only(self):
        withdrawal = {
            "name": "payload.bin",
            "hashes": _hash("payload-a"),
        }
        plan = build_reverification_plan(
            _five_step_layout(),
            _five_step_links(),
            [withdrawal],
        )

        self.assertEqual(plan.reverify_steps, ["compile-a", "package-a"])
        self.assertEqual(plan.unmatched_withdrawals, [])

    def test_unmatched_withdrawal_is_reported(self):
        withdrawal = {
            "name": "payload.bin",
            "hashes": _hash("not-in-the-chain"),
        }
        plan = build_reverification_plan(
            _five_step_layout(),
            _five_step_links(),
            [withdrawal],
        )

        self.assertEqual(plan.reverify_steps, [])
        self.assertEqual(len(plan.unmatched_withdrawals), 1)
        self.assertEqual(
            plan.unmatched_withdrawals[0].hashes,
            _hash("not-in-the-chain"),
        )

    def test_missing_trusted_signature_invalidates_only_that_step(self):
        links = {
            name: next(iter(step_links.values()))
            for name, step_links in _five_step_links().items()
        }
        trusted_signers = {name: [KEY] for name in links}
        trusted_signers["package-b"] = []

        plan = build_reverification_plan(
            _five_step_layout(),
            links,
            [],
            trusted_signers=trusted_signers,
        )

        self.assertEqual(plan.reverify_steps, ["package-b"])
        self.assertEqual(
            plan.get_step("package-b").findings[0]["code"],
            "untrusted_signature",
        )
        self.assertEqual(plan.get_step("package-a").action, ACTION_REUSE)

    def test_plan_is_json_serializable_and_renderable(self):
        plan = build_reverification_plan(
            _five_step_layout(),
            _five_step_links(),
            [_withdraw_branch_a()],
            layout_verified=True,
        )

        data = json.loads(plan.to_json())
        self.assertEqual(
            data["summary"]["reverify"], ["compile-a", "package-a"]
        )
        self.assertTrue(data["layout_verified"])

        rendered = render_plan(plan)
        self.assertIn("[REVERIFY] compile-a", rendered)
        self.assertIn("[REUSE] compile-b", rendered)
        self.assertIn("Rerun order: compile-a, package-a", rendered)
        self.assertIn("payload.bin", rendered)

    def test_dependency_must_match_by_hash(self):
        layout = _five_step_layout()
        links = _five_step_links()
        links["package-a"] = {
            KEY: Link(
                name="package-a",
                materials={"payload.bin": _hash("different-payload")},
                products={"a.pkg": _hash("pkg-a")},
            )
        }

        plan = build_reverification_plan(
            layout,
            links,
            [_withdraw_branch_a()],
        )

        package_a = plan.get_step("package-a")
        self.assertFalse(
            any(
                dependency.producer == "compile-a"
                for dependency in package_a.dependencies
            )
        )
        self.assertEqual(package_a.action, ACTION_REUSE)

    def test_dsse_envelope_link_is_supported(self):
        links = _five_step_links()
        links["fetch"] = {KEY: Envelope.from_signable(links["fetch"][KEY])}

        plan = build_reverification_plan(
            _five_step_layout(),
            links,
            [_withdraw_branch_a()],
        )

        self.assertEqual(plan.get_step("fetch").action, ACTION_REUSE)
        self.assertEqual(plan.get_step("fetch").trusted_signers, [KEY])

    def test_only_consumers_of_the_withdrawn_product_are_cut(self):
        layout = Layout(
            steps=[
                _step(
                    "build",
                    products=[
                        ["CREATE", "payload.bin"],
                        ["CREATE", "sidecar.txt"],
                    ],
                ),
                _step(
                    "consume-payload",
                    materials=[
                        [
                            "MATCH",
                            "payload.bin",
                            "WITH",
                            "PRODUCTS",
                            "FROM",
                            "build",
                        ]
                    ],
                    products=[["CREATE", "a.pkg"]],
                ),
                _step(
                    "consume-sidecar",
                    materials=[
                        [
                            "MATCH",
                            "sidecar.txt",
                            "WITH",
                            "PRODUCTS",
                            "FROM",
                            "build",
                        ]
                    ],
                    products=[["CREATE", "b.pkg"]],
                ),
            ],
            keys={KEY: SignerStore.rsa_pub},
        )
        links = {
            "build": {
                KEY: Link(
                    name="build",
                    products={
                        "payload.bin": _hash("payload"),
                        "sidecar.txt": _hash("sidecar"),
                    },
                )
            },
            "consume-payload": {
                KEY: Link(
                    name="consume-payload",
                    materials={"payload.bin": _hash("payload")},
                    products={"a.pkg": _hash("a")},
                )
            },
            "consume-sidecar": {
                KEY: Link(
                    name="consume-sidecar",
                    materials={"sidecar.txt": _hash("sidecar")},
                    products={"b.pkg": _hash("b")},
                )
            },
        }

        plan = build_reverification_plan(
            layout,
            links,
            [
                {
                    "step": "build",
                    "name": "payload.bin",
                    "hashes": _hash("payload"),
                }
            ],
        )

        self.assertEqual(plan.reverify_steps, ["build", "consume-payload"])
        self.assertEqual(plan.retained_steps, ["consume-sidecar"])
        self.assertFalse(
            any(
                edge.producer == "build"
                for edge in plan.get_step("consume-sidecar").dependencies
                if edge.producer_path == "payload.bin"
            )
        )


class TestVerifyAndBuildPlan(unittest.TestCase, TmpDirMixin):
    """End-to-end test using signed layout and link files."""

    @classmethod
    def setUpClass(cls):
        cls.set_up_test_dir()

    @classmethod
    def tearDownClass(cls):
        cls.tear_down_test_dir()

    def _write_metadata(self, path, signable):
        metadata = Metablock(signed=signable)
        metadata.create_signature(SignerStore.rsa)
        metadata.dump(path)

    def test_verified_five_step_chain(self):
        layout = _five_step_layout(SignerStore.rsa_pub["keyid"])
        self._write_metadata("root.layout", layout)

        for name, links in _five_step_links().items():
            link = next(iter(links.values()))
            self._write_metadata(
                FILENAME_FORMAT.format(
                    step_name=name, keyid=SignerStore.rsa_pub["keyid"]
                ),
                link,
            )

        plan = verify_and_build_plan(
            Metadata.load("root.layout"),
            {SignerStore.rsa_pub["keyid"]: SignerStore.rsa_pub},
            ".",
            [_withdraw_branch_a()],
        )

        self.assertTrue(plan.layout_verified)
        self.assertEqual(plan.reverify_steps, ["compile-a", "package-a"])
        self.assertEqual(
            plan.retained_steps, ["fetch", "compile-b", "package-b"]
        )

    def test_load_withdrawn_artifacts_wrapper(self):
        path = "withdrawn.json"
        with open(path, "w", encoding="utf8") as file_object:
            json.dump(
                {"withdrawn_artifacts": [_withdraw_branch_a()]}, file_object
            )

        records = load_withdrawn_artifacts(path)
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0]["step"], "compile-a")


if __name__ == "__main__":
    unittest.main()
