# Copyright New York University and the in-toto contributors
# SPDX-License-Identifier: Apache-2.0

"""Tests for the optional artifact absence acceptance layer."""

import os
import shutil
import tempfile
import unittest

from in_toto import acceptance, runlib, verifylib
from in_toto.exceptions import (
    AcceptanceError,
    SignatureVerificationError,
)
from in_toto.models.layout import Layout, Step
from in_toto.models.link import Link
from in_toto.models.metadata import Metablock
from tests.common import SignerStore, VersionedPython

KEY = SignerStore.rsa
PUBKEY = SignerStore.rsa_pub
KEYID = PUBKEY["keyid"]
ENUM = acceptance.ENUMERATION_KEY
CONFIRMED = acceptance.CONFIRMED_NONE
OMISSION = acceptance.ALLOWED_OMISSION
MISSING = acceptance.EVIDENCE_MISSING
PRESENT = acceptance.ARTIFACTS_PRESENT


def make_link(name, products=None, materials=None, enumeration=None):
    """Create a validly signed link metadata object."""
    byproducts = {}
    if enumeration is not None:
        byproducts[ENUM] = enumeration
    link = Link(
        name=name,
        materials=materials or {},
        products=products or {},
        byproducts=byproducts,
    )
    metadata = Metablock(signed=link)
    metadata.create_signature(KEY)
    return metadata


def products_declaration(boundary, complete=True, exclusions=None):
    return {
        "products": {
            "boundary": boundary,
            "complete": complete,
            "exclusions": exclusions or [],
        }
    }


class TestArtifactAbsenceCheck(unittest.TestCase):
    def setUp(self):
        self.check = acceptance.ArtifactAbsenceCheck(
            patterns=["*.debug"], scope=["dist"]
        )

    def audit(self, metadata, label):
        return acceptance.audit_metadata(
            metadata, self.check, PUBKEY, label=label
        )

    def test_two_links_distinguish_confirmed_none_from_missing_evidence(self):
        good = make_link("build", enumeration=products_declaration(["dist"]))
        no_declaration = make_link("build")
        wrong_scope = make_link(
            "build", enumeration=products_declaration(["src"])
        )

        good_obs = self.audit(good, "good.link")
        missing_obs = self.audit(no_declaration, "missing.link")
        wrong_obs = self.audit(wrong_scope, "wrong.link")

        self.assertEqual(good_obs.status, CONFIRMED)
        self.assertIn("complete signed enumeration", good_obs.reason)
        self.assertEqual(good_obs.missing_evidence, [])

        self.assertEqual(missing_obs.status, MISSING)
        self.assertEqual(wrong_obs.status, MISSING)

        missing_text = " ".join(missing_obs.missing_evidence)
        self.assertIn("artifact_enumeration.products.boundary", missing_text)
        self.assertIn("artifact_enumeration.products.complete", missing_text)

        wrong_text = " ".join(wrong_obs.missing_evidence)
        self.assertIn("boundary covering: dist", wrong_text)

        report = acceptance.AcceptanceReport(
            self.check, links=[good_obs, missing_obs]
        )
        text = report.format_text()
        self.assertIn("good.link", text)
        self.assertIn("confirmed_none", text)
        self.assertIn("missing.link", text)
        self.assertIn(
            "needs: signed artifact_enumeration.products.boundary", text
        )
        self.assertFalse(report.ok())

    def test_forbidden_artifact_is_reported(self):
        link = make_link(
            "build",
            products={"dist/app.debug": {"sha256": "a" * 64}},
            enumeration=products_declaration(["dist"]),
        )
        obs = self.audit(link, "present.link")
        self.assertEqual(obs.status, PRESENT)
        self.assertEqual(obs.forbidden_count, 1)

    def test_masking_exclusion_is_not_confirmed(self):
        masked = make_link(
            "build",
            enumeration=products_declaration(
                ["dist"],
                exclusions=[
                    {"pattern": "**/*.debug", "reason": "debug files stripped"}
                ],
            ),
        )
        obs = self.audit(masked, "masked.link")
        self.assertEqual(obs.status, MISSING)

        permissive = acceptance.ArtifactAbsenceCheck(
            patterns=["*.debug"],
            scope=["dist"],
            allow_forbidden_exclusions=True,
        )
        obs = acceptance.audit_metadata(
            masked, permissive, PUBKEY, label="masked.link"
        )
        self.assertEqual(obs.status, OMISSION)

    def test_masking_exclusion_requires_a_reason_even_when_permitted(self):
        masked = make_link(
            "build",
            enumeration=products_declaration(
                ["dist"],
                exclusions=[{"pattern": "**/*.debug"}],
            ),
        )
        permissive = acceptance.ArtifactAbsenceCheck(
            patterns=["*.debug"],
            scope=["dist"],
            allow_forbidden_exclusions=True,
        )
        obs = acceptance.audit_metadata(
            masked, permissive, PUBKEY, label="masked.link"
        )
        self.assertEqual(obs.status, MISSING)
        self.assertIn(
            "has no reason", " ".join(obs.missing_evidence) + obs.reason
        )

    def test_unrelated_exclusion_keeps_confirmed_none(self):
        link = make_link(
            "build",
            enumeration=products_declaration(
                ["dist"],
                exclusions=[
                    {
                        "pattern": "dist/**/*.map",
                        "reason": "maps are out of scope",
                    }
                ],
            ),
        )
        self.assertEqual(self.audit(link, "maps.link").status, CONFIRMED)

    def test_declaration_is_covered_by_the_signature(self):
        metadata = make_link(
            "build", enumeration=products_declaration(["dist"])
        )
        metadata.verify_signature(PUBKEY)
        metadata.signed.byproducts[ENUM]["products"]["boundary"] = ["src"]
        with self.assertRaises(SignatureVerificationError):
            metadata.verify_signature(PUBKEY)


class TestStepCommitments(unittest.TestCase):
    def setUp(self):
        self.check = acceptance.ArtifactAbsenceCheck(
            patterns=["*.debug"], scope=["dist"]
        )

    def test_no_commitment_allows_omission(self):
        step = Step(name="lint", expected_products=[])
        link = Link(name="lint", products={})
        obs = acceptance.audit_link(link, self.check, step=step)
        self.assertEqual(obs.status, OMISSION)

    def test_positive_commitment_requires_enumeration(self):
        step = Step(name="build", expected_products=[["CREATE", "dist/*"]])
        link = Link(name="build", products={})
        obs = acceptance.audit_link(link, self.check, step=step)
        self.assertEqual(obs.status, MISSING)
        self.assertIn("boundary covering: dist", " ".join(obs.missing_evidence))

    def test_commitment_outside_scope_allows_omission(self):
        step = Step(name="package", expected_products=[["CREATE", "pkg/*"]])
        link = Link(name="package", products={})
        obs = acceptance.audit_link(link, self.check, step=step)
        self.assertEqual(obs.status, OMISSION)


class TestIndependentObservations(unittest.TestCase):
    def setUp(self):
        self.check = acceptance.ArtifactAbsenceCheck(
            patterns=["*.debug"], scope=["dist"]
        )
        self.build = Step(
            name="build", expected_products=[["CREATE", "dist/*"]]
        )
        self.package = Step(
            name="package",
            expected_materials=[
                ["MATCH", "*", "WITH", "PRODUCTS", "FROM", "build"]
            ],
            expected_products=[["CREATE", "pkg/*"]],
        )
        self.layout = Layout(steps=[self.build, self.package])

    def assess(self, package_enumeration):
        build_link = Link(name="build", products={})
        package_link = Link(
            name="package",
            materials={},
            products={},
            byproducts={ENUM: package_enumeration},
        )
        chain = {
            "build": {"k1": build_link},
            "package": {"k1": package_link},
        }
        report = acceptance.audit_layout(self.layout, chain, self.check)
        return {item.step: item for item in report.steps}

    def test_following_step_proves_absence_in_its_own_scope(self):
        assessment = self.assess(
            {"materials": {"boundary": ["dist"], "complete": True}}
        )
        self.assertEqual(assessment["build"].status, CONFIRMED)

    def test_following_step_with_narrower_scope_does_not_prove_absence(self):
        assessment = self.assess(
            {"materials": {"boundary": ["src"], "complete": True}}
        )
        self.assertEqual(assessment["build"].status, MISSING)


class TestRecordEnumeration(unittest.TestCase):
    def setUp(self):
        self.cwd = os.getcwd()
        self.tmp = tempfile.mkdtemp()
        os.chdir(self.tmp)

    def tearDown(self):
        os.chdir(self.cwd)
        shutil.rmtree(self.tmp)

    def test_record_enumeration_enables_confirmed_none(self):
        metadata = runlib.in_toto_run(
            "build",
            [],
            ["."],
            [VersionedPython, "-c", "pass"],
            signer=KEY,
            record_enumeration=True,
        )
        link = metadata.get_payload()
        self.assertIn(ENUM, link.byproducts)
        self.assertEqual(link.byproducts[ENUM]["products"]["boundary"], ["."])
        check = acceptance.ArtifactAbsenceCheck(
            patterns=["*.debug"], scope=["."]
        )
        self.assertEqual(acceptance.audit_link(link, check).status, CONFIRMED)

    def test_optional_layer_is_wired_into_in_toto_verify(self):
        layout_key_dict = {KEYID: PUBKEY}
        step = Step(
            name="build",
            pubkeys=[KEYID],
            expected_products=[["CREATE", "*"]],
        )
        layout = Layout(steps=[step], keys=layout_key_dict)
        layout_metadata = Metablock(signed=layout)
        layout_metadata.create_signature(KEY)
        check = acceptance.ArtifactAbsenceCheck(
            patterns=["*.debug"], scope=["."]
        )

        runlib.in_toto_run(
            "build",
            [],
            ["."],
            [VersionedPython, "-c", "pass"],
            signer=KEY,
            record_enumeration=True,
        )
        verifylib.in_toto_verify(
            layout_metadata,
            layout_key_dict,
            self.tmp,
            artifact_absence_check=check,
        )

        runlib.in_toto_run(
            "build",
            [],
            ["."],
            [VersionedPython, "-c", "pass"],
            signer=KEY,
            record_enumeration=False,
        )
        with self.assertRaises(AcceptanceError):
            verifylib.in_toto_verify(
                layout_metadata,
                layout_key_dict,
                self.tmp,
                artifact_absence_check=check,
            )


if __name__ == "__main__":
    unittest.main()
