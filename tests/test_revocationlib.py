# Copyright New York University and the in-toto contributors
# SPDX-License-Identifier: Apache-2.0

"""Tests for the layout-authorized, offline revocation workflow."""

import json
import os
import unittest
from datetime import datetime, timezone

from dateutil.relativedelta import relativedelta

from in_toto import revocationlib, verifylib
from in_toto.exceptions import RevocationError
from in_toto.in_toto_verify import main as in_toto_verify_main
from in_toto.models.layout import Layout, Step
from in_toto.models.link import Link
from in_toto.models.metadata import Metablock
from in_toto.models.revocation import ReplacementProof, Revocation
from tests.common import CliTestCase, SignerStore, TmpDirMixin

OLD_HASH = {"sha256": "1" * 64}
NEW_HASH = {"sha256": "2" * 64}
OTHER_HASH = {"sha256": "3" * 64}
ARTIFACT = "foo/bar.tar.gz"
RELEASE = "release-42"


def _future_expiry(months=1):
    return (datetime.now(timezone.utc) + relativedelta(months=months)).strftime(
        "%Y-%m-%dT%H:%M:%SZ"
    )


def _past_expiry():
    return (datetime.now(timezone.utc) + relativedelta(months=-1)).strftime(
        "%Y-%m-%dT%H:%M:%SZ"
    )


class RevocationTestCase(unittest.TestCase, TmpDirMixin):
    """Shared fixtures building a layout, links and signed metadata."""

    @classmethod
    def setUpClass(cls):
        cls.set_up_test_dir()
        cls.owner = SignerStore.rsa
        cls.owner_pub = SignerStore.rsa_pub
        cls.other_signer = SignerStore.ecdsa

        cls.revocation_root = os.path.join(cls.test_dir, "revocations")
        os.makedirs(cls.revocation_root, exist_ok=True)

    def setUp(self):
        # Each test gets an isolated revocation directory so signed metadata
        # from one test never leaks into another.
        self.revocation_dir = os.path.join(
            self.revocation_root, self._testMethodName
        )
        os.makedirs(self.revocation_dir, exist_ok=True)

    @classmethod
    def tearDownClass(cls):
        cls.tear_down_test_dir()

    def build_layout(self, release_id=RELEASE, revocation_keys=None):
        keys = revocation_keys
        if keys is None:
            keys = {self.owner_pub["keyid"]: self.owner_pub}
        return Layout(
            steps=[Step(name="package")],
            revocation_keys=keys,
            release_id=release_id,
        )

    def build_chain(self, product_hashes):
        link = Link(
            name="package",
            products={ARTIFACT: dict(product_hashes)},
            materials={},
        )
        return {"package": {self.owner_pub["keyid"]: link}}

    def sign_and_dump(self, signable, filename, signer=None):
        signer = signer or self.owner
        metadata = Metablock(signed=signable)
        metadata.create_signature(signer)
        path = os.path.join(self.revocation_dir, filename)
        metadata.dump(path)
        return path

    def build_revocation(  # noqa: PLR0913
        self,
        filename="old-build.revoke",
        hashes=None,
        scope=None,
        release_id=RELEASE,
        expires=None,
        signer=None,
        revocation_id="rev-1",
    ):
        revocation = Revocation(
            revocation_id=revocation_id,
            artifact_path=ARTIFACT,
            artifact_hashes=dict(hashes or OLD_HASH),
            scope=[] if scope is None else scope,
            release_id=release_id,
            expires=expires or _future_expiry(),
            reason="vulnerable build",
        )
        return self.sign_and_dump(revocation, filename, signer)

    def build_proof(  # noqa: PLR0913
        self,
        filename="new-build.replace",
        hashes=None,
        revocation_id="rev-1",
        release_id=RELEASE,
        path=ARTIFACT,
        expires=None,
        signer=None,
        proof_id="proof-1",
    ):
        proof = ReplacementProof(
            proof_id=proof_id,
            revocation_id=revocation_id,
            release_id=release_id,
            artifact_path=path,
            artifact_hashes=dict(hashes or NEW_HASH),
            expires=expires or _future_expiry(),
        )
        return self.sign_and_dump(proof, filename, signer)


class TestLoadRevocations(RevocationTestCase):
    """Loading and verifying revocation statements."""

    def test_load_verified_revocation(self):
        self.build_revocation()
        layout = self.build_layout()
        revocations = revocationlib.load_revocations(
            self.revocation_dir, layout
        )
        self.assertEqual(len(revocations), 1)
        self.assertEqual(revocations[0].revocation_id, "rev-1")

    def test_reject_unauthorized_signer(self):
        self.build_revocation(signer=self.other_signer)
        layout = self.build_layout()
        with self.assertRaises(RevocationError):
            revocationlib.load_revocations(self.revocation_dir, layout)

    def test_reject_when_layout_has_no_revocation_keys(self):
        self.build_revocation()
        layout = self.build_layout(revocation_keys={})
        with self.assertRaises(RevocationError):
            revocationlib.load_revocations(self.revocation_dir, layout)

    def test_reject_expired_revocation(self):
        self.build_revocation(expires=_past_expiry())
        layout = self.build_layout()
        with self.assertRaises(RevocationError):
            revocationlib.load_revocations(self.revocation_dir, layout)

    def test_reject_malformed_expiry(self):
        self.build_revocation(expires="not-a-date")
        layout = self.build_layout()
        with self.assertRaises(RevocationError):
            revocationlib.load_revocations(self.revocation_dir, layout)

    def test_reject_different_release(self):
        self.build_revocation(release_id="other-release")
        layout = self.build_layout()
        with self.assertRaises(RevocationError):
            revocationlib.load_revocations(self.revocation_dir, layout)

    def test_reject_missing_release_binding(self):
        self.build_revocation(release_id="")
        layout = self.build_layout()
        with self.assertRaises(RevocationError):
            revocationlib.load_revocations(self.revocation_dir, layout)

    def test_reject_duplicate_revocation_id(self):
        self.build_revocation(filename="a.revoke")
        self.build_revocation(filename="b.revoke")
        layout = self.build_layout()
        with self.assertRaises(RevocationError):
            revocationlib.load_revocations(self.revocation_dir, layout)

    def test_empty_directory_returns_empty_list(self):
        layout = self.build_layout()
        self.assertEqual(
            revocationlib.load_revocations(self.revocation_dir, layout), []
        )

    def test_reject_wrong_payload_type_in_revocation_file(self):
        link = Link(name="not-a-revocation")
        metadata = Metablock(signed=link)
        metadata.create_signature(self.owner)
        metadata.dump(os.path.join(self.revocation_dir, "wrong.revoke"))
        layout = self.build_layout()
        with self.assertRaises(RevocationError):
            revocationlib.load_revocations(self.revocation_dir, layout)


class TestLoadReplacementProofs(RevocationTestCase):
    """Loading and verifying offline replacement proofs."""

    def test_load_verified_proof(self):
        self.build_proof()
        layout = self.build_layout()
        proofs = revocationlib.load_replacement_proofs(
            self.revocation_dir, layout
        )
        self.assertIn("rev-1", proofs)

    def test_reject_unauthorized_proof(self):
        self.build_proof(signer=self.other_signer)
        layout = self.build_layout()
        with self.assertRaises(RevocationError):
            revocationlib.load_replacement_proofs(self.revocation_dir, layout)

    def test_reject_expired_proof(self):
        self.build_proof(expires=_past_expiry())
        layout = self.build_layout()
        with self.assertRaises(RevocationError):
            revocationlib.load_replacement_proofs(self.revocation_dir, layout)

    def test_reject_proof_different_release(self):
        self.build_proof(release_id="other-release")
        layout = self.build_layout()
        with self.assertRaises(RevocationError):
            revocationlib.load_replacement_proofs(self.revocation_dir, layout)


class TestApplyRevocations(RevocationTestCase):
    """Applying verified revocations to chain link artifacts."""

    def _load(self, layout):
        revocations = revocationlib.load_revocations(
            self.revocation_dir, layout
        )
        proofs = revocationlib.load_replacement_proofs(
            self.revocation_dir, layout
        )
        return revocations, proofs

    def test_revoked_version_replaced(self):
        self.build_revocation()
        self.build_proof()
        layout = self.build_layout()
        chain = self.build_chain(OLD_HASH)

        revocations, proofs = self._load(layout)
        report = revocationlib.apply_revocations(
            chain, layout, revocations, proofs
        )

        link = chain["package"][self.owner_pub["keyid"]]
        self.assertEqual(link.products[ARTIFACT], NEW_HASH)
        self.assertEqual(len(report["revoked"]), 1)
        self.assertEqual(len(report["replaced"]), 1)
        self.assertEqual(report["pending"], [])

    def test_same_path_unrevoked_version_kept(self):
        # The revocation names OLD_HASH; the delivery carries a different
        # version at the same path, which must remain untouched.
        self.build_revocation()
        layout = self.build_layout()
        chain = self.build_chain(OTHER_HASH)

        revocations, proofs = self._load(layout)
        report = revocationlib.apply_revocations(
            chain, layout, revocations, proofs
        )

        link = chain["package"][self.owner_pub["keyid"]]
        self.assertEqual(link.products[ARTIFACT], OTHER_HASH)
        self.assertEqual(len(report["revoked"]), 1)
        self.assertEqual(report["replaced"], [])
        self.assertEqual(report["pending"], [])

    def test_revoked_without_proof_fails_and_reports_pending(self):
        self.build_revocation()
        layout = self.build_layout()
        chain = self.build_chain(OLD_HASH)

        revocations, proofs = self._load(layout)
        with self.assertRaises(RevocationError):
            revocationlib.apply_revocations(chain, layout, revocations, proofs)

    def test_proof_reintroducing_revoked_version_fails(self):
        self.build_revocation()
        self.build_proof(hashes=OLD_HASH)
        layout = self.build_layout()
        chain = self.build_chain(OLD_HASH)

        revocations, proofs = self._load(layout)
        with self.assertRaises(RevocationError):
            revocationlib.apply_revocations(chain, layout, revocations, proofs)

    def test_proof_for_different_path_fails(self):
        self.build_revocation()
        self.build_proof(path="other/path.tar.gz")
        layout = self.build_layout()
        chain = self.build_chain(OLD_HASH)

        revocations, proofs = self._load(layout)
        with self.assertRaises(RevocationError):
            revocationlib.apply_revocations(chain, layout, revocations, proofs)

    def test_proof_without_matching_revocation_fails(self):
        self.build_revocation()
        self.build_proof(revocation_id="unknown-rev")
        layout = self.build_layout()
        chain = self.build_chain(OLD_HASH)

        revocations, proofs = self._load(layout)
        with self.assertRaises(RevocationError):
            revocationlib.apply_revocations(chain, layout, revocations, proofs)

    def test_scope_limits_revocation(self):
        # Scoped to a different step, so the revoked version in "package"
        # is not affected.
        self.build_revocation(scope=["other-step"])
        layout = self.build_layout()
        chain = self.build_chain(OLD_HASH)

        revocations, proofs = self._load(layout)
        report = revocationlib.apply_revocations(
            chain, layout, revocations, proofs
        )
        link = chain["package"][self.owner_pub["keyid"]]
        self.assertEqual(link.products[ARTIFACT], OLD_HASH)
        self.assertEqual(report["replaced"], [])

    def test_orphan_proof_referencing_unknown_revocation_fails(self):
        # A proof whose revocation id does not exist among the verified
        # revocations cannot authorize any replacement.
        self.build_revocation()
        self.build_proof(revocation_id="does-not-exist", proof_id="p-x")
        layout = self.build_layout()
        chain = self.build_chain(OLD_HASH)

        revocations = revocationlib.load_revocations(
            self.revocation_dir, layout
        )
        # Drop the on-disk matching revocation so the proof is an orphan.
        proofs = revocationlib.load_replacement_proofs(
            self.revocation_dir, layout
        )
        with self.assertRaises(RevocationError):
            revocationlib.apply_revocations(
                chain, layout, revocations[1:], proofs
            )

    def test_revocation_matches_materials_and_products(self):
        self.build_revocation()
        self.build_proof()
        layout = self.build_layout()
        link = Link(
            name="package",
            materials={ARTIFACT: dict(OLD_HASH)},
            products={ARTIFACT: dict(OLD_HASH)},
        )
        chain = {"package": {self.owner_pub["keyid"]: link}}

        revocations, proofs = self._load(layout)
        revocationlib.apply_revocations(chain, layout, revocations, proofs)
        self.assertEqual(link.materials[ARTIFACT], NEW_HASH)
        self.assertEqual(link.products[ARTIFACT], NEW_HASH)


class TestAcceptanceRecords(RevocationTestCase):
    """The three equally named acceptance record files."""

    def test_three_records_same_name_side_by_side(self):
        self.build_revocation()
        self.build_proof()
        layout = self.build_layout()
        chain = self.build_chain(OLD_HASH)

        revocations = revocationlib.load_revocations(
            self.revocation_dir, layout
        )
        proofs = revocationlib.load_replacement_proofs(
            self.revocation_dir, layout
        )
        report = revocationlib.apply_revocations(
            chain, layout, revocations, proofs
        )

        record_dir = os.path.join(self.test_dir, "acceptance")
        paths = revocationlib.write_acceptance_records(report, record_dir)

        expected = {
            "revoked": os.path.join(record_dir, "revoked", "acceptance.json"),
            "replaced": os.path.join(record_dir, "replaced", "acceptance.json"),
            "pending": os.path.join(record_dir, "pending", "acceptance.json"),
        }
        self.assertEqual(paths, expected)
        for path in paths.values():
            self.assertTrue(os.path.isfile(path))

        with open(expected["revoked"], encoding="utf8") as fp:
            revoked = json.load(fp)
        self.assertEqual(revoked[0]["artifact_path"], ARTIFACT)

        with open(expected["replaced"], encoding="utf8") as fp:
            replaced = json.load(fp)
        self.assertEqual(replaced[0]["replacement_hashes"], NEW_HASH)

        with open(expected["pending"], encoding="utf8") as fp:
            self.assertEqual(json.load(fp), [])


class TestReplayProtection(RevocationTestCase):
    """Stale middleware evidence must not resurrect a revoked build."""

    def test_revocation_from_other_release_rejected(self):
        # A revocation statement replayed from a different release order.
        self.build_revocation(release_id="stale-release")
        layout = self.build_layout(release_id=RELEASE)
        with self.assertRaises(RevocationError):
            revocationlib.load_revocations(self.revocation_dir, layout)

    def test_proof_from_other_release_rejected(self):
        self.build_revocation()
        self.build_proof(release_id="stale-release")
        layout = self.build_layout(release_id=RELEASE)
        with self.assertRaises(RevocationError):
            revocationlib.load_replacement_proofs(self.revocation_dir, layout)

    def test_expired_revocation_cannot_be_replayed(self):
        self.build_revocation(expires=_past_expiry())
        layout = self.build_layout()
        with self.assertRaises(RevocationError):
            revocationlib.load_revocations(self.revocation_dir, layout)


class TestInTotoVerifyIntegration(RevocationTestCase):
    """End-to-end integration with verifylib.in_toto_verify."""

    def _build_signed_layout(self, **kwargs):
        keyid = self.owner_pub["keyid"]
        step = Step(name="package", pubkeys=[keyid])
        layout = Layout(
            steps=[step],
            keys={keyid: self.owner_pub},
            revocation_keys=kwargs.get(
                "revocation_keys",
                {keyid: self.owner_pub},
            ),
            release_id=kwargs.get("release_id", RELEASE),
        )
        metadata = Metablock(signed=layout)
        metadata.create_signature(self.owner)
        return metadata

    def _dump_link(self, product_hashes):
        link = Link(
            name="package",
            materials={},
            products={ARTIFACT: dict(product_hashes)},
        )
        metadata = Metablock(signed=link)
        metadata.create_signature(self.owner)
        filename = "package.{:.8}.link".format(self.owner_pub["keyid"])
        metadata.dump(os.path.join(self.test_dir, filename))

    def test_verify_without_revocation_dir_is_unchanged(self):
        self._dump_link(OLD_HASH)
        layout = self._build_signed_layout()
        summary = verifylib.in_toto_verify(
            layout,
            {self.owner_pub["keyid"]: self.owner_pub},
            link_dir_path=self.test_dir,
        )
        self.assertEqual(summary.type_, "link")

    def test_verify_revoked_without_proof_fails(self):
        self._dump_link(OLD_HASH)
        self.build_revocation()
        layout = self._build_signed_layout()
        with self.assertRaises(RevocationError):
            verifylib.in_toto_verify(
                layout,
                {self.owner_pub["keyid"]: self.owner_pub},
                link_dir_path=self.test_dir,
                revocation_dir_path=self.revocation_dir,
            )

    def test_verify_revoked_with_proof_and_records_passes(self):
        self._dump_link(OLD_HASH)
        self.build_revocation()
        self.build_proof()
        layout = self._build_signed_layout()
        record_dir = os.path.join(self.test_dir, "acceptance")
        verifylib.in_toto_verify(
            layout,
            {self.owner_pub["keyid"]: self.owner_pub},
            link_dir_path=self.test_dir,
            revocation_dir_path=self.revocation_dir,
            acceptance_record_path=record_dir,
        )
        for category in ("revoked", "replaced", "pending"):
            path = os.path.join(record_dir, category, "acceptance.json")
            self.assertTrue(os.path.isfile(path))

    def test_verify_unrevoked_same_path_version_passes(self):
        # Revocation targets OLD_HASH; the link carries OTHER_HASH at the
        # same path, so the un-revoked version must verify without a proof.
        self._dump_link(OTHER_HASH)
        self.build_revocation()
        layout = self._build_signed_layout()
        verifylib.in_toto_verify(
            layout,
            {self.owner_pub["keyid"]: self.owner_pub},
            link_dir_path=self.test_dir,
            revocation_dir_path=self.revocation_dir,
        )


if __name__ == "__main__":
    unittest.main()


class TestVerifyCli(RevocationTestCase, CliTestCase):
    """The in-toto-verify CLI exposes the optional revocation options."""

    cli_main_func = staticmethod(in_toto_verify_main)

    def _prepare_delivery(self, product_hashes):
        keyid = self.owner_pub["keyid"]
        step = Step(name="package", pubkeys=[keyid])
        layout = Layout(
            steps=[step],
            keys={keyid: self.owner_pub},
            revocation_keys={keyid: self.owner_pub},
            release_id=RELEASE,
        )
        layout_metadata = Metablock(signed=layout)
        layout_metadata.create_signature(self.owner)
        layout_path = os.path.join(self.test_dir, "root.layout")
        layout_metadata.dump(layout_path)

        link = Link(
            name="package",
            materials={},
            products={ARTIFACT: dict(product_hashes)},
        )
        link_metadata = Metablock(signed=link)
        link_metadata.create_signature(self.owner)
        link_metadata.dump(
            os.path.join(
                self.test_dir,
                f"package.{keyid:.8}.link",
            )
        )
        return layout_path

    def test_cli_revoked_without_proof_exits_nonzero(self):
        layout_path = self._prepare_delivery(OLD_HASH)
        self.build_revocation()
        self.assert_cli_sys_exit(
            [
                "--layout",
                layout_path,
                "--verification-keys",
                os.path.join(
                    os.path.dirname(__file__), "pems", "rsa_public.pem"
                ),
                "--link-dir",
                self.test_dir,
                "--revocation-dir",
                self.revocation_dir,
            ],
            1,
        )

    def test_cli_revoked_with_proof_and_records_exits_zero(self):
        layout_path = self._prepare_delivery(OLD_HASH)
        self.build_revocation()
        self.build_proof()
        record_dir = os.path.join(self.test_dir, "acceptance")
        self.assert_cli_sys_exit(
            [
                "--layout",
                layout_path,
                "--verification-keys",
                os.path.join(
                    os.path.dirname(__file__), "pems", "rsa_public.pem"
                ),
                "--link-dir",
                self.test_dir,
                "--revocation-dir",
                self.revocation_dir,
                "--acceptance-record-dir",
                record_dir,
            ],
            0,
        )
        for category in ("revoked", "replaced", "pending"):
            self.assertTrue(
                os.path.isfile(
                    os.path.join(record_dir, category, "acceptance.json")
                )
            )
