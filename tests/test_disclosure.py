"""Tests for privacy-minimised local disclosure receipts."""

from __future__ import annotations

import hashlib
import json
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path

from in_toto.disclosure import (
    ApprovedArtifact,
    RuleBasis,
    StepDisclosure,
    VerifiedStep,
    build_disclosure_receipt,
    main as disclosure_main,
    match_bases_from_rules,
)
from in_toto.models.layout import Layout, Step
from in_toto.models.link import FILENAME_FORMAT, Link
from in_toto.models.metadata import Metablock
from in_toto.runlib import record_artifacts_as_dict
from in_toto.verifylib import in_toto_verify, verify_item_rules
from tests.common import SignerStore


def hash_dict(text: str) -> dict[str, str]:
    """Return a deterministic in-toto-compatible sha256 hash dictionary."""
    digest = hashlib.sha256(text.encode("utf-8")).hexdigest()
    return {"sha256": digest}


class DisclosureReceiptTests(unittest.TestCase):
    """Behavior and confidentiality tests for receipt projection."""

    def setUp(self) -> None:
        self.shared_hash = hash_dict("A fictional story about two tides.\n")
        self.partner_hash = hash_dict("A fictional partner packet.\n")
        self.hidden_packet_hash = hash_dict("A fictional hidden packet.\n")

        self.origin = VerifiedStep(
            name="story-origin",
            link=Link(
                name="story-origin",
                products={"fork/story-seed.txt": self.shared_hash},
                command=["write-story"],
            ),
            key_id="origin-key",
            disclosure={
                "public_step": "story origin",
                "story_correlation": "two-tides",
            },
        )
        self.authorized_copy = VerifiedStep(
            name="authorized-copy",
            link=Link(
                name="authorized-copy",
                materials={"fork/story-seed.txt": self.shared_hash},
                products={"fork/authorized-story.txt": self.shared_hash},
                command=["cp", "fork/story-seed.txt", "fork/authorized-story.txt"],
            ),
            key_id="authorized-key",
            disclosure=StepDisclosure(
                fields={
                    "public_step": "authorized copy",
                    "story_correlation": "two-tides",
                }
            ),
        )
        self.hidden_copy = VerifiedStep(
            name="secret-unauthorized-fork",
            link=Link(
                name="secret-unauthorized-fork",
                materials={"fork/story-seed.txt": self.shared_hash},
                products={"fork/secret-branch-story.txt": self.shared_hash},
                command=[
                    "cp",
                    "fork/story-seed.txt",
                    "fork/secret-branch-story.txt",
                ],
            ),
            authorized=False,
            key_id="hidden-key",
        )
        self.partner_pack = VerifiedStep(
            name="partner-pack",
            link=Link(
                name="partner-pack",
                materials={"fork/authorized-story.txt": self.shared_hash},
                products={"fork/partner-packet.txt": self.partner_hash},
                command=["pack", "fork/authorized-story.txt"],
            ),
            key_id="partner-key",
            disclosure={"public_step": "partner packaging"},
        )
        self.hidden_pack = VerifiedStep(
            name="hidden-fork-pack",
            link=Link(
                name="hidden-fork-pack",
                materials={"fork/secret-branch-story.txt": self.shared_hash},
                products={"fork/hidden-packet.txt": self.hidden_packet_hash},
                command=["pack", "fork/secret-branch-story.txt"],
            ),
            authorized=False,
            key_id="hidden-pack-key",
        )

        self.approval = ApprovedArtifact.from_digest(
            purpose="partner-brief",
            digest=self.partner_hash["sha256"],
            path="fork/partner-packet.txt",
            step="partner-pack",
            kind="products",
            public_label="Two Tides partner packet",
        )

    def fork_bases(self, *, include_hidden: bool = True):
        bases = [
            RuleBasis.artifact_match(
                prior_step="story-origin",
                prior_path="fork/story-seed.txt",
                current_step="authorized-copy",
                current_path="fork/story-seed.txt",
                rule=[
                    "MATCH",
                    "fork/story-seed.txt",
                    "WITH",
                    "PRODUCTS",
                    "FROM",
                    "story-origin",
                ],
            ),
            RuleBasis.material_product(
                step="authorized-copy",
                material="fork/story-seed.txt",
                product="fork/authorized-story.txt",
                rule={
                    "rule_type": "checked-copy-map",
                    "command": [
                        "cp",
                        "fork/story-seed.txt",
                        "fork/authorized-story.txt",
                    ],
                },
            ),
            RuleBasis.artifact_match(
                prior_step="authorized-copy",
                prior_path="fork/authorized-story.txt",
                current_step="partner-pack",
                current_path="fork/authorized-story.txt",
                rule=[
                    "MATCH",
                    "fork/authorized-story.txt",
                    "WITH",
                    "PRODUCTS",
                    "FROM",
                    "authorized-copy",
                ],
            ),
            RuleBasis.material_product(
                step="partner-pack",
                material="fork/authorized-story.txt",
                product="fork/partner-packet.txt",
                rule={"rule_type": "checked-pack-map"},
            ),
        ]
        hidden_bases = [
            RuleBasis.artifact_match(
                prior_step="story-origin",
                prior_path="fork/story-seed.txt",
                current_step="secret-unauthorized-fork",
                current_path="fork/story-seed.txt",
                rule={"rule_type": "hidden-match"},
            ),
            RuleBasis.material_product(
                step="secret-unauthorized-fork",
                material="fork/story-seed.txt",
                product="fork/secret-branch-story.txt",
                rule={"rule_type": "hidden-copy-map"},
            ),
            RuleBasis.artifact_match(
                prior_step="secret-unauthorized-fork",
                prior_path="fork/secret-branch-story.txt",
                current_step="hidden-fork-pack",
                current_path="fork/secret-branch-story.txt",
                rule={"rule_type": "hidden-match"},
            ),
            RuleBasis.material_product(
                step="hidden-fork-pack",
                material="fork/secret-branch-story.txt",
                product="fork/hidden-packet.txt",
                rule={"rule_type": "hidden-pack-map"},
            ),
        ]
        if include_hidden:
            bases.extend(hidden_bases)
        return bases

    def fork_steps(self, *, include_hidden: bool = True):
        steps = [
            self.origin,
            self.authorized_copy,
            self.partner_pack,
        ]
        if include_hidden:
            steps.extend([self.hidden_copy, self.hidden_pack])
        return steps

    def test_authorized_fork_chain_and_internal_receipt(self):
        bundle = build_disclosure_receipt(
            approval=self.approval,
            steps=self.fork_steps(),
            rule_bases=self.fork_bases(),
        )

        self.assertEqual(bundle.public["provenance"]["status"], "complete")
        self.assertEqual(
            [step["public_step"] for step in bundle.public["steps"]],
            ["story origin", "authorized copy", "partner packaging"],
        )
        self.assertIn("secret-unauthorized-fork", json.dumps(bundle.internal))
        self.assertIn("fork/secret-branch-story.txt", json.dumps(bundle.internal))
        self.assertIn(self.shared_hash["sha256"], json.dumps(bundle.internal))

        public_text = json.dumps(bundle.public).lower()
        for secret in [
            "secret-unauthorized-fork",
            "secret-branch",
            "hidden-fork-pack",
            "hidden-packet",
            self.hidden_packet_hash["sha256"],
            self.shared_hash["sha256"],
            self.partner_hash["sha256"],
            "hidden-key",
        ]:
            self.assertNotIn(secret.lower(), public_text)

    def test_hidden_branch_does_not_change_public_receipt(self):
        with_hidden = build_disclosure_receipt(
            approval=self.approval,
            steps=self.fork_steps(include_hidden=True),
            rule_bases=self.fork_bases(include_hidden=True),
        ).public
        without_hidden = build_disclosure_receipt(
            approval=self.approval,
            steps=self.fork_steps(include_hidden=False),
            rule_bases=self.fork_bases(include_hidden=False),
        ).public

        self.assertEqual(with_hidden, without_hidden)

    def test_public_receipt_has_fixed_minimal_schema(self):
        public = build_disclosure_receipt(
            approval=self.approval,
            steps=self.fork_steps(),
            rule_bases=self.fork_bases(),
        ).public

        self.assertEqual(
            set(public),
            {
                "schema",
                "approved_use",
                "public_artifact",
                "provenance",
                "steps",
            },
        )
        self.assertEqual(set(public["provenance"]), {"status"})
        self.assertNotIn("receipt_id", public)
        self.assertNotIn("diagnostics", public)
        self.assertNotIn("stats", public)

    def test_changing_only_purpose_preserves_authorized_chain(self):
        original = build_disclosure_receipt(
            approval=self.approval,
            steps=self.fork_steps(),
            rule_bases=self.fork_bases(),
        ).public
        changed_approval = replace(self.approval, purpose="classroom-use")
        changed = build_disclosure_receipt(
            approval=changed_approval,
            steps=self.fork_steps(),
            rule_bases=self.fork_bases(),
        ).public

        self.assertEqual(original["approved_use"], "partner-brief")
        self.assertEqual(changed["approved_use"], "classroom-use")
        original_without_use = {**original, "approved_use": None}
        changed_without_use = {**changed, "approved_use": None}
        self.assertEqual(original_without_use, changed_without_use)

    def test_same_digest_without_rule_basis_is_not_connected(self):
        stranger = VerifiedStep(
            name="digest-coincidence",
            link=Link(
                name="digest-coincidence",
                products={"elsewhere/same-bytes.txt": self.shared_hash}
            ),
            disclosure={"public_step": "unrelated same-digest use"},
        )
        bundle = build_disclosure_receipt(
            approval=replace(
                self.approval,
                path="fork/partner-packet.txt",
            ),
            steps=self.fork_steps(include_hidden=False) + [stranger],
            rule_bases=[],
        )

        self.assertEqual(
            [step["public_step"] for step in bundle.public["steps"]],
            ["partner packaging"],
        )
        self.assertNotIn(
            "unrelated same-digest use", json.dumps(bundle.public)
        )

    def test_unauthorized_and_divergent_steps_have_identical_public_gap(self):
        bases = self.fork_bases(include_hidden=False)
        unauthorized_steps = [
            replace(step, authorized=False)
            if step.name == "partner-pack"
            else step
            for step in self.fork_steps(include_hidden=False)
        ]
        divergent_steps = [
            replace(step, source_divergent=True)
            if step.name == "partner-pack"
            else step
            for step in self.fork_steps(include_hidden=False)
        ]

        unauthorized_public = build_disclosure_receipt(
            approval=self.approval,
            steps=unauthorized_steps,
            rule_bases=bases,
        ).public
        divergent_public = build_disclosure_receipt(
            approval=self.approval,
            steps=divergent_steps,
            rule_bases=bases,
        ).public

        self.assertEqual(unauthorized_public, divergent_public)
        self.assertEqual(
            unauthorized_public["provenance"]["status"], "evidence_gap"
        )
        self.assertEqual(unauthorized_public["steps"], [])
        public_text = json.dumps(unauthorized_public).lower()
        self.assertNotIn("unauthorized", public_text)
        self.assertNotIn("divergence", public_text)
        self.assertNotIn("partner-pack", public_text)


class RenameDisclosureTests(unittest.TestCase):
    """Renamed artifact association and in-toto MATCH reuse tests."""

    def setUp(self) -> None:
        self.notes_hash = hash_dict("Three lighthouse notes folded into one.\n")
        self.final_hash = hash_dict("Published lighthouse reading copy.\n")
        self.links = {
            "notes-author": Link(
                name="notes-author",
                products={"rename/draft-notes.txt": self.notes_hash},
                command=["write"],
            ),
            "rename-step": Link(
                name="rename-step",
                materials={"rename/draft-notes.txt": self.notes_hash},
                products={"rename/polished-notes.txt": self.notes_hash},
                command=["mv", "rename/draft-notes.txt", "rename/polished-notes.txt"],
            ),
            "reading-pack": Link(
                name="reading-pack",
                materials={"rename/polished-notes.txt": self.notes_hash},
                products={"rename/reading-copy.txt": self.final_hash},
                command=["pack"],
            ),
        }
        self.steps = [
            VerifiedStep(
                name="notes-author",
                link=self.links["notes-author"],
                disclosure={
                    "public_step": "drafting",
                    "approved_correlation": "lighthouse-reading",
                },
            ),
            VerifiedStep(
                name="rename-step",
                link=self.links["rename-step"],
                disclosure={
                    "public_step": "rename and consistency check",
                    "approved_correlation": "lighthouse-reading",
                    "association": "same approved text after an approved rename",
                },
            ),
            VerifiedStep(
                name="reading-pack",
                link=self.links["reading-pack"],
                disclosure={
                    "public_step": "reading copy packaging",
                    "approved_correlation": "lighthouse-reading",
                },
            ),
        ]
        self.bases = [
            RuleBasis.artifact_match(
                prior_step="notes-author",
                prior_path="rename/draft-notes.txt",
                current_step="rename-step",
                current_path="rename/draft-notes.txt",
                rule=[
                    "MATCH",
                    "rename/draft-notes.txt",
                    "WITH",
                    "PRODUCTS",
                    "FROM",
                    "notes-author",
                ],
            ),
            RuleBasis.material_product(
                step="rename-step",
                material="rename/draft-notes.txt",
                product="rename/polished-notes.txt",
                rule={
                    "rule_type": "approved-rename",
                    "command": [
                        "mv",
                        "rename/draft-notes.txt",
                        "rename/polished-notes.txt",
                    ],
                },
            ),
            RuleBasis.artifact_match(
                prior_step="rename-step",
                prior_path="rename/polished-notes.txt",
                current_step="reading-pack",
                current_path="rename/polished-notes.txt",
                rule=[
                    "MATCH",
                    "rename/polished-notes.txt",
                    "WITH",
                    "PRODUCTS",
                    "FROM",
                    "rename-step",
                ],
            ),
            RuleBasis.material_product(
                step="reading-pack",
                material="rename/polished-notes.txt",
                product="rename/reading-copy.txt",
                rule={"rule_type": "checked-pack-map"},
            ),
        ]
        self.approval = ApprovedArtifact.from_digest(
            purpose="reading-club-distribution",
            digest=self.final_hash["sha256"],
            path="rename/reading-copy.txt",
            step="reading-pack",
            kind="products",
        )

    def test_public_rename_association_hides_internal_names_and_digests(self):
        bundle = build_disclosure_receipt(
            approval=self.approval,
            steps=self.steps,
            rule_bases=self.bases,
        )

        self.assertEqual(bundle.public["provenance"]["status"], "complete")
        correlations = [
            step["approved_correlation"] for step in bundle.public["steps"]
        ]
        self.assertEqual(
            correlations,
            ["lighthouse-reading", "lighthouse-reading", "lighthouse-reading"],
        )
        public_text = json.dumps(bundle.public)
        self.assertNotIn("draft-notes.txt", public_text)
        self.assertNotIn("polished-notes.txt", public_text)
        self.assertNotIn(self.notes_hash["sha256"], public_text)
        self.assertNotIn(self.final_hash["sha256"], public_text)
        self.assertIn("same approved text after an approved rename", public_text)

        internal_text = json.dumps(bundle.internal)
        self.assertIn("rename/draft-notes.txt", internal_text)
        self.assertIn("rename/polished-notes.txt", internal_text)
        self.assertIn(self.notes_hash["sha256"], internal_text)

    def test_digest_equality_does_not_replace_rename_rule_basis(self):
        bases = [basis for basis in self.bases if "approved-rename" not in json.dumps(basis.rule)]
        bundle = build_disclosure_receipt(
            approval=self.approval,
            steps=self.steps,
            rule_bases=bases,
        )

        public_step_names = [
            step["public_step"] for step in bundle.public["steps"]
        ]
        self.assertNotIn("drafting", public_step_names)
        self.assertIn("rename and consistency check", public_step_names)
        self.assertIn("reading copy packaging", public_step_names)

    def test_match_bases_come_from_existing_in_toto_rule_checker(self):
        rules = [
            [
                "MATCH",
                "rename/polished-notes.txt",
                "WITH",
                "PRODUCTS",
                "FROM",
                "rename-step",
            ],
            ["DISALLOW", "*"],
        ]
        verify_item_rules(
            "reading-pack", "materials", rules, self.links
        )
        bases = match_bases_from_rules(
            source_name="reading-pack",
            source_type="materials",
            rules=rules,
            links=self.links,
        )

        self.assertEqual(len(bases), 1)
        self.assertEqual(bases[0].source_step, "rename-step")
        self.assertEqual(bases[0].source_path, "rename/polished-notes.txt")
        self.assertEqual(bases[0].target_step, "reading-pack")
        self.assertEqual(bases[0].target_path, "rename/polished-notes.txt")


class SignedLocalMaterialsIntegrationTests(unittest.TestCase):
    """Exercise real files, signed links, and ``in_toto_verify``."""

    def test_signed_rename_chain_passes_existing_verifier(self):
        signer = SignerStore.ed25519
        public_key = SignerStore.ed25519_pub
        keyid = public_key["keyid"]

        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            links_dir = root / "links"
            links_dir.mkdir()

            draft = root / "draft.txt"
            draft.write_text("A signed fictional draft.\n", encoding="utf-8")
            author_products = record_artifacts_as_dict(
                ["draft.txt"], base_path=str(root)
            )
            author_link = Link(
                name="signed-author",
                materials={},
                products=author_products,
                command=["write"],
            )
            self._dump_signed_link(
                author_link, signer, keyid, links_dir
            )

            rename_materials = record_artifacts_as_dict(
                ["draft.txt"], base_path=str(root)
            )
            draft.rename(root / "polished.txt")
            rename_products = record_artifacts_as_dict(
                ["polished.txt"], base_path=str(root)
            )
            rename_link = Link(
                name="signed-rename",
                materials=rename_materials,
                products=rename_products,
                command=["mv", "draft.txt", "polished.txt"],
            )
            self._dump_signed_link(
                rename_link, signer, keyid, links_dir
            )

            final_text = root / "reading-copy.txt"
            final_text.write_text("Signed fictional reading copy.\n", encoding="utf-8")
            pack_materials = record_artifacts_as_dict(
                ["polished.txt"], base_path=str(root)
            )
            pack_products = record_artifacts_as_dict(
                ["reading-copy.txt"], base_path=str(root)
            )
            pack_link = Link(
                name="signed-pack",
                materials=pack_materials,
                products=pack_products,
                command=["pack"],
            )
            self._dump_signed_link(pack_link, signer, keyid, links_dir)

            layout = Layout.read(
                {
                    "_type": "layout",
                    "keys": {keyid: public_key},
                    "steps": [
                        {
                            "name": "signed-author",
                            "pubkeys": [keyid],
                            "expected_materials": [],
                            "expected_products": [
                                ["CREATE", "draft.txt"],
                                ["DISALLOW", "*"],
                            ],
                        },
                        {
                            "name": "signed-rename",
                            "pubkeys": [keyid],
                            "expected_materials": [
                                [
                                    "MATCH",
                                    "draft.txt",
                                    "WITH",
                                    "PRODUCTS",
                                    "FROM",
                                    "signed-author",
                                ],
                                ["DISALLOW", "*"],
                            ],
                            "expected_products": [
                                ["CREATE", "polished.txt"],
                                ["DISALLOW", "*"],
                            ],
                        },
                        {
                            "name": "signed-pack",
                            "pubkeys": [keyid],
                            "expected_materials": [
                                [
                                    "MATCH",
                                    "polished.txt",
                                    "WITH",
                                    "PRODUCTS",
                                    "FROM",
                                    "signed-rename",
                                ],
                                ["DISALLOW", "*"],
                            ],
                            "expected_products": [
                                ["CREATE", "reading-copy.txt"],
                                ["DISALLOW", "*"],
                            ],
                        },
                    ],
                    "inspect": [],
                }
            )
            layout_metablock = Metablock(signed=layout)
            layout_metablock.create_signature(signer)

            summary = in_toto_verify(
                layout_metablock,
                {keyid: public_key},
                link_dir_path=str(links_dir),
                persist_inspection_links=False,
            )
            self.assertEqual(summary.name, "")

            bundle = build_disclosure_receipt(
                approval=ApprovedArtifact(
                    purpose="signed-demo-use",
                    hashes=pack_products["reading-copy.txt"],
                    path="reading-copy.txt",
                    step="signed-pack",
                    kind="products",
                ),
                steps=[
                    VerifiedStep(
                        name="signed-author",
                        link=author_link,
                        key_id=keyid,
                        disclosure={"public_step": "signed drafting"},
                    ),
                    VerifiedStep(
                        name="signed-rename",
                        link=rename_link,
                        key_id=keyid,
                        disclosure={
                            "public_step": "signed rename",
                            "correlation": "signed-fiction",
                        },
                    ),
                    VerifiedStep(
                        name="signed-pack",
                        link=pack_link,
                        key_id=keyid,
                        disclosure={
                            "public_step": "signed packaging",
                            "correlation": "signed-fiction",
                        },
                    ),
                ],
                rule_bases=[
                    RuleBasis.material_product(
                        step="signed-rename",
                        material="draft.txt",
                        product="polished.txt",
                        rule={"rule_type": "signed-rename-map"},
                    ),
                    RuleBasis.material_product(
                        step="signed-pack",
                        material="polished.txt",
                        product="reading-copy.txt",
                        rule={"rule_type": "signed-pack-map"},
                    ),
                ]
                + match_bases_from_rules(
                    source_name="signed-rename",
                    source_type="materials",
                    rules=layout.steps[1].expected_materials[:1],
                    links={
                        "signed-author": author_link,
                        "signed-rename": rename_link,
                    },
                )
                + match_bases_from_rules(
                    source_name="signed-pack",
                    source_type="materials",
                    rules=layout.steps[2].expected_materials[:1],
                    links={
                        "signed-rename": rename_link,
                        "signed-pack": pack_link,
                    },
                ),
            )
            self.assertEqual(
                bundle.public["provenance"]["status"], "complete"
            )
            self.assertEqual(len(bundle.public["steps"]), 3)

    @staticmethod
    def _dump_signed_link(link, signer, keyid, directory: Path) -> None:
        metablock = Metablock(signed=link)
        metablock.create_signature(signer)
        filename = FILENAME_FORMAT.format(step_name=link.name, keyid=keyid)
        metablock.dump(str(directory / filename))


class DisclosureCliTests(unittest.TestCase):
    """CLI smoke coverage for local receipt generation."""

    def test_main_writes_public_and_internal_receipts(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            directory = Path(temporary_directory)
            digest_value = hash_dict("cli fictional artifact")
            request = {
                "approval": {
                    "purpose": "cli-check",
                    "hashes": digest_value,
                    "path": "artifact.txt",
                    "step": "cli-step",
                    "kind": "products",
                },
                "steps": [
                    {
                        "name": "cli-step",
                        "link": {
                            "_type": "link",
                            "name": "cli-step",
                            "materials": {},
                            "products": {"artifact.txt": digest_value},
                            "byproducts": {},
                            "command": ["write"],
                            "environment": {},
                        },
                        "disclosure": {"public_step": "cli step"},
                    }
                ],
                "rule_bases": [],
            }
            request_path = directory / "request.json"
            internal_path = directory / "internal.json"
            public_path = directory / "public.json"
            request_path.write_text(json.dumps(request), encoding="utf-8")

            exit_code = disclosure_main(
                [
                    str(request_path),
                    "--internal-out",
                    str(internal_path),
                    "--public-out",
                    str(public_path),
                ]
            )

            self.assertEqual(exit_code, 0)
            public = json.loads(public_path.read_text(encoding="utf-8"))
            internal = json.loads(internal_path.read_text(encoding="utf-8"))
            self.assertEqual(public["steps"], [{"public_step": "cli step"}])
            self.assertEqual(internal["schema"], "in-toto/internal-disclosure-receipt/v1")


if __name__ == "__main__":
    unittest.main()
