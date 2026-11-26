# Copyright New York University and the in-toto contributors
# SPDX-License-Identifier: Apache-2.0

"""Tests for optional offline rejection-ticket reporting."""

import os
import tempfile
import unittest
from datetime import datetime, timedelta, timezone

from in_toto.models.layout import Layout
from in_toto.models.link import FILENAME_FORMAT, Link
from in_toto.models.metadata import Metadata, Metablock
from in_toto.models.rejection import RejectionTicket
from in_toto.offline import verify_offline
from in_toto.verifylib import in_toto_verify
from tests.common import SignerStore


NOW = datetime(2026, 11, 27, 12, 0, tzinfo=timezone.utc)
PAST = (NOW - timedelta(hours=1)).strftime("%Y-%m-%dT%H:%M:%SZ")
FUTURE = (NOW + timedelta(hours=2)).strftime("%Y-%m-%dT%H:%M:%SZ")
LATER = NOW + timedelta(hours=3)
DIGEST = "a" * 64


class OfflineRejectionTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.link_dir = self.tmp.name

    def tearDown(self):
        self.tmp.cleanup()

    def layout(self, threshold=2, version="layout-v1"):
        rsa_id = SignerStore.rsa_pub["keyid"]
        ecdsa_id = SignerStore.ecdsa_pub["keyid"]
        layout = Layout.read(
            {
                "_type": "layout",
                "version": version,
                "expires": "2099-01-01T00:00:00Z",
                "keys": {
                    rsa_id: SignerStore.rsa_pub,
                    ecdsa_id: SignerStore.ecdsa_pub,
                },
                "steps": [
                    {
                        "name": "write-code",
                        "threshold": threshold,
                        "pubkeys": [rsa_id, ecdsa_id],
                    }
                ],
                "inspect": [],
            }
        )
        layout.version = version
        return layout

    def dump_link(self, step="write-code", digest=DIGEST, signer=None):
        signer = signer or SignerStore.rsa
        keyid = SignerStore.rsa_pub["keyid"]
        link = Link(
            name=step,
            products={"artifact.bin": {"sha256": digest}},
        )
        metadata = Metablock(signed=link, signatures=[])
        metadata.create_signature(signer)
        path = os.path.join(
            self.link_dir,
            FILENAME_FORMAT.format(step_name=step, keyid=keyid),
        )
        metadata.dump(path)
        return metadata

    def ticket(self, **overrides):
        values = {
            "ticket_id": "ticket-1",
            "layout_version": "layout-v1",
            "step": "write-code",
            "artifact_digest": DIGEST,
            "approver": SignerStore.ed25519_pub["keyid"],
            "valid_from": PAST,
            "valid_until": FUTURE,
        }
        values.update(overrides)
        return RejectionTicket(**values).sign(SignerStore.ed25519)

    def verify(self, layout=None, tickets=None, when=NOW, **kwargs):
        return verify_offline(
            layout or self.layout(),
            {},
            link_dir_path=self.link_dir,
            tickets=tickets or [],
            approver_keys=[SignerStore.ed25519_pub],
            verification_time=when,
            **kwargs,
        )

    def test_missing_signatures_and_rejection_reported_separately(self):
        self.dump_link()
        report = self.verify(tickets=[self.ticket()])

        self.assertFalse(report.verified)
        self.assertEqual(1, report.thresholds["write-code"]["valid_count"])
        self.assertEqual(1, report.thresholds["write-code"].missing_count)
        self.assertEqual(1, report.missing_signatures["write-code"])
        self.assertEqual(1, len(report.active_rejections))
        self.assertEqual("write-code", report.blocked_steps[0])

    def test_expired_ticket_releases_block_but_not_signature_shortfall(self):
        self.dump_link()
        ticket = self.ticket()

        before = self.verify(tickets=[ticket])
        self.assertEqual(1, len(before.blocks))

        after = self.verify(tickets=[ticket], when=LATER)
        self.assertEqual([], after.active_rejections)
        self.assertEqual(1, len(after.released_blocks))
        released = after.released_blocks[0]
        self.assertEqual("write-code", released["step"])
        self.assertEqual("expired", released["release_reason"])
        self.assertEqual(1, after.missing_signatures["write-code"])
        self.assertFalse(after.verified)

    def test_same_approver_correction_withdraws_rejection(self):
        self.dump_link()
        first = self.ticket(ticket_id="first")
        correction = self.ticket(
            ticket_id="second",
            supersedes="first",
            decision="approve",
            issued_at=NOW.strftime("%Y-%m-%dT%H:%M:%SZ"),
        )

        report = self.verify(
            layout=self.layout(threshold=1), tickets=[first, correction]
        )
        self.assertTrue(report.threshold_complete)
        self.assertEqual([], report.active_rejections)
        self.assertEqual("withdrawn", report.released_blocks[0]["release_reason"])
        self.assertTrue(report.verified)

    def test_invalid_signature_is_reported_and_does_not_block(self):
        ticket = self.ticket()
        ticket.signatures[0]["sig"] = "00" * 64
        report = self.verify(tickets=[ticket])

        self.assertEqual([], report.active_rejections)
        self.assertEqual(1, len(report.invalid_tickets))
        self.assertFalse(report.verified)

    def test_in_toto_verify_offline_keyword_returns_report(self):
        self.dump_link()
        report = in_toto_verify(
            self.layout(),
            {},
            self.link_dir,
            offline=True,
            rejection_tickets=[self.ticket()],
            approver_keys=[SignerStore.ed25519_pub],
            verification_time=NOW,
        )
        self.assertEqual(1, len(report.active_rejections))

    def test_signed_ticket_metadata_roundtrip(self):
        path = os.path.join(self.link_dir, "rejection.json")
        self.ticket().dump(path)
        loaded = Metadata.load(path)
        self.assertIsInstance(loaded.get_payload(), RejectionTicket)


class DelegatedRejectionTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.link_dir = self.tmp.name
        self.rsa_id = SignerStore.rsa_pub["keyid"]
        self.ecdsa_id = SignerStore.ecdsa_pub["keyid"]

    def tearDown(self):
        self.tmp.cleanup()

    def test_sublayout_key_authorizes_sublayout_step_ticket(self):
        sublayout = Layout.read(
            {
                "_type": "layout",
                "version": "sub-v1",
                "expires": "2099-01-01T00:00:00Z",
                "keys": {self.ecdsa_id: SignerStore.ecdsa_pub},
                "steps": [
                    {
                        "name": "child",
                        "threshold": 1,
                        "pubkeys": [self.ecdsa_id],
                    }
                ],
                "inspect": [],
            }
        )
        child_link = Link(
            name="child", products={"x": {"sha256": "b" * 64}}
        )
        link_md = Metablock(signed=child_link, signatures=[])
        link_md.create_signature(SignerStore.ecdsa)
        delegated_dir = os.path.join(
            self.link_dir, f"delegate.{self.rsa_id[:8]}"
        )
        os.mkdir(delegated_dir)
        link_md.dump(
            os.path.join(
                delegated_dir,
                FILENAME_FORMAT.format(
                    step_name="child", keyid=self.ecdsa_id
                ),
            )
        )

        layout_md = Metablock(signed=sublayout, signatures=[])
        layout_md.create_signature(SignerStore.rsa)
        layout_md.dump(
            os.path.join(
                self.link_dir,
                FILENAME_FORMAT.format(
                    step_name="delegate", keyid=self.rsa_id
                ),
            )
        )

        root = Layout.read(
            {
                "_type": "layout",
                "version": "root-v1",
                "expires": "2099-01-01T00:00:00Z",
                "keys": {self.rsa_id: SignerStore.rsa_pub},
                "steps": [
                    {
                        "name": "delegate",
                        "threshold": 1,
                        "pubkeys": [self.rsa_id],
                    }
                ],
                "inspect": [],
            }
        )
        ticket = RejectionTicket(
            layout_version="sub-v1",
            step="child",
            artifact_digest="b" * 64,
            approver=self.ecdsa_id,
            valid_from=PAST,
            valid_until=FUTURE,
        ).sign(SignerStore.ecdsa)

        report = verify_offline(
            root,
            {},
            link_dir_path=self.link_dir,
            tickets=[ticket],
            verification_time=NOW,
        )
        record = report.all_rejection_tickets[0]
        self.assertEqual("valid", record["status"])
        self.assertTrue(record["authorized"])
        self.assertEqual(1, len(report.active_rejections))


if __name__ == "__main__":
    unittest.main()
