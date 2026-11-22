#!/usr/bin/env python
# vim: set ai et ts=4 sw=4 sts=4:
"""Tests for public-certificate de-duplication preflight checks."""

from __future__ import print_function
import base64
import binascii
import json
import os
import unittest
from collections import OrderedDict

import jks
from jks.cert_dedup import (
    DedupPlan,
    check_certificate_objects,
    check_chain_slots,
    preflight_certificate_dedup,
    replay_synthetic,
)


CUR_PATH = os.path.dirname(os.path.abspath(__file__))
KS_PATH = os.path.join(CUR_PATH, "keystores")

A = ("X.509", b"synthetic-public-a")
B = ("X.509", b"synthetic-public-b")
C = ("X.509", b"synthetic-public-c")


class CertificateDedupTests(unittest.TestCase):
    def test_ordered_slots_recover_two_chains(self):
        visible = OrderedDict([
            ("alpha", [A, B, A]),
            ("beta", [C, A]),
        ])
        plan = DedupPlan(
            certificates=OrderedDict([
                ("pub-a", A),
                ("pub-b", B),
                ("pub-c", C),
            ]),
            chains=OrderedDict([
                ("alpha", ["pub-a", "pub-b", "pub-a"]),
                ("beta", ["pub-c", "pub-a"]),
            ]),
        )

        report = preflight_certificate_dedup(visible, plan)

        self.assertTrue(report.ok)
        self.assertTrue(report.objects_ok)
        self.assertTrue(report.slots_ok)
        self.assertEqual(report.entries["alpha"].chain_length, 3)
        self.assertEqual(
            [item.status for item in report.entries["alpha"].evidence],
            ["match", "match", "match"],
        )
        self.assertEqual(
            [item.expected_fingerprint for item in report.entries["alpha"].evidence],
            [report.entries["alpha"].expected[0].fingerprint,
             report.entries["alpha"].expected[1].fingerprint,
             report.entries["alpha"].expected[0].fingerprint],
        )

    def test_certificate_set_recovers_objects_but_not_slots(self):
        visible = {"gamma": [A, B, A]}
        plan = DedupPlan(
            certificates=OrderedDict([("pub-a", A), ("pub-b", B)]),
            chains={"gamma": {"pub-a", "pub-b"}},
        )

        report = preflight_certificate_dedup(visible, plan)
        entry = report.entries["gamma"]

        self.assertTrue(report.objects_ok)
        self.assertFalse(report.slots_ok)
        self.assertFalse(report.ok)
        self.assertEqual(entry.lost_positions, [0, 1, 2])
        self.assertEqual(entry.duplicate_lost_positions, [2])
        self.assertEqual(entry.duplicate_losses[0].expected_count, 2)
        self.assertEqual(entry.duplicate_losses[0].actual_count, 1)
        self.assertEqual(entry.duplicate_losses[0].lost_positions, [2])

    def test_chain_order_is_checked(self):
        visible = {"alpha": [A, B]}
        plan = DedupPlan(
            certificates={"pub-a": A, "pub-b": B},
            chains={"alpha": ["pub-b", "pub-a"]},
        )

        report = preflight_certificate_dedup(visible, plan)

        self.assertTrue(report.objects_ok)
        self.assertFalse(report.slots_ok)
        self.assertEqual(report.entries["alpha"].lost_positions, [0, 1])
        self.assertEqual(report.entries["alpha"].order_mismatch_positions, [0, 1])
        self.assertEqual(
            [item.status for item in report.entries["alpha"].evidence],
            ["wrong_order", "wrong_order"],
        )

    def test_missing_certificate_object_is_reported_separately(self):
        visible = {"alpha": [A, B]}
        plan = DedupPlan(
            certificates={"pub-a": A},
            chains={"alpha": ["pub-a", "pub-a"]},
        )

        report = preflight_certificate_dedup(visible, plan)

        self.assertFalse(report.objects_ok)
        self.assertFalse(report.slots_ok)
        self.assertEqual(len(report.missing_objects), 1)
        self.assertEqual(
            report.missing_objects[0]["entries"]["alpha"], [1])
        self.assertEqual(report.entries["alpha"].lost_positions, [1])

    def test_unresolved_reference_fails_both_layers(self):
        visible = {"alpha": [A, B]}
        plan = DedupPlan(
            certificates={"pub-a": A},
            chains={"alpha": ["pub-a", "unknown"]},
        )

        report = preflight_certificate_dedup(visible, plan)

        self.assertFalse(report.objects_ok)
        self.assertFalse(report.slots_ok)
        self.assertEqual(len(report.objects.unresolved), 1)
        self.assertEqual(
            report.entries["alpha"].evidence[1].status,
            "unresolved_reference",
        )

    def test_unreadable_entries_are_listed_separately(self):
        secret = jks.SecretKeyEntry(alias="secret")
        visible = {"secret": secret, "alpha": [A]}
        plan = DedupPlan(
            certificates={"pub-a": A},
            chains={"alpha": ["pub-a"]},
        )

        report = preflight_certificate_dedup(visible, plan)

        self.assertTrue(report.ok)
        self.assertEqual(
            report.unreadable_entries,
            [{
                "entry": "secret",
                "reason": "no_public_chain",
                "detail": "entry has no cert_chain or cert attribute",
            }],
        )
        self.assertFalse(report.entries["secret"].readable)
        self.assertNotIn("secret", report.slots.entries)

    def test_trusted_certificate_is_a_single_slot_chain(self):
        trusted = jks.TrustedCertEntry(
            alias="trusted", type="X.509", cert=A[1])
        plan = DedupPlan(
            certificates={"pub-a": A},
            chains={"trusted": ["pub-a"]},
        )

        report = preflight_certificate_dedup({"trusted": trusted}, plan)

        self.assertTrue(report.ok)
        self.assertEqual(report.entries["trusted"].chain_length, 1)

    def test_real_pyjks_private_key_entry_round_trips(self):
        store = jks.KeyStore.load(
            os.path.join(KS_PATH, "jks", "RSA2048_3certs.jks"),
            "12345678",
        )
        private_key = store.private_keys["mykey"]
        certificates = OrderedDict()
        references = []
        for index, cert_record in enumerate(private_key.cert_chain):
            object_id = "cert-%d" % index
            certificates[object_id] = cert_record
            references.append(object_id)
        plan = DedupPlan(
            certificates=certificates,
            chains={"mykey": references},
        )

        report = preflight_certificate_dedup(store, plan)

        self.assertTrue(report.ok)
        self.assertEqual(report.entries["mykey"].chain_length, 3)
        self.assertEqual(
            [item.cert for item in report.entries["mykey"].actual],
            [cert_record[1] for cert_record in private_key.cert_chain],
        )

    def test_separate_layer_entry_points(self):
        visible = {"alpha": [A, B]}
        plan = DedupPlan(
            certificates={"pub-a": A, "pub-b": B},
            chains={"alpha": ["pub-a", "pub-b"]},
        )

        objects = check_certificate_objects(visible, plan)
        slots = check_chain_slots(visible, plan)

        self.assertTrue(objects.ok)
        self.assertTrue(slots.ok)
        self.assertTrue(objects.entry_results["alpha"].objects_ok)
        self.assertTrue(slots.entries["alpha"].slots_ok)

    def test_report_is_json_serializable(self):
        report = preflight_certificate_dedup(
            {"alpha": [A]},
            DedupPlan(
                certificates={"pub-a": A},
                chains={"alpha": ["pub-a"]},
            ),
        )

        encoded = json.dumps(report.as_dict())
        decoded = json.loads(encoded)

        self.assertTrue(decoded["ok"])
        self.assertEqual(decoded["entries"]["alpha"]["chain_length"], 1)

    def test_synthetic_replay_expected_outcomes(self):
        replay = replay_synthetic()
        first = replay["cases"][0]
        second = replay["cases"][1]

        self.assertTrue(first["report"].ok)
        self.assertTrue(first["report"].entries["alpha"].slots_ok)
        self.assertTrue(first["report"].entries["beta"].slots_ok)

        self.assertTrue(second["report"].objects_ok)
        self.assertFalse(second["report"].slots_ok)
        self.assertEqual(
            second["report"].entries["gamma"].lost_positions, [0, 1, 2])
        self.assertEqual(
            second["report"].entries["gamma"].duplicate_lost_positions, [2])


    def test_json_shaped_text_material_and_position_map(self):
        visible = {
            "entries": [
                {
                    "alias": "alpha",
                    "chain": {
                        "cert_chain": [
                            {"type": "X.509", "cert": "text-a"},
                            {"type": "X.509", "cert": "text-b"},
                        ]
                    },
                }
            ]
        }
        plan = {
            "certificates": {
                "pub-a": {"type": "X.509", "cert": "text-a"},
                "pub-b": {"type": "X.509", "cert": "text-b"},
            },
            "chains": {
                "alpha": {"positions": {"1": "pub-b", "0": "pub-a"}}
            },
        }

        report = preflight_certificate_dedup(visible, plan)

        self.assertTrue(report.ok)
        self.assertEqual(list(report.entries), ["alpha"])
        self.assertEqual(report.entries["alpha"].chain_length, 2)

    def test_plan_object_with_objects_and_slots_attributes(self):
        class PlanObject(object):
            pass

        plan = PlanObject()
        plan.objects = {"pub-a": A}
        plan.slots = {"alpha": ["pub-a"]}

        report = preflight_certificate_dedup({"alpha": [A]}, plan)

        self.assertTrue(report.ok)
        self.assertEqual(report.entries["alpha"].evidence[0].status, "match")


    def test_complete_object_table_stays_recoverable_with_bad_reference(self):
        visible = {"alpha": [A, B]}
        plan = DedupPlan(
            certificates={"pub-a": A, "pub-b": B},
            chains={"alpha": ["pub-a", "unknown"]},
        )

        report = preflight_certificate_dedup(visible, plan)

        self.assertTrue(report.objects_ok)
        self.assertFalse(report.slots_ok)
        self.assertEqual(len(report.objects.unresolved), 1)
        self.assertEqual(
            report.entries["alpha"].evidence[1].status,
            "unresolved_reference",
        )


    def test_base64_and_hex_material_encodings(self):
        payload = b"encoded-public-material"
        encoded_base64 = "base64:" + base64.b64encode(payload).decode("ascii")
        encoded_hex = "hex:" + binascii.hexlify(payload).decode("ascii")

        report = preflight_certificate_dedup(
            {"alpha": [("X.509", encoded_base64)]},
            {
                "certificates": {
                    "pub-a": {"type": "X.509", "cert": encoded_hex}
                },
                "chains": {"alpha": ["pub-a"]},
            },
        )

        self.assertTrue(report.ok)
        self.assertEqual(report.entries["alpha"].actual[0].cert, payload)


if __name__ == "__main__":
    unittest.main()
