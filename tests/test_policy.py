# coding: utf-8
from __future__ import unicode_literals, division, absolute_import, print_function

import os
import unittest

from asn1crypto import pem, x509

from certvalidator.context import ValidationContext
from certvalidator.policy import query_certificate_policies


P1 = "1.3.6.1.4.1.99999.1.1"
P2 = "1.3.6.1.4.1.99999.1.2"
UNREADABLE_OID = "1.3.6.1.4.1.99999.9.9"

fixtures_dir = os.path.join(os.path.dirname(__file__), "fixtures", "synthetic_policy_tree")


def load_cert(name):
    with open(os.path.join(fixtures_dir, name + ".crt"), "rb") as f:
        data = f.read()
    if pem.detect(data):
        _, _, data = pem.unarmor(data)
    return x509.Certificate.load(data)


class SyntheticPolicyTreeTests(unittest.TestCase):

    def setUp(self):
        self.root = load_cert("root")
        self.mid_good = load_cert("mid_good")
        self.mid_bad = load_cert("mid_bad")
        self.issuer_good = load_cert("issuer_good")
        self.issuer_bad = load_cert("issuer_bad")
        self.leaf = load_cert("leaf")

    def _context(self):
        return ValidationContext(
            trust_roots=[self.root],
            other_certs=[
                self.mid_good,
                self.mid_bad,
                self.issuer_good,
                self.issuer_bad,
            ],
            revocation_mode="soft-fail"
        )

    def test_only_fully_supported_path_is_accepted(self):
        query = query_certificate_policies(
            self.leaf,
            validation_context=self._context(),
            initial_policy_set=set([P1])
        )

        self.assertEqual(2, len(query.results))
        accepted = query.accepted_results
        self.assertEqual(1, len(accepted))
        good = accepted[0]
        self.assertEqual([P2], good.final_policies)
        self.assertEqual([P2], good.leaf_policies)
        self.assertEqual(set([P1]), good.initial_policy_set)
        self.assertEqual("accepted", good.status)
        self.assertTrue(any(
            hop["mapping_status"] == "applied"
            for hop in good.hops
        ))
        self.assertTrue(any(
            trail["policy_trail"] == ["any_policy", P1, P1, P2]
            for trail in good.final_policy_trails
        ))

        rejected = [result for result in query.results if not result.accepted]
        self.assertEqual(1, len(rejected))
        bad = rejected[0]
        self.assertEqual([P2], bad.leaf_policies)
        self.assertEqual([P2], bad.declared_final_policies)
        self.assertEqual(good.declared_final_policies, bad.declared_final_policies)
        self.assertEqual([], bad.final_policies)
        self.assertNotEqual(good.path_id, bad.path_id)
        self.assertTrue(any("Bad Mid CA" in item["subject"] for item in bad.chain))
        self.assertTrue(any(
            hop["mapping_status"] == "inhibited"
            for hop in bad.hops
        ))
        self.assertTrue(any(
            hop["policy_constraints"] and
            hop["policy_constraints"]["inhibit_policy_mapping"] == 0 and
            hop["state_after"]["policy_mapping"] == 0
            for hop in bad.hops
        ))
        self.assertEqual("no_valid_policy", bad.status)

    def test_any_policy_initial_domain(self):
        query = query_certificate_policies(
            self.leaf,
            validation_context=self._context()
        )
        accepted = query.accepted_results
        self.assertEqual(1, len(accepted))
        self.assertEqual([P2], accepted[0].final_policies)

    def test_unreadable_extension_stays_pending(self):
        leaf_pending = load_cert("leaf_pending")
        context = ValidationContext(
            trust_roots=[self.root],
            other_certs=[
                self.mid_good,
                self.mid_bad,
                self.issuer_good,
                self.issuer_bad,
            ],
            revocation_mode="soft-fail"
        )
        query = query_certificate_policies(
            leaf_pending,
            validation_context=context,
            initial_policy_set=set([P1])
        )
        self.assertEqual(2, len(query.results))
        self.assertEqual([], query.accepted_results)
        pending = query.pending
        self.assertTrue(any(
            item["oid"] == UNREADABLE_OID and item["critical"]
            for item in pending
        ))
        self.assertTrue(all(result.status == 'pending' for result in query.results))

    def test_initial_domain_is_enforced(self):
        query = query_certificate_policies(
            self.leaf,
            validation_context=self._context(),
            initial_policy_set=set([P2])
        )
        self.assertEqual(2, len(query.results))
        self.assertEqual([], query.accepted_results)


if __name__ == "__main__":
    unittest.main()
