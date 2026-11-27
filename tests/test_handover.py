"""Receiving-check (接收核对) tests: one document, two receiving domains."""

import unittest
from os.path import dirname, join

from msoffcrypto.handover import (
    STATUS_RECEIVED,
    STATUS_RELEASED,
    STATUS_SUSPENDED,
    DomainPolicy,
    build_receiving_slip,
    countersign,
    inspect_protection,
    render_slip,
)

DATA_DIR = join(dirname(__file__), "inputs")

#: Same protected test document handed over to both warehouses.
DOCUMENT = join(DATA_DIR, "example_password.xlsx")

#: Vault A (总库) may retain every public field and requires the core ones.
POLICY_A = DomainPolicy(
    domain="vault-a",
    allowed_fields=None,
    required_fields={"format", "encrypted", "encryption_type"},
)

#: Vault B (分库) may not retain password salt material, yet requires it.
POLICY_B = DomainPolicy(
    domain="vault-b",
    allowed_fields={"format", "encrypted", "encryption_type", "key_types"},
    required_fields={"encryption_type", "password_salt"},
)


class HandoverTest(unittest.TestCase):
    def test_public_protection_metadata(self):
        fields = inspect_protection(DOCUMENT)
        self.assertEqual(fields["format"], "ooxml")
        self.assertIs(fields["encrypted"], True)
        self.assertEqual(fields["encryption_type"], "agile")
        self.assertEqual(fields["password_hash_algorithm"], "SHA512")
        self.assertEqual(fields["password_key_bits"], 256)
        self.assertTrue(fields["password_salt"].startswith("base64:"))

    def test_two_slips_share_preservation_id(self):
        slip_a = build_receiving_slip(DOCUMENT, POLICY_A)
        slip_b = build_receiving_slip(DOCUMENT, POLICY_B)
        # 保全标识一致，证明两张接收单来自同一来源文件。
        self.assertEqual(slip_a.preservation_id, slip_b.preservation_id)
        self.assertTrue(slip_a.preservation_id.startswith("sha256:"))
        # 但两个接收域的字段许可不同。
        self.assertNotEqual(
            sorted(slip_a.deliverable_fields), sorted(slip_b.deliverable_fields)
        )

    def test_unrestricted_domain_receives_all_public_fields(self):
        slip = build_receiving_slip(DOCUMENT, POLICY_A)
        self.assertEqual(slip.status, STATUS_RECEIVED)
        self.assertFalse(slip.pending_auditor_signoff)
        self.assertEqual(slip.deliverable_fields, slip.public_fields)
        self.assertEqual(slip.withheld_fields, [])
        self.assertEqual(slip.missing_required_fields, [])

    def test_restricted_required_field_suspends_slip(self):
        slip = build_receiving_slip(DOCUMENT, POLICY_B)
        # 必填字段 password_salt 受限，接收单必须明确挂起。
        self.assertEqual(slip.status, STATUS_SUSPENDED)
        self.assertTrue(slip.pending_auditor_signoff)
        self.assertEqual(slip.missing_required_fields, ["password_salt"])
        self.assertIn("password_salt", slip.withheld_fields)
        self.assertNotIn("password_salt", slip.deliverable_fields)
        # 许可范围内的字段照常交付。
        self.assertEqual(
            sorted(slip.deliverable_fields),
            ["encrypted", "encryption_type", "format", "key_types"],
        )

    def test_countersign_releases_suspended_slip(self):
        slip = build_receiving_slip(DOCUMENT, POLICY_B)
        countersign(slip, auditor="auditor-chen", note="盐值字段线下移交")
        self.assertEqual(slip.status, STATUS_RELEASED)
        self.assertFalse(slip.pending_auditor_signoff)
        self.assertEqual(slip.auditor_signoff["auditor"], "auditor-chen")

    def test_countersign_rejects_unsuspended_slip(self):
        slip = build_receiving_slip(DOCUMENT, POLICY_A)
        with self.assertRaises(ValueError):
            countersign(slip, auditor="auditor-chen")

    def test_render_slip_marks_suspension(self):
        slip = build_receiving_slip(DOCUMENT, POLICY_B)
        text = render_slip(slip)
        self.assertIn("挂起", text)
        self.assertIn("password_salt", text)
        self.assertIn(slip.preservation_id, text)

    def test_plain_document_is_received_without_encryption(self):
        policy = DomainPolicy(domain="vault-a", required_fields={"encrypted"})
        slip = build_receiving_slip(join(DATA_DIR, "plain.xls"), policy)
        self.assertEqual(slip.status, STATUS_RECEIVED)
        self.assertIs(slip.deliverable_fields["encrypted"], False)


if __name__ == "__main__":
    unittest.main()

