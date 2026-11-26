#!/usr/bin/env python
# -*- coding: utf-8 -*-
import os
import unittest

from Registry.RegistryParse import parse_multisz


def encode_multisz(values):
    data = b""
    for value in values:
        data += value.encode("utf-16-le") + b"\x00\x00"
    return data + b"\x00\x00"


class MultiSZSequenceTests(unittest.TestCase):
    def test_preserves_duplicates_and_ordinals(self):
        members = parse_multisz(encode_multisz(["alice", "alice", "bob"]))

        self.assertEqual([m.value for m in members], ["alice", "alice", "bob"])
        self.assertEqual([m.ordinal for m in members], [1, 2, 3])
        self.assertEqual([m.index for m in members], [0, 1, 2])
        self.assertEqual(members[1].byte_offset, members[0].byte_offset + 12)

    def test_preserves_internal_and_trailing_empty_values(self):
        internal = parse_multisz(encode_multisz(["alice", "", "bob"]))
        trailing = parse_multisz(encode_multisz(["alice", ""]))
        only_empty = parse_multisz(b"\x00\x00\x00\x00")
        empty_list = parse_multisz(b"\x00\x00")

        self.assertEqual([m.value for m in internal], ["alice", "", "bob"])
        self.assertEqual([m.ordinal for m in internal], [1, 2, 3])
        self.assertEqual(internal[1].byte_length, 0)

        self.assertEqual([m.value for m in trailing], ["alice", ""])
        self.assertEqual(trailing[1].ordinal, 2)

        self.assertEqual([m.value for m in only_empty], [""])
        self.assertEqual(empty_list, [])

    def test_does_not_emit_terminator_artifacts(self):
        members = parse_multisz(encode_multisz(["wuauserv", "gpsvc"]))
        self.assertEqual([m.value for m in members], ["wuauserv", "gpsvc"])
        self.assertEqual(len(members), 2)

    def test_generated_hives_preserve_key_position(self):
        from Registry.SequenceAudit import read_sequence

        path = os.path.join(os.path.dirname(__file__), "reg_samples",
                            "audit_recipients_baseline.hive")
        snapshot = read_sequence(path, "AuditConfig", "AuditRecipients")

        self.assertEqual(snapshot.key_path, "AuditConfig")
        self.assertEqual(snapshot.key_offset, 0x1024)
        self.assertIsNotNone(snapshot.value_offset)
        self.assertEqual(snapshot.values, ["alice", "", "bob", "alice", "rob"])
        self.assertEqual(snapshot.members[1].ordinal, 2)
        self.assertEqual(snapshot.members[1].value, "")
        self.assertTrue(snapshot.raw_hex)


if __name__ == "__main__":
    unittest.main(verbosity=2)
