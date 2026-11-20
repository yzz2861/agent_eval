import unittest

from universal_guard import bind_evidence, parse_artifact

from .fixtures import build_artifact, evidence_for, parsed_artifact


def _rebuild_with_tampered_digest():
    data = bytearray(build_artifact())
    parsed = parsed_artifact()
    for slc in parsed.slices:
        data[slc.fat_offset + slc.fat_size - 1] ^= 0xFF
    return parse_artifact(bytes(data))


class TestEvidenceBinding(unittest.TestCase):
    def setUp(self):
        self.artifact = parsed_artifact()

    def test_matching_digest_binds_to_slice(self):
        bound, unmatched = bind_evidence(
            self.artifact.slices, evidence_for(self.artifact)
        )
        self.assertEqual(unmatched, [])
        for index in range(2):
            binding = bound[index]
            self.assertTrue(binding.digest_matches)
            self.assertTrue(binding.cdhash_matches)

    def test_stale_digest_fails_binding_after_bytes_change(self):
        original_evidence = evidence_for(self.artifact)
        rebuilt = _rebuild_with_tampered_digest()
        bound, unmatched = bind_evidence(
            rebuilt.slices, original_evidence
        )
        self.assertTrue(unmatched)
        self.assertIn(
            "evidence_digest_mismatch",
            [reason.code for reason in unmatched],
        )
        for binding in bound.values():
            self.assertFalse(binding.digest_matches)

    def test_evidence_for_unknown_architecture_is_unmatched(self):
        bogus = [
            {
                "verified": True,
                "digest_algorithm": "sha256",
                "digest_value": "00" * 32,
                "cpu_type": 999,
                "cpu_subtype": 0,
            }
        ]
        bound, unmatched = bind_evidence(self.artifact.slices, bogus)
        self.assertEqual(bound, {})
        self.assertEqual(unmatched[0].code, "evidence_arch_not_present")

    def test_wrong_cdhash_claim_is_flagged(self):
        evidence = evidence_for(self.artifact)
        evidence[0]["expected_cdhash"] = "11" * 32
        bound, _unmatched = bind_evidence(self.artifact.slices, evidence)
        self.assertFalse(bound[0].cdhash_matches)
        self.assertTrue(bound[1].cdhash_matches)


if __name__ == "__main__":
    unittest.main()
