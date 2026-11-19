"""Oracle, dual-budget and syntax-unit reduction tests."""

import hashlib
import random
import unittest

from oletools.rtf_fuzz import model, mutators, oracle, reducer, seeds


class OracleTest(unittest.TestCase):
    def setUp(self):
        self.rng = random.Random(42)
        self.payload, self.documents = seeds.default_seed_corpus()
        self.baseline = oracle.extract(self.documents["hex_plain"])
        self.payload_md5 = hashlib.md5(self.payload).hexdigest()

    def test_extract_captures_fingerprints(self):
        self.assertEqual(self.baseline.object_count, 1)
        fingerprint = self.baseline.object_fingerprints[0]
        self.assertEqual(fingerprint["md5"], self.payload_md5)
        self.assertTrue(fingerprint["is_ole"])

    def test_valid_oracle_accepts_equivalent_variant(self):
        mutation = mutators.insert_blank_hex_fragment(
            model.parse_rtf(self.documents["hex_plain"]), self.rng)
        variant = oracle.extract(model.render(mutation.tree))
        self.assertIsNone(oracle.compare_valid(
            self.baseline, variant, mutation.as_record()))

    def test_valid_oracle_flags_byte_difference(self):
        mutation = mutators.corrupt_hex_digit(
            model.parse_rtf(self.documents["hex_plain"]), self.rng)
        variant = oracle.extract(model.render(mutation.tree))
        difference = oracle.compare_valid(
            self.baseline, variant, mutation.as_record())
        self.assertIsNotNone(difference)
        self.assertEqual(difference.kind, "valid_variant_byte_difference")

    def test_invalid_oracle_flags_silent_full_recovery(self):
        mutation = mutators.drop_opening_brace(
            model.parse_rtf(self.documents["hex_plain"]), self.rng)
        variant = oracle.extract(model.render(mutation.tree))
        difference = oracle.compare_invalid(
            self.baseline, variant, mutation.as_record(), self.payload_md5)
        if difference is not None:
            self.assertEqual(difference.kind,
                             "invalid_silent_full_object")

    def test_parser_exception_is_captured_not_raised(self):
        result = oracle.extract(b"{\\objdata \\bin9 abc")
        # malformed input must never escape the oracle as an exception
        self.assertIsInstance(result, oracle.ExtractionResult)


class BudgetTest(unittest.TestCase):
    def test_step_budget_blocks_after_limit(self):
        budget = oracle.Budget(max_steps=2, max_bytes=10 ** 9)
        document = b"{\\rtf1}"
        self.assertIsNotNone(oracle.run_with_budget(document, budget))
        self.assertIsNotNone(oracle.run_with_budget(document, budget))
        self.assertIsNone(oracle.run_with_budget(document, budget))
        self.assertEqual(budget.stop_reason, "max_steps_reached")

    def test_byte_budget_blocks_oversized_parse(self):
        budget = oracle.Budget(max_steps=10, max_bytes=5)
        self.assertIsNone(oracle.run_with_budget(b"{\\rtf1}", budget))
        self.assertEqual(budget.stop_reason, "max_bytes_reached")
        self.assertEqual(budget.steps_used, 0)


class ReducerTest(unittest.TestCase):
    def test_reduction_keeps_exact_difference_signature(self):
        rng = random.Random(7)
        baseline = oracle.extract(self_doc := seeds.default_seed_corpus()[1]["hex_plain"])
        payload, documents = seeds.default_seed_corpus()
        tree = model.parse_rtf(documents["hex_plain"])
        first = mutators.insert_ignored_group(tree, rng)
        second = mutators.corrupt_hex_digit(first.tree, rng)
        chain = [first.as_record(), second.as_record()]
        variant = oracle.extract(model.render(second.tree))
        difference = oracle.compare_valid(baseline, variant, chain)
        budget = oracle.Budget(max_steps=300, max_bytes=10 ** 7)
        comparator = lambda doc: oracle.compare_valid(
            baseline, oracle.extract(doc), chain)
        outcome = reducer.reduce_finding(
            second.tree, difference, budget, comparator)
        self.assertTrue(outcome.signature_kept)
        self.assertLessEqual(outcome.reduced_size, outcome.original_size)
        reduced_diff = comparator(outcome.document)
        self.assertEqual(reduced_diff.signature(), difference.signature())


if __name__ == "__main__":
    unittest.main()
