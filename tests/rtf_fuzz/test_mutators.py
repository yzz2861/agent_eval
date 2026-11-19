"""Structure-aware mutator tests: equivalence and contradiction checks."""

import random
import unittest

from oletools import rtfobj
from oletools.rtf_fuzz import model, mutators, seeds


def _extract(document):
    parser = rtfobj.RtfObjParser(document)
    parser.parse()
    return [rtf_object.rawdata for rtf_object in parser.objects]

LENGTH_CONTRADICTIONS = {
    "bin_length_too_large", "bin_length_too_small",
    "bin_negative_length", "bin_missing_length",
}


class MutatorTest(unittest.TestCase):
    def setUp(self):
        self.rng = random.Random(20261119)
        self.payload, self.documents = seeds.default_seed_corpus()
        self.reference = _extract(self.documents["hex_plain"])

    def test_every_valid_mutator_preserves_object_bytes(self):
        exercised = set()
        for _ in range(200):
            name, document = sorted(self.documents.items())[_ % 7]
            tree = model.parse_rtf(document)
            mutation = mutators.valid_mutation(tree, self.rng)
            if mutation is None:
                continue
            self.assertEqual(_extract(model.render(mutation.tree)),
                             self.reference, mutation.name)
            exercised.add(mutation.name)
        self.assertTrue(exercised)

    def test_blank_and_legal_fragments_never_change_result(self):
        for name in ("insert_blank_hex_fragment", "insert_newline_fragment",
                     "insert_ignored_group", "insert_nonhex_in_hex"):
            function = getattr(mutators, name)
            for seed_name, document in sorted(self.documents.items()):
                mutation = function(model.parse_rtf(document), self.rng)
                if mutation is None:
                    continue
                self.assertEqual(
                    _extract(model.render(mutation.tree)), self.reference,
                    (name, seed_name))

    def test_length_contradiction_never_silently_yields_full_object(self):
        for name in LENGTH_CONTRADICTIONS:
            function = getattr(mutators, name)
            for seed_name in ("bin_single", "bin_multi", "mixed_hex_bin"):
                document = self.documents[seed_name]
                mutation = function(model.parse_rtf(document), self.rng)
                if mutation is None:
                    continue
                extracted = _extract(model.render(mutation.tree))
                self.assertFalse(
                    extracted == self.reference,
                    "%s on %s silently produced the full object"
                    % (name, seed_name))

    def test_invalid_mutators_record_transformation_chain(self):
        document = self.documents["hex_plain"]
        mutation = mutators.invalid_mutation(
            model.parse_rtf(document), self.rng)
        self.assertIsNotNone(mutation)
        record = mutation.as_record()
        self.assertEqual(record["category"], "invalid")
        self.assertTrue(record["name"])

    def test_mutators_do_not_mutate_input_tree(self):
        tree = model.parse_rtf(self.documents["hex_plain"])
        before = model.render(tree)
        mutators.insert_blank_hex_fragment(tree, self.rng)
        self.assertEqual(model.render(tree), before)


if __name__ == "__main__":
    unittest.main()
