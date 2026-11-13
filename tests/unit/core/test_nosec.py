#
# SPDX-License-Identifier: Apache-2.0
import testtools

from bandit.core import extension_loader
from bandit.core import nosec as b_nosec


class NosecParseTests(testtools.TestCase):
    def setUp(self):
        super().setUp()
        self.extman = extension_loader.MANAGER

    def _parse(self, comment):
        return b_nosec.parse_nosec_comment(comment, 1, self.extman)

    def test_plain_comment_is_not_nosec(self):
        self.assertIsNone(self._parse("# a regular comment"))
        self.assertIsNone(self._parse("# nosecreek"))

    def test_blanket_nosec_without_id(self):
        for comment in ("# nosec", "#nosec", "#  nosec  ", "# NOSEC"):
            record = self._parse(comment)
            self.assertTrue(record.valid)
            self.assertTrue(record.blanket)
            self.assertEqual([], record.selectors)
            self.assertTrue(record.suppresses("B602"))
            self.assertTrue(record.suppresses("B101"))

    def test_blanket_nosec_keeps_original_comment(self):
        comment = "# type: ignore # nosec # noqa: E501"
        record = self._parse(comment)
        self.assertTrue(record.blanket)
        self.assertEqual(comment, record.comment)

    def test_test_id_normalization(self):
        record = self._parse("# nosec: b602")
        self.assertTrue(record.valid)
        self.assertFalse(record.blanket)
        self.assertEqual(["B602"], record.selectors)
        self.assertEqual({"B602"}, record.test_ids)
        self.assertTrue(record.suppresses("B602"))
        self.assertFalse(record.suppresses("B607"))

    def test_optional_colon_and_spacing(self):
        record = self._parse("# NOSEC  B602 ,  b607 ")
        self.assertEqual(["B602", "B607"], record.selectors)
        self.assertEqual({"B602", "B607"}, record.test_ids)

    def test_plugin_name_alias_resolves_to_test_id(self):
        record = self._parse("# nosec assert_used")
        self.assertEqual(["assert_used"], record.selectors)
        self.assertEqual({"B101"}, record.test_ids)
        self.assertTrue(record.suppresses("B101"))

    def test_mixed_id_and_plugin_on_one_line(self):
        record = self._parse(
            "# nosec B602, subprocess_popen_with_shell_equals_true"
        )
        self.assertEqual(
            ["B602", "subprocess_popen_with_shell_equals_true"],
            record.selectors,
        )
        self.assertEqual({"B602"}, record.test_ids)
        self.assertTrue(record.suppresses("B602"))

    def test_wildcard_selector(self):
        record = self._parse("# nosec B60*")
        self.assertTrue(record.valid)
        self.assertEqual(["B60*"], record.selectors)
        self.assertEqual(set(), record.test_ids)
        self.assertTrue(record.suppresses("B602"))
        self.assertTrue(record.suppresses("B607"))
        self.assertFalse(record.suppresses("B101"))

    def test_unknown_test_id_is_invalid_not_blanket(self):
        record = self._parse("# nosec B999")
        self.assertFalse(record.valid)
        self.assertFalse(record.blanket)
        self.assertFalse(record.suppresses("B602"))
        self.assertIn("B999", record.error)

    def test_unknown_plugin_name_is_invalid(self):
        record = self._parse("# nosec not_a_real_plugin")
        self.assertFalse(record.valid)
        self.assertIn("not_a_real_plugin", record.error)

    def test_space_separated_selectors_are_rejected(self):
        record = self._parse("# nosec B607 B602")
        self.assertFalse(record.valid)
        self.assertFalse(record.blanket)
        self.assertFalse(record.suppresses("B602"))

    def test_duplicate_selectors_are_rejected(self):
        record = self._parse("# nosec B602, B602")
        self.assertFalse(record.valid)
        self.assertIn("duplicate", record.error)
        record = self._parse("# nosec b602, B602")
        self.assertFalse(record.valid)

    def test_empty_and_garbage_selectors_are_rejected(self):
        for comment in ("# nosec: ,B602", "# nosec Bx12", "# nosec B12"):
            record = self._parse(comment)
            self.assertFalse(record.valid, comment)
            self.assertFalse(record.suppresses("B602"))

    def test_wildcard_matching_nothing_is_rejected(self):
        record = self._parse("# nosec B99*")
        self.assertFalse(record.valid)
        self.assertIn("wildcard", record.error)

    def test_inline_comment_with_trailing_hash_directives(self):
        comment = "# type: ignore # nosec B607 # noqa: E501"
        record = self._parse(comment)
        self.assertTrue(record.valid)
        self.assertEqual(["B607"], record.selectors)
        self.assertEqual(comment, record.comment)
