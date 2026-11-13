import unittest

from secure.headers import Vary
from secure.headers.base_header import HeaderDefaultValue


class TestVary(unittest.TestCase):
    def test_default_value(self) -> None:
        self.assertEqual(Vary().header_value, HeaderDefaultValue.VARY.value)
        self.assertEqual(Vary().header_name, "Vary")

    def test_adds_fields_in_canonical_order(self) -> None:
        vary = Vary().user_agent().cookie().accept_encoding().authorization()
        self.assertEqual(vary.header_value, "Accept-Encoding, Authorization, Cookie, User-Agent")

    def test_deduplicates_field_names_case_insensitively(self) -> None:
        vary = Vary().add("Cookie").add("cookie").add("COOKIE")
        self.assertEqual(vary.header_value, "Cookie")

    def test_merge_preserves_existing_fields(self) -> None:
        vary = Vary().merge("Accept-Encoding").merge("Cookie, Authorization")
        self.assertEqual(vary.header_value, "Accept-Encoding, Authorization, Cookie")

    def test_parse_and_value_are_stable(self) -> None:
        vary = Vary.parse("accept-encoding, accept-language").add("Cookie")
        self.assertEqual(vary.header_value, "Accept-Encoding, Accept-Language, Cookie")
        vary.value("Cookie")
        self.assertEqual(vary.header_value, "Cookie")
        vary.clear()
        self.assertEqual(vary.header_value, "Accept-Encoding")

    def test_wildcard_dominates(self) -> None:
        vary = Vary().cookie().any().authorization()
        self.assertEqual(vary.header_value, "*")

    def test_rejects_invalid_field_names_and_crlf(self) -> None:
        with self.assertRaises(ValueError):
            Vary().add("bad field")
        with self.assertRaises(ValueError):
            Vary().value("bad\rvalue")


if __name__ == "__main__":
    unittest.main()
