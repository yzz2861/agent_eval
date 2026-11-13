import unittest

from secure.headers import CacheControl


class TestCacheControlMerging(unittest.TestCase):
    def test_parse_preserves_existing_directives(self) -> None:
        parsed = CacheControl.parse("private, max-age=600, no-cache, custom=value")
        self.assertEqual(parsed.header_value, "no-cache, private, max-age=600, custom=value")

    def test_sensitive_baseline(self) -> None:
        self.assertEqual(
            CacheControl().sensitive().header_value,
            "no-store, private, max-age=0",
        )

    def test_merge_keeps_existing_private_and_stricter_directives(self) -> None:
        merged = (
            CacheControl()
            .sensitive()
            .merge("private, max-age=600, no-cache, must-revalidate, proxy-revalidate, s-maxage=600")
        )
        value = merged.header_value

        self.assertIn("no-store", value)
        self.assertIn("private", value)
        self.assertIn("max-age=0", value)
        self.assertIn("s-maxage=0", value)
        self.assertIn("no-cache", value)
        self.assertIn("must-revalidate", value)
        self.assertIn("proxy-revalidate", value)
        self.assertNotIn("max-age=600", value)
        self.assertNotIn("s-maxage=600", value)

    def test_merge_drops_public_and_immutable_for_sensitive_responses(self) -> None:
        merged = CacheControl().sensitive().merge("public, max-age=31536000, immutable")
        self.assertEqual(merged.header_value, "no-store, private, max-age=0")

    def test_merge_deduplicates_and_orders_directives(self) -> None:
        merged = CacheControl().sensitive().merge("max-age=60, no-store, private, max-age=30, no-cache, no-store")
        self.assertEqual(merged.header_value, "no-store, no-cache, private, max-age=0")

    def test_duplicate_headers_merge_into_one_value(self) -> None:
        first = CacheControl().sensitive()
        first.merge("private, max-age=600")
        first.merge("no-cache")
        self.assertEqual(first.header_value, "no-store, no-cache, private, max-age=0")

    def test_value_and_default_behavior_remain_compatible(self) -> None:
        self.assertEqual(CacheControl().header_value, "no-store, max-age=0")
        self.assertEqual(CacheControl().no_cache().header_value, "no-cache")
        self.assertEqual(CacheControl().value("public, max-age=60").header_value, "public, max-age=60")


if __name__ == "__main__":
    unittest.main()
