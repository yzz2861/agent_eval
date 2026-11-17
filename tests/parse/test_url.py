# -*- coding: utf-8 -*-
#  This program is free software; you can redistribute it and/or modify
#  it under the terms of the GNU General Public License as published by
#  the Free Software Foundation; either version 2 of the License, or
#  (at your option) any later version.
#
#  This program is distributed in the hope that it will be useful,
#  but WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#  GNU General Public License for more details.
#
#  You should have received a copy of the GNU General Public License
#  along with this program; if not, write to the Free Software
#  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
#  MA 02110-1301, USA.
#
#  Author: Mauro Soria

from unittest import TestCase

from lib.core.settings import DUMMY_URL
from lib.parse.url import (
    append_query_string,
    canonical_path,
    canonical_url,
    clean_path,
    ensure_trailing_path_slash,
    parse_path,
    same_origin,
    same_origin_path,
)


class TestURLParsers(TestCase):
    def test_clean_path(self):
        self.assertEqual(clean_path("/foo?a=1#a=1"), "/foo")
        self.assertEqual(clean_path("/foo?a=1#a=1", keep_queries=True), "/foo?a=1")

    def test_parse_path(self):
        self.assertEqual(
            parse_path("foo/bar"),
            "foo/bar",
            "Path parser gives unexpected result")
        self.assertEqual(
            parse_path("/foo/bar"),
            "foo/bar",
            "Path parser gives unexpected result")
        self.assertEqual(
            parse_path(f"{DUMMY_URL}foo/bar"),
            "foo/bar",
            "Path parser gives unexpected result",
        )

    def test_ensure_trailing_path_slash_preserves_query(self):
        self.assertEqual(
            ensure_trailing_path_slash("https://example.com/admin?debug=true"),
            "https://example.com/admin/?debug=true",
        )

    def test_append_query_string(self):
        self.assertEqual(append_query_string("admin", "debug=true"), "admin?debug=true")
        self.assertEqual(
            append_query_string("admin?existing=true", "debug=true"),
            "admin?existing=true",
        )

    def test_same_origin_normalizes_host_case_and_default_ports(self):
        self.assertTrue(
            same_origin(
                "https://example.com/path",
                "https://EXAMPLE.COM:443/other",
            )
        )
        self.assertTrue(
            same_origin(
                "http://[2001:db8::1]/path",
                "http://[2001:DB8::1]:80/other",
            )
        )

    def test_same_origin_rejects_origin_changes_and_invalid_ports(self):
        base_url = "https://example.com/path"

        for url in (
            "https://other.example/path",
            "http://example.com/path",
            "https://example.com:444/path",
            "https://example.com:0/path",
            "https://example.com:invalid/path",
            "https://[invalid/path",
        ):
            with self.subTest(url=url):
                self.assertFalse(same_origin(base_url, url))

    def test_default_ports_preserve_origin_matching_for_hostnames_and_ip_literals(self):
        for host in ("example.test", "192.0.2.1", "[2001:db8::1]", "[::ffff:192.0.2.1]"):
            for scheme, port in (("http", 80), ("https", 443)):
                with self.subTest(host=host, scheme=scheme):
                    implicit = f"{scheme}://{host}/first"
                    explicit = f"{scheme}://{host}:{port}/second"
                    self.assertTrue(same_origin(implicit, explicit))
                    self.assertTrue(same_origin(explicit, implicit))
                    self.assertFalse(same_origin(implicit, f"{scheme}://{host}:8080/"))
        # This helper does not invent default ports for other schemes.
        self.assertTrue(same_origin("custom://example.test/a", "custom://example.test/b"))
        self.assertFalse(same_origin("custom://example.test/a", "custom://example.test:80/b"))

    def test_same_origin_path_resolves_relative_and_protocol_relative_urls(self):
        base_url = "https://example.com/admin"

        self.assertEqual(same_origin_path(base_url, "admin/"), "admin/")
        self.assertEqual(same_origin_path(base_url, "/admin/"), "admin/")
        self.assertIsNone(same_origin_path(base_url, "//other.example/admin/"))


class TestCanonicalPath(TestCase):
    def test_percent_encoding_variants_collapse(self):
        # Encoded unreserved characters decode to their literal form.
        self.assertEqual(canonical_path("%61dmin"), "admin")
        self.assertEqual(canonical_path("%61%64%6din"), "admin")
        self.assertEqual(
            canonical_path("%7euser/profile"),
            canonical_path("~user/profile"),
        )
        # Mixed-case hex triplets normalize to uppercase hex digits.
        self.assertEqual(canonical_path("a%2fb"), canonical_path("a%2Fb"))
        self.assertEqual(canonical_path("q%3fx"), canonical_path("q%3Fx"))

    def test_encoded_separators_keep_distinct_resources(self):
        # An encoded slash must never become a path separator.
        self.assertNotEqual(canonical_path("a%2Fb"), canonical_path("a/b"))
        self.assertNotEqual(canonical_path("q%3Fa"), canonical_path("q/a"))

    def test_case_folding_keeps_reserved_hex_triplets_uppercase(self):
        self.assertEqual(canonical_path("Admin%2f"), "admin%2F")
        self.assertEqual(canonical_path("caf%c3%a9"), "caf%C3%A9")

    def test_trailing_slash_variants_collapse(self):
        self.assertEqual(canonical_path("admin/"), canonical_path("admin"))
        self.assertEqual(
            canonical_path("nested/deep/"),
            canonical_path("nested/deep"),
        )
        # Multiple trailing slashes collapse as well.
        self.assertEqual(canonical_path("admin//"), canonical_path("admin"))
        # Root stays root.
        self.assertEqual(canonical_path("/"), "/")

    def test_case_variants_collapse(self):
        self.assertEqual(canonical_path("Admin/Users"), canonical_path("admin/users"))
        self.assertEqual(
            canonical_path("API/v1/EntrIES"),
            canonical_path("api/v1/entries"),
        )

    def test_queries_and_fragments_are_ignored(self):
        self.assertEqual(canonical_path("admin?a=1#frag"), "admin")
        self.assertEqual(
            canonical_path("Admin/?x=2", keep_trailing_slash=True),
            "admin/",
        )

    def test_keep_trailing_slash_preserves_directory_semantics(self):
        self.assertEqual(
            canonical_path("Admin/", keep_trailing_slash=True),
            "admin/",
        )
        self.assertEqual(
            canonical_path("admin", keep_trailing_slash=True),
            "admin",
        )


class TestCanonicalURL(TestCase):
    def test_origin_is_case_insensitive_and_default_ports_vanish(self):
        self.assertEqual(
            canonical_url("https://EXAMPLE.TEST:443/Admin/"),
            canonical_url("https://example.test/admin"),
        )
        self.assertEqual(
            canonical_url("http://Example.Test:80/a/"),
            canonical_url("http://example.test/a"),
        )

    def test_non_default_ports_remain_distinct(self):
        self.assertNotEqual(
            canonical_url("https://example.test:8443/admin"),
            canonical_url("https://example.test/admin"),
        )

    def test_path_variants_share_one_canonical_key(self):
        variants = (
            "https://example.test/Admin/",
            "https://example.test/admin",
            "https://example.test/%61dmin/",
            "https://example.test/ADMIN//",
        )
        keys = {canonical_url(value) for value in variants}
        self.assertEqual(keys, {"https://example.test/admin"})

    def test_origin_relative_input_is_treated_as_a_path(self):
        self.assertEqual(canonical_url("/Admin/"), "admin")
        self.assertEqual(canonical_url("/Admin/"), canonical_path("admin"))
