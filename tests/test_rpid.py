# coding=utf-8

# Copyright (c) 2013 Yubico AB
# All rights reserved.
#
#   Redistribution and use in source and binary forms, with or
#   without modification, are permitted provided that the following
#   conditions are met:
#
#    1. Redistributions of source code must retain the above copyright
#       notice, this list of conditions and the following disclaimer.
#    2. Redistributions in binary form must reproduce the above
#       copyright notice, this list of conditions and the following
#       disclaimer in the documentation and/or other materials provided
#       with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
# "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
# LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
# FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
# COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
# INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
# BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
# LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
# CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
# LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
# ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.

import unittest

from fido2.rpid import (
    InvalidConfigurationError,
    OriginMismatchError,
    RpIdMismatchError,
    RpIdPolicy,
    verify_origin,
    verify_rp_id,
)


class TestRpId(unittest.TestCase):
    def test_valid_ids(self):
        self.assertTrue(verify_rp_id("example.com", "https://register.example.com"))
        self.assertTrue(verify_rp_id("example.com", "https://fido.example.com"))
        self.assertTrue(verify_rp_id("example.com", "https://www.example.com:444"))

    def test_invalid_ids(self):
        self.assertFalse(verify_rp_id("example.com", "http://example.com"))
        self.assertFalse(verify_rp_id("example.com", "http://www.example.com"))
        self.assertFalse(verify_rp_id("example.com", "https://example-test.com"))

        self.assertFalse(
            verify_rp_id("companyA.hosting.example.com", "https://register.example.com")
        )
        self.assertFalse(
            verify_rp_id(
                "companyA.hosting.example.com", "https://companyB.hosting.example.com"
            )
        )

    def test_suffix_list(self):
        self.assertFalse(verify_rp_id("co.uk", "https://foobar.co.uk"))
        self.assertTrue(verify_rp_id("foobar.co.uk", "https://site.foobar.co.uk"))
        self.assertFalse(verify_rp_id("appspot.com", "https://example.appspot.com"))
        self.assertTrue(
            verify_rp_id("example.appspot.com", "https://example.appspot.com")
        )

    def test_suffix_list_wildcard(self):
        # *.ck means any X.ck is a public suffix
        self.assertFalse(verify_rp_id("example.ck", "https://evil.example.ck"))
        self.assertFalse(verify_rp_id("example.np", "https://evil.example.np"))
        # Exact match still works
        self.assertTrue(verify_rp_id("example.ck", "https://example.ck"))

    def test_suffix_list_wildcard_exception(self):
        # !www.ck means www.ck is NOT a public suffix despite *.ck
        self.assertTrue(verify_rp_id("www.ck", "https://sub.www.ck"))

    def test_localhost_http_secure_context(self):
        # Localhost and subdomains are secure contexts in most browsers
        self.assertTrue(verify_rp_id("localhost", "http://localhost"))
        self.assertTrue(verify_rp_id("localhost", "http://example.localhost"))
        self.assertTrue(verify_rp_id("example.localhost", "http://example.localhost"))
        self.assertTrue(verify_rp_id("localhost", "http://localhost:8000"))
        self.assertFalse(verify_rp_id("localhost", "http://"))

    def test_subdomain_and_parent_domain(self):
        self.assertTrue(verify_rp_id("login.example.com", "https://login.example.com"))
        self.assertTrue(
            verify_rp_id("login.example.com", "https://app.login.example.com")
        )
        # A sibling tenant must not be accepted merely due to a string prefix.
        self.assertFalse(
            verify_rp_id(
                "companyA.hosting.example.com",
                "https://companyA.hosting.example.com.evil.com",
            )
        )
        self.assertFalse(
            verify_rp_id("login.example.com", "https://notlogin.example.com")
        )

    def test_evil_subdomain_uses_same_rp_id(self):
        # The suffix rule makes the subdomain usable, which is standard WebAuthn
        # behavior; origin allow lists are responsible for tenant isolation.
        self.assertTrue(
            verify_rp_id("login.example.com", "https://evil.login.example.com")
        )
        policy = RpIdPolicy(
            "login.example.com",
            ["https://login.example.com"],
        )
        self.assertTrue(policy.verify_origin("https://login.example.com"))
        self.assertFalse(policy.verify_origin("https://evil.login.example.com"))

    def test_trailing_dot_normalization(self):
        self.assertTrue(verify_rp_id("example.com.", "https://example.com"))
        self.assertTrue(verify_rp_id("example.com", "https://example.com."))
        self.assertTrue(verify_rp_id("example.com", "https://WWW.Example.COM."))
        self.assertFalse(verify_rp_id("example.com..", "https://example.com"))

    def test_case_normalization(self):
        self.assertTrue(verify_rp_id("EXAMPLE.com", "https://example.com"))
        self.assertTrue(verify_rp_id("example.com", "https://Example.COM"))

    def test_idna_normalization(self):
        self.assertTrue(verify_rp_id("\u4f8b\u3048.jp", "https://xn--r8jz45g.jp"))
        self.assertTrue(verify_rp_id("xn--r8jz45g.jp", "https://\u4f8b\u3048.jp"))
        self.assertTrue(
            verify_rp_id("\u4f8b\u3048.jp", "https://www.\u4f8b\u3048.jp")
        )
        # A Unicode look-alike must not pass a string-prefix check.
        self.assertFalse(
            verify_rp_id("example.com", "https://example.com.\u4f8b\u3048.jp")
        )

    def test_ipv4_and_ipv6_origins(self):
        self.assertTrue(verify_rp_id("192.168.0.1", "https://192.168.0.1"))
        self.assertTrue(verify_rp_id("192.168.0.1", "https://192.168.0.1:8443"))
        self.assertFalse(verify_rp_id("192.168.0.1", "https://192.168.0.2"))
        # IP literals never support suffix matching, even against a domain RP ID.
        self.assertFalse(verify_rp_id("168.0.1", "https://192.168.0.1"))
        self.assertFalse(verify_rp_id("192.168.0.1", "https://10.192.168.0.1"))
        self.assertTrue(
            verify_rp_id("2001:db8::1", "https://[2001:db8::1]:8443")
        )
        self.assertTrue(
            verify_rp_id("2001:db8::1", "https://[2001:0db8:0000::0001]")
        )
        self.assertFalse(verify_rp_id("2001:db8::1", "https://[2001:db8::2]"))
        self.assertFalse(verify_rp_id("0xc0.0xa8.0.1", "https://192.168.0.1"))

    def test_origin_allow_list_exact_match(self):
        allowed = [
            "https://example.com",
            "https://login.example.com:8443",
            "http://localhost:8000",
        ]
        self.assertTrue(verify_origin("https://example.com", allowed))
        # Default ports are normalized away.
        self.assertTrue(verify_origin("https://example.com:443", allowed))
        self.assertTrue(verify_origin("https://EXAMPLE.com.", allowed))
        self.assertTrue(verify_origin("http://localhost:8000/", allowed))
        # Scheme, host and port must all match exactly.
        self.assertFalse(verify_origin("http://example.com", allowed))
        self.assertFalse(verify_origin("https://other.example.com", allowed))
        self.assertFalse(verify_origin("https://login.example.com", allowed))
        # Userinfo, paths and fragments are not origins.
        self.assertFalse(verify_origin("https://user@example.com", allowed))
        self.assertFalse(verify_origin("https://example.com/path", allowed))
        self.assertFalse(verify_origin("https://example.com#fragment", allowed))
        self.assertFalse(verify_origin("https://example.com?query", allowed))
        self.assertFalse(verify_origin("https://evil.com\\@example.com", allowed))

    def test_empty_allow_list_denies_all(self):
        self.assertFalse(verify_origin("https://example.com", []))
        policy = RpIdPolicy("example.com", [])
        self.assertFalse(policy.verify_origin("https://example.com"))
        with self.assertRaises(OriginMismatchError):
            policy.check_origin("https://example.com")

    def test_policy_validates_configuration(self):
        with self.assertRaises(InvalidConfigurationError):
            RpIdPolicy("co.uk", ["https://foobar.co.uk"])
        with self.assertRaises(InvalidConfigurationError):
            RpIdPolicy("example.com", ["not-an-origin"])
        with self.assertRaises(InvalidConfigurationError):
            RpIdPolicy("example.com", ["https://user@example.com"])
        with self.assertRaises(InvalidConfigurationError):
            RpIdPolicy("not a domain", ["https://example.com"])
        # localhost remains usable for development.
        RpIdPolicy("localhost", ["http://localhost:8000"])

    def test_policy_error_types_are_distinct(self):
        policy = RpIdPolicy(
            "example.com", ["https://example.com", "https://app.example.com:8443"]
        )
        policy.validate("example.com", "https://example.com")
        with self.assertRaises(OriginMismatchError):
            policy.check_origin("https://evil.example.com")
        with self.assertRaises(RpIdMismatchError):
            policy.check_rp_id("other.com", "https://example.com")

    def test_malformed_inputs_never_raise_from_boolean_api(self):
        for rp_id in ("", None, "example..com", "ex_ample.com"):
            self.assertFalse(verify_rp_id(rp_id, "https://example.com"))
        for origin in (
            "",
            None,
            "not a url",
            "ftp://example.com",
            "https://",
            "https://example.com:bad",
        ):
            self.assertFalse(verify_rp_id("example.com", origin))
            self.assertFalse(verify_origin(origin, ["https://example.com"]))

    def test_policy_binds_configured_rp_id(self):
        policy = RpIdPolicy("example.com", ["https://app.example.com"])
        self.assertTrue(policy.verify_rp_id(origin="https://app.example.com"))
        self.assertFalse(policy.verify_rp_id(origin="https://other.com"))
        policy.validate(origin="https://app.example.com")
        with self.assertRaises(RpIdMismatchError):
            policy.check_rp_id(origin="https://other.com")
        with self.assertRaises(InvalidConfigurationError):
            RpIdPolicy("example.com", "https://example.com")
