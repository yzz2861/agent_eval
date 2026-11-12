#!/usr/bin/env python

import base64
import datetime
import hashlib
import os
import subprocess
import sys
import time
import unittest
from urllib.parse import parse_qsl, urlparse
from warnings import warn

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "src"))
import pyotp  # noqa

try:
    from zoneinfo import ZoneInfo
except ImportError:  # pragma: no cover - Python < 3.9
    ZoneInfo = None

ZONEINFO_AVAILABLE = ZoneInfo is not None
TZSET_AVAILABLE = hasattr(time, "tzset")

UTC = datetime.timezone.utc
FIXED_TS = 1710055800  # 2024-03-10T07:30:00Z, a Sunday just after the US spring-forward
SECRET = "ABCDEFGH"


class HOTPExampleValuesFromTheRFC(unittest.TestCase):
    def test_match_rfc(self):
        # 12345678901234567890 in Bas32
        # GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ
        hotp = pyotp.HOTP("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ")
        self.assertEqual(hotp.at(0), "755224")
        self.assertEqual(hotp.at(1), "287082")
        self.assertEqual(hotp.at(2), "359152")
        self.assertEqual(hotp.at(3), "969429")
        self.assertEqual(hotp.at(4), "338314")
        self.assertEqual(hotp.at(5), "254676")
        self.assertEqual(hotp.at(6), "287922")
        self.assertEqual(hotp.at(7), "162583")
        self.assertEqual(hotp.at(8), "399871")
        self.assertEqual(hotp.at(9), "520489")

    def test_invalid_input(self):
        hotp = pyotp.HOTP("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ")
        with self.assertRaises(ValueError):
            hotp.at(-1)

    def test_verify_otp_reuse(self):
        hotp = pyotp.HOTP("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ")
        self.assertTrue(hotp.verify("520489", 9))
        self.assertFalse(hotp.verify("520489", 10))
        self.assertFalse(hotp.verify("520489", 10))

    def test_provisioning_uri(self):
        hotp = pyotp.HOTP("wrn3pqx5uqxqvnqr", name="mark@percival")

        url = urlparse(hotp.provisioning_uri())
        self.assertEqual(url.scheme, "otpauth")
        self.assertEqual(url.netloc, "hotp")
        self.assertEqual(url.path, "/mark%40percival")
        self.assertEqual(dict(parse_qsl(url.query)), {"secret": "wrn3pqx5uqxqvnqr", "counter": "0"})
        self.assertEqual(hotp.provisioning_uri(), pyotp.parse_uri(hotp.provisioning_uri()).provisioning_uri())

        hotp = pyotp.HOTP("wrn3pqx5uqxqvnqr", name="mark@percival", initial_count=12)
        url = urlparse(hotp.provisioning_uri())
        self.assertEqual(url.scheme, "otpauth")
        self.assertEqual(url.netloc, "hotp")
        self.assertEqual(url.path, "/mark%40percival")
        self.assertEqual(dict(parse_qsl(url.query)), {"secret": "wrn3pqx5uqxqvnqr", "counter": "12"})
        self.assertEqual(hotp.provisioning_uri(), pyotp.parse_uri(hotp.provisioning_uri()).provisioning_uri())

        hotp = pyotp.HOTP("wrn3pqx5uqxqvnqr", name="mark@percival", issuer="FooCorp!")
        url = urlparse(hotp.provisioning_uri())
        self.assertEqual(url.scheme, "otpauth")
        self.assertEqual(url.netloc, "hotp")
        self.assertEqual(url.path, "/FooCorp%21:mark%40percival")
        self.assertEqual(
            dict(parse_qsl(url.query)), {"secret": "wrn3pqx5uqxqvnqr", "counter": "0", "issuer": "FooCorp!"}
        )
        self.assertEqual(hotp.provisioning_uri(), pyotp.parse_uri(hotp.provisioning_uri()).provisioning_uri())

        key = "c7uxuqhgflpw7oruedmglbrk7u6242vb"
        hotp = pyotp.HOTP(key, digits=8, digest=hashlib.sha256, name="baco@peperina", issuer="FooCorp")
        url = urlparse(hotp.provisioning_uri())
        self.assertEqual(url.scheme, "otpauth")
        self.assertEqual(url.netloc, "hotp")
        self.assertEqual(url.path, "/FooCorp:baco%40peperina")
        self.assertEqual(
            dict(parse_qsl(url.query)),
            {
                "secret": "c7uxuqhgflpw7oruedmglbrk7u6242vb",
                "counter": "0",
                "issuer": "FooCorp",
                "digits": "8",
                "algorithm": "SHA256",
            },
        )
        self.assertEqual(hotp.provisioning_uri(), pyotp.parse_uri(hotp.provisioning_uri()).provisioning_uri())

        hotp = pyotp.HOTP(key, digits=8, name="baco@peperina", issuer="Foo Corp", initial_count=10)
        url = urlparse(hotp.provisioning_uri())
        self.assertEqual(url.scheme, "otpauth")
        self.assertEqual(url.netloc, "hotp")
        self.assertEqual(url.path, "/Foo%20Corp:baco%40peperina")
        self.assertEqual(
            dict(parse_qsl(url.query)),
            {"secret": "c7uxuqhgflpw7oruedmglbrk7u6242vb", "counter": "10", "issuer": "Foo Corp", "digits": "8"},
        )
        self.assertEqual(hotp.provisioning_uri(), pyotp.parse_uri(hotp.provisioning_uri()).provisioning_uri())

        # initial_count=0 must be respected even though 0 is falsy
        hotp = pyotp.HOTP("wrn3pqx5uqxqvnqr", name="mark@percival", initial_count=7)
        url = urlparse(hotp.provisioning_uri(initial_count=0))
        self.assertEqual(dict(parse_qsl(url.query))["counter"], "0")

        code = pyotp.totp.TOTP("S46SQCPPTCNPROMHWYBDCTBZXV")
        self.assertEqual(code.provisioning_uri(), "otpauth://totp/Secret?secret=S46SQCPPTCNPROMHWYBDCTBZXV")
        code.verify("123456")
        self.assertEqual(code.provisioning_uri(), "otpauth://totp/Secret?secret=S46SQCPPTCNPROMHWYBDCTBZXV")

    def test_other_secret(self):
        hotp = pyotp.HOTP("N3OVNIBRERIO5OHGVCMDGS4V4RJ3AUZOUN34J6FRM4P6JIFCG3ZA")
        self.assertEqual(hotp.at(0), "737863")
        self.assertEqual(hotp.at(1), "390601")
        self.assertEqual(hotp.at(2), "363354")
        self.assertEqual(hotp.at(3), "936780")
        self.assertEqual(hotp.at(4), "654019")


class TOTPExampleValuesFromTheRFC(unittest.TestCase):
    RFC_VALUES = {
        (hashlib.sha1, b"12345678901234567890"): (
            (59, "94287082"),
            (1111111109, "07081804"),
            (1111111111, "14050471"),
            (1234567890, "89005924"),
            (2000000000, "69279037"),
            (20000000000, "65353130"),
        ),
        (hashlib.sha256, b"12345678901234567890123456789012"): (
            (59, 46119246),
            (1111111109, "68084774"),
            (1111111111, "67062674"),
            (1234567890, "91819424"),
            (2000000000, "90698825"),
            (20000000000, "77737706"),
        ),
        (hashlib.sha512, b"1234567890123456789012345678901234567890123456789012345678901234"): (
            (59, 90693936),
            (1111111109, "25091201"),
            (1111111111, "99943326"),
            (1234567890, "93441116"),
            (2000000000, "38618901"),
            (20000000000, "47863826"),
        ),
    }

    def test_match_rfc(self):
        for digest, secret in self.RFC_VALUES:
            totp = pyotp.TOTP(base64.b32encode(secret), 8, digest)
            for utime, code in self.RFC_VALUES[(digest, secret)]:
                if utime > sys.maxsize:
                    warn(
                        "32-bit platforms use native functions to handle timestamps, so they fail this test"
                        + " (and will fail after 19 January 2038)"
                    )
                    continue
                value = totp.at(utime)
                msg = "%s != %s (%s, time=%d)"
                msg %= (value, code, digest().name, utime)
                self.assertEqual(value, str(code), msg)

    def test_match_rfc_digit_length(self):
        totp = pyotp.TOTP("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ")
        self.assertEqual(totp.at(1111111111), "050471")
        self.assertEqual(totp.at(1234567890), "005924")
        self.assertEqual(totp.at(2000000000), "279037")

    def test_match_google_authenticator_output(self):
        totp = pyotp.TOTP("wrn3pqx5uqxqvnqr")
        with Timecop(1297553958):
            self.assertEqual(totp.now(), "102705")

    def test_validate_totp(self):
        totp = pyotp.TOTP("wrn3pqx5uqxqvnqr")
        with Timecop(1297553958):
            self.assertTrue(totp.verify("102705"))
            self.assertTrue(totp.verify("102705"))
        with Timecop(1297553958 + 30):
            self.assertFalse(totp.verify("102705"))

    def test_input_before_epoch(self):
        totp = pyotp.TOTP("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ")
        # -1 and -29.5 round down to 0 (epoch)
        self.assertEqual(totp.at(-1), "755224")
        self.assertEqual(totp.at(-29.5), "755224")
        with self.assertRaises(ValueError):
            totp.at(-30)

    def test_validate_totp_with_digit_length(self):
        totp = pyotp.TOTP("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ")
        with Timecop(1111111111):
            self.assertTrue(totp.verify("050471"))
        with Timecop(1297553958 + 30):
            self.assertFalse(totp.verify("050471"))

    def test_provisioning_uri(self):
        totp = pyotp.TOTP("wrn3pqx5uqxqvnqr", name="mark@percival")
        url = urlparse(totp.provisioning_uri())
        self.assertEqual(url.scheme, "otpauth")
        self.assertEqual(url.netloc, "totp")
        self.assertEqual(url.path, "/mark%40percival")
        self.assertEqual(dict(parse_qsl(url.query)), {"secret": "wrn3pqx5uqxqvnqr"})
        self.assertEqual(totp.provisioning_uri(), pyotp.parse_uri(totp.provisioning_uri()).provisioning_uri())

        totp = pyotp.TOTP("wrn3pqx5uqxqvnqr", name="mark@percival", issuer="FooCorp!")
        url = urlparse(totp.provisioning_uri())
        self.assertEqual(url.scheme, "otpauth")
        self.assertEqual(url.netloc, "totp")
        self.assertEqual(url.path, "/FooCorp%21:mark%40percival")
        self.assertEqual(dict(parse_qsl(url.query)), {"secret": "wrn3pqx5uqxqvnqr", "issuer": "FooCorp!"})
        self.assertEqual(totp.provisioning_uri(), pyotp.parse_uri(totp.provisioning_uri()).provisioning_uri())

        key = "c7uxuqhgflpw7oruedmglbrk7u6242vb"
        totp = pyotp.TOTP(key, digits=8, interval=60, digest=hashlib.sha256, name="baco@peperina", issuer="FooCorp")
        url = urlparse(totp.provisioning_uri())
        self.assertEqual(url.scheme, "otpauth")
        self.assertEqual(url.netloc, "totp")
        self.assertEqual(url.path, "/FooCorp:baco%40peperina")
        self.assertEqual(
            dict(parse_qsl(url.query)),
            {
                "secret": "c7uxuqhgflpw7oruedmglbrk7u6242vb",
                "issuer": "FooCorp",
                "digits": "8",
                "period": "60",
                "algorithm": "SHA256",
            },
        )
        self.assertEqual(totp.provisioning_uri(), pyotp.parse_uri(totp.provisioning_uri()).provisioning_uri())

        totp = pyotp.TOTP(key, digits=8, interval=60, name="baco@peperina", issuer="FooCorp")
        url = urlparse(totp.provisioning_uri())
        self.assertEqual(url.scheme, "otpauth")
        self.assertEqual(url.netloc, "totp")
        self.assertEqual(url.path, "/FooCorp:baco%40peperina")
        self.assertEqual(
            dict(parse_qsl(url.query)),
            {"secret": "c7uxuqhgflpw7oruedmglbrk7u6242vb", "issuer": "FooCorp", "digits": "8", "period": "60"},
        )
        self.assertEqual(totp.provisioning_uri(), pyotp.parse_uri(totp.provisioning_uri()).provisioning_uri())

        totp = pyotp.TOTP(key, digits=8, name="baco@peperina", issuer="FooCorp")
        url = urlparse(totp.provisioning_uri())
        self.assertEqual(url.scheme, "otpauth")
        self.assertEqual(url.netloc, "totp")
        self.assertEqual(url.path, "/FooCorp:baco%40peperina")
        self.assertEqual(
            dict(parse_qsl(url.query)),
            {"secret": "c7uxuqhgflpw7oruedmglbrk7u6242vb", "issuer": "FooCorp", "digits": "8"},
        )
        self.assertEqual(totp.provisioning_uri(), pyotp.parse_uri(totp.provisioning_uri()).provisioning_uri())

    def test_random_key_generation(self):
        self.assertEqual(len(pyotp.random_base32()), 32)
        self.assertEqual(len(pyotp.random_base32(length=34)), 34)
        self.assertEqual(len(pyotp.random_hex()), 40)
        self.assertEqual(len(pyotp.random_hex(length=42)), 42)
        with self.assertRaises(ValueError):
            pyotp.random_base32(length=31)
        with self.assertRaises(ValueError):
            pyotp.random_hex(length=39)


class SteamTOTP(unittest.TestCase):
    def test_match_examples(self):
        steam = pyotp.contrib.Steam("BASE32SECRET3232")

        self.assertEqual(steam.at(0), "2TC8B")
        self.assertEqual(steam.at(30), "YKKK4")
        self.assertEqual(steam.at(60), "M4HQB")
        self.assertEqual(steam.at(90), "DTVB3")

        steam = pyotp.contrib.Steam("FMXNK4QEGKVPULRTADY6JIDK5VHUBGZW")

        self.assertEqual(steam.at(0), "C5V56")
        self.assertEqual(steam.at(30), "QJY8Y")
        self.assertEqual(steam.at(60), "R3WQY")
        self.assertEqual(steam.at(90), "JG3T3")

    def test_verify(self):
        steam = pyotp.contrib.Steam("BASE32SECRET3232")
        with Timecop(1662883100):
            self.assertTrue(steam.verify("N3G63"))
        with Timecop(1662883100 + 30):
            self.assertFalse(steam.verify("N3G63"))

        with Timecop(946681223):
            self.assertTrue(steam.verify("7VP3X"))
        with Timecop(946681223 + 30):
            self.assertFalse(steam.verify("7VP3X"))

        steam = pyotp.contrib.Steam("FMXNK4QEGKVPULRTADY6JIDK5VHUBGZW")
        with Timecop(1662884261):
            self.assertTrue(steam.verify("V6WKJ"))
        with Timecop(1662884261 + 30):
            self.assertFalse(steam.verify("V6WKJ"))

        with Timecop(946681223):
            self.assertTrue(steam.verify("4MK54"))
        with Timecop(946681223 + 30):
            self.assertFalse(steam.verify("4MK54"))


class CompareDigestTest(unittest.TestCase):
    method = staticmethod(pyotp.utils.compare_digest)

    def test_comparisons(self):
        self.assertTrue(self.method("", ""))
        self.assertTrue(self.method("a", "a"))
        self.assertTrue(self.method("a" * 1000, "a" * 1000))

        self.assertFalse(self.method("", "a"))
        self.assertFalse(self.method("a", ""))
        self.assertFalse(self.method("a" * 999 + "b", "a" * 1000))


class StringComparisonTest(CompareDigestTest):
    method = staticmethod(pyotp.utils.strings_equal)

    def test_fullwidth_input(self):
        self.assertTrue(self.method("ｘs１２３45", "xs12345"))

    def test_unicode_equal(self):
        self.assertTrue(self.method("ěšč45", "ěšč45"))


class CounterOffsetTest(unittest.TestCase):
    def test_counter_offset(self):
        totp = pyotp.TOTP("ABCDEFGH")
        self.assertEqual(totp.at(200), "028307")
        self.assertTrue(totp.at(200, 1), "681610")


class ValidWindowTest(unittest.TestCase):
    def test_valid_window(self):
        totp = pyotp.TOTP("ABCDEFGH")
        self.assertTrue(totp.verify("451564", 200, 1))
        self.assertTrue(totp.verify("028307", 200, 1))
        self.assertTrue(totp.verify("681610", 200, 1))
        self.assertFalse(totp.verify("195979", 200, 1))


class GetTimeCodeTest(unittest.TestCase):
    def test_timecode(self):
        totp = pyotp.TOTP("ABCDEFGH")
        self.assertEqual(totp.verify_and_get_timecode("451564", 200, 1), 5)
        self.assertEqual(totp.verify_and_get_timecode("028307", 200, 1), 6)
        self.assertEqual(totp.verify_and_get_timecode("681610", 200, 1), 7)
        self.assertFalse(totp.verify_and_get_timecode("195979", 200, 1))


class DigestFunctionTest(unittest.TestCase):
    def test_md5(self):
        with self.assertRaises(ValueError) as cm:
            pyotp.OTP(s="secret", digest=hashlib.md5)
        self.assertEqual(
            "selected digest function must generate digest size greater than or equals to 18 bytes", str(cm.exception)
        )

    def test_shake128(self):
        with self.assertRaises(ValueError) as cm:
            pyotp.OTP(s="secret", digest=hashlib.shake_128)
        self.assertEqual(
            "selected digest function must generate digest size greater than or equals to 18 bytes", str(cm.exception)
        )


class ParseUriTest(unittest.TestCase):
    def test_invalids(self):
        with self.assertRaises(ValueError) as cm:
            pyotp.parse_uri("http://hello.com")
        self.assertEqual("Not an otpauth URI", str(cm.exception))

        with self.assertRaises(ValueError) as cm:
            pyotp.parse_uri("otpauth://totp")
        self.assertEqual("No secret found in URI", str(cm.exception))

        with self.assertRaises(ValueError) as cm:
            pyotp.parse_uri("otpauth://derp?secret=foo")
        self.assertEqual("Not a supported OTP type", str(cm.exception))

        with self.assertRaises(ValueError) as cm:
            pyotp.parse_uri("otpauth://totp?digits=-1")
        self.assertEqual("Digits may only be 6, 7, or 8", str(cm.exception))

        with self.assertRaises(ValueError) as cm:
            pyotp.parse_uri("otpauth://totp/SomeIssuer:?issuer=AnotherIssuer")
        self.assertEqual("If issuer is specified in both label and parameters, it should be equal.", str(cm.exception))

        with self.assertRaises(ValueError) as cm:
            pyotp.parse_uri("otpauth://totp?algorithm=aes")
        self.assertEqual("Invalid value for algorithm, must be SHA1, SHA256 or SHA512", str(cm.exception))

    def test_parse_steam(self):
        otp = pyotp.parse_uri("otpauth://totp/Steam:?secret=SOME_SECRET&encoder=steam")
        self.assertEqual(type(otp), pyotp.contrib.Steam)

        otp = pyotp.parse_uri("otpauth://totp/Steam:?secret=SOME_SECRET")
        self.assertNotEqual(type(otp), pyotp.contrib.Steam)

    @unittest.skipIf(sys.version_info < (3, 6), "Skipping test that requires deterministic dict key enumeration")
    def test_algorithms(self):
        otp = pyotp.parse_uri("otpauth://totp?algorithm=SHA1&secret=GEZDGNBV&algorithm=SHA1")
        self.assertEqual(hashlib.sha1, otp.digest)
        self.assertEqual(otp.at(0), "734055")
        self.assertEqual(otp.at(30), "662488")
        self.assertEqual(otp.at(60), "289363")
        self.assertEqual(otp.provisioning_uri(), "otpauth://totp/Secret?secret=GEZDGNBV")
        self.assertEqual(otp.provisioning_uri(name="n", issuer_name="i"), "otpauth://totp/i:n?secret=GEZDGNBV&issuer=i")

        otp = pyotp.parse_uri("otpauth://totp?algorithm=SHA1&secret=GEZDGNBV&algorithm=SHA1&period=60")
        self.assertEqual(hashlib.sha1, otp.digest)
        self.assertEqual(otp.at(30), "734055")
        self.assertEqual(otp.at(60), "662488")
        self.assertEqual(
            otp.provisioning_uri(name="n", issuer_name="i"), "otpauth://totp/i:n?secret=GEZDGNBV&issuer=i&period=60"
        )

        otp = pyotp.parse_uri("otpauth://hotp?algorithm=SHA1&secret=GEZDGNBV&algorithm=SHA1")
        self.assertEqual(hashlib.sha1, otp.digest)
        self.assertEqual(otp.at(0), "734055")
        self.assertEqual(otp.at(1), "662488")
        self.assertEqual(otp.at(2), "289363")
        self.assertEqual(
            otp.provisioning_uri(name="n", issuer_name="i"), "otpauth://hotp/i:n?secret=GEZDGNBV&issuer=i&counter=0"
        )

        otp = pyotp.parse_uri("otpauth://hotp?algorithm=SHA1&secret=GEZDGNBV&algorithm=SHA1&counter=1")
        self.assertEqual(hashlib.sha1, otp.digest)
        self.assertEqual(otp.at(0), "662488")
        self.assertEqual(otp.at(1), "289363")
        self.assertEqual(
            otp.provisioning_uri(name="n", issuer_name="i"), "otpauth://hotp/i:n?secret=GEZDGNBV&issuer=i&counter=1"
        )

        otp = pyotp.parse_uri("otpauth://totp?algorithm=SHA1&secret=GEZDGNBV&algorithm=SHA256")
        self.assertEqual(hashlib.sha256, otp.digest)
        self.assertEqual(otp.at(0), "918961")
        self.assertEqual(otp.at(9000), "934470")

        otp = pyotp.parse_uri("otpauth://totp?algorithm=SHA1&secret=GEZDGNBV&algorithm=SHA512")
        self.assertEqual(hashlib.sha512, otp.digest)
        self.assertEqual(otp.at(0), "816660")
        self.assertEqual(otp.at(9000), "524153")

        self.assertEqual(
            otp.provisioning_uri(name="n", issuer_name="i", image="https://test.net/test.png"),
            "otpauth://totp/i:n?secret=GEZDGNBV&issuer=i&algorithm=SHA512&image=https%3A%2F%2Ftest.net%2Ftest.png",
        )
        with self.assertRaises(ValueError):
            otp.provisioning_uri(name="n", issuer_name="i", image="nourl")

        otp = pyotp.parse_uri(otp.provisioning_uri(name="n", issuer_name="i", image="https://test.net/test.png"))
        self.assertEqual(hashlib.sha512, otp.digest)

        otp = pyotp.parse_uri("otpauth://totp/Steam:?secret=FMXNK4QEGKVPULRTADY6JIDK5VHUBGZW&encoder=steam")
        self.assertEqual(type(otp), pyotp.contrib.Steam)
        self.assertEqual(otp.at(0), "C5V56")
        self.assertEqual(otp.at(30), "QJY8Y")
        self.assertEqual(otp.at(60), "R3WQY")
        self.assertEqual(otp.at(90), "JG3T3")

        # period and digits should be ignored
        otp = pyotp.parse_uri(
            "otpauth://totp/Steam:?secret=FMXNK4QEGKVPULRTADY6JIDK5VHUBGZW&period=15&digits=7&encoder=steam"
        )
        self.assertEqual(type(otp), pyotp.contrib.Steam)
        self.assertEqual(otp.at(0), "C5V56")
        self.assertEqual(otp.at(30), "QJY8Y")
        self.assertEqual(otp.at(60), "R3WQY")
        self.assertEqual(otp.at(90), "JG3T3")

        pyotp.parse_uri("otpauth://totp?secret=abc&image=foobar")

    def test_parse_encoded_colon_in_label(self):
        # Regression test for issue #174: an encoded colon (%3A) inside the
        # issuer or account name must not be treated as the issuer:account
        # separator. The label issuer and the query issuer should still match.
        otp = pyotp.parse_uri(
            "otpauth://totp/Text%3A%20More%20Text:Secret?secret=FFFFFFFAAAAAABBBBBBB&issuer=Text%3A%20More%20Text"
        )
        self.assertEqual(otp.name, "Secret")
        self.assertEqual(otp.issuer, "Text: More Text")

        # An encoded colon in the account name (no issuer) is kept intact.
        otp = pyotp.parse_uri("otpauth://totp/a%3Ab?secret=GEZDGNBV")
        self.assertEqual(otp.name, "a:b")
        self.assertIsNone(otp.issuer)

        # Round-trip: building the URI and parsing it back preserves both parts.
        source = pyotp.TOTP("FFFFFFFAAAAAABBBBBBB", name="Secret", issuer="Text: More Text")
        roundtrip = pyotp.parse_uri(source.provisioning_uri())
        self.assertEqual(roundtrip.name, "Secret")
        self.assertEqual(roundtrip.issuer, "Text: More Text")

        # A percent-encoded space in a plain issuer (no colon) still decodes.
        otp = pyotp.parse_uri("otpauth://totp/Big%20Corp:bob?secret=GEZDGNBV&issuer=Big%20Corp")
        self.assertEqual(otp.name, "bob")
        self.assertEqual(otp.issuer, "Big Corp")


@unittest.skipUnless(ZONEINFO_AVAILABLE, "zoneinfo is required for timezone policy tests")
class TimePolicyTest(unittest.TestCase):
    def setUp(self):
        self.local = pyotp.TOTP(SECRET)
        self.strict = pyotp.TOTP(SECRET, time_policy=pyotp.TimePolicy.UTC)
        self.utc_dt = datetime.datetime.fromtimestamp(FIXED_TS, UTC)

    def test_time_policy_enum_coercion(self):
        self.assertEqual(pyotp.TimePolicy.coerce("utc"), pyotp.TimePolicy.UTC)
        self.assertEqual(pyotp.TimePolicy.coerce("local"), pyotp.TimePolicy.LOCAL)
        self.assertIs(pyotp.TimePolicy.coerce(pyotp.TimePolicy.UTC), pyotp.TimePolicy.UTC)
        with self.assertRaises(ValueError):
            pyotp.TimePolicy.coerce("europe/paris")
        with self.assertRaises(ValueError):
            pyotp.TOTP(SECRET, time_policy="bogus")
        with self.assertRaises(TypeError):
            pyotp.TOTP(SECRET, default_tz="UTC")

    def test_fixed_utc_instant_same_code_in_every_timezone_representation(self):
        reference = self.strict.at(FIXED_TS)
        for zone_name in ("UTC", "Asia/Shanghai", "America/New_York"):
            zone = ZoneInfo(zone_name)
            aware = datetime.datetime.fromtimestamp(FIXED_TS, zone)
            self.assertEqual(aware.astimezone(UTC).replace(tzinfo=None), self.utc_dt.replace(tzinfo=None))
            self.assertEqual(self.strict.at(aware), reference, zone_name)
            self.assertEqual(self.strict.timecode(aware), self.strict.timecode(FIXED_TS), zone_name)

    def test_aware_datetimes_always_converted_to_utc(self):
        reference = self.strict.at(FIXED_TS)
        shanghai = ZoneInfo("Asia/Shanghai")
        new_york = ZoneInfo("America/New_York")
        self.assertEqual(
            self.strict.at(datetime.datetime.fromtimestamp(FIXED_TS, shanghai)),
            reference,
        )
        self.assertEqual(
            self.strict.at(datetime.datetime.fromtimestamp(FIXED_TS, new_york)),
            reference,
        )
        # aware datetimes are converted to UTC even in the legacy local policy
        self.assertEqual(self.local.at(datetime.datetime.fromtimestamp(FIXED_TS, new_york)), reference)

    def test_naive_datetime_rejected_in_strict_mode_without_declared_tz(self):
        naive = self.utc_dt.replace(tzinfo=None)
        with self.assertRaises(ValueError) as cm:
            self.strict.at(naive)
        self._assert_safe_error(str(cm.exception))
        with self.assertRaises(ValueError):
            self.strict.verify("123456", naive)
        with self.assertRaises(ValueError):
            self.strict.timecode(naive)

    def test_naive_datetime_accepted_with_default_tz(self):
        new_york = ZoneInfo("America/New_York")
        strict_ny = pyotp.TOTP(SECRET, time_policy="utc", default_tz=new_york)
        naive_ny = datetime.datetime.fromtimestamp(FIXED_TS, new_york).replace(tzinfo=None)
        self.assertEqual(strict_ny.at(naive_ny), self.strict.at(FIXED_TS))
        self.assertEqual(strict_ny.timecode(naive_ny), self.strict.timecode(FIXED_TS))

    def test_naive_datetime_accepted_with_per_call_tzinfo(self):
        shanghai = ZoneInfo("Asia/Shanghai")
        naive_sh = datetime.datetime.fromtimestamp(FIXED_TS, shanghai).replace(tzinfo=None)
        self.assertEqual(self.strict.at(naive_sh, tzinfo=shanghai), self.strict.at(FIXED_TS))
        self.assertEqual(self.strict.timecode(naive_sh, tzinfo=shanghai), self.strict.timecode(FIXED_TS))
        # per-call tzinfo wins over default_tz
        strict_ny = pyotp.TOTP(SECRET, time_policy=pyotp.TimePolicy.UTC, default_tz=ZoneInfo("America/New_York"))
        self.assertEqual(strict_ny.at(naive_sh, tzinfo=shanghai), self.strict.at(FIXED_TS))
        with self.assertRaises(TypeError):
            self.strict.at(naive_sh, tzinfo="Asia/Shanghai")

    def test_numeric_timestamps_are_utc_seconds_in_strict_mode(self):
        self.assertEqual(self.strict.at(FIXED_TS), self.strict.at(self.utc_dt))
        self.assertEqual(self.strict.at(float(FIXED_TS)), self.strict.at(FIXED_TS))

    def test_float_timestamps_truncated_toward_zero(self):
        base_timecode = self.strict.timecode(FIXED_TS)
        self.assertEqual(self.strict.at(FIXED_TS + 29.9), self.strict.at(FIXED_TS))
        self.assertEqual(self.strict.timecode(FIXED_TS + 29.9), base_timecode)
        self.assertEqual(self.strict.at(FIXED_TS + 30.0), self.strict.at(FIXED_TS + 30))
        self.assertNotEqual(self.strict.at(FIXED_TS + 30.0), self.strict.at(FIXED_TS))
        # negative fractional seconds truncate toward zero: -1 and -29.5 both land on timecode 0
        self.assertEqual(self.strict.at(-1), self.strict.at(0))
        self.assertEqual(self.strict.at(-29.5), self.strict.at(0))

    def test_millisecond_and_nanosecond_timestamps_rejected(self):
        for bad_value in (FIXED_TS * 1000, FIXED_TS * 1_000_000_000, FIXED_TS * 1000.0):
            with self.assertRaises(ValueError) as cm:
                self.strict.at(bad_value)
            self._assert_safe_error(str(cm.exception))
            with self.assertRaises(ValueError):
                self.local.at(bad_value)

    def test_non_finite_and_wrong_type_inputs(self):
        for bad_value in (float("nan"), float("inf"), float("-inf")):
            with self.assertRaises(ValueError):
                self.strict.at(bad_value)
        for bad_value in (True, False):
            with self.assertRaises(TypeError):
                self.strict.at(bad_value)
        with self.assertRaises(TypeError):
            self.strict.at("1710055800")
        with self.assertRaises(TypeError):
            pyotp.utils.normalize_timestamp("1710055800")

    def test_negative_time_before_epoch(self):
        epoch_code = self.strict.at(0)
        self.assertEqual(self.strict.at(-1), epoch_code)
        self.assertEqual(self.strict.at(-29.5), epoch_code)
        with self.assertRaises(ValueError):
            self.strict.at(-30)
        # legacy policy keeps the same externally visible behavior
        self.assertEqual(self.local.at(-1), self.local.at(0))
        self.assertEqual(self.local.at(-29.5), self.local.at(0))
        with self.assertRaises(ValueError):
            self.local.at(-30)

    def test_dst_gap_and_repeated_time_are_stable(self):
        new_york = ZoneInfo("America/New_York")
        # nonexistent wall-clock time 02:30 during the 2024 spring-forward gap
        gap = datetime.datetime(2024, 3, 10, 2, 30, tzinfo=new_york)
        gap_before = gap.replace(fold=0)
        gap_after = gap.replace(fold=1)
        self.assertEqual(self.strict.timecode(gap_before), self.strict.timecode(gap_before))
        self.assertEqual(self.strict.timecode(gap_after), self.strict.timecode(gap_after))
        self.assertNotEqual(
            self.strict.timecode(gap_before),
            self.strict.timecode(gap_after),
        )
        # repeated wall-clock time 01:30 during the 2024 fall-back
        repeated = datetime.datetime(2024, 11, 3, 1, 30, tzinfo=new_york)
        first_pass = repeated.replace(fold=0)
        second_pass = repeated.replace(fold=1)
        self.assertEqual(first_pass.astimezone(UTC), datetime.datetime(2024, 11, 3, 5, 30, tzinfo=UTC))
        self.assertEqual(second_pass.astimezone(UTC), datetime.datetime(2024, 11, 3, 6, 30, tzinfo=UTC))
        self.assertEqual(
            self.strict.timecode(first_pass),
            self.strict.timecode(datetime.datetime(2024, 11, 3, 5, 30, tzinfo=UTC)),
        )
        self.assertEqual(
            self.strict.timecode(second_pass),
            self.strict.timecode(datetime.datetime(2024, 11, 3, 6, 30, tzinfo=UTC)),
        )
        self.assertNotEqual(self.strict.timecode(first_pass), self.strict.timecode(second_pass))

    def test_default_policy_preserves_legacy_local_behavior(self):
        self.assertEqual(self.local.time_policy, pyotp.TimePolicy.LOCAL)
        # numeric timestamps keep producing the legacy result
        self.assertEqual(self.local.at(FIXED_TS), self.local.at(datetime.datetime.fromtimestamp(FIXED_TS)))
        self.assertEqual(self.local.at(FIXED_TS + 29.9), self.local.at(FIXED_TS))
        # naive datetimes are accepted and interpreted as local time
        naive = datetime.datetime.fromtimestamp(FIXED_TS).replace(tzinfo=None)
        self.assertEqual(self.local.timecode(naive), self.local.timecode(FIXED_TS))

    def _assert_safe_error(self, message):
        self.assertNotIn(SECRET, message)
        for otp_value in (self.strict.at(FIXED_TS), self.local.at(FIXED_TS)):
            self.assertNotIn(otp_value, message)


@unittest.skipUnless(ZONEINFO_AVAILABLE, "zoneinfo is required for window boundary tests")
class ValidWindowPolicyTest(unittest.TestCase):
    def setUp(self):
        self.strict = pyotp.TOTP(SECRET, time_policy=pyotp.TimePolicy.UTC)
        # last whole second of a 30-second interval
        self.boundary = (FIXED_TS // 30) * 30 + 29

    def test_window_uses_one_base_timecode_on_boundary(self):
        current = self.strict.at(self.boundary)
        previous = self.strict.at(self.boundary - 30)
        nxt = self.strict.at(self.boundary + 30)
        outside = self.strict.at(self.boundary - 60)
        self.assertTrue(self.strict.verify(current, self.boundary, valid_window=1))
        self.assertTrue(self.strict.verify(previous, self.boundary, valid_window=1))
        self.assertTrue(self.strict.verify(nxt, self.boundary, valid_window=1))
        self.assertFalse(self.strict.verify(outside, self.boundary, valid_window=1))

    def test_window_symmetric_with_naive_declared_datetime(self):
        shanghai = ZoneInfo("Asia/Shanghai")
        bound_dt = datetime.datetime.fromtimestamp(self.boundary, shanghai).replace(tzinfo=None)
        previous = self.strict.at(self.boundary - 30)
        nxt = self.strict.at(self.boundary + 30)
        self.assertTrue(self.strict.verify(previous, bound_dt, valid_window=1, tzinfo=shanghai))
        self.assertTrue(self.strict.verify(nxt, bound_dt, valid_window=1, tzinfo=shanghai))
        self.assertFalse(
            self.strict.verify(self.strict.at(self.boundary - 60), bound_dt, valid_window=1, tzinfo=shanghai)
        )

    def test_verify_and_get_timecode_matches_generation_path(self):
        for offset, expected_code in (
            (-1, self.strict.at(self.boundary - 30)),
            (0, self.strict.at(self.boundary)),
            (1, self.strict.at(self.boundary + 30)),
        ):
            timecode = self.strict.verify_and_get_timecode(expected_code, self.boundary, valid_window=1)
            self.assertEqual(timecode, self.strict.timecode(self.boundary) + offset)
        self.assertFalse(
            self.strict.verify_and_get_timecode(self.strict.at(self.boundary - 60), self.boundary, valid_window=1)
        )

    def test_negative_valid_window_rejected(self):
        with self.assertRaises(ValueError):
            self.strict.verify("123456", self.boundary, valid_window=-1)
        with self.assertRaises(ValueError):
            self.strict.verify_and_get_timecode("123456", self.boundary, valid_window=-1)

    def test_error_messages_do_not_leak_otp_or_secret(self):
        with self.assertRaises(ValueError) as cm:
            self.strict.verify("123456", FIXED_TS * 1000)
        message = str(cm.exception)
        self.assertNotIn(SECRET, message)
        self.assertNotIn(self.strict.at(FIXED_TS), message)


@unittest.skipUnless(ZONEINFO_AVAILABLE and TZSET_AVAILABLE, "tzset/zoneinfo required for process TZ tests")
class ProcessTimezoneTest(unittest.TestCase):
    def test_same_utc_instant_matches_across_tz_processes(self):
        script = (
            "import datetime, sys; sys.path.insert(0, 'src'); import pyotp; "
            "totp = pyotp.TOTP('" + SECRET + "', time_policy=pyotp.TimePolicy.UTC); "
            "print(totp.at(" + str(FIXED_TS) + ")); "
            "print(totp.at(datetime.datetime.fromtimestamp(" + str(FIXED_TS) + ", datetime.timezone.utc)))"
        )
        env = dict(os.environ)
        codes = set()
        for zone in ("UTC", "Asia/Shanghai", "America/New_York"):
            env["TZ"] = zone
            output = subprocess.run(
                [sys.executable, "-c", script],
                cwd=os.path.dirname(os.path.abspath(__file__)),
                env=env,
                check=True,
                capture_output=True,
                text=True,
            )
            lines = output.stdout.split()
            self.assertEqual(len(lines), 2)
            self.assertEqual(lines[0], lines[1])
            codes.add(lines[0])
        self.assertEqual(len(codes), 1)


class Timecop(object):
    """
    Half-assed clone of timecop.rb, just enough to pass our tests.
    """

    def __init__(self, freeze_timestamp):
        self.freeze_timestamp = freeze_timestamp

    def __enter__(self):
        self.real_datetime = datetime.datetime
        datetime.datetime = self.frozen_datetime()

    def __exit__(self, type, value, traceback):
        datetime.datetime = self.real_datetime

    def frozen_datetime(self):
        class FrozenDateTime(datetime.datetime):
            @classmethod
            def now(cls, **kwargs):
                return cls.fromtimestamp(timecop.freeze_timestamp)

        timecop = self
        return FrozenDateTime


if __name__ == "__main__":
    unittest.main()
