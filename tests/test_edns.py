# -*- coding: utf-8
# Copyright (C) Dnspython Contributors, see LICENSE for text of ISC license

# Copyright (C) 2003-2007, 2009-2011 Nominum, Inc.
#
# Permission to use, copy, modify, and distribute this software and its
# documentation for any purpose with or without fee is hereby granted,
# provided that the above copyright notice and this permission notice
# appear in all copies.
#
# THE SOFTWARE IS PROVIDED "AS IS" AND NOMINUM DISCLAIMS ALL WARRANTIES
# WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
# MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL NOMINUM BE LIABLE FOR
# ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
# WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
# ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT
# OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

import operator
import struct
import unittest
from io import BytesIO

import dns.exception
import dns.edns
import dns.wire


def _option_wire(otype, data):
    """Build the wire bytes of one EDNS option."""
    return struct.pack("!HH", int(otype), len(data)) + data


def _parse_options(rdata):
    """Parse an OPT option list through the shared OPT entry point."""
    parser = dns.wire.Parser(rdata)
    with parser.restrict_to(len(rdata)):
        return dns.edns.options_from_wire_parser(parser)


# A well-formed 8-byte client cookie; tests never assert on this value in an
# error path, and error messages must not echo it.
_CLIENT_COOKIE = b"01234567"
_COOKIE_RDATA = _option_wire(dns.edns.COOKIE, _CLIENT_COOKIE)


class OptionTestCase(unittest.TestCase):
    def testGenericOption(self):
        opt = dns.edns.GenericOption(3, b"data")
        io = BytesIO()
        opt.to_wire(io)
        data = io.getvalue()
        self.assertEqual(data, b"data")
        self.assertEqual(dns.edns.option_from_wire(3, data, 0, len(data)), opt)
        self.assertEqual(str(opt), "Generic 3")

    def testECSOption_prefix_length(self):
        opt = dns.edns.ECSOption("1.2.255.33", 20)
        io = BytesIO()
        opt.to_wire(io)
        data = io.getvalue()
        self.assertEqual(data, b"\x00\x01\x14\x00\x01\x02\xf0")

    def testECSOption(self):
        opt = dns.edns.ECSOption("1.2.3.4", 24)
        io = BytesIO()
        opt.to_wire(io)
        data = io.getvalue()
        self.assertEqual(data, b"\x00\x01\x18\x00\x01\x02\x03")
        # default srclen
        opt = dns.edns.ECSOption("1.2.3.4")
        io = BytesIO()
        opt.to_wire(io)
        data = io.getvalue()
        self.assertEqual(data, b"\x00\x01\x18\x00\x01\x02\x03")
        self.assertEqual(opt.to_text(), "ECS 1.2.3.4/24 scope/0")

    def testECSOption25(self):
        opt = dns.edns.ECSOption("1.2.3.255", 25)
        io = BytesIO()
        opt.to_wire(io)
        data = io.getvalue()
        self.assertEqual(data, b"\x00\x01\x19\x00\x01\x02\x03\x80")

        opt2 = dns.edns.option_from_wire(dns.edns.ECS, data, 0, len(data))
        self.assertEqual(opt2.otype, dns.edns.ECS)
        self.assertEqual(opt2.address, "1.2.3.128")
        self.assertEqual(opt2.srclen, 25)
        self.assertEqual(opt2.scopelen, 0)

    def testECSOption_v6(self):
        opt = dns.edns.ECSOption("2001:4b98::1")
        io = BytesIO()
        opt.to_wire(io)
        data = io.getvalue()
        self.assertEqual(data, b"\x00\x02\x38\x00\x20\x01\x4b\x98\x00\x00\x00")

        opt2 = dns.edns.option_from_wire(dns.edns.ECS, data, 0, len(data))
        self.assertEqual(opt2.otype, dns.edns.ECS)
        self.assertEqual(opt2.address, "2001:4b98::")
        self.assertEqual(opt2.srclen, 56)
        self.assertEqual(opt2.scopelen, 0)

    def testECSOption_from_text_valid(self):
        ecs1 = dns.edns.ECSOption.from_text("1.2.3.4/24/0")
        self.assertEqual(ecs1, dns.edns.ECSOption("1.2.3.4", 24, 0))

        ecs2 = dns.edns.ECSOption.from_text("1.2.3.4/24")
        self.assertEqual(ecs2, dns.edns.ECSOption("1.2.3.4", 24, 0))

        ecs3 = dns.edns.ECSOption.from_text("ECS 1.2.3.4/24")
        self.assertEqual(ecs3, dns.edns.ECSOption("1.2.3.4", 24, 0))

        ecs4 = dns.edns.ECSOption.from_text("ECS 1.2.3.4/24/32")
        self.assertEqual(ecs4, dns.edns.ECSOption("1.2.3.4", 24, 32))

        ecs5 = dns.edns.ECSOption.from_text("2001:4b98::1/64/56")
        self.assertEqual(ecs5, dns.edns.ECSOption("2001:4b98::1", 64, 56))

        ecs6 = dns.edns.ECSOption.from_text("2001:4b98::1/64")
        self.assertEqual(ecs6, dns.edns.ECSOption("2001:4b98::1", 64, 0))

        ecs7 = dns.edns.ECSOption.from_text("ECS 2001:4b98::1/0")
        self.assertEqual(ecs7, dns.edns.ECSOption("2001:4b98::1", 0, 0))

        ecs8 = dns.edns.ECSOption.from_text("ECS 2001:4b98::1/64/128")
        self.assertEqual(ecs8, dns.edns.ECSOption("2001:4b98::1", 64, 128))

    def testECSOption_from_text_invalid(self):
        with self.assertRaises(ValueError):
            dns.edns.ECSOption.from_text("some random text 1.2.3.4/24/0 24")

        with self.assertRaises(ValueError):
            dns.edns.ECSOption.from_text("1.2.3.4/twentyfour")

        with self.assertRaises(ValueError):
            dns.edns.ECSOption.from_text("BOGUS 1.2.3.4/5/6/7")

        with self.assertRaises(ValueError):
            dns.edns.ECSOption.from_text("1.2.3.4/5/6/7")

        with self.assertRaises(ValueError):
            dns.edns.ECSOption.from_text("1.2.3.4/24/O")  # <-- that's not a zero

        with self.assertRaises(ValueError):
            dns.edns.ECSOption.from_text("")

        with self.assertRaises(ValueError):
            dns.edns.ECSOption.from_text("1.2.3.4/2001:4b98::1/24")

    def testECSOption_from_text_accepts_to_text(self):
        for opt in (
            dns.edns.ECSOption("1.2.3.4", 24, 32),
            dns.edns.ECSOption("1.2.3.4", 24, 0),
            dns.edns.ECSOption("2001:4b98::1", 64, 128),
        ):
            self.assertEqual(dns.edns.ECSOption.from_text(opt.to_text()), opt)

    def testECSOption_from_text_scope_form_invalid(self):
        # Three-token forms that to_text() never emits stay ValueErrors.
        with self.assertRaises(ValueError):
            dns.edns.ECSOption.from_text("ECS 1.2.3.4 scope/32")

        with self.assertRaises(ValueError):
            dns.edns.ECSOption.from_text("BOGUS 1.2.3.4/24 scope/32")

        with self.assertRaises(ValueError):
            dns.edns.ECSOption.from_text("ECS 1.2.3.4/24 32")

        with self.assertRaises(ValueError):
            dns.edns.ECSOption.from_text("ECS 1.2.3.4/24/0 scope/32")

    def testECSOption_from_wire_invalid(self):
        with self.assertRaises(ValueError):
            opt = dns.edns.option_from_wire(
                dns.edns.ECS, b"\x00\xff\x18\x00\x01\x02\x03", 0, 7
            )

    def testECSOption_from_wire_nonzero_pad(self):
        # srclen 25 leaves 7 padding bits in the final octet; they must be 0.
        with self.assertRaises(ValueError):
            dns.edns.option_from_wire(
                dns.edns.ECS, b"\x00\x01\x19\x00\x01\x02\x03\xff", 0, 8
            )

    def testECSOption_from_wire_srclen_too_long(self):
        # srclen 40 exceeds 32 bits for IPv4.
        with self.assertRaises(ValueError):
            dns.edns.option_from_wire(
                dns.edns.ECS, b"\x00\x01\x28\x00\x01\x02\x03\x04\x05", 0, 9
            )
        # srclen 129 exceeds 128 bits for IPv6.
        with self.assertRaises(ValueError):
            dns.edns.option_from_wire(
                dns.edns.ECS, b"\x00\x02\x81\x00" + b"\x00" * 17, 0, 21
            )

    def testECSOption_from_wire_scopelen_too_long(self):
        # scopelen 200 exceeds 128 bits for IPv6.
        with self.assertRaises(ValueError):
            dns.edns.option_from_wire(
                dns.edns.ECS,
                b"\x00\x02\x38\xc8" + b"\x20\x01\x4b\x98\x00\x00\x00",
                0,
                11,
            )

    def testEDEOption(self):
        opt = dns.edns.EDEOption(3)
        io = BytesIO()
        opt.to_wire(io)
        data = io.getvalue()
        self.assertEqual(data, b"\x00\x03")
        self.assertEqual(str(opt), "EDE 3 (Stale Answer)")
        # with text
        opt = dns.edns.EDEOption(16, "test")
        io = BytesIO()
        opt.to_wire(io)
        data = io.getvalue()
        self.assertEqual(data, b"\x00\x10test")

    def testEDEOption_invalid(self):
        with self.assertRaises(ValueError):
            opt = dns.edns.EDEOption(-1)
        with self.assertRaises(ValueError):
            opt = dns.edns.EDEOption(65536)
        with self.assertRaises(ValueError):
            opt = dns.edns.EDEOption(0, 0)

    def testEDEOption_from_wire(self):
        data = b"\x00\01"
        self.assertEqual(
            dns.edns.option_from_wire(dns.edns.EDE, data, 0, 2), dns.edns.EDEOption(1)
        )
        data = b"\x00\01test"
        self.assertEqual(
            dns.edns.option_from_wire(dns.edns.EDE, data, 0, 6),
            dns.edns.EDEOption(1, "test"),
        )
        # utf-8 text MAY be null-terminated
        data = b"\x00\01test\x00"
        self.assertEqual(
            dns.edns.option_from_wire(dns.edns.EDE, data, 0, 7),
            dns.edns.EDEOption(1, "test"),
        )

    def test_basic_relations(self):
        o1 = dns.edns.ECSOption.from_text("1.2.3.0/24/0")
        o2 = dns.edns.ECSOption.from_text("1.2.4.0/24/0")
        self.assertTrue(o1 == o1)
        self.assertTrue(o1 != o2)
        self.assertTrue(o1 < o2)
        self.assertTrue(o1 <= o2)
        self.assertTrue(o2 > o1)
        self.assertTrue(o2 >= o1)
        o1 = dns.edns.ECSOption.from_text("1.2.4.0/23/0")
        o2 = dns.edns.ECSOption.from_text("1.2.4.0/24/0")
        self.assertTrue(o1 < o2)
        o1 = dns.edns.ECSOption.from_text("1.2.4.0/24/0")
        o2 = dns.edns.ECSOption.from_text("1.2.4.0/24/1")
        self.assertTrue(o1 < o2)

    def test_incompatible_relations(self):
        o1 = dns.edns.GenericOption(3, b"data")
        o2 = dns.edns.ECSOption.from_text("1.2.3.5/24/0")
        for oper in [operator.lt, operator.le, operator.ge, operator.gt]:
            self.assertRaises(TypeError, lambda: oper(o1, o2))
        self.assertFalse(o1 == o2)
        self.assertTrue(o1 != o2)
        self.assertFalse(o1 == 123)
        self.assertTrue(o1 != 123)

    def testNSIDOption(self):
        opt = dns.edns.NSIDOption(b"testing")
        io = BytesIO()
        opt.to_wire(io)
        data = io.getvalue()
        self.assertEqual(data, b"testing")
        self.assertEqual(str(opt), "NSID testing")
        opt = dns.edns.NSIDOption(b"\xfe\xff")
        io = BytesIO()
        opt.to_wire(io)
        data = io.getvalue()
        self.assertEqual(data, b"\xfe\xff")
        self.assertEqual(str(opt), "NSID feff")
        o = dns.edns.option_from_wire(dns.edns.OptionType.NSID, data, 0, len(data))
        self.assertEqual(o.nsid, b"\xfe\xff")

    def testCookieOption(self):
        opt = dns.edns.CookieOption(b"12345678", b"")
        io = BytesIO()
        opt.to_wire(io)
        data = io.getvalue()
        self.assertEqual(data, b"12345678")
        self.assertEqual(str(opt), "COOKIE 3132333435363738")
        opt = dns.edns.CookieOption(b"12345678", b"abcdefgh")
        data = opt.to_wire()
        self.assertEqual(data, b"12345678abcdefgh")
        self.assertEqual(str(opt), "COOKIE 31323334353637386162636465666768")
        # maximal server
        opt = dns.edns.CookieOption(b"12345678", b"abcdefghabcdefghabcdefghabcdefgh")
        io = BytesIO()
        opt.to_wire(io)
        data = io.getvalue()
        self.assertEqual(data, b"12345678abcdefghabcdefghabcdefghabcdefgh")
        # from wire
        opt2 = dns.edns.option_from_wire(dns.edns.OptionType.COOKIE, data, 0, len(data))
        self.assertEqual(opt.client, opt2.client)
        self.assertEqual(opt.server, opt2.server)
        # client too short
        with self.assertRaises(ValueError):
            opt = dns.edns.CookieOption(b"1234567", b"")
        # client too long
        with self.assertRaises(ValueError):
            opt = dns.edns.CookieOption(b"123456789", b"")
        # server too short
        with self.assertRaises(ValueError):
            opt = dns.edns.CookieOption(b"12345678", b"a")
        # server too long
        with self.assertRaises(ValueError):
            opt = dns.edns.CookieOption(
                b"12345678", b"abcdefghabcdefghabcdefghabcdefghi"
            )

    def testReportChannelOption(self):
        agent_domain = dns.name.from_text("agent.example.")
        expected_wire = b"\x05agent\x07example\x00"
        opt = dns.edns.ReportChannelOption(agent_domain)
        io = BytesIO()
        opt.to_wire(io)
        data = io.getvalue()
        self.assertEqual(data, expected_wire)
        self.assertEqual(str(opt), "REPORTCHANNEL agent.example.")
        opt2 = dns.edns.option_from_wire(
            dns.edns.OptionType.REPORTCHANNEL, expected_wire, 0, len(expected_wire)
        )
        self.assertEqual(opt2.agent_domain, agent_domain)

    def testEDEExtraTextLanguageOption(self):
        language = "en"
        expected_wire = bytes(language, "utf8")
        opt = dns.edns.EDEExtraTextLanguageOption(language)
        io = BytesIO()
        opt.to_wire(io)
        data = io.getvalue()
        self.assertEqual(data, expected_wire)
        self.assertEqual(str(opt), "EDE-EXTRA-TEXT-LANGUAGE en")
        opt2 = dns.edns.option_from_wire(
            dns.edns.OptionType.EDE_EXTRA_TEXT_LANGUAGE,
            expected_wire,
            0,
            len(expected_wire),
        )
        self.assertEqual(opt2.language, language)

    def testFilteringContactOption(self):
        contact = "mailto:support@example.com"
        expected_wire = bytes(contact, "utf8")
        opt = dns.edns.FilteringContactOption(contact)
        io = BytesIO()
        opt.to_wire(io)
        data = io.getvalue()
        self.assertEqual(data, expected_wire)
        self.assertEqual(str(opt), "FILTERING-CONTACT mailto:support@example.com")
        opt2 = dns.edns.option_from_wire(
            dns.edns.OptionType.FILTERING_CONTACT, expected_wire, 0, len(expected_wire)
        )
        self.assertEqual(opt2.contact, contact)

    def testFilteringOrganizationOption(self):
        organization = "The Example Organization"
        expected_wire = bytes(organization, "utf8")
        opt = dns.edns.FilteringOrganizationOption(organization)
        io = BytesIO()
        opt.to_wire(io)
        data = io.getvalue()
        self.assertEqual(data, expected_wire)
        self.assertEqual(str(opt), "FILTERING-ORGANIZATION The Example Organization")
        opt2 = dns.edns.option_from_wire(
            dns.edns.OptionType.FILTERING_ORGANIZATION,
            expected_wire,
            0,
            len(expected_wire),
        )
        self.assertEqual(opt2.organization, organization)

    def testFilteringDBOption(self):
        db = "Government Anti-Piracy Policies #1"
        expected_wire = b"Government Anti-Piracy Policies #1"
        opt = dns.edns.FilteringDBOption(db)
        io = BytesIO()
        opt.to_wire(io)
        data = io.getvalue()
        self.assertEqual(data, expected_wire)
        self.assertEqual(str(opt), "FILTERING-DB Government Anti-Piracy Policies #1")
        opt2 = dns.edns.option_from_wire(
            dns.edns.OptionType.FILTERING_DB, expected_wire, 0, len(expected_wire)
        )
        self.assertEqual(opt2.db, db)

    def test_text_option_to_text_escapes_controls(self):
        text = "blocked\r\n;ANSWER\nwww.example. 300 IN A 192.0.2.1\x1b[2J\x9b\\"
        escaped = "blocked\\013\\010;ANSWER\\010www.example. 300 IN A 192.0.2.1\\027[2J\\155\\\\"
        wire = b"\x00\x11" + text.encode("utf8")
        opt = dns.edns.option_from_wire(dns.edns.OptionType.EDE, wire, 0, len(wire))
        self.assertEqual(opt.text, text)
        self.assertEqual(str(opt), "EDE 17 (Filtered): " + escaped)
        for otype, prefix in (
            (dns.edns.OptionType.EDE_EXTRA_TEXT_LANGUAGE, "EDE-EXTRA-TEXT-LANGUAGE"),
            (dns.edns.OptionType.FILTERING_CONTACT, "FILTERING-CONTACT"),
            (dns.edns.OptionType.FILTERING_ORGANIZATION, "FILTERING-ORGANIZATION"),
            (dns.edns.OptionType.FILTERING_DB, "FILTERING-DB"),
        ):
            wire = text.encode("utf8")
            opt = dns.edns.option_from_wire(otype, wire, 0, len(wire))
            self.assertEqual(str(opt), f"{prefix} {escaped}")
            self.assertEqual(opt.to_wire(), wire)

    def test_option_registration(self):
        U32OptionType = 9999

        class U32Option(dns.edns.Option):
            def __init__(self, value=None):
                super().__init__(U32OptionType)
                self.value = value

            def to_wire(self, file=None):
                data = struct.pack("!I", self.value)
                if file:
                    file.write(data)
                else:
                    return data

            @classmethod
            def from_wire_parser(cls, otype, parser):
                (value,) = parser.get_struct("!I")
                return cls(value)

        try:
            dns.edns.register_type(U32Option, U32OptionType)
            generic = dns.edns.GenericOption(U32OptionType, b"\x00\x00\x00\x01")
            wire1 = generic.to_wire()
            u32 = dns.edns.option_from_wire_parser(
                U32OptionType, dns.wire.Parser(wire1)
            )
            self.assertEqual(u32.value, 1)
            wire2 = u32.to_wire()
            self.assertEqual(wire1, wire2)
            self.assertEqual(u32, generic)
        finally:
            dns.edns._type_to_class.pop(U32OptionType, None)

        opt = dns.edns.option_from_wire_parser(9999, dns.wire.Parser(wire1))
        self.assertEqual(opt, generic)

    def test_to_generic(self):
        nsid = dns.edns.NSIDOption(b"testing")
        assert nsid.to_generic().data == b"testing"

        ecs = dns.edns.ECSOption("1.2.3.0", 24)
        assert ecs.to_generic().data == b"\x00\x01\x18\x00\x01\x02\x03"

        generic = dns.edns.GenericOption(12345, "foo")
        assert generic.to_generic() is generic


class WireValidationTestCase(unittest.TestCase):
    def assertEDNSError(self, rdata, option_code, offset, category):
        with self.assertRaises(dns.edns.EDNSError) as cm:
            _parse_options(rdata)
        error = cm.exception
        self.assertIsInstance(error, dns.exception.FormError)
        self.assertIsInstance(error, ValueError)
        self.assertEqual(error.option_code, option_code)
        self.assertEqual(error.offset, offset)
        self.assertEqual(error.length_category, category)
        return error

    def test_duplicate_cookie_rejected_with_metadata(self):
        rdata = _COOKIE_RDATA + _option_wire(dns.edns.COOKIE, _CLIENT_COOKIE)
        error = self.assertEDNSError(
            rdata,
            dns.edns.COOKIE,
            len(_COOKIE_RDATA),
            dns.edns.LENGTH_CATEGORY_OPTION,
        )
        # The cookie value must never appear in the error text.
        self.assertNotIn(_CLIENT_COOKIE.hex(), str(error))
        self.assertNotIn(_CLIENT_COOKIE, str(error).encode())

    def test_duplicate_ecs_rejected(self):
        ecs = dns.edns.ECSOption("1.2.3.0", 24).to_wire()
        rdata = _option_wire(dns.edns.ECS, ecs) * 2
        self.assertEDNSError(
            rdata,
            dns.edns.ECS,
            4 + len(ecs),
            dns.edns.LENGTH_CATEGORY_OPTION,
        )

    def test_non_singleton_duplicates_are_kept(self):
        # EDE may occur multiple times; all occurrences are retained.
        ede1 = _option_wire(dns.edns.EDE, b"\x00\x03")
        ede2 = _option_wire(dns.edns.EDE, b"\x00\x10extra")
        options = _parse_options(ede1 + ede2)
        self.assertEqual(len(options), 2)
        self.assertEqual([o.otype for o in options], [dns.edns.EDE, dns.edns.EDE])

    def test_cookie_short_client(self):
        rdata = _option_wire(dns.edns.COOKIE, b"short")
        self.assertEDNSError(
            rdata,
            dns.edns.COOKIE,
            0,
            dns.edns.LENGTH_CATEGORY_ADDRESS,
        )

    def test_cookie_bad_server_length(self):
        # One trailing byte is neither an empty nor an 8..32 byte server
        # cookie.
        rdata = _option_wire(dns.edns.COOKIE, _CLIENT_COOKIE + b"x")
        self.assertEDNSError(
            rdata,
            dns.edns.COOKIE,
            0,
            dns.edns.LENGTH_CATEGORY_ADDRESS,
        )

    def test_cookie_valid_server_round_trips(self):
        server = b"abcdefgh"
        rdata = _option_wire(dns.edns.COOKIE, _CLIENT_COOKIE + server)
        options = _parse_options(rdata)
        self.assertEqual(options[0].client, _CLIENT_COOKIE)
        self.assertEqual(options[0].server, server)
        self.assertEqual(options[0].to_wire(), _CLIENT_COOKIE + server)

    def test_ecs_unknown_family_checked_before_address_read(self):
        # Family 9 with a declared 4-byte address; an unknown family must be
        # reported rather than reading a fixed-width address.
        rdata = _option_wire(dns.edns.ECS, b"\x00\x09\x18\x00\x01\x02\x03\x04")
        self.assertEDNSError(
            rdata,
            dns.edns.ECS,
            0,
            dns.edns.LENGTH_CATEGORY_OPTION,
        )

    def test_ecs_short_option(self):
        # The 24-bit prefix needs 3 address bytes but only two are present;
        # the option's own length disagrees with its prefix length.
        rdata = _option_wire(dns.edns.ECS, b"\x00\x01\x18\x00\x01\x02")
        self.assertEDNSError(
            rdata,
            dns.edns.ECS,
            0,
            dns.edns.LENGTH_CATEGORY_ADDRESS,
        )

    def test_ecs_long_option(self):
        # Trailing bytes beyond the prefix length are a length mismatch.
        rdata = _option_wire(dns.edns.ECS, b"\x00\x01\x18\x00\x01\x02\x03\x04")
        self.assertEDNSError(
            rdata,
            dns.edns.ECS,
            0,
            dns.edns.LENGTH_CATEGORY_ADDRESS,
        )

    def test_ecs_fixed_header_truncated(self):
        rdata = _option_wire(dns.edns.ECS, b"\x00\x01\x18")
        self.assertEDNSError(
            rdata,
            dns.edns.ECS,
            0,
            dns.edns.LENGTH_CATEGORY_ADDRESS,
        )

    def test_padding_valid(self):
        rdata = _option_wire(dns.edns.PADDING, b"\x00" * 16)
        options = _parse_options(rdata)
        self.assertIsInstance(options[0], dns.edns.PaddingOption)
        self.assertEqual(options[0].padding, 16)
        self.assertEqual(options[0].to_wire(), b"\x00" * 16)
        # Empty padding, as emitted by the renderer, is valid.
        self.assertEqual(
            _parse_options(_option_wire(dns.edns.PADDING, b""))[0].padding, 0
        )

    def test_padding_non_zero_rejected_without_echo(self):
        payload = b"\x00\x00\x07\x00"
        rdata = _option_wire(dns.edns.PADDING, payload)
        error = self.assertEDNSError(
            rdata,
            dns.edns.PADDING,
            0,
            dns.edns.LENGTH_CATEGORY_ADDRESS,
        )
        self.assertNotIn(repr(payload), str(error))

    def test_unknown_option_preserves_raw_bytes(self):
        payload = b"\xde\xad\xbe\xef\x00\x01"
        rdata = _option_wire(65000, payload)
        options = _parse_options(rdata)
        self.assertEqual(len(options), 1)
        self.assertIsInstance(options[0], dns.edns.GenericOption)
        self.assertEqual(int(options[0].otype), 65000)
        # Round-trip at the full option-list level reproduces the bytes.
        rebuilt = b"".join(_option_wire(o.otype, o.to_wire()) for o in options)
        self.assertEqual(rebuilt, rdata)

    def test_unknown_option_between_known_options(self):
        rdata = (
            _option_wire(dns.edns.NSID, b"ab")
            + _option_wire(65001, b"raw")
            + _option_wire(dns.edns.EDE, b"\x00\x03")
        )
        options = _parse_options(rdata)
        self.assertEqual(
            [int(o.otype) for o in options],
            [dns.edns.NSID, 65001, dns.edns.EDE],
        )
        rebuilt = b"".join(_option_wire(o.otype, o.to_wire()) for o in options)
        self.assertEqual(rebuilt, rdata)

    def test_truncated_option_header(self):
        # Only three bytes remain where a four-byte option header is needed.
        rdata = b"\x00\x0a\x00"
        error = self.assertEDNSError(rdata, None, 0, dns.edns.LENGTH_CATEGORY_OPTION)
        self.assertNotIn(_CLIENT_COOKIE.hex(), str(error))

    def test_declared_length_runs_past_rdata(self):
        # Header claims 10 bytes but only 4 follow; the second option's offset
        # is reported relative to the start of the rdata.
        first = _option_wire(dns.edns.NSID, b"ab")
        second = struct.pack("!HH", dns.edns.COOKIE, 10) + _CLIENT_COOKIE
        self.assertEDNSError(
            first + second,
            dns.edns.COOKIE,
            len(first),
            dns.edns.LENGTH_CATEGORY_OPTION,
        )

    def test_trailing_partial_header_after_valid_option(self):
        rdata = _option_wire(dns.edns.NSID, b"ab") + b"\x00\x0a"
        self.assertEDNSError(
            rdata, None, len(rdata) - 2, dns.edns.LENGTH_CATEGORY_OPTION
        )

    def test_too_many_options(self):
        rdata = b"".join(
            _option_wire(dns.edns.EDE, b"\x00\x00")
            for _ in range(dns.edns.MAX_OPTIONS + 1)
        )
        self.assertEDNSError(
            rdata,
            dns.edns.EDE,
            dns.edns.MAX_OPTIONS * 6,
            dns.edns.LENGTH_CATEGORY_TOTAL,
        )

    def test_max_options_accepted(self):
        rdata = b"".join(
            _option_wire(dns.edns.EDE, b"\x00\x00") for _ in range(dns.edns.MAX_OPTIONS)
        )
        self.assertEqual(len(_parse_options(rdata)), dns.edns.MAX_OPTIONS)

    def test_rdata_length_cap(self):
        parser = dns.wire.Parser(b"\x00" * (dns.edns.MAX_OPT_RDATA_LENGTH + 1))
        with self.assertRaises(dns.edns.EDNSError) as cm:
            dns.edns.options_from_wire_parser(parser)
        self.assertEqual(cm.exception.length_category, dns.edns.LENGTH_CATEGORY_TOTAL)

    def test_full_option_list_round_trip(self):
        rdata = (
            _option_wire(dns.edns.NSID, b"node-1")
            + _option_wire(dns.edns.COOKIE, _CLIENT_COOKIE)
            + _option_wire(dns.edns.ECS, dns.edns.ECSOption("1.2.3.0", 24).to_wire())
            + _option_wire(65002, b"\x01\x02\x03")
        )
        options = _parse_options(rdata)
        rebuilt = b"".join(_option_wire(o.otype, o.to_wire()) for o in options)
        self.assertEqual(rebuilt, rdata)

    def test_error_details_helper_has_no_payload(self):
        rdata = _option_wire(dns.edns.COOKIE, b"short")
        with self.assertRaises(dns.edns.EDNSError) as cm:
            _parse_options(rdata)
        details = cm.exception.details()
        self.assertIn("option_code=10", details)
        self.assertIn("offset=0", details)
        self.assertIn("length_category=address", details)


if __name__ == "__main__":
    unittest.main()
