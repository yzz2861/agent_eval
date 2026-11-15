#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
    Test zone file parsing (dnslib.dns.ZoneParser) and the ZoneResolver
    local zone resolver (dnslib.zoneresolver.ZoneResolver)

    Covers:

        - '@' owner / target expansion against the current origin
        - relative vs absolute (trailing dot) names
        - multi-line (parenthesised) TXT records
        - quoted strings, escaped quotes and \\DDD octal escapes
        - $ORIGIN / $TTL directives (applied in order)
        - TTL inheritance and validation
        - duplicate records and CNAME conflicts
        - error reporting (file:line, no zone content echoed)
        - ZoneResolver query handling and zone (AXFR) output stability

    Runs under both unittest and pytest:

        python -m pytest -q dnslib/test_zoneresolver.py
        python dnslib/test_zoneresolver.py
"""

from __future__ import print_function

import unittest

from dnslib import DNSRecord,QTYPE,RCODE
from dnslib.dns import RR,ZoneParser,ZoneError
from dnslib.zoneresolver import ZoneResolver

ZONE = """$ORIGIN example.com.
$TTL 3600
@       IN SOA ns1 admin ( 1 3h 1h 1w 1h )
@       IN NS ns1
@       IN A 1.2.3.4
www     IN A 2.3.4.5
alias   IN CNAME @
abs     IN CNAME target.other.org.
txt     300 IN TXT ( "line1\\100\\"quoted\\""
                     "line2" )
sub.example.org.  IN A 9.9.9.9
$ORIGIN sub.example.com.
branch  60 IN A 5.6.7.8
"""

class TestZoneParser(unittest.TestCase):

    def test_at_owner_and_target(self):
        rr = RR.fromZone("@ 60 IN A 1.2.3.4",origin="example.com")[0]
        self.assertEqual(str(rr.rname),"example.com.")
        # '@' in RDATA expands to origin (not the root/literal '@')
        rr = RR.fromZone("alias 60 IN CNAME @",origin="example.com")[0]
        self.assertEqual(str(rr.rname),"alias.example.com.")
        self.assertEqual(str(rr.rdata.label),"example.com.")

    def test_at_default_origin_is_root(self):
        # No origin specified - '@' deterministically resolves to root
        rr = RR.fromZone("@ 60 IN A 1.2.3.4")[0]
        self.assertEqual(str(rr.rname),".")

    def test_relative_and_absolute_names(self):
        rr = RR.fromZone(ZONE,fname="db.example.com")
        names = [str(r.rname) for r in rr]
        self.assertIn("www.example.com.",names)          # relative owner
        self.assertIn("sub.example.org.",names)          # absolute owner
        self.assertIn("branch.sub.example.com.",names)   # after $ORIGIN
        # Absolute CNAME target is not re-expanded
        abs_rr = [r for r in rr if str(r.rname) == "abs.example.com."][0]
        self.assertEqual(str(abs_rr.rdata.label),"target.other.org.")
        # Relative names in RDATA expand against origin
        soa = [r for r in rr if QTYPE[r.rtype] == "SOA"][0]
        self.assertEqual(str(soa.rdata.mname),"ns1.example.com.")
        self.assertEqual(str(soa.rdata.rname),"admin.example.com.")

    def test_multiline_txt(self):
        rr = RR.fromZone(ZONE,fname="db.example.com")
        txt = [r for r in rr if QTYPE[r.rtype] == "TXT"][0]
        # Parenthesised record spans lines; both strings in one record
        self.assertEqual(txt.rdata.data,[b'line1@"quoted"',b"line2"])
        self.assertEqual(txt.ttl,300)

    def test_octal_and_escaped_quote(self):
        rr = RR.fromZone(r'x 60 IN TXT "a\100b\042c"',origin="example.com")[0]
        self.assertEqual(rr.rdata.data,[b'a@b"c'])
        # Round-trip through zone format
        rr2 = RR.fromZone(rr.toZone())[0]
        self.assertEqual(rr2.rdata.data,[b'a@b"c'])

    def test_origin_switch_in_order(self):
        rr = RR.fromZone(ZONE,fname="db.example.com")
        branch = [r for r in rr if str(r.rname).startswith("branch")][0]
        self.assertEqual(str(branch.rname),"branch.sub.example.com.")
        self.assertEqual(branch.ttl,60)

    def test_ttl_inheritance(self):
        rr = RR.fromZone(ZONE,fname="db.example.com")
        by_name = dict((str(r.rname),r) for r in rr)
        # $TTL 3600 inherited
        self.assertEqual(by_name["www.example.com."].ttl,3600)
        # Explicit TTL overrides
        self.assertEqual(by_name["txt.example.com."].ttl,300)
        # SOA time suffixes
        soa = [r for r in rr if QTYPE[r.rtype] == "SOA"][0]
        self.assertEqual(soa.rdata.times,(1,10800,3600,604800,3600))

    def test_ttl_suffix(self):
        rr = RR.fromZone("www 1h IN A 1.2.3.4",origin="example.com")[0]
        self.assertEqual(rr.ttl,3600)

    def test_bad_ttl(self):
        for zone in ("www 99999999999 IN A 1.2.3.4",   # out of range
                     "www 10x IN A 1.2.3.4",           # invalid
                     "$TTL 99999999999\nwww IN A 1.2.3.4"):
            with self.assertRaises(ZoneError):
                RR.fromZone(zone,origin="example.com",fname="db.example.com")

    def test_cname_conflict(self):
        with self.assertRaises(ZoneError):
            RR.fromZone("www 60 IN A 1.2.3.4\nwww 60 IN CNAME x\n",
                        origin="example.com")
        with self.assertRaises(ZoneError):
            RR.fromZone("www 60 IN CNAME x\nwww 60 IN A 1.2.3.4\n",
                        origin="example.com")

    def test_duplicate_dropped(self):
        rr = RR.fromZone("www.example.com. 60 IN A 1.2.3.4\n"
                         "www.example.com. 60 IN A 1.2.3.4\n")
        self.assertEqual(len(rr),1)

    def test_bad_escape(self):
        with self.assertRaises(ZoneError):
            RR.fromZone(r'www 60 IN TXT "abc\999def"',origin="example.com")
        with self.assertRaises(ZoneError):
            RR.fromZone(r'www 60 IN TXT "abc\777def"',origin="example.com")

    def test_unterminated_quote(self):
        # Newline must not be swallowed into the quoted string
        with self.assertRaises(ZoneError):
            RR.fromZone('www 60 IN TXT "abc\nnext 60 IN A 1.2.3.4"',
                        origin="example.com")

    def test_missing_origin_arg(self):
        with self.assertRaises(ZoneError):
            RR.fromZone("$ORIGIN\nwww 60 IN A 1.2.3.4")

    def test_unbalanced_paren(self):
        with self.assertRaises(ZoneError):
            RR.fromZone("www 60 IN TXT ( \"abc\"",origin="example.com")

    def test_error_context(self):
        secret = "PRIVKEY-" + "x" * 200
        zone = ("www 60 IN TXT \"%s\"\n" % secret) + \
               "bad 99999999999 IN A 1.2.3.4\n"
        try:
            RR.fromZone(zone,origin="example.com",fname="db.example.com")
            self.fail("Expected ZoneError")
        except ZoneError as e:
            msg = str(e)
            self.assertIn("db.example.com:2:",msg)
            # Error must not echo the zone contents / key material
            self.assertNotIn(secret,msg)
            self.assertNotIn("PRIVKEY",msg)

    def test_zone_output_stable(self):
        # Record order, TTLs, text values and zone (AXFR) output
        rr = RR.fromZone(ZONE,fname="db.example.com")
        self.assertEqual([r.toZone() for r in rr],[
            "example.com.            3600    IN      SOA     ns1.example.com. admin.example.com. 1 10800 3600 604800 3600",
            "example.com.            3600    IN      NS      ns1.example.com.",
            "example.com.            3600    IN      A       1.2.3.4",
            "www.example.com.        3600    IN      A       2.3.4.5",
            "alias.example.com.      3600    IN      CNAME   example.com.",
            "abs.example.com.        3600    IN      CNAME   target.other.org.",
            "txt.example.com.        300     IN      TXT     \"line1@\\\"quoted\\\"\" \"line2\"",
            "sub.example.org.        3600    IN      A       9.9.9.9",
            "branch.sub.example.com. 60      IN      A       5.6.7.8",
        ])

class TestZoneResolver(unittest.TestCase):

    def setUp(self):
        self.resolver = ZoneResolver(ZONE)

    def resolve(self,name,qtype):
        q = DNSRecord.question(name,qtype)
        return self.resolver.resolve(q,None)

    def test_resolve_a(self):
        reply = self.resolve("www.example.com","A")
        self.assertEqual(reply.header.rcode,RCODE.NOERROR)
        self.assertEqual(len(reply.rr),1)
        ans = reply.rr[0]
        self.assertEqual(str(ans.rname),"www.example.com.")
        self.assertEqual(ans.ttl,3600)
        self.assertEqual(str(ans.rdata),"2.3.4.5")

    def test_resolve_at_origin(self):
        reply = self.resolve("example.com","A")
        self.assertEqual(reply.header.rcode,RCODE.NOERROR)
        self.assertEqual(str(reply.rr[0].rname),"example.com.")
        self.assertEqual(str(reply.rr[0].rdata),"1.2.3.4")

    def test_resolve_cname(self):
        reply = self.resolve("alias.example.com","A")
        self.assertEqual(reply.header.rcode,RCODE.NOERROR)
        cname = [r for r in reply.rr if QTYPE[r.rtype] == "CNAME"]
        self.assertEqual(len(cname),1)
        # CNAME target expanded to origin
        self.assertEqual(str(cname[0].rdata.label),"example.com.")
        # Additional section contains A record for target
        self.assertTrue(any(str(r.rname) == "example.com." and
                            QTYPE[r.rtype] == "A" for r in reply.ar))

    def test_resolve_txt(self):
        reply = self.resolve("txt.example.com","TXT")
        self.assertEqual(reply.rr[0].rdata.data,[b'line1@"quoted"',b"line2"])
        self.assertEqual(reply.rr[0].ttl,300)

    def test_resolve_nxdomain(self):
        reply = self.resolve("nosuch.example.com","A")
        self.assertEqual(reply.header.rcode,RCODE.NXDOMAIN)

    def test_zone_order_preserved(self):
        names = [str(rr.rname) for _,_,rr in self.resolver.zone]
        self.assertEqual(names,[
            "example.com.","example.com.","example.com.",
            "www.example.com.","alias.example.com.","abs.example.com.",
            "txt.example.com.","sub.example.org.","branch.sub.example.com.",
        ])

    def test_zone_file_name_in_error(self):
        import io
        f = io.StringIO("www 99999999999 IN A 1.2.3.4\n")
        f.name = "db.bad"
        with self.assertRaises(ZoneError) as cm:
            ZoneResolver(f)
        self.assertIn("db.bad:1:",str(cm.exception))

if __name__ == '__main__':
    unittest.main()
