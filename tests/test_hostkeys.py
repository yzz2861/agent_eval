# Copyright (C) 2006-2007  Robey Pointer <robeypointer@gmail.com>
#
# This file is part of paramiko.
#
# Paramiko is free software; you can redistribute it and/or modify it under the
# terms of the GNU Lesser General Public License as published by the Free
# Software Foundation; either version 2.1 of the License, or (at your option)
# any later version.
#
# Paramiko is distributed in the hope that it will be useful, but WITHOUT ANY
# WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR
# A PARTICULAR PURPOSE.  See the GNU Lesser General Public License for more
# details.
#
# You should have received a copy of the GNU Lesser General Public License
# along with Paramiko; if not, write to the Free Software Foundation, Inc.,
# 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301 USA.

"""
Some unit tests for HostKeys.
"""

from base64 import decodebytes
from binascii import hexlify
import os
import unittest

import paramiko
import pytest

from ._util import _support


test_hosts_file = """\
secure.example.com ssh-rsa AAAAB3NzaC1yc2EAAAABIwAAAIEA1PD6U2/TVxET6lkpKhOk5r\
9q/kAYG6sP9f5zuUYP8i7FOFp/6ncCEbbtg/lB+A3iidyxoSWl+9jtoyyDOOVX4UIDV9G11Ml8om3\
D+jrpI9cycZHqilK0HmxDeCuxbwyMuaCygU9gS2qoRvNLWZk70OpIKSSpBo0Wl3/XUmz9uhc=
broken.example.com ssh-rsa AAAA
happy.example.com ssh-rsa AAAAB3NzaC1yc2EAAAABIwAAAIEA8bP1ZA7DCZDB9J0s50l31M\
BGQ3GQ/Fc7SX6gkpXkwcZryoi4kNFhHu5LvHcZPdxXV1D+uTMfGS1eyd2Yz/DoNWXNAl8TI0cAsW\
5ymME3bQ4J/k1IKxCtz/bAlAqFgKoc+EolMziDYqWIATtW0rYTJvzGAzTmMj80/QpsFH+Pc2M=
modern.example.com ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIKHEChAIxsh2hr8Q\
+Ea1AAHZyfEB2elEc2YgduVzBtp+
curvy.example.com ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlz\
dHAyNTYAAABBBAa+pY7djSpbg5viAcZhPt56AO3U3Sd7h7dnlUp0EjfDgyYHYQxl2QZ4JGgfwR5iv9\
T9iRZjQzvJd5s+kBAZtpk=
"""

test_hosts_file_tabs = """\
secure.example.com\tssh-rsa\tAAAAB3NzaC1yc2EAAAABIwAAAIEA1PD6U2/TVxET6lkpKhOk5r\
9q/kAYG6sP9f5zuUYP8i7FOFp/6ncCEbbtg/lB+A3iidyxoSWl+9jtoyyDOOVX4UIDV9G11Ml8om3\
D+jrpI9cycZHqilK0HmxDeCuxbwyMuaCygU9gS2qoRvNLWZk70OpIKSSpBo0Wl3/XUmz9uhc=
happy.example.com\tssh-rsa AAAAB3NzaC1yc2EAAAABIwAAAIEA8bP1ZA7DCZDB9J0s50l31M\
BGQ3GQ/Fc7SX6gkpXkwcZryoi4kNFhHu5LvHcZPdxXV1D+uTMfGS1eyd2Yz/DoNWXNAl8TI0cAsW\
5ymME3bQ4J/k1IKxCtz/bAlAqFgKoc+EolMziDYqWIATtW0rYTJvzGAzTmMj80/QpsFH+Pc2M=
modern.example.com\tssh-ed25519\tAAAAC3NzaC1lZDI1NTE5AAAAIKHEChAIxsh2hr8Q\
+Ea1AAHZyfEB2elEc2YgduVzBtp+
curvy.example.com\tecdsa-sha2-nistp256\tAAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbml\
zdHAyNTYAAABBBAa+pY7djSpbg5viAcZhPt56AO3U3Sd7h7dnlUp0EjfDgyYHYQxl2QZ4JGgfwR5iv\
9T9iRZjQzvJd5s+kBAZtpk=
"""

keyblob = b"""\
AAAAB3NzaC1yc2EAAAABIwAAAIEA8bP1ZA7DCZDB9J0s50l31MBGQ3GQ/Fc7SX6gkpXkwcZryoi4k\
NFhHu5LvHcZPdxXV1D+uTMfGS1eyd2Yz/DoNWXNAl8TI0cAsW5ymME3bQ4J/k1IKxCtz/bAlAqFgK\
oc+EolMziDYqWIATtW0rYTJvzGAzTmMj80/QpsFH+Pc2M="""


class HostKeysTest(unittest.TestCase):
    def setUp(self):
        with open("hostfile.temp", "w") as f:
            f.write(test_hosts_file)

    def tearDown(self):
        os.unlink("hostfile.temp")

    def test_load(self):
        hostdict = paramiko.HostKeys("hostfile.temp")
        assert len(hostdict) == 4
        self.assertEqual(1, len(list(hostdict.values())[0]))
        self.assertEqual(1, len(list(hostdict.values())[1]))
        fp = hexlify(
            hostdict["secure.example.com"]["ssh-rsa"].get_fingerprint()
        ).upper()
        self.assertEqual(b"E6684DB30E109B67B70FF1DC5C7F1363", fp)

    def test_add(self):
        hostdict = paramiko.HostKeys("hostfile.temp")
        hh = "|1|BMsIC6cUIP2zBuXR3t2LRcJYjzM=|hpkJMysjTk/+zzUUzxQEa2ieq6c="
        key = paramiko.RSAKey(data=decodebytes(keyblob))
        hostdict.add(hh, "ssh-rsa", key)
        assert len(hostdict) == 5
        x = hostdict["foo.example.com"]
        fp = hexlify(x["ssh-rsa"].get_fingerprint()).upper()
        self.assertEqual(b"7EC91BB336CB6D810B124B1353C32396", fp)
        self.assertTrue(hostdict.check("foo.example.com", key))

    def test_dict(self):
        hostdict = paramiko.HostKeys("hostfile.temp")
        self.assertTrue("secure.example.com" in hostdict)
        self.assertTrue("not.example.com" not in hostdict)
        self.assertTrue("secure.example.com" in hostdict)
        self.assertTrue("not.example.com" not in hostdict)
        x = hostdict.get("secure.example.com", None)
        self.assertTrue(x is not None)
        fp = hexlify(x["ssh-rsa"].get_fingerprint()).upper()
        self.assertEqual(b"E6684DB30E109B67B70FF1DC5C7F1363", fp)
        assert list(hostdict) == hostdict.keys()
        assert len(list(hostdict)) == len(hostdict.keys()) == 4

    def test_dict_set(self):
        hostdict = paramiko.HostKeys("hostfile.temp")
        key = paramiko.RSAKey(data=decodebytes(keyblob))
        key_ed25519 = paramiko.Ed25519Key.from_private_key_file(
            _support("ed25519.key")
        )
        hostdict["secure.example.com"] = {
            "ssh-rsa": key,
            "ssh-ed25519": key_ed25519,
        }
        hostdict["fake.example.com"] = {}
        hostdict["fake.example.com"]["ssh-rsa"] = key

        assert len(hostdict) == 5
        self.assertEqual(2, len(list(hostdict.values())[0]))
        self.assertEqual(1, len(list(hostdict.values())[1]))
        self.assertEqual(1, len(list(hostdict.values())[2]))
        fp = hexlify(
            hostdict["secure.example.com"]["ssh-rsa"].get_fingerprint()
        ).upper()
        self.assertEqual(b"7EC91BB336CB6D810B124B1353C32396", fp)
        fp = hexlify(
            hostdict["secure.example.com"]["ssh-ed25519"].get_fingerprint()
        ).upper()
        self.assertEqual(b"B3D522AAF9755EE8CD0EEA02B929A280", fp)

    def test_delitem(self):
        hostdict = paramiko.HostKeys("hostfile.temp")
        target = "happy.example.com"
        hostdict[target]  # will KeyError if not present
        del hostdict[target]
        try:
            hostdict[target]
        except KeyError:
            pass  # Good
        else:
            assert False, "Entry was not deleted from HostKeys on delitem!"

    def test_entry_delitem(self):
        hostdict = paramiko.HostKeys("hostfile.temp")
        target = "happy.example.com"
        entry = hostdict[target]
        key_type_list = [key_type for key_type in entry]
        for key_type in key_type_list:
            del entry[key_type]

        # will KeyError if not present
        for key_type in key_type_list:
            try:
                del entry[key_type]
            except KeyError:
                pass  # Good
            else:
                assert False, "Key was not deleted from Entry on delitem!"


class HostKeysTabsTest(HostKeysTest):
    def setUp(self):
        with open("hostfile.temp", "w") as f:
            f.write(test_hosts_file_tabs)


class HostKeyNormalizationTest(unittest.TestCase):
    def setUp(self):
        self.key = paramiko.RSAKey(data=decodebytes(keyblob))

    def test_dns_case_and_trailing_dot_are_equivalent(self):
        hostdict = paramiko.HostKeys()
        hostdict.add("Secure.Example.COM.", "ssh-rsa", self.key)
        for hostname in (
            "secure.example.com",
            "SECURE.EXAMPLE.COM",
            "secure.example.com.",
        ):
            assert hostdict.lookup(hostname) is not None
        assert hostdict.keys() == ["secure.example.com"]

    def test_non_default_port_uses_bracket_canonical_form(self):
        normalized = paramiko.hostkeys.normalize_host_key(
            "db.internal:2222"
        )
        assert normalized.canonical == "[db.internal]:2222"
        assert normalized.port == 2222
        assert normalized.family == "dns"

        hostdict = paramiko.HostKeys()
        hostdict.add("[db.internal]:2222", "ssh-rsa", self.key)
        assert hostdict.lookup("[db.internal]:2222") is not None
        assert hostdict.lookup("db.internal") is None

    def test_default_port_matches_bare_entry(self):
        hostdict = paramiko.HostKeys()
        hostdict.add("db.internal", "ssh-rsa", self.key)
        assert hostdict.lookup("[db.internal]:22") is not None

    def test_lenient_lookup_falls_back_to_bare_host(self):
        hostdict = paramiko.HostKeys()
        hostdict.add("db.internal", "ssh-rsa", self.key)
        result = hostdict.explain("[db.internal]:2222")
        assert result.matched is True
        assert result.fallback_used is True
        assert hostdict.lookup("[db.internal]:2222") is not None

    def test_strict_lookup_does_not_fall_back_to_bare_host(self):
        hostdict = paramiko.HostKeys(strict=True)
        hostdict.add("db.internal", "ssh-rsa", self.key)
        assert hostdict.lookup("[db.internal]:2222") is None
        result = hostdict.explain("[db.internal]:2222")
        assert result.matched is False
        assert result.fallback_used is False
        with pytest.raises(paramiko.hostkeys.UnknownHostKey):
            result.require()

    def test_ipv4_port_and_family(self):
        normalized = paramiko.hostkeys.normalize_host_key(
            "10.20.30.40:2222"
        )
        assert normalized.family == "ipv4"
        assert normalized.canonical == "[10.20.30.40]:2222"

        hostdict = paramiko.HostKeys()
        hostdict.add("10.20.30.40:2222", "ssh-rsa", self.key)
        assert hostdict.lookup("[10.20.30.40]:2222") is not None
        assert hostdict.lookup("10.20.30.40") is None

    def test_bare_ipv6_is_not_split_on_colons(self):
        for value in ("2001:DB8::1", "[2001:db8::1]"):
            normalized = paramiko.hostkeys.normalize_host_key(value)
            assert normalized.family == "ipv6"
            assert normalized.host == "2001:db8::1"
            assert normalized.port == 22

        hostdict = paramiko.HostKeys()
        hostdict.add("2001:db8::1", "ssh-rsa", self.key)
        assert hostdict.lookup("2001:DB8::1") is not None

    def test_bracketed_ipv6_with_port(self):
        normalized = paramiko.hostkeys.normalize_host_key(
            "[2001:db8::1]:2222"
        )
        assert normalized.family == "ipv6"
        assert normalized.port == 2222
        assert normalized.canonical == "[2001:db8::1]:2222"

        hostdict = paramiko.HostKeys()
        hostdict.add("[2001:db8::1]:2222", "ssh-rsa", self.key)
        assert hostdict.lookup("[2001:DB8::1]:2222") is not None
        assert hostdict.lookup("[2001:db8::1]:3333") is None
        assert hostdict.lookup("2001:db8::1") is None

    def test_ipv6_scope_id_is_preserved(self):
        normalized = paramiko.hostkeys.normalize_host_key(
            "[fe80::1%eth0]:2222"
        )
        assert normalized.scope_id == "eth0"
        assert normalized.canonical == "[fe80::1%eth0]:2222"

        hostdict = paramiko.HostKeys()
        hostdict.add("fe80::1%eth0", "ssh-rsa", self.key)
        assert hostdict.lookup("FE80::1%eth0") is not None
        assert hostdict.lookup("fe80::1%wlan0") is None
        with pytest.raises(paramiko.hostkeys.HostKeyParseError):
            paramiko.hostkeys.normalize_host_key("fe80::1%eth0:2222")

    def test_combined_line_matches_each_independent_host(self):
        hostdict = paramiko.HostKeys()
        hostdict.add("a.example.com", "ssh-rsa", self.key)
        entry = paramiko.hostkeys.HostKeyEntry(
            [
                "b.example.com",
                "B.EXAMPLE.COM.",
                "[2001:DB8::1]:2222",
            ],
            self.key,
        )
        hostdict._entries.append(entry)
        assert hostdict.lookup("b.example.com") is not None
        assert hostdict.lookup("[2001:db8::1]:2222") is not None
        assert hostdict.lookup("a.example.com") is not None

    def test_wildcard_matches_one_label_only(self):
        hostdict = paramiko.HostKeys()
        hostdict.add("*.example.com", "ssh-rsa", self.key)
        assert hostdict.lookup("foo.example.com") is not None
        assert hostdict.lookup("a.b.example.com") is None
        assert hostdict.lookup("example.com") is None

    def test_question_mark_matches_one_character_only(self):
        hostdict = paramiko.HostKeys()
        hostdict.add("a?c.example.com", "ssh-rsa", self.key)
        assert hostdict.lookup("abc.example.com") is not None
        assert hostdict.lookup("axxc.example.com") is None
        assert hostdict.lookup("a.c.example.com") is None

    def test_wildcard_does_not_span_ports(self):
        hostdict = paramiko.HostKeys()
        hostdict.add("*.example.com", "ssh-rsa", self.key)
        assert hostdict.lookup("[foo.example.com]:2222") is None

    def test_hashed_lookup_uses_canonical_hmac_input(self):
        salt = "BMsIC6cUIP2zBuXR3t2LRcJYjzM="
        hashed = paramiko.HostKeys.hash_host(
            "[DB.Internal.]:2222", salt
        )
        hostdict = paramiko.HostKeys()
        hostdict.add(hashed, "ssh-rsa", self.key)
        assert hostdict.lookup("[db.internal]:2222") is not None
        assert hostdict.lookup("[db.internal]:3333") is None
        assert hostdict.lookup("db.internal") is None

    def test_hashed_and_plain_spellings_share_canonical_value(self):
        salt = "BMsIC6cUIP2zBuXR3t2LRcJYjzM="
        assert paramiko.HostKeys.hash_host(
            "FOO.Example.Com.", salt
        ) == paramiko.HostKeys.hash_host("foo.example.com", salt)
        assert paramiko.HostKeys.hash_host(
            "[2001:DB8::1]:2222", salt
        ) == paramiko.HostKeys.hash_host(
            "[2001:db8::1]:2222", salt
        )

    def test_hashed_bare_entry_does_not_match_port_lookup(self):
        salt = "BMsIC6cUIP2zBuXR3t2LRcJYjzM="
        hashed = paramiko.HostKeys.hash_host("db.internal", salt)
        hostdict = paramiko.HostKeys()
        hostdict.add(hashed, "ssh-rsa", self.key)
        assert hostdict.lookup("[db.internal]:2222") is None

    def test_save_round_trip_normalizes_host_fields(self):
        hostdict = paramiko.HostKeys()
        hostdict.add("DB.Internal.", "ssh-rsa", self.key)
        hostdict.add("[db.internal]:2222", "ssh-rsa", self.key)
        hostdict.add("[2001:DB8::1]:2222", "ssh-rsa", self.key)
        hostdict.save("hostfile.normalized.temp")
        try:
            contents = open("hostfile.normalized.temp").read()
            assert "db.internal ssh-rsa" in contents
            assert "[db.internal]:2222 ssh-rsa" in contents
            assert "[2001:db8::1]:2222 ssh-rsa" in contents
            reloaded = paramiko.HostKeys("hostfile.normalized.temp")
            assert reloaded.lookup("db.internal") is not None
            assert reloaded.lookup("[db.internal]:2222") is not None
            assert reloaded.lookup("[2001:db8::1]:2222") is not None
        finally:
            os.unlink("hostfile.normalized.temp")


class HostKeyLoadErrorTest(unittest.TestCase):
    def setUp(self):
        self.key = paramiko.RSAKey(data=decodebytes(keyblob))
        self.other_key = paramiko.RSAKey.generate(2048)

    def _write(self, lines):
        with open("hostfile.errors.temp", "w") as f:
            f.write("\n".join(lines) + "\n")

    def tearDown(self):
        if os.path.exists("hostfile.errors.temp"):
            os.unlink("hostfile.errors.temp")

    def test_bad_line_is_distinct_from_unknown_host(self):
        self._write(["onlytwo fields"])
        hostdict = paramiko.HostKeys("hostfile.errors.temp")
        assert len(hostdict.load_errors) == 1
        assert isinstance(
            hostdict.load_errors[0], paramiko.hostkeys.HostKeyParseError
        )
        assert hostdict.lookup("anything.example") is None
        result = hostdict.explain("anything.example")
        assert isinstance(
            result, paramiko.hostkeys.HostKeyLookupResult
        )

    def test_duplicate_and_conflict_are_distinct_errors(self):
        base = "db.internal ssh-rsa {}".format(self.key.get_base64())
        duplicate = "DB.INTERNAL. ssh-rsa {}".format(self.key.get_base64())
        conflict = "db.internal ssh-rsa {}".format(
            self.other_key.get_base64()
        )
        self._write([base, duplicate, conflict])
        hostdict = paramiko.HostKeys("hostfile.errors.temp")
        error_types = [type(error) for error in hostdict.load_errors]
        assert paramiko.hostkeys.DuplicateHostKeyEntry in error_types
        assert paramiko.hostkeys.ConflictingHostKeyType in error_types
        assert hostdict.lookup("db.internal") is not None

    def test_strict_mode_raises_each_error_type(self):
        cases = [
            (["onlytwo fields"], paramiko.hostkeys.HostKeyParseError),
            (
                [
                    "db.internal ssh-rsa {}".format(self.key.get_base64()),
                    "DB.INTERNAL. ssh-rsa {}".format(
                        self.key.get_base64()
                    ),
                ],
                paramiko.hostkeys.DuplicateHostKeyEntry,
            ),
            (
                [
                    "db.internal ssh-rsa {}".format(self.key.get_base64()),
                    "db.internal ssh-rsa {}".format(
                        self.other_key.get_base64()
                    ),
                ],
                paramiko.hostkeys.ConflictingHostKeyType,
            ),
        ]
        for lines, expected in cases:
            self._write(lines)
            with pytest.raises(expected):
                paramiko.HostKeys("hostfile.errors.temp", strict=True)
