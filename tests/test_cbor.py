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

import pytest

from fido2 import cbor

_TEST_VECTORS = [
    ("00", 0),
    ("01", 1),
    ("0a", 10),
    ("17", 23),
    ("1818", 24),
    ("1819", 25),
    ("1864", 100),
    ("1903e8", 1000),
    ("1a000f4240", 1000000),
    ("1b000000e8d4a51000", 1000000000000),
    ("1bffffffffffffffff", 18446744073709551615),
    # ('c249010000000000000000', 18446744073709551616),
    ("3bffffffffffffffff", -18446744073709551616),
    # ('c349010000000000000000', -18446744073709551617),
    ("20", -1),
    ("29", -10),
    ("3863", -100),
    ("3903e7", -1000),
    # ('f90000', 0.0),
    # ('f98000', -0.0),
    # ('f93c00', 1.0),
    # ('fb3ff199999999999a', 1.1),
    # ('f93e00', 1.5),
    # ('f97bff', 65504.0),
    # ('fa47c35000', 100000.0),
    # ('fa7f7fffff', 3.4028234663852886e+38),
    # ('fb7e37e43c8800759c', 1e+300),
    # ('f90001', 5.960464477539063e-08),
    # ('f90400', 6.103515625e-05),
    # ('f9c400', -4.0),
    # ('fbc010666666666666', -4.1),
    # ('f97c00', None),
    # ('f97e00', None),
    # ('f9fc00', None),
    # ('fa7f800000', None),
    # ('fa7fc00000', None),
    # ('faff800000', None),
    # ('fb7ff0000000000000', None),
    # ('fb7ff8000000000000', None),
    # ('fbfff0000000000000', None),
    ("f4", False),
    ("f5", True),
    # ('f6', None),
    # ('f7', None),
    # ('f0', None),
    # ('f818', None),
    # ('f8ff', None),
    # ('c074323031332d30332d32315432303a30343a30305a', None),
    # ('c11a514b67b0', None),
    # ('c1fb41d452d9ec200000', None),
    # ('d74401020304', None),
    # ('d818456449455446', None),
    # ('d82076687474703a2f2f7777772e6578616d706c652e636f6d', None),
    ("40", b""),
    ("4401020304", b"\1\2\3\4"),
    ("60", ""),
    ("6161", "a"),
    ("6449455446", "IETF"),
    ("62225c", '"\\'),
    ("62c3bc", "ü"),
    ("63e6b0b4", "水"),
    ("64f0908591", "𐅑"),
    ("80", []),
    ("83010203", [1, 2, 3]),
    ("8301820203820405", [1, [2, 3], [4, 5]]),
    (
        "98190102030405060708090a0b0c0d0e0f101112131415161718181819",
        [
            1,
            2,
            3,
            4,
            5,
            6,
            7,
            8,
            9,
            10,
            11,
            12,
            13,
            14,
            15,
            16,
            17,
            18,
            19,
            20,
            21,
            22,
            23,
            24,
            25,
        ],
    ),
    ("a0", {}),
    ("a201020304", {1: 2, 3: 4}),
    ("a26161016162820203", {"a": 1, "b": [2, 3]}),
    ("826161a161626163", ["a", {"b": "c"}]),
    (
        "a56161614161626142616361436164614461656145",
        {"c": "C", "d": "D", "a": "A", "b": "B", "e": "E"},
    ),
    # ('5f42010243030405ff', None),
    # ('7f657374726561646d696e67ff', 'streaming'),
    # ('9fff', []),
    # ('9f018202039f0405ffff', [1, [2, 3], [4, 5]]),
    # ('9f01820203820405ff', [1, [2, 3], [4, 5]]),
    # ('83018202039f0405ff', [1, [2, 3], [4, 5]]),
    # ('83019f0203ff820405', [1, [2, 3], [4, 5]]),
    # ('9f0102030405060708090a0b0c0d0e0f101112131415161718181819ff', [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25]),  # noqa E501
    # ('bf61610161629f0203ffff', {'a': 1, 'b': [2, 3]}),
    # ('826161bf61626163ff', ['a', {'b': 'c'}]),
    # ('bf6346756ef563416d7421ff', {'Amt': -2, 'Fun': True}),
]


def cbor2hex(data):
    return cbor.encode(data).hex()


@pytest.mark.parametrize("data,value", _TEST_VECTORS)
def test_cbor_test_vectors(data, value):
    """
    From https://github.com/cbor/test-vectors
    Unsupported values are commented out.
    """
    assert cbor.decode_from(bytes.fromhex(data)) == (value, b"")
    assert cbor.decode(bytes.fromhex(data)) == value
    assert cbor2hex(value) == data


# FIDO Canonical tests
# As defined in section 6 of:
# https://fidoalliance.org/specs/fido-v2.0-ps-20170927/fido-client-to-authenticator-protocol-v2.0-ps-20170927.html


@pytest.mark.parametrize(
    "value,expected",
    [
        (0, "00"),
        (23, "17"),
        (24, "1818"),
        (255, "18ff"),
        (256, "190100"),
        (65535, "19ffff"),
        (65536, "1a00010000"),
        (4294967295, "1affffffff"),
        (4294967296, "1b0000000100000000"),
        (-1, "20"),
        (-24, "37"),
        (-25, "3818"),
    ],
)
def test_fido_canonical_integers(value, expected):
    assert cbor2hex(value) == expected


@pytest.mark.parametrize(
    "value,expected",
    [
        ({"3": 0, b"2": 0, 1: 0}, "a30100413200613300"),
        ({"3": 0, b"": 0, 256: 0}, "a3190100004000613300"),
        (
            {4294967296: 0, 255: 0, 256: 0, 0: 0},
            "a4000018ff00190100001b000000010000000000",
        ),
        ({b"22": 0, b"3": 0, b"111": 0}, "a3413300423232004331313100"),
        ({b"001": 0, b"003": 0, b"002": 0}, "a3433030310043303032004330303300"),
        ({True: 0, False: 0}, "a2f400f500"),
    ],
)
def test_fido_canonical_key_order(value, expected):
    assert cbor2hex(value) == expected


@pytest.mark.parametrize(
    "value,expected",
    [
        (b"", "40"),
        (b"\x01\x02\x03\x04", "4401020304"),
        (bytearray(b""), "40"),
        (bytearray(b"\x01\x02\x03\x04"), "4401020304"),
        (memoryview(b""), "40"),
        (memoryview(b"\x01\x02\x03\x04"), "4401020304"),
    ],
)
def test_bytes_like_encoding(value, expected):
    """Test that bytearray and memoryview are encoded as bytes."""
    assert cbor2hex(value) == expected


# Strict-mode decoding tests


@pytest.mark.parametrize("data,value", _TEST_VECTORS)
def test_strict_test_vectors(data, value):
    """All canonical test vectors must also decode in strict mode."""
    assert cbor.decode(bytes.fromhex(data), strict=True) == value


def test_strict_distinct_key_types():
    """Integer 1 and text "1" are different keys and must both survive."""
    # {1: 0, "1": 1}
    data = bytes.fromhex("a20100613101")
    assert cbor.decode(data, strict=True) == {1: 0, "1": 1}
    assert cbor.decode(data) == {1: 0, "1": 1}


def test_strict_distinct_int_and_bool_keys():
    """Boolean true and integer 1 are different keys in CBOR."""
    # {true: 0, 1: 1} is not a duplicate key situation
    data = bytes.fromhex("a2f5000101")
    cbor.decode(data, strict=True)  # Must not raise


def test_duplicate_key_non_strict_last_wins():
    """Non-strict mode keeps existing behavior: last value wins."""
    data = bytes.fromhex("a2010001 01".replace(" ", ""))
    assert cbor.decode(data) == {1: 1}


def test_strict_duplicate_int_key():
    data = bytes.fromhex("a201000101")
    with pytest.raises(ValueError, match="Duplicate map key"):
        cbor.decode(data, strict=True)


def test_strict_duplicate_text_key():
    # {"a": 0, "a": 1}
    data = bytes.fromhex("a2616100616101")
    with pytest.raises(ValueError, match="Duplicate map key"):
        cbor.decode(data, strict=True)


def test_strict_duplicate_key_error_message():
    """Errors indicate the path and key type, without echoing payload data."""
    # {1: 0, 1: h'deadbeef'}
    data = bytes.fromhex("a201000144deadbeef")
    with pytest.raises(ValueError) as excinfo:
        cbor.decode(data, strict=True)
    message = str(excinfo.value)
    assert "Duplicate map key" in message
    assert "'int'" in message
    assert "$" in message
    assert "deadbeef" not in message


def test_strict_duplicate_key_nested():
    """Duplicate keys are detected in nested maps, with a path."""
    # {"a": {1: 0, 1: 1}}
    data = bytes.fromhex("a16161a201000101")
    with pytest.raises(ValueError) as excinfo:
        cbor.decode(data, strict=True)
    message = str(excinfo.value)
    assert "Duplicate map key" in message
    assert "$['a']" in message
    # Non-strict mode still accepts it
    assert cbor.decode(data) == {"a": {1: 1}}


def test_strict_duplicate_key_canonical_collision():
    """0 encoded as 0x00 and non-canonically as 0x1800 is the same key."""
    # {0: 0, 0(non-canonical): 1}
    data = bytes.fromhex("a20000180001")
    with pytest.raises(ValueError):
        cbor.decode(data, strict=True)
    # Non-strict mode accepts and collapses to a single key
    assert cbor.decode(data) == {0: 1}


@pytest.mark.parametrize(
    "data",
    [
        "1800",  # 0 encoded with 1 byte
        "190017",  # 23 encoded with 2 bytes
        "1a0000ffff",  # 65535 encoded with 4 bytes
        "1b00000000ffffffff",  # 2**32-1 encoded with 8 bytes
        "3800",  # -1 encoded with 1 byte
    ],
)
def test_strict_noncanonical_integers(data):
    value = bytes.fromhex(data)
    with pytest.raises(ValueError, match="Non-canonical integer"):
        cbor.decode(value, strict=True)
    # Non-strict mode decodes them as before
    cbor.decode(value)


def test_depth_limit():
    """Deeply nested arrays are rejected in both modes."""
    bomb = b"\x81" * 1000 + b"\x00"
    for strict in (False, True):
        with pytest.raises(ValueError, match="nesting depth"):
            cbor.decode(bomb, strict=strict)
    # A legitimately nested structure still decodes
    ok = b"\x81" * 50 + b"\x00"
    value = cbor.decode(ok)
    for _ in range(50):
        value = value[0]
    assert value == 0


def test_strict_string_length_limit():
    data = b"\x58\x40" + b"\x00" * 64  # 64-byte byte string
    with pytest.raises(ValueError, match="exceeds maximum"):
        cbor.decode(data, strict=True, max_string_length=32)
    # Limit is not enforced in non-strict mode
    assert cbor.decode(data, max_string_length=32) == b"\x00" * 64
    # Default limit is generous enough for real-world data
    assert cbor.decode(data, strict=True) == b"\x00" * 64


@pytest.mark.parametrize(
    "data",
    [
        b"",  # Empty input
        b"\x18",  # Truncated 1-byte integer
        b"\x19\x01",  # Truncated 2-byte integer
        b"\x1b\x00\x00",  # Truncated 8-byte integer
        b"\x44\x01\x02",  # Truncated byte string
        b"\x61",  # Truncated text string
        b"\x82\x01",  # Truncated array
        b"\xa1\x01",  # Truncated map (missing value)
        b"\xa1",  # Truncated map (missing key)
        b"\x9b\xff\xff\xff\xff\xff\xff\xff\xff",  # Huge array, no elements
    ],
)
def test_truncated_data(data):
    """Truncated input raises a clean ValueError in both modes."""
    for strict in (False, True):
        with pytest.raises(ValueError, match="Truncated"):
            cbor.decode(data, strict=strict)


def test_strict_invalid_map_key_type():
    """Arrays and maps are not valid map keys in strict mode."""
    data = bytes.fromhex("a18000")  # {[]: 0}
    with pytest.raises(ValueError, match="Invalid map key"):
        cbor.decode(data, strict=True)


@pytest.mark.parametrize("data", ["f6", "f7", "f8ff", "f98000", "fb3ff199999999999a"])
def test_strict_rejects_simple_and_float_values(data):
    """Only booleans are supported simple values in strict mode.

    This includes 0xf98000, the floating point value -0.0, which must not be
    confused with the integer 0.
    """
    with pytest.raises(ValueError, match="simple or floating point"):
        cbor.decode(bytes.fromhex(data), strict=True)


def test_unsupported_major_type():
    """Tags (major type 6) are rejected with a clean error."""
    for strict in (False, True):
        with pytest.raises(ValueError, match="major type"):
            cbor.decode(bytes.fromhex("c000"), strict=strict)


def test_strict_decode_from_returns_rest():
    data = bytes.fromhex("a201000301") + b"trailing"
    value, rest = cbor.decode_from(data, strict=True)
    assert value == {1: 0, 3: 1}
    assert rest == b"trailing"


def test_strict_decode_deterministic():
    """The same malformed input always produces the same error."""
    data = bytes.fromhex("a16161a201000101")
    results = set()
    for _ in range(3):
        with pytest.raises(ValueError) as excinfo:
            cbor.decode(data, strict=True)
        results.add(str(excinfo.value))
    assert len(results) == 1
