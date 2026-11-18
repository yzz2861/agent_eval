import base64
import json
from urllib.parse import quote

import pytest

from detect_secrets.derivation.transforms import MAX_CHAIN_DEPTH
from detect_secrets.derivation.transforms import TRANSFORMS
from detect_secrets.derivation.transforms import Base64DecodeTransform
from detect_secrets.derivation.transforms import HexDecodeTransform
from detect_secrets.derivation.transforms import JsonUnescapeTransform
from detect_secrets.derivation.transforms import UrlDecodeTransform
from detect_secrets.derivation.transforms import decode_once
from detect_secrets.derivation.transforms import get_transform


SECRET = "AKIATEST-123_456.secret/value"


class TestUrlDecode:
    @staticmethod
    def test_verifies_canonical_round_trip():
        encoded = quote(SECRET, safe='')
        assert UrlDecodeTransform().decode(encoded) == SECRET

    @staticmethod
    def test_ignores_plain_text():
        assert UrlDecodeTransform().decode("plain-secret-value") is None

    @staticmethod
    def test_rejects_non_canonical_encoding():
        # Letters are never percent-encoded canonically; this decodes to a
        # real value but cannot be re-encoded back to the observation.
        assert UrlDecodeTransform().decode("%41%42%43") is None

    @staticmethod
    def test_rejects_invalid_percent_sequence():
        assert UrlDecodeTransform().decode("%ZZ") is None


class TestJsonUnescape:
    @staticmethod
    def test_verifies_canonical_round_trip():
        secret = 'line\\nbreak\\tand\\"quote-1234'
        escaped = json.dumps(secret)[1:-1]
        assert chr(92) in escaped
        assert JsonUnescapeTransform().decode(escaped) == secret

    @staticmethod
    def test_handles_unicode_escape():
        escaped = r"caf\u00e9-secret-1234"
        assert JsonUnescapeTransform().decode(escaped) == "caf\u00e9-secret-1234"

    @staticmethod
    def test_ignores_plain_text():
        assert JsonUnescapeTransform().decode("plain-secret-value") is None

    @staticmethod
    def test_rejects_broken_escape():
        assert JsonUnescapeTransform().decode("bad" + chr(92) + "u00zz") is None


class TestBase64Decode:
    @staticmethod
    def test_verifies_canonical_round_trip():
        encoded = base64.b64encode(SECRET.encode()).decode()
        assert Base64DecodeTransform().decode(encoded) == SECRET

    @staticmethod
    def test_rejects_unpadded_input():
        encoded = base64.b64encode(SECRET.encode()).decode().rstrip("=")
        assert Base64DecodeTransform().decode(encoded) is None

    @staticmethod
    def test_rejects_non_alphabet_input():
        assert Base64DecodeTransform().decode("not base64!!!") is None

    @staticmethod
    def test_rejects_binary_payload():
        encoded = base64.b64encode(bytes(range(8))).decode()
        assert Base64DecodeTransform().decode(encoded) is None

    @staticmethod
    def test_rejects_short_input():
        assert Base64DecodeTransform().decode("ABCD") is None


class TestHexDecode:
    @staticmethod
    def test_verifies_canonical_round_trip():
        encoded = SECRET.encode().hex()
        assert HexDecodeTransform().decode(encoded) == SECRET

    @staticmethod
    def test_accepts_uppercase():
        encoded = SECRET.encode().hex().upper()
        assert HexDecodeTransform().decode(encoded) == SECRET

    @staticmethod
    def test_rejects_odd_length():
        assert HexDecodeTransform().decode("abc") is None

    @staticmethod
    def test_rejects_non_hex():
        assert HexDecodeTransform().decode("nothexstr") is None


class TestRegistry:
    @staticmethod
    def test_registry_is_ordered_and_complete():
        assert [transform.name for transform in TRANSFORMS] == [
            "url_decode",
            "json_unescape",
            "base64_decode",
            "hex_decode",
        ]

    @staticmethod
    def test_get_transform_and_decode_once():
        encoded = quote(SECRET, safe="")
        result = decode_once("url_decode", encoded)
        assert result is not None
        assert result.transform == "url_decode"
        assert result.decoded == SECRET
        assert get_transform("url_decode").name == "url_decode"

    @staticmethod
    def test_decode_once_returns_none_for_unverifiable():
        assert decode_once("url_decode", "plain-value") is None

    @staticmethod
    def test_unknown_transform_raises():
        with pytest.raises(KeyError):
            get_transform("does_not_exist")

    @staticmethod
    def test_chain_depth_is_bounded():
        assert MAX_CHAIN_DEPTH == 3
