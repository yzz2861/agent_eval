import json

import pytest

from itsdangerous import RFC8785JSON
from itsdangerous import Serializer
from itsdangerous.exc import BadPayload

EXPECTED_SIGNATURE = "TnBltU5I_9i7bggz2Sg0Sx6WCkA"


class TestNumbers:
    @pytest.mark.parametrize(
        ("value", "expected"),
        [
            (0, "0"),
            (1, "1"),
            (-1, "-1"),
            (0.0, "0"),
            (-0.0, "0"),
            (1.0, "1"),
            (-2.5, "-2.5"),
            (0.1, "0.1"),
            (100.0, "100"),
            (1e20, "100000000000000000000"),
            (1e21, "1e+21"),
            (1e-6, "0.000001"),
            (1e-7, "1e-7"),
            (5e-324, "5e-324"),
            (1.7976931348623157e308, "1.7976931348623157e+308"),
            (2.2250738585072014e-308, "2.2250738585072014e-308"),
            (0.30000000000000004, "0.30000000000000004"),
            (3.141592653589793, "3.141592653589793"),
            (123456789.123456789, "123456789.12345679"),
            (333333333.3333333, "333333333.3333333"),
            (9007199254740991, "9007199254740991"),
            (9007199254740992, "9007199254740992"),
            (-9007199254740992, "-9007199254740992"),
        ],
    )
    def test_number_vectors(self, value, expected):
        assert RFC8785JSON.dumps(value) == expected

    @pytest.mark.parametrize("value", [float("inf"), float("-inf"), float("nan")])
    def test_non_finite_rejected(self, value):
        with pytest.raises(ValueError, match="non-finite"):
            RFC8785JSON.dumps(value)

    @pytest.mark.parametrize("value", [2**53 + 1, -(2**53) - 1, 10**30, 2**60])
    def test_int_out_of_domain_rejected(self, value):
        with pytest.raises(ValueError, match="2"):
            RFC8785JSON.dumps(value)


class TestStrings:
    def test_escapes(self):
        value = '"\\\b\t\n\f\r\x00\x1f'
        assert RFC8785JSON.dumps(value) == '"\\"\\\\\\b\\t\\n\\f\\r\\u0000\\u001f"'

    def test_non_ascii_literal(self):
        assert RFC8785JSON.dumps("é𝄞中") == '"é𝄞中"'

    @pytest.mark.parametrize(
        "value",
        [
            "\ud800",
            "\udfff",
            "ok\udc00bad",
            {"\ud800": 1},
            {"k": "\ud801"},
        ],
    )
    def test_lone_surrogate_rejected(self, value):
        with pytest.raises(ValueError, match="surrogate"):
            RFC8785JSON.dumps(value)


class TestStructures:
    def test_scalars_and_containers(self):
        assert RFC8785JSON.dumps(None) == "null"
        assert RFC8785JSON.dumps(True) == "true"
        assert RFC8785JSON.dumps(False) == "false"
        assert RFC8785JSON.dumps([]) == "[]"
        assert RFC8785JSON.dumps({}) == "{}"
        assert RFC8785JSON.dumps([1, "a", None]) == '[1,"a",null]'
        assert RFC8785JSON.dumps((1, 2)) == "[1,2]"

    def test_keys_sorted_by_utf16(self):
        # U+10000 is D800 DC00 in UTF-16, so it sorts before U+FFFF
        # even though its code point is higher.
        data = {"\uffff": 1, "\U00010000": 2}
        assert RFC8785JSON.dumps(data) == '{"\U00010000":2,"\uffff":1}'
        # Code point order, as used by json.dumps(sort_keys=True),
        # would produce the opposite order.
        assert (
            json.dumps(data, sort_keys=True, ensure_ascii=False, separators=(",", ":"))
            == '{"\uffff":1,"\U00010000":2}'
        )

    def test_insertion_order_independent(self):
        a = {"b": 1, "a": {"y": 2, "x": 3}}
        b = {"a": {"x": 3, "y": 2}, "b": 1}
        expected = '{"a":{"x":3,"y":2},"b":1}'
        assert RFC8785JSON.dumps(a) == expected
        assert RFC8785JSON.dumps(b) == expected

    def test_non_string_key_rejected(self):
        with pytest.raises(TypeError, match="keys must be strings"):
            RFC8785JSON.dumps({1: "a"})

    def test_unsupported_type_rejected(self):
        with pytest.raises(TypeError, match="not serializable"):
            RFC8785JSON.dumps(object())

    def test_round_trip(self):
        data = {"a": [1, 2.5, "x", None, True], "b": {"c": "é"}}
        assert RFC8785JSON.loads(RFC8785JSON.dumps(data)) == data


class TestLoads:
    def test_duplicate_keys_rejected(self):
        with pytest.raises(ValueError, match="duplicate object key"):
            RFC8785JSON.loads('{"a": 1, "b": 2, "a": 3}')

    @pytest.mark.parametrize("payload", ["NaN", "Infinity", "-Infinity"])
    def test_non_json_constants_rejected(self, payload):
        with pytest.raises(ValueError, match="not valid JSON"):
            RFC8785JSON.loads(payload)


class TestSerializerIntegration:
    def test_signature_is_canonical(self):
        s = Serializer("secret", serializer=RFC8785JSON)
        a = s.dumps({"b": 1, "a": {"y": [1, 2], "x": "é"}})
        b = s.dumps({"a": {"x": "é", "y": [1, 2]}, "b": 1})
        assert isinstance(a, str)
        assert a == b
        assert s.loads(a) == {"a": {"x": "é", "y": [1, 2]}, "b": 1}

    def test_signature_matches_expected(self):
        s = Serializer("secret", serializer=RFC8785JSON)
        token = s.dumps({"b": 1, "a": {"x": 3, "y": 2}})
        payload, _, signature = token.rpartition(".")
        assert payload == '{"a":{"x":3,"y":2},"b":1}'
        assert signature == EXPECTED_SIGNATURE

    def test_loads_duplicate_keys_bad_payload(self):
        s = Serializer("secret", serializer=RFC8785JSON)
        token = s.make_signer().sign(b'{"a": 1, "a": 2}')

        with pytest.raises(BadPayload):
            s.loads(token)

    def test_default_serializer_unchanged(self):
        assert Serializer.default_serializer is json
        token = Serializer("secret").dumps({"b": 1, "a": 2})
        assert token.startswith('{"b": 1, "a": 2}.')
