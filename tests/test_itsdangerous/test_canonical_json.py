from __future__ import annotations

import json
import math

import pytest

from itsdangerous import CanonicalJSONSerializer
from itsdangerous import Serializer


@pytest.fixture()
def canonical() -> CanonicalJSONSerializer:
    return CanonicalJSONSerializer()


# RFC 8785, Appendix B.1: integer values serialized as ECMAScript Number.
@pytest.mark.parametrize(
    ("value", "expected"),
    [
        (0.0, "0"),
        (-0.0, "0"),
        (1.0, "1"),
        (-1.0, "-1"),
        (100.0, "100"),
        (-100.0, "-100"),
        (9007199254740992.0, "9007199254740992"),
        (float("-9007199254740993"), "-9007199254740992"),
        (1e20, "100000000000000000000"),
        (1e21, "1e+21"),
        (1e22, "1e+22"),
    ],
)
def test_integer_number_vectors(
    canonical: CanonicalJSONSerializer, value: float, expected: str
) -> None:
    assert canonical.dumps(value) == expected


# RFC 8785, Appendix B.2: non-integer values.
@pytest.mark.parametrize(
    ("value", "expected"),
    [
        (0.0001, "0.0001"),
        (0.00001, "0.00001"),
        (0.000001, "0.000001"),
        (0.0000001, "1e-7"),
        (1.5, "1.5"),
        (-1.5, "-1.5"),
        (0.1, "0.1"),
        (-0.1, "-0.1"),
        (1.0000000000000002, "1.0000000000000002"),
        (float("12345678901234567890"), "12345678901234567000"),
        (5e-324, "5e-324"),
        (4.8568064173901e250, "4.8568064173901e+250"),
        (-4.8568064173901e250, "-4.8568064173901e+250"),
        (1.7976931348623157e308, "1.7976931348623157e+308"),
        (5e-42, "5e-42"),
    ],
)
def test_non_integer_number_vectors(
    canonical: CanonicalJSONSerializer, value: float, expected: str
) -> None:
    assert canonical.dumps(value) == expected


def test_negative_zero_roundtrip(canonical: CanonicalJSONSerializer) -> None:
    assert canonical.dumps(-0.0) == "0"
    assert math.copysign(1.0, canonical.loads(canonical.dumps(-0.0))) == 1.0


def test_rfc8785_appendix_a3_example(canonical: CanonicalJSONSerializer) -> None:
    value = {
        "numbers": [333333333.33333329, 49, 0.3],
        "string": '\u03b1\u03b2\u03b3\U0001d11e"\b\f\n\r\tf',
        "null": None,
    }
    expected = (
        '{"null":null,"numbers":[333333333.3333333,49,0.3],'
        '"string":"\u03b1\u03b2\u03b3\U0001d11e\\"\\b\\f\\n\\r\\tf"}'
    )
    assert canonical.dumps(value) == expected


def test_object_member_insertion_order_does_not_matter(
    canonical: CanonicalJSONSerializer,
) -> None:
    keys = ["\U0001f426", "\u00e9", "A", "\u3042", "\ue000", "\ud7ff"]
    first = {key: 1 for key in keys}
    second = {key: 1 for key in reversed(keys)}
    expected = '{"A":1,"\u00e9":1,"\u3042":1,"\ud7ff":1,"\U0001f426":1,"\ue000":1}'
    assert canonical.dumps(first) == expected
    assert canonical.dumps(second) == expected


def test_supplementary_plane_keys_sort_by_utf16_code_units(
    canonical: CanonicalJSONSerializer,
) -> None:
    # U+1F426 is encoded as the surrogate pair D83D DD26 in UTF-16, so it
    # sorts between U+D7FF and U+E000, not by its Unicode code point.
    value = {"\U0001f426": 1, "\ud7ff": 2, "\ue000": 3}
    assert canonical.dumps(value) == ('{"\ud7ff":2,"\U0001f426":1,"\ue000":3}')
    assert json.dumps(value, sort_keys=True, ensure_ascii=False) != canonical.dumps(
        value
    )


@pytest.mark.parametrize(
    "value",
    [float("nan"), float("inf"), float("-inf")],
)
def test_rejects_non_finite_numbers(
    canonical: CanonicalJSONSerializer, value: float
) -> None:
    with pytest.raises(ValueError):
        canonical.dumps(value)


@pytest.mark.parametrize("value", [10**100, -(10**100), 9007199254740993])
def test_rejects_ints_outside_double_domain(
    canonical: CanonicalJSONSerializer, value: int
) -> None:
    with pytest.raises(ValueError):
        canonical.dumps(value)


def test_exact_doubledomain_integers_are_allowed(
    canonical: CanonicalJSONSerializer,
) -> None:
    assert canonical.dumps(9007199254740992) == "9007199254740992"
    assert canonical.dumps(10**20) == "100000000000000000000"


def test_rejects_lone_surrogates_on_dump(canonical: CanonicalJSONSerializer) -> None:
    with pytest.raises(ValueError):
        canonical.dumps(chr(0xD800))

    with pytest.raises(ValueError):
        canonical.dumps({chr(0xDC00): 1})


def test_rejects_lone_surrogates_on_load(canonical: CanonicalJSONSerializer) -> None:
    with pytest.raises(ValueError):
        canonical.loads('"' + chr(0xD800) + '"')

    with pytest.raises(ValueError):
        canonical.loads('{"' + chr(0xDD26) + '":1}')


def test_rejects_duplicate_keys_on_load(canonical: CanonicalJSONSerializer) -> None:
    with pytest.raises(ValueError, match="Duplicate"):
        canonical.loads('{"a":1,"a":2}')

    with pytest.raises(ValueError, match="Duplicate"):
        canonical.loads('{"o":{"x":1,"x":2}}')


@pytest.mark.parametrize("token", ["NaN", "Infinity", "-Infinity"])
def test_rejects_non_finite_json_tokens(
    canonical: CanonicalJSONSerializer, token: str
) -> None:
    with pytest.raises(ValueError):
        canonical.loads(token)


def test_rejects_non_string_mapping_keys(canonical: CanonicalJSONSerializer) -> None:
    with pytest.raises(TypeError):
        canonical.dumps({1: 2})


def test_rejects_unsupported_type(canonical: CanonicalJSONSerializer) -> None:
    with pytest.raises(TypeError):
        canonical.dumps(object())


def test_dumps_takes_no_options(canonical: CanonicalJSONSerializer) -> None:
    with pytest.raises(TypeError):
        canonical.dumps({}, indent=2)


def test_string_escaping(canonical: CanonicalJSONSerializer) -> None:
    assert canonical.dumps("\u0000\u001f /") == '"\\u0000\\u001f /"'
    assert canonical.dumps(chr(0x5C)) == '"' + chr(0x5C) * 2 + '"'  # backslash
    assert canonical.dumps(chr(0x22)) == '"\\""'  # quotation mark
    assert canonical.dumps(chr(0x08) + chr(0x0C)) == '"\\b\\f"'


def test_roundtrip(canonical: CanonicalJSONSerializer) -> None:
    value = {
        "a": [1, 2, 3.5, -0.0],
        "b": {"\U0001f426": None, "x": True, "y": False},
    }
    assert canonical.loads(canonical.dumps(value)) == value


def test_serializer_uses_canonical_form() -> None:
    signed = Serializer("secret-key", serializer=CanonicalJSONSerializer)
    # Different insertion order and -0.0 vs 0.0 produce one signature.
    first = signed.dumps({"b": 1, "a": [1.5, -0.0, 1e21]})
    second = signed.dumps({"a": [1.5, 0.0, 1e21], "b": 1})
    assert first == second
    assert signed.loads(first) == {"a": [1.5, 0.0, 1e21], "b": 1}


def test_signature_golden_value() -> None:
    # Independently reproduced with Node.js crypto (sha1 django-concat
    # key derivation, HMAC-SHA1, URL-safe base64). Plain sort_keys output
    # would start with {"b":1,...} and would not match this signature.
    signed = Serializer("secret-key", serializer=CanonicalJSONSerializer)
    token = '{"a":[1.5,0,1e+21],"b":1}.NWRiKvmiC97k2m_nH0_XyOvrUDs'
    assert signed.dumps({"b": 1, "a": [1.5, -0.0, 1e21]}) == token
    assert signed.loads(token) == {"a": [1.5, 0.0, 1e21], "b": 1}


def test_default_serializer_is_unchanged() -> None:
    # The plain default still emits whitespace and preserves insertion order.
    default = Serializer("secret-key")
    token = default.dumps({"b": 1, "a": 2})
    assert token.startswith('{"b": 1, "a": 2}.')
    assert default.loads(token) == {"b": 1, "a": 2}
