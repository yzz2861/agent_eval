from __future__ import annotations

from base64 import b64encode
from decimal import Decimal

import pytest

from werkzeug.datastructures import Headers
from werkzeug.http import dump_dictionary
from werkzeug.http import dump_item
from werkzeug.http import dump_list
from werkzeug.http import InnerList
from werkzeug.http import Item
from werkzeug.http import parse_dictionary
from werkzeug.http import parse_item
from werkzeug.http import parse_list
from werkzeug.http import StructuredFieldError
from werkzeug.http import Token


@pytest.mark.parametrize(
    ("value", "serialized"),
    [
        (
            Item(42, {"a": Item(True, {"b": Decimal("1.5")})}),
            "42;a=?1;b=1.5",
        ),
        (Item(-1), "-1"),
        (Item(Decimal("1.20")), "1.20"),
        (Item(Decimal("-0.0")), "-0.0"),
        (Item("hello world"), '"hello world"'),
        (Item(Token("x-token:42")), "x-token:42"),
        (Item(b"abc"), f":{b64encode(b'abc').decode()}:"),
        (Item(False), "?0"),
    ],
)
def test_item_canonical_examples(value, serialized):
    assert dump_item(value) == serialized
    assert parse_item(serialized) == value


def test_list_canonical_examples():
    value = [
        Item(Token("abc")),
        Item(False, {"foo": Item(True)}),
        InnerList(
            [Item(1), Item("two"), Item(b"three")],
            {"flag": Item(True, {"number": Decimal("1.5")})},
        ),
    ]
    serialized = 'abc, ?0;foo=?1, (1 "two" :dGhyZWU=:);flag=?1;number=1.5'
    assert dump_list(value) == serialized
    assert parse_list(serialized) == value


def test_dictionary_canonical_examples():
    value = {
        "abc": Item(True),
        "no": Item(False),
        "inner": InnerList([Item(1), Item(Token("two"))]),
        "decimal": Item(Decimal("1.20"), {"quoted": Item("a;b")}),
    }
    serialized = 'abc, no=?0, inner=(1 two), decimal=1.20;quoted="a;b"'
    assert dump_dictionary(value) == serialized
    assert parse_dictionary(serialized) == value


@pytest.mark.parametrize("value", ["", "   ", "\t", "  abc  "])
def test_empty_and_padded_lists_and_dictionaries(value):
    if value.strip():
        expected_list = [Item(Token("abc"))]
        expected_dictionary = {"abc": Item(True)}
    else:
        expected_list = []
        expected_dictionary = {}

    assert parse_list(value) == expected_list
    assert parse_dictionary(value) == expected_dictionary


@pytest.mark.parametrize(
    ("value", "position"),
    [
        ("abc,def", 3),
        ("a, b extra", 1),
        ("a,,b", 1),
        ("a,", 1),
        (" a", 0),
        ("?", 0),
        ("?2", 0),
        ("1000000000000000", 0),
        ("-1000000000000000", 0),
        ("1000000000000.0", 13),
        ("-1000000000000.0", 14),
        ("1.", 1),
        ('"unterminated', 0),
        ('"bad\\n"', 5),
        ("1abc", 1),
        (":YWJj=:", 0),
        (":YW=:", 0),
        ("(1", 0),
        ("(1 x)", 0),
        ("(1 ;x=1)", 0),
        ("1;X=1", 2),
        ("a=1,a=2", 1),
        ("1;", 2),
        ("1;x", 3),
        ("1;x=??1", 4),
        ("1\t", 1),
    ],
)
def test_invalid_input_reports_position(value, position):
    with pytest.raises(StructuredFieldError) as exc_info:
        parse_item(value)

    assert exc_info.value.position == position


@pytest.mark.parametrize(
    ("value", "parser"),
    [
        ("a=1,b=2", parse_list),
        ("x=1,x=2", parse_dictionary),
        ("a b", parse_list),
        ("a b", parse_dictionary),
        ("1;", parse_list),
    ],
)
def test_invalid_lists_and_dictionaries(value, parser):
    with pytest.raises(StructuredFieldError):
        parser(value)


@pytest.mark.parametrize(
    ("dumper", "value"),
    [
        (dump_item, 10**15),
        (dump_item, -(10**15)),
        (dump_item, 1.0),
        (dump_item, Decimal("0.0001")),
        (dump_item, Decimal("100000000000000.0")),
        (dump_item, None),
        (dump_item, [1]),
        (dump_item, Token("1bad")),
        (dump_item, "\x00"),
        (dump_dictionary, {"X": True}),
        (dump_dictionary, {"a": [1]}),
    ],
)
def test_invalid_serialization(dumper, value):
    with pytest.raises((StructuredFieldError, TypeError)):
        dumper(value)


def test_token_string_and_bytes_remain_distinct():
    assert parse_item("abc") != Item("abc")
    assert parse_item("abc").value == Token("abc")
    assert parse_item('"abc"').value == "abc"
    assert parse_item(":YWJj:").value == b"abc"
    assert dump_item(Item(Token("abc"))) == "abc"
    assert dump_item(Item("abc")) == '"abc"'


def test_decimal_uses_exact_value():
    item = parse_item("0.10")
    assert item.value == Decimal("0.10")
    assert dump_item(item) == "0.10"
    assert item != Item(Decimal("0.1"))


def test_parameters_are_recursive_not_flattened():
    assert parse_item("1;x=1;x=2") == Item(1, {"x": Item(1, {"x": 2})})


def test_headers_item_round_trip_and_repeated_field_error():
    headers = Headers()
    headers.set_item("X-Item", 42, foo=True)
    assert headers["X-Item"] == "42;foo=?1"
    assert headers.get_item("X-Item") == Item(42, {"foo": True})
    assert headers.get_item("missing") is None

    headers.add("X-Item", "7")

    with pytest.raises(StructuredFieldError) as exc_info:
        headers.get_item("X-Item")

    assert exc_info.value.field == 1


def test_headers_repeated_list_fields_merge_by_field_shape():
    headers = Headers()
    headers.set_list("X-List", [Item(1), InnerList([Item(2)])])
    headers.add("X-List", "3, 4")
    assert headers.get_list("X-List") == [
        Item(1),
        InnerList([Item(2)]),
        Item(3),
        Item(4),
    ]
    assert headers["X-List"] == "1, (2)"
    assert headers.getlist("X-List") == ["1, (2)", "3, 4"]


def test_headers_repeated_dictionary_fields_merge():
    headers = Headers()
    headers.set_dictionary("X-Dict", {"a": Item(1)})
    headers.add("X-Dict", "b=2")
    assert headers.get_dictionary("X-Dict") == {
        "a": Item(1),
        "b": Item(2),
    }

    headers.add("X-Dict", "a=3")

    with pytest.raises(StructuredFieldError) as exc_info:
        headers.get_dictionary("X-Dict")

    assert exc_info.value.field == 2
    assert exc_info.value.position == 0

    headers.pop("X-Dict")
    headers.add("X-Dict", "a=1")
    headers.add("X-Dict", "ok, a=2")

    with pytest.raises(StructuredFieldError) as exc_info:
        headers.get_dictionary("X-Dict")

    assert exc_info.value.field == 1
    assert exc_info.value.position == 4


def test_headers_invalid_repeated_field_reports_field_and_position():
    headers = Headers([("X-List", "1"), ("X-List", "a,b bad")])

    with pytest.raises(StructuredFieldError) as exc_info:
        headers.get_list("X-List")

    assert exc_info.value.field == 1
    assert exc_info.value.position == 4


def test_headers_repeated_fields_do_not_ignore_empty_line():
    list_headers = Headers([("X", "1"), ("X", "")])

    with pytest.raises(StructuredFieldError) as exc_info:
        list_headers.get_list("X")

    assert exc_info.value.field == 1
    assert exc_info.value.position == 0

    dictionary_headers = Headers([("X", "a=1"), ("X", "")])

    with pytest.raises(StructuredFieldError) as exc_info:
        dictionary_headers.get_dictionary("X")

    assert exc_info.value.field == 1
    assert exc_info.value.position == 0


def test_headers_structured_setters_replace_existing_fields():
    headers = Headers()
    headers.add("X", "1")
    headers.add("X", "2")
    headers.set_dictionary("X", {"a": Item(True)})
    assert headers.getlist("X") == ["a"]
    assert headers.get_dictionary("X") == {"a": Item(True)}


def test_existing_plain_header_api_still_works():
    headers = Headers([("X-Plain", "foo, bar"), ("X-Plain", "baz")])
    assert headers["X-Plain"] == "foo, bar"
    assert headers.getlist("X-Plain") == ["foo, bar", "baz"]
    headers.set("X-Plain", "qux", filename="x")
    assert headers["X-Plain"] == "qux; filename=x"
