from __future__ import annotations

import pytest

from werkzeug import http
from werkzeug._structured_fields import StructuredFieldParseError
from werkzeug._structured_fields import StructuredFieldSerializeError
from werkzeug._structured_fields import Token
from werkzeug.datastructures import EnvironHeaders
from werkzeug.datastructures import Headers


class TestToken:
    def test_is_string(self):
        assert Token("abc") == "abc"
        assert isinstance(Token("abc"), str)

    def test_serialized_without_quotes(self):
        assert http.serialize_structured_item(Token("abc")) == "abc"
        assert http.serialize_structured_item("abc") == '"abc"'


class TestParseItem:
    @pytest.mark.parametrize(
        ("raw", "value"),
        [
            # RFC 8941 Appendix B and section examples.
            ("?1", True),
            ("?0", False),
            ("42", 42),
            ("-42", -42),
            ("999999999999999", 999999999999999),
            ("-999999999999999", -999999999999999),
            ("4.5", 4.5),
            ("-1.14", -1.14),
            ("10.0", 10.0),
            ('"hello world"', "hello world"),
            ('"x\\\\y"', r"x\y"),
            (":cHJldGVuZCB0aHRuZw==:", b"pretend thtng"),
            ("foo123", Token("foo123")),
            ("*star", Token("*star")),
        ],
    )
    def test_examples(self, raw, value):
        from decimal import Decimal

        parsed, parameters = http.parse_structured_item(raw)

        assert parameters == {}

        if isinstance(value, float):
            assert parsed == Decimal(str(value))
            assert isinstance(parsed, Decimal)
        else:
            assert parsed == value

    @pytest.mark.parametrize(
        ("raw", "value", "parameters"),
        [
            ("abc", Token("abc"), {}),
            ("abc;a=1;b=?0", Token("abc"), {"a": 1, "b": False}),
            (
                'foo; a="bar"; b; *c=:YWJj:',
                Token("foo"),
                {"a": "bar", "b": True, "*c": b"abc"},
            ),
            (
                "1.5; neg=-1; dec=-0.25; t=?1; f=?0",
                1.5,
                {
                    "neg": -1,
                    "dec": -0.25,
                    "t": True,
                    "f": False,
                },
            ),
        ],
    )
    def test_parameters(self, raw, value, parameters):
        from decimal import Decimal

        parsed_value, parsed_parameters = http.parse_structured_item(raw)
        assert parsed_parameters == parameters
        assert list(parsed_parameters) == list(parameters)

        if isinstance(value, float):
            assert parsed_value == Decimal(str(value))
        else:
            assert parsed_value == value

    @pytest.mark.parametrize(
        "raw",
        [
            "",
            " ",
            "1 2",
            "1;",
            "1; a=",
            "1; 1a=2",
            "1; a=1; a=2",
            "?2",
            "?",
            "-",
            "1.",
            "1.1234",
            "1000000000000000",
            "-1000000000000000",
            "9999999999999999",
            "1234567890123.0",
            "12.1234567890123",
            "1, 2",
            "[1]",
            "'string'",
            '"unclosed',
            '"bad\\a"',
            '"é"',
            ":unclosed",
            ":",
            ":YWJ",
            ":YW=:",
            "(1 2)",
            "1;\tabc",
        ],
    )
    def test_invalid(self, raw):
        with pytest.raises(StructuredFieldParseError) as exc_info:
            http.parse_structured_item(raw)

        assert isinstance(exc_info.value.position, int)
        assert exc_info.value.position >= 0

    def test_error_position(self):
        with pytest.raises(StructuredFieldParseError) as exc_info:
            http.parse_structured_item("1; a=?2")

        # "?" is at index 6, the bad boolean byte is at index 7.
        assert exc_info.value.position == 7

        with pytest.raises(StructuredFieldParseError) as exc_info:
            http.parse_structured_item('"abc" extra')

        assert exc_info.value.position == 6

    def test_leading_and_trailing_ows(self):
        assert http.parse_structured_item("  1\t") == (1, {})

    def test_number_bounds(self):
        from decimal import Decimal

        assert http.parse_structured_item("999999999999999")[0] == 999999999999999
        assert http.parse_structured_item("-999999999999999")[0] == -999999999999999
        assert http.parse_structured_item("999999999999.999")[0] == Decimal(
            "999999999999.999"
        )
        assert http.parse_structured_item("-999999999999.999")[0] == Decimal(
            "-999999999999.999"
        )

        for raw in (
            "1000000000000000",
            "-1000000000000000",
            "1234567890123.0",
            "1.1234",
        ):
            with pytest.raises(StructuredFieldParseError):
                http.parse_structured_item(raw)

    def test_negative_zero_is_canonical(self):
        from decimal import Decimal

        assert http.serialize_structured_item(Decimal("-0.0")) == "0.0"


class TestParseList:
    @pytest.mark.parametrize(
        ("raw", "expected"),
        [
            ("", []),
            ("  \t ", []),
            ("1", [(1, {})]),
            ("1,  2", [(1, {}), (2, {})]),
            ("\t1, 2\t", [(1, {}), (2, {})]),
            (
                '1, 4.5, "hello", foo, ?0, :YWJj:',
                [
                    (1, {}),
                    (4.5, {}),
                    ("hello", {}),
                    (Token("foo"), {}),
                    (False, {}),
                    (b"abc", {}),
                ],
            ),
            (
                '("foo" "bar")',
                [([("foo", {}), ("bar", {})], {})],
            ),
            ("(1)", [([(1, {})], {})]),
            ("(1  )", [([(1, {})], {})]),
            (
                "(1 2); a=1, (3 4); b=?1",
                [
                    ([(1, {}), (2, {})], {"a": 1}),
                    ([(3, {}), (4, {})], {"b": True}),
                ],
            ),
            (
                "foo;a=1;b=2, ()",
                [(Token("foo"), {"a": 1, "b": 2}), ([], {})],
            ),
        ],
    )
    def test_examples(self, raw, expected):
        from decimal import Decimal

        result = http.parse_structured_list(raw)

        def normalize(value):
            if isinstance(value, float):
                return Decimal(str(value))

            if isinstance(value, tuple):
                return tuple(normalize(part) for part in value)

            if isinstance(value, list):
                return [normalize(part) for part in value]

            if isinstance(value, dict):
                return {key: normalize(item) for key, item in value.items()}

            return value

        assert normalize(result) == normalize(expected)

    @pytest.mark.parametrize(
        "raw",
        [
            "1,",
            "1,,2",
            "1,2",
            "(1",
            "(1,,2)",
            "(1\t2)",
            "(;a=1)",
            "1; a=1 2",
            "1, (1 2) extra",
        ],
    )
    def test_invalid(self, raw):
        with pytest.raises(StructuredFieldParseError) as exc_info:
            http.parse_structured_list(raw)

        assert isinstance(exc_info.value.position, int)


class TestParseDictionary:
    @pytest.mark.parametrize(
        ("raw", "expected"),
        [
            ("", {}),
            (
                'abc=1.23, d="x", ef, *g=?1',
                {
                    "abc": (1.23, {}),
                    "d": ("x", {}),
                    "ef": (True, {}),
                    "*g": (True, {}),
                },
            ),
            (
                "a=(1 2); q=1, b, c=2",
                {
                    "a": ([(1, {}), (2, {})], {"q": 1}),
                    "b": (True, {}),
                    "c": (2, {}),
                },
            ),
        ],
    )
    def test_examples(self, raw, expected):
        from decimal import Decimal

        result = http.parse_structured_dictionary(raw)
        assert list(result) == list(expected)

        for key, member in expected.items():
            if isinstance(member[0], float):
                assert result[key][0] == Decimal(str(member[0]))
            else:
                assert result[key] == member

    @pytest.mark.parametrize(
        "raw",
        [
            "a=1, a=2",
            "a=1; b=1; b=2",
            "1",
            "a=",
            "a=1,",
            "a=(1 2) extra",
        ],
    )
    def test_invalid(self, raw):
        with pytest.raises(StructuredFieldParseError) as exc_info:
            http.parse_structured_dictionary(raw)

        assert isinstance(exc_info.value.position, int)

    def test_duplicate_key_position(self):
        with pytest.raises(StructuredFieldParseError) as exc_info:
            http.parse_structured_dictionary("a=1, a=2")

        assert exc_info.value.position == 6


class TestSerialize:
    @pytest.mark.parametrize(
        ("value", "expected"),
        [
            (True, "?1"),
            (False, "?0"),
            (42, "42"),
            (-42, "-42"),
            (999999999999999, "999999999999999"),
            ("hello", '"hello"'),
            ('a"b\\c', '"a\\"b\\\\c"'),
            (Token("x-token.1"), "x-token.1"),
            (b"abc", ":YWJj:"),
        ],
    )
    def test_bare_items(self, value, expected):
        assert http.serialize_structured_item(value) == expected

    @pytest.mark.parametrize(
        ("value", "expected"),
        [
            ("1.0", "1.0"),
            ("1.50", "1.50"),
            ("1.500", "1.500"),
            ("-0.25", "-0.25"),
            ("100", "100.0"),
            ("-0", "0.0"),
            ("999999999999.999", "999999999999.999"),
        ],
    )
    def test_decimal_exact(self, value, expected):
        from decimal import Decimal

        assert http.serialize_structured_item(Decimal(value)) == expected

    def test_item_with_parameters(self):
        from decimal import Decimal

        item = (Token("foo"), {"a": True, "b": False, "c": Decimal("1.5")})
        assert http.serialize_structured_item(item) == "foo; a=?1; b=?0; c=1.5"

    def test_list_and_inner_list(self):
        members = [
            (1, {"q": True}),
            (Token("x"), {}),
            ([("a", {}), ("b", {})], {"p": 1}),
        ]
        assert http.serialize_structured_list(members) == '1; q=?1, x, ("a" "b"); p=1'
        assert http.serialize_structured_list([]) == ""
        assert http.serialize_structured_dictionary({}) == ""

    def test_dictionary(self):
        members = {
            "a": (1, {"q": True}),
            "b": True,
            "c": ([(1, {}), (2, {})], {}),
            "d": Token("x"),
        }
        assert (
            http.serialize_structured_dictionary(members)
            == "a=1; q=?1, b, c=(1 2), d=x"
        )

    def test_order_is_preserved(self):
        members = {"z": (1, {}), "a": (2, {}), "m": (3, {})}
        assert http.serialize_structured_dictionary(members) == "z=1, a=2, m=3"

        item = (1, {"z": True, "a": True, "m": True})
        assert http.serialize_structured_item(item) == "1; z=?1; a=?1; m=?1"

    @pytest.mark.parametrize(
        "value",
        [
            1.5,
            10**15,
            -(10**15),
            None,
            [1],
            {"a": 1},
            (1,),
            (1, [], {}),
            Token("1bad"),
            Token("bad token"),
            "caf\u00e9",
            "\x00",
        ],
    )
    def test_invalid_items(self, value):
        with pytest.raises(StructuredFieldSerializeError):
            http.serialize_structured_item(value)

    def test_invalid_decimal(self):
        from decimal import Decimal

        for value in (
            "1.1234",
            "1000000000000",
            "NaN",
            "Infinity",
        ):
            with pytest.raises(StructuredFieldSerializeError):
                http.serialize_structured_item(Decimal(value))

    def test_invalid_parameter_value(self):
        with pytest.raises(StructuredFieldSerializeError):
            http.serialize_structured_item((1, {"a": [1, 2]}))

        with pytest.raises(StructuredFieldSerializeError):
            http.serialize_structured_item((1, ("a", 1)))

    @pytest.mark.parametrize(
        ("members", "bad_key"),
        [
            ({"1": (1, {})}, "1"),
            ({"a b": (1, {})}, "a b"),
        ],
    )
    def test_invalid_dictionary(self, members, bad_key):
        with pytest.raises(StructuredFieldSerializeError) as exc_info:
            http.serialize_structured_dictionary(members)

        assert bad_key in str(exc_info.value)


class TestRoundTrip:
    @pytest.mark.parametrize(
        "raw",
        [
            "?1",
            "?0",
            "-999999999999999",
            "999999999999999",
            "4.5",
            "-1.001",
            ":YWJjZA==:",
            '"a \\" b"',
            "foo_1.2",
            'foo; a=1.5; b=?1; c=:YWJj:; d="x"',
        ],
    )
    def test_item(self, raw):
        parsed = http.parse_structured_item(raw)
        assert http.serialize_structured_item(parsed) == raw

    @pytest.mark.parametrize(
        "raw",
        [
            "",
            "1, 2, 3",
            '1, "two", ?1, foo, 4.5, :YTo=:',
            '("a" "b"); q=1.5, (); empty=?0',
            '(1; x=?1 2; y="z"); p=-1',
        ],
    )
    def test_list(self, raw):
        parsed = http.parse_structured_list(raw)
        assert http.serialize_structured_list(parsed) == raw

    @pytest.mark.parametrize(
        "raw",
        [
            "",
            "a=1, b=2.5, c=?1",
            "a=?1, b=?1, c=?1",
            'a=("x" "y"); p=1, b=(1 -2); q=?0',
            "a=foo_1; v=1; t=?1",
        ],
    )
    def test_dictionary(self, raw):
        parsed = http.parse_structured_dictionary(raw)
        assert http.serialize_structured_dictionary(parsed) == raw

    def test_canonical_form(self):
        # Parsing accepts loose whitespace, serializing produces canonical form.
        assert (
            http.serialize_structured_list(
                http.parse_structured_list("1;  a=1;  b=2, ( 1  2 ); p=1")
            )
            == "1; a=1; b=2, (1 2); p=1"
        )


class TestHeadersStructured:
    def test_item_roundtrip(self):
        from decimal import Decimal

        headers = Headers()
        headers.set_item("X-Foo", Token("abc"), q=Decimal("1.5"), flag=True)
        assert headers["X-Foo"] == "abc; q=1.5; flag=?1"
        assert headers.get_item("x-foo") == (
            Token("abc"),
            {"q": Decimal("1.5"), "flag": True},
        )

    def test_set_item_tuple(self):
        headers = Headers()
        headers.set_item("X-Foo", (1, {"a": True}))
        assert headers["X-Foo"] == "1; a=?1"

        with pytest.raises(TypeError):
            headers.set_item("X-Foo", (1, {}), a=True)

    def test_missing(self):
        headers = Headers()
        assert headers.get_item("X-Foo") is None
        assert headers.get_item("X-Foo", "default") == "default"
        assert headers.get_list("X-Foo") == []
        assert headers.get_dictionary("X-Foo") == {}

    def test_list_combines_multiple_lines(self):
        headers = Headers()
        headers.add("X-List", "1, (2 3)")
        headers.add("X-List", "4; a=1, 5")

        assert headers.get_list("x-list") == [
            (1, {}),
            ([(2, {}), (3, {})], {}),
            (4, {"a": 1}),
            (5, {}),
        ]

        headers.set_list("X-List", [(1, {}), (2, {})])
        assert headers.getlist("X-List") == ["1, 2"]

    def test_dictionary_combines_multiple_lines(self):
        headers = Headers()
        headers.add("X-Dict", "a=1, b=2")
        headers.add("X-Dict", "c=(1 2)")

        assert headers.get_dictionary("x-dict") == {
            "a": (1, {}),
            "b": (2, {}),
            "c": ([(1, {}), (2, {})], {}),
        }

        headers.set_dictionary("X-Dict", {"a": (1, {})})
        assert headers.getlist("X-Dict") == ["a=1"]

    def test_dictionary_duplicate_across_lines(self):
        headers = Headers()
        headers.add("X-Dict", "a=1")
        headers.add("X-Dict", "a=2")

        with pytest.raises(StructuredFieldParseError):
            headers.get_dictionary("x-dict")

    def test_item_multiple_lines_is_error(self):
        headers = Headers()
        headers.add("X-Item", "1")
        headers.add("X-Item", "2")

        with pytest.raises(StructuredFieldParseError):
            headers.get_item("x-item")

    def test_invalid_line_does_not_fallback(self):
        headers = Headers()
        headers.add("X-List", "1,bad item")

        with pytest.raises(StructuredFieldParseError) as exc_info:
            headers.get_list("x-list")

        assert exc_info.value.position == 3

    def test_immutable(self):
        headers = EnvironHeaders({})

        with pytest.raises(TypeError):
            headers.set_item("X-Foo", 1)

        with pytest.raises(TypeError):
            headers.set_list("X-Foo", [])

        with pytest.raises(TypeError):
            headers.set_dictionary("X-Foo", {})

    def test_regular_header_api_still_works(self):
        headers = Headers()
        headers.add("X-Custom", "foo, bar")
        assert headers.getlist("X-Custom") == ["foo, bar"]
        headers.setlist("X-Custom", ["a", "b"])
        assert headers.getlist("X-Custom") == ["a", "b"]
