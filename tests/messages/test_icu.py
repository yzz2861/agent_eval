#
# Copyright (C) 2026 the Babel team
# All rights reserved.
#
# This software is licensed as described in the file LICENSE, which
# you should have received as part of this distribution. The terms
# are also available at https://github.com/python-babel/babel/blob/master/LICENSE.
#
import pytest

from babel.messages import icu
from babel.messages.icu import IcuSyntaxError, compare, parse


def _names(pattern):
    return {arg.name: arg.kind for arg in parse(pattern).arguments}


@pytest.mark.parametrize(
    'pattern',
    [
        'Hello world',
        'Hello {name}!',
        '{count, number}',
        '{count, number, :: percent}',
        '{when, date, short}',
        "It is {time, time, ''o''clock''}",
        '{count, plural, one {# apple} other {# apples}}',
        '{count, plural, offset:1 =0 {no apples} one {# apple} other {# apples}}',
        '{count, plural, offset: 1 =0 {no apples} other {# apples}}',
        '{n, selectordinal, one {#st} two {#nd} few {#rd} other {#th}}',
        '{gender, select, female {her} male {him} other {them}}',
        # nested arguments, including a plural inside a plural
        ('{count, plural, other {{inner, plural, '
         'one {# inner} other {# inners}} for #}}'),
        # '#' inside a select branch nested in a plural refers to the plural
        '{count, plural, one {{g, select, other {#}}} other {x}}',
        # repeated use of the same argument
        '{a} and {a} and {a, number}',
        # apostrophe edge cases
        "It's a nice day",
        "''",
        "'{' '}' '#' \"'\"",
        "don''t worry, '{curly}' is literal",
        "a '#' inside quotes is not special",
    ],
)
def test_parse_valid(pattern):
    parse(pattern)


@pytest.mark.parametrize(
    ('pattern', 'message'),
    [
        ('{count, plural, one {# apple}}', "'other'"),
        ('{g, select, female {x}}', "'other'"),
        ('# not in plural', "'#'"),
        ('{g, select, other {#}}', "'#'"),
        ('{n, selectordinal, weird {#} other {#}}', 'invalid plural keyword'),
        ('{n, plural, =x {x} other {y}}', 'invalid explicit plural selector'),
        ('{n, plural, one {#} one {#} other {#}}', 'duplicate selector'),
        ('{n, plural, one {#} offset:2 other {#}}', 'must precede'),
        ('{n, plural, offset:1 offset:2 other {#}}', "duplicate 'offset:'"),
        ('{n, select, offset:1 other {x}}', 'offset'),
        ('{n, plural, offset:x other {#}}', 'invalid offset value'),
        ('{n, plural, other {', 'unclosed'),
        ('{n, plural,}', 'at least one branch'),
        ('{n, plural other {x}}', 'expected'),
        ('{n, number, {x}}', 'simple argument style'),
        ('{n, plural, other {x}', 'unclosed argument'),
        ("'{ unterminated", 'unterminated quoted section'),
        ('{, plural, other {x}}', 'missing argument name'),
        ('hello } world', "unexpected '}'"),
        ('{a}}', "unexpected '}'"),
    ],
)
def test_parse_invalid(pattern, message):
    with pytest.raises(IcuSyntaxError, match=message):
        parse(pattern)


def test_argument_paths():
    result = parse(
        '{count, plural, one {{gender, select, other {{name}}}} other {x}}',
    )
    paths = {arg.name: arg.path for arg in result.arguments}
    assert paths['count'] == ('count',)
    assert paths['gender'] == ('count', 'one', 'gender')
    assert paths['name'] == ('count', 'one', 'gender', 'other')


def test_location_tracks_line_and_column():
    pattern = '{a, plural, other {#}}' + chr(10) + '# bad'
    with pytest.raises(IcuSyntaxError) as exc_info:
        parse(pattern)
    assert exc_info.value.location.line == 2
    assert exc_info.value.location.column == 1


def test_conflicting_argument_kinds_within_one_pattern():
    with pytest.raises(IcuSyntaxError, match='conflicting types'):
        parse('{a, plural, other {{a, select, other {x}}}}')


@pytest.mark.parametrize(
    ('source', 'translation'),
    [
        # identical text
        (
            '{count, plural, one {# apple} other {# apples}}',
            '{count, plural, one {# apfel} other {# apfel}}',
        ),
        # target language adds a plural category and explicit selectors
        (
            '{count, plural, one {# apple} other {# apples}}',
            '{count, plural, one {#} two {#} few {#} many {#} other {#}}',
        ),
        # different branch texts are fine; selectors may differ per language
        (
            '{g, select, en {Hi} other {Hello}}',
            '{g, select, female {Liebe} male {Lieber} other {Hallo}}',
        ),
        # arguments may be dropped, reordered and repeated
        ('{a} {b}', '{b}{b}{b}'),
        ('{a, plural, other {{b}}}', '{a, plural, other {x}}'),
        # bare arg vs typed simple arg are both "simple"
        ('{count}', '{count, number}'),
        ('{count, number}', '{count}'),
        # selectordinal kept across languages
        (
            '{n, selectordinal, one {#st} other {#th}}',
            '{n, selectordinal, few {#e} other {#e}}',
        ),
    ],
)
def test_compare_compatible(source, translation):
    assert compare(source, translation) == []


@pytest.mark.parametrize(
    ('source', 'translation', 'message'),
    [
        # unknown argument in translation
        (
            '{count, plural, other {#}}',
            '{count, plural, other {#}} {extra}',
            'unknown argument',
        ),
        # structural kind mismatch
        (
            '{g, select, other {x}}',
            '{g, plural, other {#}}',
            'incompatible kind',
        ),
        (
            '{n, plural, other {#}}',
            '{n, selectordinal, other {#}}',
            'incompatible kind',
        ),
        # malformed translation (missing 'other')
        (
            '{count, plural, other {#}}',
            '{count, plural, one {#}}',
            "'other'",
        ),
        # malformed source is reported too
        (
            '{count, plural, one {#}}',
            '{count, plural, other {#}}',
            "'other'",
        ),
    ],
)
def test_compare_incompatible(source, translation, message):
    errors = compare(source, translation)
    assert errors
    assert any(message in str(error) for error in errors)


def test_compare_error_includes_path_and_location():
    errors = compare(
        '{a, plural, other {{b, select, other {x}}}}',
        '{a, plural, other {{b, plural, other {#}}}}',
    )
    assert len(errors) == 1
    error = errors[0]
    assert error.path == ('a', 'other', 'b')
    assert error.location is not None
    assert 'parameter path: a.other.b' in str(error)
    assert 'line 1, column' in str(error)


def test_quoted_hash_is_not_special():
    names = _names("'{#}' and {x}")
    assert names == {'x': icu.SIMPLE}


def test_quoted_braces_are_literal():
    names = _names("'{nested}' {real}")
    assert names == {'real': icu.SIMPLE}
