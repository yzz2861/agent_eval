import dataclasses
import functools
import json
import pprint
from pathlib import Path

import pytest
from webencodings import Encoding, lookup

from tinycss2 import (  # isort:skip
    parse_blocks_contents, parse_component_value_list, parse_declaration_list,
    parse_one_component_value, parse_one_declaration, parse_one_rule,
    parse_rule_list, parse_stylesheet, parse_stylesheet_bytes, serialize)
from tinycss2.limits import ResourceLimits  # isort:skip
from tinycss2.ast import (  # isort:skip
    AtKeywordToken, AtRule, Comment, CurlyBracketsBlock, Declaration,
    DimensionToken, FunctionBlock, HashToken, IdentToken, LiteralToken,
    NumberToken, ParenthesesBlock, ParseError, PercentageToken, QualifiedRule,
    SquareBracketsBlock, StringToken, UnicodeRangeToken, URLToken,
    WhitespaceToken)
from tinycss2.color3 import RGBA  # isort:skip
from tinycss2.color3 import parse_color as parse_color3  # isort:skip
from tinycss2.color4 import Color  # isort:skip
from tinycss2.color4 import parse_color as parse_color4  # isort:skip
from tinycss2.color5 import parse_color as parse_color5  # isort:skip
from tinycss2.nth import parse_nth, serialize_nth  # isort:skip


def generic(func):
    implementations = func()

    @functools.wraps(func)
    def run(value):
        repr(value)  # Test that this does not raise.
        return implementations[type(value)](value)
    return run


@generic
def to_json():
    def numeric(t):
        return [
            t.representation, t.value,
            'integer' if t.int_value is not None else 'number']
    return {
        type(None): lambda _: None,
        str: lambda s: s,
        int: lambda s: s,
        list: lambda li: [to_json(el) for el in li],
        tuple: lambda li: [to_json(el) for el in li],
        Encoding: lambda e: e.name,
        ParseError: lambda e: ['error', e.kind],

        Comment: lambda t: '/* … */',
        WhitespaceToken: lambda t: ' ',
        LiteralToken: lambda t: t.value,
        IdentToken: lambda t: ['ident', t.value],
        AtKeywordToken: lambda t: ['at-keyword', t.value],
        HashToken: lambda t: [
            'hash', t.value, 'id' if t.is_identifier else 'unrestricted'],
        StringToken: lambda t: ['string', t.value],
        URLToken: lambda t: ['url', t.value],
        NumberToken: lambda t: ['number', *numeric(t)],
        PercentageToken: lambda t: ['percentage', *numeric(t)],
        DimensionToken: lambda t: ['dimension', *numeric(t), t.unit],
        UnicodeRangeToken: lambda t: ['unicode-range', t.start, t.end],

        CurlyBracketsBlock: lambda t: ['{}', *to_json(t.content)],
        SquareBracketsBlock: lambda t: ['[]', *to_json(t.content)],
        ParenthesesBlock: lambda t: ['()', *to_json(t.content)],
        FunctionBlock: lambda t: ['function', t.name, *to_json(t.arguments)],

        Declaration: lambda d: ['declaration', d.name, to_json(d.value), d.important],
        AtRule: lambda r: [
            'at-rule', r.at_keyword, to_json(r.prelude), to_json(r.content)],
        QualifiedRule: lambda r: [
            'qualified rule', to_json(r.prelude), to_json(r.content)],

        RGBA: lambda v: [round(c, 6) for c in v],
        Color: lambda v: [
            v.space,
            [round(c, 6) for c in v.params],
            v.function_name,
            [None if arg is None else round(arg, 6) for arg in v.args],
            v.alpha,
        ],
    }


def load_json(filename):
    path = Path(__file__).parent / 'css-parsing-tests' / filename
    json_data = json.loads(path.read_text(encoding='utf-8'))
    return list(zip(json_data[::2], json_data[1::2]))


def json_test(filename=None):
    def decorator(function):
        filename_ = filename or function.__name__.split('_', 1)[-1] + '.json'

        @pytest.mark.parametrize(('css', 'expected'), load_json(filename_))
        def test(css, expected):
            value = to_json(function(css))
            if value != expected:  # pragma: no cover
                pprint.pprint(value)
                assert value == expected
        return test
    return decorator


SKIP = {'skip_comments': True, 'skip_whitespace': True}


@json_test()
def test_component_value_list(input):
    return parse_component_value_list(input, skip_comments=True)


@json_test()
def test_one_component_value(input):
    return parse_one_component_value(input, skip_comments=True)


@json_test()
def test_declaration_list(input):
    return parse_declaration_list(input, **SKIP)


@json_test()
def test_blocks_contents(input):
    return parse_blocks_contents(input, **SKIP)


@json_test()
def test_one_declaration(input):
    return parse_one_declaration(input, skip_comments=True)


@json_test()
def test_stylesheet(input):
    return parse_stylesheet(input, **SKIP)


@json_test()
def test_rule_list(input):
    return parse_rule_list(input, **SKIP)


@json_test()
def test_one_rule(input):
    return parse_one_rule(input, skip_comments=True)


@json_test(filename='An+B.json')
def test_nth(input):
    return parse_nth(input)


@pytest.mark.parametrize(('a', 'b', 'expected'), [
    (0, 0, '0'), (0, 1, '1'), (0, -2, '-2'), (1, 0, 'n'), (1, 3, 'n+3'), (1, -3, 'n-3'),
    (-1, 0, '-n'), (-1, 3, '-n+3'), (-1, -3, '-n-3'), (2, 0, '2n'), (2, 1, '2n+1'),
    (2, -4, '2n-4'), (-2, 0, '-2n'), (-2, 1, '-2n+1'), (-2, -4, '-2n-4'),
])
def test_serialize_nth(a, b, expected):
    assert serialize_nth(a, b) == expected
    assert parse_nth(expected) == (a, b)


@json_test(filename='An+B.json')
def test_round_trip_nth(input):
    if numbers := parse_nth(input):
        return parse_nth(serialize_nth(*numbers))


@pytest.mark.parametrize('invalid', ['+', '+/**/', 'n+', 'n +', '-n-', '2n +'])
def test_nth_invalid_does_not_crash(invalid):
    # Truncated/invalid An+B fragments must return None per parse_nth's
    # documented contract, not raise StopIteration or AttributeError.
    assert parse_nth(invalid) is None


def test_nth_leading_plus_whitespace_still_invalid():
    # The fix for the above must not make '+ n' (whitespace after a leading
    # '+') accidentally valid: only '+n' is a valid nth expression.
    assert parse_nth('+n') == (1, 0)
    assert parse_nth('+ n') is None


def _number(value):
    if value is None:
        return 'none'
    value = round(value + 0.0000001, 6)
    return str(int(value) if value.is_integer() else value)


def _build_color(color):
    if color is None:
        return
    (*coordinates, alpha) = color
    result = f'color({color.space}'
    for coordinate in coordinates:
        result += f' {_number(coordinate)}'
    if alpha != 1:
        result += f' / {_number(alpha)}'
    result += ')'
    return result


def test_color_currentcolor_3():
    for value in ('currentcolor', 'currentColor', 'CURRENTCOLOR'):
        assert parse_color3(value) == 'currentColor'


def test_color_currentcolor_4():
    for value in ('currentcolor', 'currentColor', 'CURRENTCOLOR'):
        assert parse_color4(value) == 'currentcolor'


def test_color_currentcolor_5():
    for value in ('currentcolor', 'currentColor', 'CURRENTCOLOR'):
        assert parse_color5(value) == 'currentcolor'


@json_test()
def test_color_function_4(input):
    return _build_color(parse_color4(input))


@json_test(filename='color_function_4.json')
def test_color_function_4_with_5(input):
    return _build_color(parse_color5(input))


@json_test()
def test_color_functions_5(input):
    if input.startswith('light-dark'):
        result = []
        result.append(_build_color(parse_color5(input, ('light',))))
        result.append(_build_color(parse_color5(input, ('dark',))))
    else:
        result = _build_color(parse_color5(input))
    return result


@json_test()
def test_color_hexadecimal_3(input):
    if not (color := parse_color3(input)):
        return None
    (*coordinates, alpha) = color
    result = f'rgb{"a" if alpha != 1 else ""}('
    result += f'{", ".join(_number(coordinate * 255) for coordinate in coordinates)}'
    if alpha != 1:
        result += f', {_number(alpha)}'
    result += ')'
    return result


@json_test(filename='color_hexadecimal_3.json')
def test_color_hexadecimal_3_with_4(input):
    if not (color := parse_color4(input)):
        return None
    (*coordinates, alpha) = color
    result = f'rgb{"a" if alpha != 1 else ""}('
    result += f'{", ".join(_number(coordinate * 255) for coordinate in coordinates)}'
    if alpha != 1:
        result += f', {_number(alpha)}'
    result += ')'
    return result


@json_test()
def test_color_hexadecimal_4(input):
    if not (color := parse_color4(input)):
        return None
    assert color.space == 'srgb'
    (*coordinates, alpha) = color
    result = f'rgb{"a" if alpha != 1 else ""}('
    result += f'{", ".join(_number(coordinate * 255) for coordinate in coordinates)}'
    if alpha != 1:
        result += f', {_number(alpha)}'
    result += ')'
    return result


@json_test(filename='color_hexadecimal_4.json')
def test_color_hexadecimal_4_with_5(input):
    if not (color := parse_color5(input)):
        return None
    assert color.space == 'srgb'
    (*coordinates, alpha) = color
    result = f'rgb{"a" if alpha != 1 else ""}('
    result += f'{", ".join(_number(coordinate * 255) for coordinate in coordinates)}'
    if alpha != 1:
        result += f', {_number(alpha)}'
    result += ')'
    return result


@json_test(filename='color_hexadecimal_3.json')
def test_color_hexadecimal_3_with_5(input):
    if not (color := parse_color5(input)):
        return None
    assert color.space == 'srgb'
    (*coordinates, alpha) = color
    result = f'rgb{"a" if alpha != 1 else ""}('
    result += f'{", ".join(_number(coordinate * 255) for coordinate in coordinates)}'
    if alpha != 1:
        result += f', {_number(alpha)}'
    result += ')'
    return result


@json_test()
def test_color_hsl_3(input):
    if not (color := parse_color3(input)):
        return None
    (*coordinates, alpha) = color
    result = f'rgb{"a" if alpha != 1 else ""}('
    result += f'{", ".join(_number(coordinate * 255) for coordinate in coordinates)}'
    if alpha != 1:
        result += f', {_number(alpha)}'
    result += ')'
    return result


@json_test(filename='color_hsl_3.json')
def test_color_hsl_3_with_4(input):
    if not (color := parse_color4(input)):
        return None
    assert color.space == 'hsl'
    (*coordinates, alpha) = color.to('srgb')
    result = f'rgb{"a" if alpha != 1 else ""}('
    result += f'{", ".join(_number(coordinate * 255) for coordinate in coordinates)}'
    if alpha != 1:
        result += f', {_number(alpha)}'
    result += ')'
    return result


@json_test(filename='color_hsl_3.json')
def test_color_hsl_3_with_5(input):
    if not (color := parse_color5(input)):
        return None
    assert color.space == 'hsl'
    (*coordinates, alpha) = color.to('srgb')
    result = f'rgb{"a" if alpha != 1 else ""}('
    result += f'{", ".join(_number(coordinate * 255) for coordinate in coordinates)}'
    if alpha != 1:
        result += f', {_number(alpha)}'
    result += ')'
    return result


@json_test()
def test_color_hsl_4(input):
    if not (color := parse_color4(input)):
        return None
    assert color.space == 'hsl'
    (*coordinates, alpha) = color.to('srgb')
    result = f'rgb{"a" if alpha != 1 else ""}('
    result += f'{", ".join(_number(coordinate * 255) for coordinate in coordinates)}'
    if alpha != 1:
        result += f', {_number(alpha)}'
    result += ')'
    return result


@json_test(filename='color_hsl_4.json')
def test_color_hsl_4_with_5(input):
    if not (color := parse_color5(input)):
        return None
    assert color.space == 'hsl'
    (*coordinates, alpha) = color.to('srgb')
    result = f'rgb{"a" if alpha != 1 else ""}('
    result += f'{", ".join(_number(coordinate * 255) for coordinate in coordinates)}'
    if alpha != 1:
        result += f', {_number(alpha)}'
    result += ')'
    return result


@json_test()
def test_color_hwb_4(input):
    if not (color := parse_color4(input)):
        return None
    assert color.space == 'hwb'
    (*coordinates, alpha) = color.to('srgb')
    result = f'rgb{"a" if alpha != 1 else ""}('
    result += f'{", ".join(_number(coordinate * 255) for coordinate in coordinates)}'
    if alpha != 1:
        result += f', {_number(alpha)}'
    result += ')'
    return result


@json_test(filename='color_hwb_4.json')
def test_color_hwb_4_with_5(input):
    if not (color := parse_color5(input)):
        return None
    assert color.space == 'hwb'
    (*coordinates, alpha) = color.to('srgb')
    result = f'rgb{"a" if alpha != 1 else ""}('
    result += f'{", ".join(_number(coordinate * 255) for coordinate in coordinates)}'
    if alpha != 1:
        result += f', {_number(alpha)}'
    result += ')'
    return result


@json_test()
def test_color_keywords_3(input):
    if not (color := parse_color3(input)):
        return None
    elif isinstance(color, str):
        return color
    (*coordinates, alpha) = color
    result = f'rgb{"a" if alpha != 1 else ""}('
    result += f'{", ".join(_number(coordinate * 255) for coordinate in coordinates)}'
    if alpha != 1:
        result += f', {_number(alpha)}'
    result += ')'
    return result


@json_test(filename='color_keywords_3.json')
def test_color_keywords_3_with_4(input):
    if not (color := parse_color4(input)):
        return None
    elif isinstance(color, str):
        return color
    assert color.space == 'srgb'
    (*coordinates, alpha) = color
    result = f'rgb{"a" if alpha != 1 else ""}('
    result += f'{", ".join(_number(coordinate * 255) for coordinate in coordinates)}'
    if alpha != 1:
        result += f', {_number(alpha)}'
    result += ')'
    return result


@json_test(filename='color_keywords_3.json')
def test_color_keywords_3_with_5(input):
    if not (color := parse_color5(input)):
        return None
    elif isinstance(color, str):
        return color
    assert color.space == 'srgb'
    (*coordinates, alpha) = color
    result = f'rgb{"a" if alpha != 1 else ""}('
    result += f'{", ".join(_number(coordinate * 255) for coordinate in coordinates)}'
    if alpha != 1:
        result += f', {_number(alpha)}'
    result += ')'
    return result


@json_test()
def test_color_keywords_4(input):
    if not (color := parse_color4(input)):
        return None
    elif isinstance(color, str):
        return color
    assert color.space == 'srgb'
    (*coordinates, alpha) = color
    result = f'rgb{"a" if alpha != 1 else ""}('
    result += f'{", ".join(_number(coordinate * 255) for coordinate in coordinates)}'
    if alpha != 1:
        result += f', {_number(alpha)}'
    result += ')'
    return result


@json_test(filename='color_keywords_4.json')
def test_color_keywords_4_with_5(input):
    if not (color := parse_color5(input)):
        return None
    elif isinstance(color, str):
        return color
    assert color.space == 'srgb'
    (*coordinates, alpha) = color
    result = f'rgb{"a" if alpha != 1 else ""}('
    result += f'{", ".join(_number(coordinate * 255) for coordinate in coordinates)}'
    if alpha != 1:
        result += f', {_number(alpha)}'
    result += ')'
    return result


@json_test()
def test_color_lab_4(input):
    if not (color := parse_color4(input)):
        return None
    elif isinstance(color, str):
        return color
    assert color.space == 'lab'
    (*coordinates, alpha) = color
    result = f'{color.space}('
    result += f'{" ".join(_number(coordinate) for coordinate in coordinates)}'
    if alpha != 1:
        result += f' / {_number(alpha)}'
    result += ')'
    return result


@json_test(filename='color_lab_4.json')
def test_color_lab_4_with_5(input):
    if not (color := parse_color5(input)):
        return None
    elif isinstance(color, str):
        return color
    assert color.space == 'lab'
    (*coordinates, alpha) = color
    result = f'{color.space}('
    result += f'{" ".join(_number(coordinate) for coordinate in coordinates)}'
    if alpha != 1:
        result += f' / {_number(alpha)}'
    result += ')'
    return result


@json_test()
def test_color_oklab_4(input):
    if not (color := parse_color4(input)):
        return None
    elif isinstance(color, str):
        return color
    assert color.space == 'oklab'
    (*coordinates, alpha) = color
    result = f'{color.space}('
    result += f'{" ".join(_number(coordinate) for coordinate in coordinates)}'
    if alpha != 1:
        result += f' / {_number(alpha)}'
    result += ')'
    return result


@json_test(filename='color_oklab_4.json')
def test_color_oklab_4_with_5(input):
    if not (color := parse_color5(input)):
        return None
    elif isinstance(color, str):
        return color
    assert color.space == 'oklab'
    (*coordinates, alpha) = color
    result = f'{color.space}('
    result += f'{" ".join(_number(coordinate) for coordinate in coordinates)}'
    if alpha != 1:
        result += f' / {_number(alpha)}'
    result += ')'
    return result


@json_test()
def test_color_lch_4(input):
    if not (color := parse_color4(input)):
        return None
    elif isinstance(color, str):
        return color
    assert color.space == 'lch'
    (*coordinates, alpha) = color
    result = f'{color.space}('
    result += f'{" ".join(_number(coordinate) for coordinate in coordinates)}'
    if alpha != 1:
        result += f' / {_number(alpha)}'
    result += ')'
    return result


@json_test(filename='color_lch_4.json')
def test_color_lch_4_with_5(input):
    if not (color := parse_color5(input)):
        return None
    elif isinstance(color, str):
        return color
    assert color.space == 'lch'
    (*coordinates, alpha) = color
    result = f'{color.space}('
    result += f'{" ".join(_number(coordinate) for coordinate in coordinates)}'
    if alpha != 1:
        result += f' / {_number(alpha)}'
    result += ')'
    return result


@json_test()
def test_color_oklch_4(input):
    if not (color := parse_color4(input)):
        return None
    elif isinstance(color, str):
        return color
    assert color.space == 'oklch'
    (*coordinates, alpha) = color
    result = f'{color.space}('
    result += f'{" ".join(_number(coordinate) for coordinate in coordinates)}'
    if alpha != 1:
        result += f' / {_number(alpha)}'
    result += ')'
    return result


@json_test(filename='color_oklch_4.json')
def test_color_oklch_4_with_5(input):
    if not (color := parse_color5(input)):
        return None
    elif isinstance(color, str):
        return color
    assert color.space == 'oklch'
    (*coordinates, alpha) = color
    result = f'{color.space}('
    result += f'{" ".join(_number(coordinate) for coordinate in coordinates)}'
    if alpha != 1:
        result += f' / {_number(alpha)}'
    result += ')'
    return result


@json_test()
def test_stylesheet_bytes(kwargs):
    kwargs['css_bytes'] = kwargs['css_bytes'].encode('latin1')
    kwargs.pop('comment', None)
    if kwargs.get('environment_encoding'):
        kwargs['environment_encoding'] = lookup(kwargs['environment_encoding'])
    kwargs.update(SKIP)
    return parse_stylesheet_bytes(**kwargs)


@json_test(filename='component_value_list.json')
def test_serialization(css):
    parsed = parse_component_value_list(css, skip_comments=True)
    return parse_component_value_list(serialize(parsed), skip_comments=True)


def test_skip():
    source = '''
    /* foo */
    @media print {
        #foo {
            width: /* bar*/4px;
            color: green;
        }
    }
    '''
    no_ws = parse_stylesheet(source, skip_whitespace=True)
    no_comment = parse_stylesheet(source, skip_comments=True)
    default = parse_component_value_list(source)
    assert serialize(no_ws) != source
    assert serialize(no_comment) != source
    assert serialize(default) == source


def test_comment_eof():
    source = '/* foo '
    parsed = parse_component_value_list(source)
    assert serialize(parsed) == '/* foo */'


def test_parse_declaration_value_color():
    source = 'color:#369'
    declaration = parse_one_declaration(source)
    (value_token,) = declaration.value
    assert parse_color3(value_token) == (.2, .4, .6, 1)
    assert parse_color4(value_token) == (.2, .4, .6, 1)
    assert declaration.serialize() == source


def test_serialize_rules():
    source = '@import "a.css"; foo#bar.baz { color: red } /**/ @media print{}'
    rules = parse_rule_list(source)
    assert serialize(rules) == source


def test_serialize_declarations():
    source = 'color: #123; /**/ @top-left {} width:7px !important;'
    rules = parse_blocks_contents(source)
    assert serialize(rules) == source


def test_serialize_rules_with_functions():
    source = '''
        foo#bar.baz {
            background: url();
            color: rgb(0, 0, 0);
            width: calc(calc());
            height: calc(calc(calc()));
        }
    '''
    rules = parse_rule_list(source)
    assert serialize(rules) == source


@pytest.mark.parametrize('source', ['1\\65 2', '34\\45 56a'])
def test_serialize_e_in_unit(source):
    rules = parse_component_value_list(source)
    assert serialize(rules) == source.replace('\\45', '\\65')


def test_backslash_delim():
    source = '\\\nfoo'
    tokens = parse_component_value_list(source)
    assert [t.type for t in tokens] == ['literal', 'whitespace', 'ident']
    assert tokens[0].value == '\\'
    del tokens[1]
    assert [t.type for t in tokens] == ['literal', 'ident']
    assert serialize(tokens) == source


def test_escape_in_at_rule():
    at_rule, = parse_rule_list('@\udca9')
    assert at_rule.type == 'at-rule'
    assert at_rule.at_keyword == '\udca9'


def test_escape_in_ident():
    declaration = parse_one_declaration('background:\udca9')
    assert declaration.type == 'declaration'
    value, = declaration.value
    assert value.value == '\udca9'


def test_escape_in_dimension_token():
    dimension, = parse_component_value_list('0\\dddf')
    assert dimension.type == 'dimension'
    assert dimension.int_value == 0
    assert dimension.unit == '\udddf'


def test_escape_in_function_name():
    function, = parse_component_value_list('\\dddf()')
    assert function.type == 'function'
    assert function.name == '\udddf'


def _walk(nodes):
    for node in nodes:
        yield node
        for attr in ('content', 'arguments'):
            if hasattr(node, attr):
                yield from _walk(getattr(node, attr))


def _errors(nodes):
    return [node for node in _walk(nodes) if node.type == 'error']


def test_resource_limits_validation():
    assert ResourceLimits() == ResourceLimits(None, None, None, None, None)
    for kwargs in (
            {'max_characters': 0},
            {'max_token_bytes': -1},
            {'max_nesting': ResourceLimits.ABSOLUTE_MAX_NESTING + 1},
            {'max_consecutive_escapes': '100'},
            {'max_tokens': True},
            {'max_characters': 1.5}):
        with pytest.raises(ValueError):
            ResourceLimits(**kwargs)
    # Values up to the absolute maximum are accepted.
    limits = ResourceLimits(
        max_characters=ResourceLimits.ABSOLUTE_MAX_CHARACTERS,
        max_token_bytes=ResourceLimits.ABSOLUTE_MAX_TOKEN_BYTES,
        max_nesting=ResourceLimits.ABSOLUTE_MAX_NESTING,
        max_consecutive_escapes=(
            ResourceLimits.ABSOLUTE_MAX_CONSECUTIVE_ESCAPES),
        max_tokens=ResourceLimits.ABSOLUTE_MAX_TOKENS)
    assert limits.max_nesting == ResourceLimits.ABSOLUTE_MAX_NESTING
    with pytest.raises(TypeError):
        parse_component_value_list('a', limits={'max_tokens': 1})


def test_input_too_long_reports_position_one():
    limits = ResourceLimits(max_characters=4)
    errors = _errors(parse_component_value_list('abcdef', limits=limits))
    assert len(errors) == 1
    assert errors[0].kind == 'input-too-long'
    assert (errors[0].source_line, errors[0].source_column) == (1, 1)


def test_token_too_long_identifier_and_position():
    limits = ResourceLimits(max_token_bytes=4)
    tokens = parse_component_value_list('aa aaaaaa', limits=limits)
    error, = _errors(tokens)
    assert error.kind == 'token-too-long'
    # The oversized identifier starts on column 4 (after "aa ").
    assert (error.source_line, error.source_column) == (1, 4)
    # The small identifier before the failure is preserved.
    assert tokens[0].type == 'ident'


def test_token_too_long_unclosed_string():
    limits = ResourceLimits(max_token_bytes=8)
    tokens = parse_component_value_list('"' + 'x' * 100, limits=limits)
    error, = _errors(tokens)
    assert error.kind == 'token-too-long'
    assert (error.source_line, error.source_column) == (1, 1)


def test_token_too_long_url_and_quoted_url():
    limits = ResourceLimits(max_token_bytes=16)
    tokens = parse_component_value_list(
        'url(data:text/plain,' + 'A' * 100 + ')', limits=limits)
    assert [e.kind for e in _errors(tokens)] == ['token-too-long']
    quoted = parse_component_value_list(
        'url("' + 'B' * 100 + '")', limits=limits)
    assert [e.kind for e in _errors(quoted)] == ['token-too-long']


def test_nesting_limit_blocks_reports_deepest_position():
    limits = ResourceLimits(max_nesting=2)
    tokens = parse_component_value_list('{ [ ( x', limits=limits)
    error, = _errors(tokens)
    assert error.kind == 'nesting-too-deep'
    # '(' is the third opener, at column 5.
    assert (error.source_line, error.source_column) == (1, 5)


def test_nesting_limit_deep_comment():
    limits = ResourceLimits(max_nesting=3)
    css = '/*' + '/*' * 10 + '*/'
    tokens = parse_component_value_list(css, limits=limits)
    error, = _errors(tokens)
    assert error.kind == 'nesting-too-deep'
    assert (error.source_line, error.source_column) == (1, 1)
    # A comment within the budget is still parsed.
    assert parse_component_value_list(
        '/* a /* b */', limits=limits)[0].type == 'comment'


def test_consecutive_escapes_limited_in_ident_and_string():
    limits = ResourceLimits(max_consecutive_escapes=3)
    ident_errors = _errors(
        parse_component_value_list(r'\a ' * 10, limits=limits))
    assert [e.kind for e in ident_errors] == ['too-many-escapes']
    string_errors = _errors(
        parse_component_value_list('"' + r'\a ' * 10, limits=limits))
    assert [e.kind for e in string_errors] == ['too-many-escapes']


def test_token_count_limited():
    limits = ResourceLimits(max_tokens=3)
    tokens = parse_component_value_list('a b c d e', limits=limits)
    error, = _errors(tokens)
    assert error.kind == 'too-many-tokens'
    # The error replaces the 4th token, at the position where the budget
    # was exhausted.
    assert (error.source_line, error.source_column) == (1, 4)


def test_budgets_are_not_shared_between_parses():
    limits = ResourceLimits(max_tokens=20, max_token_bytes=100)
    first = parse_component_value_list('a b c d', limits=limits)
    second = parse_component_value_list('w x y z', limits=limits)
    assert _errors(first) == []
    assert _errors(second) == []
    assert [t.type for t in first] == ['ident', 'whitespace', 'ident',
                                       'whitespace', 'ident', 'whitespace',
                                       'ident']


def test_limits_apply_through_parser_and_bytes_apis():
    limits = ResourceLimits(max_characters=2)
    tokenizer_error, = _errors(
        parse_component_value_list('abc', limits=limits))
    assert tokenizer_error.kind == 'input-too-long'
    error = parse_one_declaration('abc', limits=limits)
    assert error.type == 'error'
    rules, encoding = parse_stylesheet_bytes(
        'abc'.encode('ascii'), limits=limits)
    assert rules[0].type == 'error'
    assert encoding.name == 'utf-8'


def test_legitimate_large_data_uri_accepted_by_defaults():
    # A 1 MB base64 data URI is a single URL token and must not trip the
    # default per-token budget.
    css = 'background:url(data:image/png;base64,' + 'A' * 1_000_000 + ')'
    tokens = parse_component_value_list(css)
    assert _errors(tokens) == []
    url_token = next(node for node in _walk(tokens) if node.type == 'url')
    assert len(url_token.value.encode('utf-8')) > 1_000_000


def test_raised_limits_allow_larger_inputs():
    css = 'x' * 10_000
    assert _errors(parse_component_value_list(
        css, limits=ResourceLimits(max_token_bytes=50)))
    assert _errors(parse_component_value_list(
        css, limits=ResourceLimits(max_token_bytes=50_000))) == []


def test_limits_are_inclusive_and_count_utf8_bytes():
    # Input exactly at the character limit is accepted.
    assert parse_component_value_list(
        'ab', limits=ResourceLimits(max_characters=2))[0].type == 'ident'
    # Each e-acute is 2 UTF-8 bytes: 4 chars == 8 bytes is accepted.
    assert _errors(parse_component_value_list(
        '\u00e9' * 4, limits=ResourceLimits(max_token_bytes=8))) == []
    errors = _errors(parse_component_value_list(
        '\u00e9' * 5, limits=ResourceLimits(max_token_bytes=8)))
    assert [e.kind for e in errors] == ['token-too-long']


def test_comment_limits_apply_even_when_comments_skipped():
    errors = _errors(parse_component_value_list(
        '/*' + '/*' * 200, skip_comments=True,
        limits=ResourceLimits(max_nesting=5)))
    assert [e.kind for e in errors] == ['nesting-too-deep']


def test_resource_limits_are_frozen():
    with pytest.raises(dataclasses.FrozenInstanceError):
        ResourceLimits().max_tokens = 1


@pytest.mark.parametrize('css', [
    '"' + 'a' * 50_000,                 # unclosed string
    '/*' + 'a' * 50_000,                # unclosed comment
    'a' * 50_000,                       # long identifier
    '"' + '\\"' * 25_000,              # escaped quotes in a string
    '{' * 10_000,                       # unclosed nested blocks
    'a(' * 10_000,                      # unclosed functions
])
def test_pathological_inputs_finish_in_linear_time(css):
    # The point of the test is the hard timeout rather than a tight bound:
    # a quadratic implementation would blow past it on these inputs.
    parse_component_value_list(css)
