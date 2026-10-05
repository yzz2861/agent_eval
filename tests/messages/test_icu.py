from io import BytesIO

import pytest

from babel.messages import Catalog, Message, icu
from babel.messages.catalog import TranslationError
from babel.messages.checkers import icu_format
from babel.messages.pofile import read_po, write_po


VALID_MESSAGES = [
    ('{name}', '{name}'),
    ('{count, number, percent}', '{count, number, integer}'),
    (
        '{count, plural, offset:1 =0 {no items} one {# item} other {# items}}',
        '{count, plural, offset:1 zero {#} one {#} few {#} many {#} other {#}}',
    ),
    (
        '{count, selectordinal, one {#st} two {#nd} few {#rd} other {#th}}',
        '{count, selectordinal, one {#re} two {#de} other {#e}}',
    ),
    (
        '{gender, select, female {Hello {her_name}} male {Hello {him_name}} '
        'other {Hello {name}}}',
        '{gender, select, female {{name} さん} other {{name}}} ',
    ),
    (
        "{count, plural, one {{gender, select, female {# her} other {#}}} other {#}}",
        "{count, plural, few {{gender, select, female {# ihr} other {#}}} other {#}}",
    ),
]


@pytest.mark.parametrize(('original', 'translation'), VALID_MESSAGES)
def test_valid_icu_messages(original, translation):
    icu.validate_translation(original, translation)


@pytest.mark.parametrize(
    ('text', 'message'),
    [
        ('{name', 'Expected closing brace'),
        ('name}', 'Unexpected closing brace'),
        ('{, number}', 'Missing argument name'),
        ('{name bogus}', 'Expected comma or closing brace'),
        ('{count, plural, one {#}}', "Missing required 'other' branch"),
        ('{count, select, male {x}}', "Missing required 'other' branch"),
        ('{count, plural, offset:x other {#}}', 'Invalid plural offset'),
        ('{count, plural, offset:1 offset:2 other {#}}', 'Duplicate plural offset'),
        ('{count, selectordinal, 0abc {#} other {#}}', 'Invalid plural branch'),
        ('{count, plural, one {#} one {#} other {#}}', 'Duplicate branch'),
        ("'{name}", 'Unterminated quoted string'),
        ("{name, number, }", 'Missing argument style'),
    ],
)
def test_invalid_icu_syntax(text, message):
    with pytest.raises(icu.ICUFormatError, match=message) as exc_info:
        icu.parse_message(text)
    assert exc_info.value.position is not None
    assert isinstance(exc_info.value.path, tuple)


@pytest.mark.parametrize(
    'text',
    [
        "It's {name}",
        "Use '{' to open",
        "Use '#': {count, plural, other {# and '#'}}",
        "{count, plural, other {''#}}",
        "{count, plural, other {{inner, plural, one {#} other {#}} #}}",
    ],
)
def test_quote_and_hash_boundaries_parse(text):
    icu.parse_message(text)


@pytest.mark.parametrize(
    ('original', 'translation', 'message', 'path'),
    [
        ('{name}', '{other}', "Unknown argument 'other'", ('other',)),
        (
            '{count, plural, other {#}}',
            '{count, select, other {#}}',
            'Incompatible argument type',
            ('count',),
        ),
        (
            '{count, plural, other {#}}',
        '{count, plural, extra {#} other {#}}',
        "Unknown branch 'extra'",
            ('count', 'extra'),
        ),
        (
            '{gender, select, female {x} other {x}}',
            '{gender, select, female {x} neuter {x} other {x}}',
            "Unknown branch 'neuter'",
            ('gender', 'neuter'),
        ),
        (
            '{a, plural, one {{b}} other {{b}}}',
            '{a, plural, one {{b} {c}} other {{b}}}',
            "Unknown argument 'c'",
            ('a', 'one', 'c'),
        ),
    ],
)
def test_invalid_icu_translation_reports_path(original, translation, message, path):
    with pytest.raises(icu.ICUFormatError, match=message) as exc_info:
        icu.validate_translation(original, translation)
    assert exc_info.value.path == path


def test_catalog_check_includes_diagnostic_details():
    catalog = Catalog(locale='ru')
    catalog.add(
        '{count, plural, one {# item} other {# items}}',
        '{count, plural, extra {#} other {#}}',
        flags=['icu-format'],
    )
    [(message, errors)] = catalog.check()
    assert message.flags == {'icu-format'}
    assert len(errors) == 1
    assert "Invalid ICU message in translation: Unknown branch 'extra'" in str(errors[0])
    assert 'at count.extra' in str(errors[0])
    assert 'line 1, column' in str(errors[0])


def test_unmarked_message_is_not_checked():
    message = Message('{count, plural, one {#}}', '{count, plural, lots {#}}')
    icu_format(None, message)
    assert message.check() == []


def test_original_syntax_error_is_reported():
    message = Message(
        '{count, plural, one {#}}',
        '{count, plural, other {#}}',
        flags=['icu-format'],
    )
    with pytest.raises(TranslationError, match='msgid.*Missing required'):
        icu_format(None, message)


def test_catalog_allows_locale_plural_categories():
    catalog = Catalog(locale='ru')
    message = Message(
        '{count, plural, one {#} other {#}}',
        '{count, plural, one {#} few {#} many {#} other {#}}',
        flags=['icu-format'],
    )
    icu_format(catalog, message)


def test_pluralizable_message_parses_both_original_forms():
    message = Message(
        ('{count, plural, one {#} other {#}}', '{count, plural, one {#}'),
        ('', ''),
        flags=['icu-format'],
    )
    with pytest.raises(TranslationError, match=r'msgid\[1\].*Missing required'):
        icu_format(None, message)


def test_pluralizable_message_checks_each_translation_form():
    message = Message(
        ('{count, plural, one {#} other {#}}', '{count, plural, one {#} other {# items}}'),
        ('{count, plural, one {#} other {#}}', '{count, plural, one {#} =7 {#} other {#}}'),
        flags=['icu-format'],
    )
    with pytest.raises(TranslationError, match=r'msgstr\[1\].*Unknown branch'):
        icu_format(None, message)


def test_po_roundtrip_preserves_icu_format_flag():
    source = (
        '#, icu-format\n'
        'msgid "{count, plural, one {# item} other {# items}}"\n'
        'msgstr "{count, plural, one {#} other {#}}"\n'
    ).encode('utf-8')
    catalog = read_po(BytesIO(source))
    message = catalog['{count, plural, one {# item} other {# items}}']
    assert message.flags == {'icu-format'}
    assert message.check(catalog=catalog) == []

    output = BytesIO()
    write_po(output, catalog)
    assert b'#, icu-format' in output.getvalue()
