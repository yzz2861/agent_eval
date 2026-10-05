#
# Copyright (C) 2007-2011 Edgewall Software, 2013-2025 the Babel team
# All rights reserved.
#
# This software is licensed as described in the file LICENSE, which
# you should have received as part of this distribution. The terms
# are also available at https://github.com/python-babel/babel/blob/master/LICENSE.
#
# This software consists of voluntary contributions made by many
# individuals. For the exact contribution history, see the revision
# history and logs, available at https://github.com/python-babel/babel/commits/master/.

from datetime import datetime
from io import BytesIO

import pytest

from babel import __version__ as VERSION
from babel.core import Locale, UnknownLocaleError
from babel.dates import format_datetime
from babel.messages import Catalog, Message, checkers
from babel.messages.catalog import TranslationError
from babel.messages.checkers import _validate_format, icu_format, python_format
from babel.messages.plurals import PLURALS
from babel.messages.pofile import read_po, write_po
from babel.util import LOCALTZ

# the last msgstr[idx] is always missing except for singular plural forms


def test_1_num_plurals_checkers():
    for _locale in [p for p in PLURALS if PLURALS[p][0] == 1]:
        try:
            locale = Locale.parse(_locale)
        except UnknownLocaleError:
            # Just an alias? Not what we're testing here, let's continue
            continue
        date = format_datetime(datetime.now(LOCALTZ), 'yyyy-MM-dd HH:mmZ', tzinfo=LOCALTZ, locale=_locale)
        plural = PLURALS[_locale][0]
        po_file = (f"""\
# {locale.english_name} translations for TestProject.
# Copyright (C) 2007 FooBar, Inc.
# This file is distributed under the same license as the TestProject
# project.
# FIRST AUTHOR <EMAIL@ADDRESS>, 2007.
#
msgid ""
msgstr ""
"Project-Id-Version: TestProject 0.1\\n"
"Report-Msgid-Bugs-To: bugs.address@email.tld\\n"
"POT-Creation-Date: 2007-04-01 15:30+0200\\n"
"PO-Revision-Date: {date}\\n"
"Last-Translator: FULL NAME <EMAIL@ADDRESS>\\n"
"Language-Team: {_locale} <LL@li.org>\n"
"Plural-Forms: nplurals={plural}; plural={plural};\\n"
"MIME-Version: 1.0\\n"
"Content-Type: text/plain; charset=utf-8\\n"
"Content-Transfer-Encoding: 8bit\\n"
"Generated-By: Babel {VERSION}\\n"

#. This will be a translator comment,
#. that will include several lines
#: project/file1.py:8
msgid "bar"
msgstr ""

#: project/file2.py:9
msgid "foobar"
msgid_plural "foobars"
msgstr[0] ""

""").encode('utf-8')

        # This test will fail for revisions <= 406 because so far
        # catalog.num_plurals was neglected
        catalog = read_po(BytesIO(po_file), _locale)
        message = catalog['foobar']
        checkers.num_plurals(catalog, message)


def test_2_num_plurals_checkers():
    # in this testcase we add an extra msgstr[idx], we should be
    # disregarding it
    for _locale in [p for p in PLURALS if PLURALS[p][0] == 2]:
        if _locale in ['nn', 'no']:
            _locale = 'nn_NO'
            num_plurals = PLURALS[_locale.split('_')[0]][0]
            plural_expr = PLURALS[_locale.split('_')[0]][1]
        else:
            num_plurals = PLURALS[_locale][0]
            plural_expr = PLURALS[_locale][1]
        try:
            locale = Locale(_locale)
            date = format_datetime(datetime.now(LOCALTZ),
                                   'yyyy-MM-dd HH:mmZ',
                                   tzinfo=LOCALTZ, locale=_locale)
        except UnknownLocaleError:
            # Just an alias? Not what we're testing here, let's continue
            continue
        po_file = f"""\
# {locale.english_name} translations for TestProject.
# Copyright (C) 2007 FooBar, Inc.
# This file is distributed under the same license as the TestProject
# project.
# FIRST AUTHOR <EMAIL@ADDRESS>, 2007.
#
msgid ""
msgstr ""
"Project-Id-Version: TestProject 0.1\\n"
"Report-Msgid-Bugs-To: bugs.address@email.tld\\n"
"POT-Creation-Date: 2007-04-01 15:30+0200\\n"
"PO-Revision-Date: {date}\\n"
"Last-Translator: FULL NAME <EMAIL@ADDRESS>\\n"
"Language-Team: {_locale} <LL@li.org>\\n"
"Plural-Forms: nplurals={num_plurals}; plural={plural_expr};\\n"
"MIME-Version: 1.0\\n"
"Content-Type: text/plain; charset=utf-8\\n"
"Content-Transfer-Encoding: 8bit\\n"
"Generated-By: Babel {VERSION}\\n"

#. This will be a translator comment,
#. that will include several lines
#: project/file1.py:8
msgid "bar"
msgstr ""

#: project/file2.py:9
msgid "foobar"
msgid_plural "foobars"
msgstr[0] ""
msgstr[1] ""
msgstr[2] ""

""".encode('utf-8')
        # we should be adding the missing msgstr[0]

        # This test will fail for revisions <= 406 because so far
        # catalog.num_plurals was neglected
        catalog = read_po(BytesIO(po_file), _locale)
        message = catalog['foobar']
        checkers.num_plurals(catalog, message)


def test_3_num_plurals_checkers():
    for _locale in [p for p in PLURALS if PLURALS[p][0] == 3]:
        plural = format_datetime(datetime.now(LOCALTZ), 'yyyy-MM-dd HH:mmZ', tzinfo=LOCALTZ, locale=_locale)
        english_name = Locale.parse(_locale).english_name
        po_file = rf"""\
# {english_name} translations for TestProject.
# Copyright (C) 2007 FooBar, Inc.
# This file is distributed under the same license as the TestProject
# project.
# FIRST AUTHOR <EMAIL@ADDRESS>, 2007.
#
msgid ""
msgstr ""
"Project-Id-Version: TestProject 0.1\n"
"Report-Msgid-Bugs-To: bugs.address@email.tld\n"
"POT-Creation-Date: 2007-04-01 15:30+0200\n"
"PO-Revision-Date: {plural}\n"
"Last-Translator: FULL NAME <EMAIL@ADDRESS>\n"
"Language-Team: {_locale} <LL@li.org>\n"
"Plural-Forms: nplurals={PLURALS[_locale][0]}; plural={PLURALS[_locale][0]};\n"
"MIME-Version: 1.0\n"
"Content-Type: text/plain; charset=utf-8\n"
"Content-Transfer-Encoding: 8bit\n"
"Generated-By: Babel {VERSION}\n"

#. This will be a translator comment,
#. that will include several lines
#: project/file1.py:8
msgid "bar"
msgstr ""

#: project/file2.py:9
msgid "foobar"
msgid_plural "foobars"
msgstr[0] ""
msgstr[1] ""

""".encode('utf-8')

        # This test will fail for revisions <= 406 because so far
        # catalog.num_plurals was neglected
        catalog = read_po(BytesIO(po_file), _locale)
        message = catalog['foobar']
        checkers.num_plurals(catalog, message)


def test_4_num_plurals_checkers():
    for _locale in [p for p in PLURALS if PLURALS[p][0] == 4]:
        date = format_datetime(datetime.now(LOCALTZ), 'yyyy-MM-dd HH:mmZ', tzinfo=LOCALTZ, locale=_locale)
        english_name = Locale.parse(_locale).english_name
        plural = PLURALS[_locale][0]
        po_file = rf"""\
# {english_name} translations for TestProject.
# Copyright (C) 2007 FooBar, Inc.
# This file is distributed under the same license as the TestProject
# project.
# FIRST AUTHOR <EMAIL@ADDRESS>, 2007.
#
msgid ""
msgstr ""
"Project-Id-Version: TestProject 0.1\n"
"Report-Msgid-Bugs-To: bugs.address@email.tld\n"
"POT-Creation-Date: 2007-04-01 15:30+0200\n"
"PO-Revision-Date: {date}\n"
"Last-Translator: FULL NAME <EMAIL@ADDRESS>\n"
"Language-Team: {_locale} <LL@li.org>\n"
"Plural-Forms: nplurals={plural}; plural={plural};\n"
"MIME-Version: 1.0\n"
"Content-Type: text/plain; charset=utf-8\n"
"Content-Transfer-Encoding: 8bit\n"
"Generated-By: Babel {VERSION}\n"

#. This will be a translator comment,
#. that will include several lines
#: project/file1.py:8
msgid "bar"
msgstr ""

#: project/file2.py:9
msgid "foobar"
msgid_plural "foobars"
msgstr[0] ""
msgstr[1] ""
msgstr[2] ""

""".encode('utf-8')

        # This test will fail for revisions <= 406 because so far
        # catalog.num_plurals was neglected
        catalog = read_po(BytesIO(po_file), _locale)
        message = catalog['foobar']
        checkers.num_plurals(catalog, message)


def test_5_num_plurals_checkers():
    for _locale in [p for p in PLURALS if PLURALS[p][0] == 5]:
        date = format_datetime(datetime.now(LOCALTZ), 'yyyy-MM-dd HH:mmZ', tzinfo=LOCALTZ, locale=_locale)
        english_name = Locale.parse(_locale).english_name
        plural = PLURALS[_locale][0]
        po_file = rf"""\
# {english_name} translations for TestProject.
# Copyright (C) 2007 FooBar, Inc.
# This file is distributed under the same license as the TestProject
# project.
# FIRST AUTHOR <EMAIL@ADDRESS>, 2007.
#
msgid ""
msgstr ""
"Project-Id-Version: TestProject 0.1\n"
"Report-Msgid-Bugs-To: bugs.address@email.tld\n"
"POT-Creation-Date: 2007-04-01 15:30+0200\n"
"PO-Revision-Date: {date}\n"
"Last-Translator: FULL NAME <EMAIL@ADDRESS>\n"
"Language-Team: {_locale} <LL@li.org>\n"
"Plural-Forms: nplurals={plural}; plural={plural};\n"
"MIME-Version: 1.0\n"
"Content-Type: text/plain; charset=utf-8\n"
"Content-Transfer-Encoding: 8bit\n"
"Generated-By: Babel {VERSION}\n"

#. This will be a translator comment,
#. that will include several lines
#: project/file1.py:8
msgid "bar"
msgstr ""

#: project/file2.py:9
msgid "foobar"
msgid_plural "foobars"
msgstr[0] ""
msgstr[1] ""
msgstr[2] ""
msgstr[3] ""

""".encode('utf-8')

        # This test will fail for revisions <= 406 because so far
        # catalog.num_plurals was neglected
        catalog = read_po(BytesIO(po_file), _locale)
        message = catalog['foobar']
        checkers.num_plurals(catalog, message)


def test_6_num_plurals_checkers():
    for _locale in [p for p in PLURALS if PLURALS[p][0] == 6]:
        english_name = Locale.parse(_locale).english_name
        date = format_datetime(datetime.now(LOCALTZ), 'yyyy-MM-dd HH:mmZ', tzinfo=LOCALTZ, locale=_locale)
        plural = PLURALS[_locale][0]
        po_file = rf"""\
# {english_name} translations for TestProject.
# Copyright (C) 2007 FooBar, Inc.
# This file is distributed under the same license as the TestProject
# project.
# FIRST AUTHOR <EMAIL@ADDRESS>, 2007.
#
msgid ""
msgstr ""
"Project-Id-Version: TestProject 0.1\n"
"Report-Msgid-Bugs-To: bugs.address@email.tld\n"
"POT-Creation-Date: 2007-04-01 15:30+0200\n"
"PO-Revision-Date: {date}\n"
"Last-Translator: FULL NAME <EMAIL@ADDRESS>\n"
"Language-Team: {_locale} <LL@li.org>\n"
"Plural-Forms: nplurals={plural}; plural={plural};\n"
"MIME-Version: 1.0\n"
"Content-Type: text/plain; charset=utf-8\n"
"Content-Transfer-Encoding: 8bit\n"
"Generated-By: Babel {VERSION}\n"

#. This will be a translator comment,
#. that will include several lines
#: project/file1.py:8
msgid "bar"
msgstr ""

#: project/file2.py:9
msgid "foobar"
msgid_plural "foobars"
msgstr[0] ""
msgstr[1] ""
msgstr[2] ""
msgstr[3] ""
msgstr[4] ""

""".encode('utf-8')

        # This test will fail for revisions <= 406 because so far
        # catalog.num_plurals was neglected
        catalog = read_po(BytesIO(po_file), _locale)
        message = catalog['foobar']
        checkers.num_plurals(catalog, message)


@pytest.mark.parametrize(
    ('msgid', 'msgstr'),
    [
        ('foo %s', 'foo'),
        (('foo %s', 'bar'), ('foo', 'bar')),
        (('foo', 'bar %s'), ('foo', 'bar')),
        (('foo %s', 'bar'), ('foo')),
        (('foo %s', 'bar %d'), ('foo %s', 'bar %d', 'baz')),
        (('foo %s', 'bar %d'), ('foo %s', 'bar %d', 'baz %d', 'qux')),
    ],
)
def test_python_format_invalid(msgid, msgstr):
    msg = Message(msgid, msgstr)
    with pytest.raises(TranslationError):
        python_format(None, msg)


@pytest.mark.parametrize(
    ('msgid', 'msgstr'),
    [
        ('foo', 'foo'),
        ('foo', 'foo %s'),
        ('foo %s', ''),
        (('foo %s', 'bar %d'), ('foo %s', 'bar %d')),
        (('foo %s', 'bar %d'), ('foo %s', 'bar %d', 'baz %d')),
        (('foo', 'bar %s'), ('foo')),
        (('foo', 'bar %s'), ('', '')),
        (('foo', 'bar %s'), ('foo', '')),
        (('foo %s', 'bar %d'), ('foo %s', '')),
    ],
)
def test_python_format_valid(msgid, msgstr):
    msg = Message(msgid, msgstr)
    python_format(None, msg)


@pytest.mark.parametrize(
    ('msgid', 'msgstr', 'error'),
    [
        ('%s %(foo)s', '%s %(foo)s', 'format string mixes positional and named placeholders'),
        ('foo %s', 'foo', 'placeholders are incompatible'),
        ('%s', '%(foo)s', 'the format strings are of different kinds'),
        ('%s', '%s %d', 'positional format placeholders are unbalanced'),
        ('%s', '%d', "incompatible format for placeholder 1: 's' and 'd' are not compatible"),
        (
            '%s %s %d',
            '%s %s %s',
            "incompatible format for placeholder 3: 'd' and 's' are not compatible",
        ),
        ('%(foo)s', '%(bar)s', "unknown named placeholder 'bar'"),
        ('%(foo)s', '%(bar)d', "unknown named placeholder 'bar'"),
        (
            '%(foo)s',
            '%(foo)d',
            "incompatible format for placeholder 'foo': 'd' and 's' are not compatible",
        ),
    ],
)
def test__validate_format_invalid(msgid, msgstr, error):
    with pytest.raises(TranslationError, match=error):
        _validate_format(msgid, msgstr)


@pytest.mark.parametrize(
    ('msgid', 'msgstr'),
    [
        ('foo', 'foo'),
        ('foo', 'foo %s'),
        ('%s foo', 'foo %s'),
        ('%i', '%d'),
        ('%d', '%u'),
        ('%x', '%X'),
        ('%f', '%F'),
        ('%F', '%g'),
        ('%g', '%G'),
        ('%(foo)s', 'foo'),
        ('%(foo)s', '%(foo)s %(foo)s'),
        ('%(bar)s foo %(n)d', '%(n)d foo %(bar)s'),
    ],
)
def test__validate_format_valid(msgid, msgstr):
    _validate_format(msgid, msgstr)


@pytest.mark.parametrize(
    ('msgid', 'msgstr', 'flags'),
    [
        # simple message with target-language-specific extra plural category
        (
            '{count, plural, one {# apple} other {# apples}}',
            '{count, plural, one {# apfel} few {# apfel} other {# apfel}}',
            {'icu-format'},
        ),
        # select branches may freely differ between languages
        (
            '{gender, select, male {his} female {her} other {their}}',
            '{gender, select, female {ihr} other {sein}}',
            {'icu-format'},
        ),
        # selectordinal with nested argument
        (
            '{n, selectordinal, one {#st} other {#th}} place',
            '{n, selectordinal, one {#er} other {#ten}} Ort',
            {'icu-format'},
        ),
        # pluralizable catalog message
        (
            ('{count, plural, one {# apple} other {# apples}}',
             '{count, plural, one {# apples} other {# apples}}'),
            ('{count, plural, one {# apfel} other {# apfel}}',
             '{count, plural, one {# apfel} few {# apfel} other {# apfel}}'),
            {'icu-format'},
        ),
    ],
)
def test_icu_format_valid(msgid, msgstr, flags):
    msg = Message(msgid, msgstr, flags=flags)
    icu_format(None, msg)


@pytest.mark.parametrize(
    ('msgid', 'msgstr', 'error'),
    [
        # missing required 'other' branch in translation
        (
            '{count, plural, other {# apples}}',
            '{count, plural, one {# apfel}}',
            "'other'",
        ),
        # unknown argument in translation
        (
            '{count, plural, other {# apples}}',
            '{count, plural, other {# apfel}} {extra}',
            'unknown argument',
        ),
        # parameter kind mismatch, with a nested parameter path
        (
            '{a, plural, other {{b, select, other {x}}}}',
            '{a, plural, other {{b, plural, other {#}}}}',
            'parameter path: a.other.b',
        ),
        # '#' outside of plural scope
        (
            '{g, select, other {x}}',
            '{g, select, other {#}}',
            "'#'",
        ),
        # unterminated quoting in translation
        (
            "It''s fine",
            "it '{breaks",
            'unterminated quoted section',
        ),
        # invalid plural in the second plural form
        (
            ('{n, plural, other {#}}', '{n, plural, other {#}}'),
            ('{n, plural, other {#}}', '{n, plural, one {#}}'),
            "'other'",
        ),
    ],
)
def test_icu_format_invalid(msgid, msgstr, error):
    msg = Message(msgid, msgstr, flags={'icu-format'})
    with pytest.raises(TranslationError, match=error):
        icu_format(None, msg)


def test_icu_format_not_guessed_without_flag():
    # Malformed-looking but ordinary strings are left alone.
    msg = Message(
        '{count, plural, one {apple}}',
        '{count, plural, other {# broken}',
    )
    assert 'icu-format' not in msg.flags
    icu_format(None, msg)  # must not raise


def test_icu_format_through_catalog_check(tmp_path):
    po_file = tmp_path / 'messages.po'
    po_file.write_text(
        '''\
msgid ""
msgstr ""
"Content-Type: text/plain; charset=utf-8\\n"
"Plural-Forms: nplurals=2; plural=(n != 1);\\n"
"Language: de\\n"

#, icu-format
msgid "{count, plural, one {# apple} other {# apples}}"
msgstr "{count, plural, one {# apfel} other {# apfel}}"

msgid "plain {not-icu"
msgstr "einfach {nicht-icu"

#, icu-format
msgid "{gender, select, other {them}}"
msgid_plural "{gender, select, other {them}}"
msgstr[0] "{gender, select, other {sie}}"
msgstr[1] "{gender, plural, one {#} other {#}}"
''',
        encoding='utf-8',
    )
    catalog = read_po(open(po_file, 'rb'))
    bad = list(catalog.check())
    assert len(bad) == 1
    message, errors = bad[0]
    assert 'icu-format' in message.flags
    assert len(errors) == 1
    text = str(errors[0])
    assert 'plural form 1' in text
    assert 'incompatible kind' in text


def test_icu_format_flag_roundtrip():
    catalog = Catalog()
    catalog.add(
        '{n, plural, other {#}}',
        '{n, plural, one {#} other {#}}',
        flags={'icu-format'},
    )
    buffer = BytesIO()
    write_po(buffer, catalog)
    buffer.seek(0)
    reread = read_po(buffer)
    assert 'icu-format' in reread['{n, plural, other {#}}'].flags
