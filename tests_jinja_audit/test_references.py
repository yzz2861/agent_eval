import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import pytest  # noqa: E402
from jinja2 import Environment  # noqa: E402

from jinja_audit import ReferenceKind, Resolution  # noqa: E402
from jinja_audit.references import (  # noqa: E402
    TemplateParseError,
    extract_references,
)

ENV = Environment()


def test_static_reference_is_fully_known():
    refs = extract_references('t.html', '{% include "a.html" %} ')
    assert len(refs) == 1
    ref = refs[0]
    assert ref.kind is ReferenceKind.INCLUDE
    assert ref.resolution is Resolution.STATIC
    assert ref.targets == ('a.html',)
    assert ref.expression == "'a.html'"
    assert ref.lineno == 1


def test_literal_candidate_list_is_bounded():
    refs = extract_references('t.html', '{% include ["a.html", "b.html"] %} ')
    assert refs[0].resolution is Resolution.CANDIDATES
    assert refs[0].targets == ('a.html', 'b.html')


def test_declared_variable_domain_is_bounded():
    source = '{% include tpl %} '
    candidates = {'t.html': {'tpl': ['a.html', 'b.html']}}
    refs = extract_references(
        't.html', source, candidates=candidates
    )
    assert refs[0].resolution is Resolution.CANDIDATES
    assert refs[0].targets == ('a.html', 'b.html')
    assert refs[0].expression == 'tpl'


def test_undeclared_variable_is_unknown_and_explains_itself():
    refs = extract_references('t.html', '{% include tpl %} ')
    assert refs[0].resolution is Resolution.UNKNOWN
    assert refs[0].is_unknown
    assert 'tpl' in refs[0].unknown_reason


def test_concat_and_filters_are_unknown_without_rendering():
    source = '{% include tpl ~ ".html" %} {% include x|default("y.html") %} '
    refs = extract_references('t.html', source)
    assert all(ref.resolution is Resolution.UNKNOWN for ref in refs)
    assert '~' in refs[0].expression


def test_all_four_constructs_are_collected():
    source = '{% extends "b.html" %} {% include "i.html" %} '
    source += '{% import "m.html" as m %} {% from "f.html" import x %} '
    refs = extract_references('t.html', source)
    assert {ref.kind for ref in refs} == set(ReferenceKind)


def test_ignore_missing_flag_is_preserved():
    refs = extract_references('t.html', '{% include "a.html" ignore missing %} ')
    assert refs[0].ignore_missing is True


def test_syntax_error_is_reported_as_parse_error():
    with pytest.raises(TemplateParseError):
        extract_references('broken.html', '{% if %} ')
