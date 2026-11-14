"""
Security regression tests for the CPE 2.3 URI binding.

Percent-encoded sequences must be consumed exactly once while parsing a URI
component, wildcard characters must only appear in their legal binding
positions and malformed input must be rejected with an error that locates the
offending component and offset.
"""

from __future__ import print_function

import pytest

from cpe.cpe2_3_uri import CPE2_3_URI
from cpe.cpe2_3_wfn import CPE2_3_WFN
from cpe.cpeset2_3 import CPESet2_3
from cpe.comp.cpecomp2_3_uri import CPEComponent2_3_URI


# ---------------------------------------------------------------------------
# Percent-encoding is consumed exactly once.
# ---------------------------------------------------------------------------

@pytest.mark.parametrize('uri, expected', [
    # '%25' decodes once into a quoted literal percent; the trailing '2a'
    # must never be interpreted as a second percent-encoded '*'.
    ('cpe:/a:vendor:product:%252a', 'version="\\%2a"'),
    ('cpe:/a:vendor:product:%253f', 'version="\\%3f"'),
    ('cpe:/a:vendor:product:%253a', 'version="\\%3a"'),
    ('cpe:/a:vendor:product:1%2502', 'version="1\\%02"'),
    ('cpe:/a:vendor:product:1%2501', 'version="1\\%01"'),
    # Triple encoding likewise collapses only one level.
    ('cpe:/a:vendor:product:%25252a', 'version="\\%252a"'),
])
def test_double_encoded_wildcards_become_quoted_literals(uri, expected):
    cpe = CPE2_3_URI(uri)
    wfn = cpe.as_wfn()
    assert expected in wfn
    # No unquoted wildcard may reach the WFN representation.
    assert 'version="*' not in wfn
    assert 'version="?' not in wfn
    # Single decode is stable under round-tripping.
    assert CPE2_3_URI(cpe.as_uri_2_3()).as_wfn() == wfn


@pytest.mark.parametrize('uri', [
    'cpe:/a:vendor:product:%25%30%32',
    'cpe:/a:vendor:product:%25%32%61',
])
def test_disallowed_encodings_are_rejected(uri):
    with pytest.raises(ValueError):
        CPE2_3_URI(uri)


def test_smuggled_wildcard_cannot_match_arbitrary_versions():
    cpe_set = CPESet2_3()
    cpe_set.append(CPE2_3_URI('cpe:/a:vendor:product:%252a'))

    target = CPE2_3_WFN(
        'wfn:[part="a", vendor="vendor", product="product", '
        'version="9\\.9\\.9"]')
    assert cpe_set.name_match(target) is False


def test_legitimate_wildcard_still_matches():
    # A legal trailing '%02' is the URI binding for an unquoted '*'.
    cpe = CPE2_3_URI('cpe:/a:vendor:product:%02')
    assert cpe.as_wfn() == (
        'wfn:[part="a", vendor="vendor", product="product", '
        'version="*"]')


@pytest.mark.parametrize('value, wfn_fragment', [
    ('%02', 'version="*"'),
    ('%02abc', 'version="*abc"'),
    ('abc%02', 'version="abc*"'),
    ('%01abc', 'version="?abc"'),
    ('abc%01', 'version="abc?"'),
    ('%01%01abc', 'version="??abc"'),
])
def test_wildcards_allowed_only_in_legal_positions(value, wfn_fragment):
    uri = 'cpe:/a:vendor:product:{0}'.format(value)
    assert wfn_fragment in CPE2_3_URI(uri).as_wfn()


@pytest.mark.parametrize('value', [
    'a%01%01b',    # embedded group of '?' surrounded by content
    'ab%01c%01',   # trailing group followed by more content is illegal
    'a%01b',       # a single embedded '?' is illegal
])
def test_embedded_wildcards_are_rejected_with_offset(value):
    with pytest.raises(ValueError) as excinfo:
        CPEComponent2_3_URI(value, 'version')
    message = str(excinfo.value)
    assert 'version' in message
    assert 'offset' in message


# ---------------------------------------------------------------------------
# Strict input validation with component/offset locations.
# ---------------------------------------------------------------------------

@pytest.mark.parametrize('value, offset', [
    ('%zz', 0),
    ('100%', 3),
    ('100%2', 3),
    ('%00', 0),
    ('%41', 0),
    ('a~b', 1),
])
def test_malformed_encoding_reports_component_and_offset(value, offset):
    with pytest.raises(ValueError) as excinfo:
        CPEComponent2_3_URI(value, 'version')
    message = str(excinfo.value)
    assert "attribute 'version'" in message
    assert 'offset {0}'.format(offset) in message


@pytest.mark.parametrize('uri', [
    'cpe:/a:1:2:3:4:5:6:7',
    'cpe:/a:1:2:3:4:5:6:7:8',
])
def test_too_many_fields_are_rejected(uri):
    with pytest.raises(ValueError) as excinfo:
        CPE2_3_URI(uri)
    assert 'too many components' in str(excinfo.value)
    assert 'offset' in str(excinfo.value)


@pytest.mark.parametrize('uri', [
    'cpe:/a:v:p:1.0::~a~b~c~d',       # only four packed values
    'cpe:/a:v:p:1.0::~a~b~c~d~e~f',   # six packed values
    'cpe:/a:v:p:1.0::a~b~c~d~e',      # missing leading tilde
])
def test_malformed_packed_edition_is_rejected(uri):
    with pytest.raises(ValueError):
        CPE2_3_URI(uri)


def test_empty_standalone_component_is_rejected():
    # The component class itself never accepts an empty string: empty fields
    # only represent the logical ANY value at the name-parsing level.
    with pytest.raises(ValueError):
        CPEComponent2_3_URI('', 'version')


def test_empty_middle_field_means_any():
    cpe = CPE2_3_URI('cpe:/a::product')
    assert 'vendor=ANY' in cpe.as_wfn()


# ---------------------------------------------------------------------------
# Unicode, mixed case and boundary lengths.
# ---------------------------------------------------------------------------

@pytest.mark.parametrize('uri', [
    # The legacy URI binding only percent-encodes an explicit punctuation set;
    # arbitrary byte sequences (including UTF-8 multibyte sequences) must not
    # be silently accepted.
    'cpe:/a:vendor:product:caf%C3%A9',
    'cpe:/a:vendor:product:%E2%98%83',
])
def test_non_binding_percent_encodings_are_rejected(uri):
    with pytest.raises(ValueError):
        CPE2_3_URI(uri)


def test_mixed_case_is_normalized():
    uri = 'cpe:/A:TauPan:CPE%7CExtra:1.2.1BETA1'
    cpe = CPE2_3_URI(uri)
    assert cpe.as_wfn() == (
        'wfn:[part="a", vendor="taupan", product="cpe\\|extra", '
        'version="1\\.2\\.1beta1"]')
    assert cpe.as_uri_2_3() == uri.lower()


def test_boundary_component_length():
    assert CPEComponent2_3_URI('a' * 4096, 'version') is not None
    with pytest.raises(ValueError):
        CPEComponent2_3_URI('a' * 4097, 'version')


def test_packed_edition_keeps_single_decode():
    uri = 'cpe:/a:v:p:1.0::~%252a~sw~ts~th~o'
    cpe = CPE2_3_URI(uri)
    assert 'edition="\\%2a"' in cpe.as_wfn()
    # The packed edition view must not decode the value a second time.
    packed = cpe[5]
    assert packed.get_value() == '~%252a~sw~ts~th~o'
