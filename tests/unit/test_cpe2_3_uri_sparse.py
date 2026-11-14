from __future__ import print_function
from cpe.cpe2_3_uri import CPE2_3_URI
from cpe.normalize import (
    CanonicalName,
    InvalidCPEError,
    convert_2_2_to_2_3,
    parse,
)

import pytest


def test_regular_cpe():
    uri = 'cpe:/a:TauPan:cpe:1.2.1BETA1'
    c = CPE2_3_URI(uri)
    assert c.as_wfn() == 'wfn:[part="a", vendor="taupan", product="cpe", version="1\\.2\\.1beta1"]'
    assert c.as_uri_2_3() == uri.lower()


def test_percent_encoded():
    uri = 'cpe:/a:TauPan:cpe%7cextra:1.2.1BETA1'
    c = CPE2_3_URI(uri)
    assert c.as_wfn() == 'wfn:[part="a", vendor="taupan", product="cpe\\|extra", version="1\\.2\\.1beta1"]'
    assert c.as_uri_2_3() == uri.lower()


def test_just_part():
    uri = 'cpe:/a'
    c = CPE2_3_URI(uri)
    assert c.as_wfn() == 'wfn:[part="a"]'
    assert c.as_uri_2_3() == uri.lower()


def test_just_vendor():
    uri = 'cpe:/:taupan'
    c = CPE2_3_URI(uri)
    assert c.as_wfn() == 'wfn:[part=ANY, vendor="taupan"]'
    assert c.as_uri_2_3() == uri.lower()


def test_just_product():
    uri = 'cpe:/::cpe'
    c = CPE2_3_URI(uri)
    assert c.as_wfn() == 'wfn:[part=ANY, vendor=ANY, product="cpe"]'
    assert c.as_uri_2_3() == uri.lower()


def test_just_version():
    uri = 'cpe:/:::version'
    cpe = CPE2_3_URI(uri)
    assert cpe.as_wfn() == ('wfn:[part=ANY, vendor=ANY, product=ANY, '
                            'version="version"'
                            ']')
    assert cpe.as_uri_2_3() == uri.lower()


def test_just_update():
    uri = 'cpe:/::::update'
    cpe = CPE2_3_URI(uri)
    assert cpe.as_wfn() == ('wfn:[part=ANY, vendor=ANY, product=ANY, '
                            'version=ANY, '
                            'update="update"'
                            ']')
    assert cpe.as_uri_2_3() == uri.lower()


def test_just_legacy_edition_uri():
    uri = 'cpe:/:::::legacy_edition'
    cpe = CPE2_3_URI(uri)
    assert cpe.as_uri_2_3() == uri.lower()


@pytest.mark.xfail
def test_just_legacy_edition_wfn():
    uri = 'cpe:/:::::legacy_edition'
    cpe = CPE2_3_URI(uri)
    # not sure if this is correct, see
    # https://github.com/nilp0inter/cpe/issues/28#issuecomment-253195951
    assert cpe.as_wfn() == ('wfn:[part=ANY, vendor=ANY, product=ANY, '
                            'version=ANY, '
                            'update=ANY, '
                            'edition="legacy_edition"'
                            ']')


def test_full_packed_edition():
    uri = 'cpe:/:::::~edition~sw_edition~target_sw~target_hw~other'
    cpe = CPE2_3_URI(uri)
    assert cpe.as_wfn() == ('wfn:[part=ANY, vendor=ANY, product=ANY, '
                            'version=ANY, '
                            'update=ANY, '
                            'edition="edition", '
                            'sw_edition="sw_edition", '
                            'target_sw="target_sw", '
                            'target_hw="target_hw", '
                            'other="other"'
                            ']')
    assert cpe.as_uri_2_3() == uri.lower()


def test_legacy_edition_uri():
    uri = 'cpe:/a:TauPan:cpe:1.2.1BETA1::legacy_edition'
    c = CPE2_3_URI(uri)
    assert c.as_uri_2_3() == uri.lower()


@pytest.mark.xfail  # see above
def test_legacy_edition_wfn():
    uri = 'cpe:/a:TauPan:cpe:1.2.1BETA1::legacy_edition'
    c = CPE2_3_URI(uri)
    assert c.as_wfn() == 'wfn:[part="a", vendor="taupan", product="cpe", version="1\\.2\\.1beta1", update=ANY, edition="legacy_edition"]'


def test_legacy_edition_packed():
    uri = 'cpe:/a:TauPan:cpe:1.2.1BETA1::~legacy_edition~~~~'
    c = CPE2_3_URI(uri)
    assert c.as_wfn() == 'wfn:[part="a", vendor="taupan", product="cpe", version="1\\.2\\.1beta1", update=ANY, edition="legacy_edition", sw_edition=ANY, target_sw=ANY, target_hw=ANY, other=ANY]'
    assert c.as_uri_2_3() == 'cpe:/a:taupan:cpe:1.2.1beta1::legacy_edition'


# ---------------------------------------------------------------------------
# Canonical comparison and cross-version normalization
# ---------------------------------------------------------------------------

def test_canonical_uri_fs_wfn_are_equal_despite_different_strings():
    uri = 'cpe:/a:mozilla:firefox:2.0.0.6::osx:zh-tw'
    fs = 'cpe:2.3:a:mozilla:firefox:2.0.0.6:*:osx:zh-tw:*:*:*:*'
    wfn = ('wfn:[part="a", vendor="mozilla", product="firefox", '
           'version="2\\.0\\.0\\.6", edition="osx", '
           'language="zh\\-tw"]')

    canonical_uri = CanonicalName.from_cpe_2_3_uri(uri)
    canonical_fs = CanonicalName.from_cpe_2_3_fs(fs)
    canonical_wfn = CanonicalName.from_cpe_2_3_wfn(wfn)

    assert canonical_uri == canonical_fs == canonical_wfn
    assert canonical_uri.is_equal(canonical_fs)


def test_canonical_name_matching_uses_cpe_semantics_not_strings():
    known = CanonicalName.from_cpe_2_3_fs(
        'cpe:2.3:a:mozilla:firefox:*:*:*:*:*:*:*:*')
    candidate = CanonicalName.from_cpe_2_3_fs(
        'cpe:2.3:a:mozilla:firefox:9.0.1:*:*:*:*:*:*:*')
    different_product = CanonicalName.from_cpe_2_3_fs(
        'cpe:2.3:a:mozilla:thunderbird:9.0.1:*:*:*:*:*:*:*')

    assert known.matches(candidate)
    assert known.is_superset(candidate)
    assert not candidate.is_superset(known)
    assert not known.matches(different_product)


def test_na_is_disjoint_from_concrete_values():
    na_name = CanonicalName.from_cpe_2_3_fs(
        'cpe:2.3:a:acme:product:1.0:-:*:*:*:*:*:*')
    concrete = CanonicalName.from_cpe_2_3_fs(
        'cpe:2.3:a:acme:product:1.0:sp1:*:*:*:*:*:*')

    assert not na_name.matches(concrete)
    assert not concrete.matches(na_name)
    assert not na_name.is_equal(concrete)


def test_2_2_and_2_3_descriptions_of_same_middleware_match():
    """Regression: two departments describe one middleware and must still
    match after canonical normalization, regardless of binding strings."""

    description_2_2 = 'cpe:/a:mozilla:firefox:2.0.0.6::osx:zh-tw'
    description_2_3 = 'cpe:2.3:a:mozilla:firefox:2.0.0.6:*:osx:zh-tw:*:*:*:*'

    rendered_2_3, canonical_2_2, _ = convert_2_2_to_2_3(description_2_2)
    canonical_2_3 = parse(description_2_3, version='fs')

    assert rendered_2_3 == description_2_2
    assert canonical_2_2 == canonical_2_3
    assert canonical_2_3.matches(canonical_2_2)


def test_sparse_uri_canonical_fields_are_any_not_undefined():
    canonical = CanonicalName.from_cpe_2_3_uri('cpe:/a:taupan')

    assert canonical.get('part') == 'a'
    assert canonical.get('vendor') == 'taupan'
    assert canonical.get('product') == 'ANY'
    assert canonical.get('other') == 'ANY'
    assert canonical.as_cpe_2_3_fs() == (
        'cpe:2.3:a:taupan:*:*:*:*:*:*:*:*:*')


@pytest.mark.parametrize('uri', [
    'cpe:/a:taupan:cpe%zz',
    'cpe:/a:taupan:cpe%2',
    'cpe:/a:taupan:cpe%7',
])
def test_invalid_2_3_percent_sequences_are_rejected(uri):
    with pytest.raises(InvalidCPEError):
        CanonicalName.from_cpe_2_3_uri(uri)


def test_wildcard_uri_is_not_downgraded_to_loose_wfn_matching():
    # %02 is the URI encoding of the WFN multi-character wildcard '*'.
    wildcard = CanonicalName.from_cpe_2_3_uri('cpe:/a:mozilla:firefox%02')
    concrete = CanonicalName.from_cpe_2_3_uri('cpe:/a:mozilla:firefox_esr')

    assert wildcard.get('product') == 'firefox*'
    assert wildcard.matches(concrete)
    # A concrete name cannot match a wildcard target because the wildcard
    # relation is undefined; it must not be treated as a plain ANY value.
    assert not concrete.matches(wildcard)
