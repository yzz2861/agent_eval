from __future__ import print_function

import pytest

from cpe.cpe import CPE
from cpe.cpe2_2 import CPE2_2
from cpe.comp.cpecomp import CPEComponent
from cpe.comp.cpecomp2_2 import CPEComponent2_2
from cpe.normalize import (
    CanonicalName,
    ConversionResult,
    InformationLoss,
    InvalidCPEError,
    UnrepresentableValueError,
    convert_2_2_to_2_3,
    convert_2_3_to_2_2,
    convert_batch,
    parse,
)


#
# Test for _get_attribute_values(self)
#
def test_get_attribute_values_1():
    c = CPE2_2('cpe:/a:mozilla:firefox:2.0.0.6::osx:zh-tw')
    assert c.get_attribute_values(CPEComponent.ATT_VENDOR) == ['mozilla']
    assert c.get_attribute_values(CPEComponent.ATT_LANGUAGE) == ['zh-tw']


#
# Test for __getitem__(self, i)
#
def test_getitem_1():
    """good index"""
    c = CPE2_2('cpe:/a:mozilla:firefox:2.0.0.6::osx:zh-tw')
    assert isinstance(c[1], CPEComponent2_2)
    assert str(c[1]) == "mozilla"


def test_getitem_2():
    """bad index"""
    c = CPE2_2('cpe:/a:mozilla:firefox:2.0.0.6::osx:zh-tw')
    with pytest.raises(IndexError):
        c[8]


def test_getitem_3():
    """bad index"""
    c = CPE2_2('cpe:/')
    with pytest.raises(IndexError):
        c[0]


#
# Test for __new__(cls, cpe_str, *args, **kwargs)
#
@pytest.mark.parametrize('s', [
    # An empty hardware part, and no OS or application part.
    'cpe:/',

    # An operation system. The CPE Name below designates all
    # Professional editions of Microsoft Windows XP, regardless of
    # service pack level.
    'cpe:/o:microsoft:windows_xp:::pro',

    # An application
    'cpe:/a:acme:product:1.0:update2:-:en-us',

    # An application
    'cpe:/a:acme:product:1.0:update2::en-us',

    # An application
    'cpe:/a:acme:product:1.0:update2:pro:en-us',

    # An application. The vendor Best Software may not have a qualified
    # DNS name, so a CPE Name for their application ABC123 would be as
    # follows:
    'cpe:/a:best_software:abc123',

    # For applications that do not have a vendor or organization
    # associated with them, this component  should use a developer's
    # name. Note that multi-word names should use underscores instead of
    # spaces.
    'cpe:/a:jon_smith:tool_name:1.2.3',

    # An application. Multi-word product names and designations should
    # be spelled out in full, replacing spaces with underscores.  The
    # example below shows how this would look for the Zone Labs
    # ZoneAlarm Internet Security Suite version 7.0.
    'cpe:/a:zonelabs:zonealarm_internet_security_suite:7.0',

    # The following example denotes Adobe Reader version 8.1
    'cpe:/a:adobe:reader:8.1',

    # The following example denotes Red Hat Enterprise Linux 4.0 Update
    # 4.
    'cpe:/o:redhat:enterprise_linux:4:update4',

    # CPE Name of Red Hat operating system with initial release of
    # Enterprise Linux 4
    'cpe:/o:redhat:enterprise_linux:4:ga',

    # An operating system
    'cpe:/o:microsoft:windows_2000::sp4:pro',

    # An application
    'cpe:/a:mozilla:firefox:2.0.0.6::osx:zh-tw',

    # This example name below represents a typical CPE Name that refers
    # to the Microsoft Windows 2000 operating system, all editions and
    # update levels.
    'cpe:/o:microsoft:windows_2000',

    # This example CPE Name below identifies Microsoft?s Windows XP
    # operating system, Professional Edition, update level "Service Pack
    # 2".
    'cpe:/o:microsoft:windows_xp::sp2:pro',

    # This example name below refers to Red Hat Enterprise Linux 3
    # Advanced Server.
    'cpe:/o:redhat:enterprise_linux:3::as',

    # This example specifies an application, specifically the Apache
    # Foundation HTTP server version 2.0.52.
    'cpe:/a:apache:httpd:2.0.52',

    # This example name below refers to a particular web browser,
    # regardless of any hardware or particular OS on which it is
    # running.
    'cpe:/a:microsoft:ie:6.0',

    # This example name below refers to a Cisco model 3825 integrated
    # services router.
    'cpe:/h:cisco:router:3825',

    # The example name below identifies a particular laptop computer
    # hardware platform. The vendor is Dell Computer, the product line
    # name is "Inspiron", and the version (or model in this example)
    # number is 8500.
    'cpe:/h:dell:inspiron:8500',

    # The CPE Name below shows an example for a virtual hardware
    # platform.
    'cpe:/h:emc:vmware_esx:2.5',

    # The CPE name below shows a valid CPE that contains a '/' in the product
    'cpe:/a:intel:proset\/wireless_wifi'
])
def test_new_legal_cpe(s):
    """legal cpe"""
    CPE2_2(s)  # Must instantiate just fine


@pytest.mark.parametrize('s', [
    # bad URI syntax
    'baduri',

    # URI with whitespaces
    'cpe:/con espacios',
])
def test_new_ilegal_cpe(s):
    """ilegal cpe"""
    with pytest.raises(ValueError):
        CPE2_2(s)


#
# Test for __len__(self)
#
@pytest.mark.parametrize('s,l', [
    # A CPE name without components
    ("cpe:/", 0),

    # A CPE name with some full components
    ("cpe:/a:i4s:javas", 3),

    # A CPE name with some empty components
    ("cpe:/a:i4s:::javas", 5),

    # A CPE name with all components
    ("cpe:/a:acme:product:1.0:update2:-:en-us", 7),
])
def test_len(s, l):
    assert len(CPE2_2(s)) == l


#
# Test for __str__(self)
#
def test_str():
    """not negate components"""
    current = str(CPE2_2('cpe:/a:acme:product:1.0:update2:-:en-us'))
    expected = "CPE v2.2: cpe:/a:acme:product:1.0:update2:-:en-us"
    assert current == expected


# ---------------------------------------------------------------------------
# Canonical, reversible 2.2 <-> 2.3 conversion
# ---------------------------------------------------------------------------

@pytest.mark.parametrize('uri', [
    'cpe:/',
    'cpe:/a:mozilla',
    'cpe:/a:mozilla:firefox:2.0.0.6::osx:zh-tw',
    'cpe:/a:acme:product:1.0:update2::en-us',
    'cpe:/a:foo:bar:1.0:::zh-tw',
    'cpe:/o:microsoft:windows_xp::sp2:pro',
    'cpe:/h:cisco:router:3825',
])
def test_canonical_2_2_uri_round_trip(uri):
    """A 2.2 URI survives a round trip through the 2.3 URI binding."""

    source = CanonicalName.from_cpe_2_2(uri)
    rendered_2_3 = source.as_cpe_2_3_uri()
    target = CanonicalName.from_cpe_2_3_uri(rendered_2_3)

    assert source == target
    rendered_2_2, losses = target.as_cpe_2_2()
    assert rendered_2_2 == uri
    assert losses == []


def test_canonical_field_order_is_stable():
    """Rendered names always follow the fixed specification attribute order."""

    canonical = CanonicalName.from_cpe_2_2(
        'cpe:/a:mozilla:firefox:2.0.0.6::osx:zh-tw')

    assert canonical.as_cpe_2_3_fs() == (
        'cpe:2.3:a:mozilla:firefox:2.0.0.6:*:osx:zh-tw:*:*:*:*')
    assert canonical.as_cpe_2_3_wfn() == (
        'wfn:[part="a", vendor="mozilla", product="firefox", '
        'version="2\\.0\\.0\\.6", edition="osx", '
        'language="zh\\-tw"]')
    assert list(canonical.attributes.keys()) == list(
        CPEComponent.CPE_COMP_KEYS_EXTENDED)


def test_hyphen_is_literal_in_2_2_but_na_in_2_3():
    """The hyphen ambiguity must be marked, not guessed."""

    uri = 'cpe:/a:acme:product:1.0:update2:-:en-us'
    c22 = CanonicalName.from_cpe_2_2(uri)
    c23 = CanonicalName.from_cpe_2_3_uri(uri)

    assert c22.get(CPEComponent.ATT_EDITION) == '\\-'
    assert c23.get(CPEComponent.ATT_EDITION) == 'NA'
    assert any(
        loss.reason == 'hyphen_literal_in_2_2' and
        loss.attribute == CPEComponent.ATT_EDITION
        for loss in c22.losses)


def test_na_cannot_be_downgraded_silently():
    """NA has no 2.2 representation: strict mode fails, lenient mode marks it."""

    canonical = parse(
        'cpe:2.3:a:acme:product:1.0:update2:-:en-us:*:*:*:*',
        version='fs')

    with pytest.raises(UnrepresentableValueError) as excinfo:
        canonical.as_cpe_2_2(strict=True)
    loss = excinfo.value.loss
    assert loss.attribute == CPEComponent.ATT_EDITION
    assert loss.reason == 'na_not_defined_in_2_2'

    rendered, losses = canonical.as_cpe_2_2(strict=False)
    assert rendered == 'cpe:/a:acme:product:1.0:update2::en-us'
    assert len(losses) == 1
    assert losses[0].reason == 'na_not_defined_in_2_2'


def test_packed_edition_round_trip_keeps_extended_attributes():
    """The tilde packed edition preserves the four extended 2.3 fields."""

    uri = 'cpe:/a:hp:diag:7.4::~~online~win2003~x64~'
    canonical = CanonicalName.from_cpe_2_3_uri(uri)

    assert canonical.get(CPEComponent.ATT_SW_EDITION) == 'online'
    assert canonical.get(CPEComponent.ATT_TARGET_SW) == 'win2003'
    assert canonical.get(CPEComponent.ATT_TARGET_HW) == 'x64'
    assert canonical.as_cpe_2_3_uri() == uri

    rendered_2_2, losses = canonical.as_cpe_2_2()
    assert rendered_2_2 == uri
    assert losses == []


@pytest.mark.parametrize('uri,expected', [
    ('cpe:/a:foo:bar%zz', 'bar\\%zz'),
    ('cpe:/a:foo:bar%2', 'bar\\%2'),
])
def test_stray_percent_is_literal_in_2_2(uri, expected):
    """In 2.2 a stray percent is data; it must survive the canonical model."""

    canonical = CanonicalName.from_cpe_2_2(uri)
    assert canonical.get(CPEComponent.ATT_PRODUCT) == expected


@pytest.mark.parametrize('uri', [
    'cpe:/a:foo:bar%zz',
    'cpe:/a:foo:bar%2',
    'cpe:/a:foo:bar%7',
])
def test_invalid_percent_encoding_rejected_in_2_3(uri):
    """The same sequences are invalid percent encodings in a 2.3 URI."""

    with pytest.raises(InvalidCPEError):
        CanonicalName.from_cpe_2_3_uri(uri)


def test_percent_encoding_round_trip_between_bindings():
    canonical = CanonicalName.from_cpe_2_2('cpe:/a:foo:bar%zz:1.0')

    assert canonical.as_cpe_2_3_uri() == 'cpe:/a:foo:bar%25zz:1.0'
    assert canonical.as_cpe_2_3_fs() == (
        'cpe:2.3:a:foo:bar\\%zz:1.0:*:*:*:*:*:*:*')

    reparsed = CanonicalName.from_cpe_2_3_uri(canonical.as_cpe_2_3_uri())
    assert reparsed == canonical


@pytest.mark.parametrize('tag', [
    'en', 'en-us', 'zh-tw', 'es-es', 'es-419', 'de-de',
])
def test_valid_language_tags_accepted(tag):
    canonical = CanonicalName.from_cpe_2_2(
        'cpe:/a:foo:bar:1.0:::{0}'.format(tag))
    assert canonical.get(CPEComponent.ATT_LANGUAGE).replace('\\', '') == tag


@pytest.mark.parametrize('tag', ['xxxx', 'en-usa', 'en-us-x', '12-us'])
def test_invalid_language_tags_rejected(tag):
    with pytest.raises(InvalidCPEError):
        CanonicalName.from_cpe_2_2('cpe:/a:foo:bar:1.0:::{0}'.format(tag))


def test_special_characters_round_trip_through_all_bindings():
    uri = r'cpe:/a:intel:proset\/wireless_wifi'
    canonical = CanonicalName.from_cpe_2_2(uri)

    assert canonical.as_cpe_2_3_uri() == \
        'cpe:/a:intel:proset%2fwireless_wifi'
    assert canonical.as_cpe_2_3_fs() == \
        r'cpe:2.3:a:intel:proset\/wireless_wifi:*:*:*:*:*:*:*:*'
    assert canonical.as_cpe_2_3_wfn() == \
        r'wfn:[part="a", vendor="intel", product="proset\/wireless_wifi"]'

    assert CanonicalName.from_cpe_2_3_fs(canonical.as_cpe_2_3_fs()) == \
        canonical
    assert CanonicalName.from_cpe_2_3_wfn(canonical.as_cpe_2_3_wfn()) == \
        canonical


def test_convert_helpers_return_loss_information():
    rendered, canonical, losses = convert_2_2_to_2_3(
        'cpe:/a:acme:product:1.0:update2:-:en-us')

    assert rendered == 'cpe:/a:acme:product:1.0:update2:-:en-us'
    assert isinstance(canonical, CanonicalName)
    assert losses and losses[0].reason == 'hyphen_literal_in_2_2'

    uri, _, losses = convert_2_3_to_2_2(
        'cpe:2.3:a:acme:product:1.0:update2:-:en-us:*:*:*:*',
        version='fs', strict=False)
    assert uri == 'cpe:/a:acme:product:1.0:update2::en-us'
    assert losses[0].reason == 'na_not_defined_in_2_2'


def test_batch_conversion_reports_partial_success_with_index():
    names = [
        'cpe:/a:ok:name',
        'baduri',
        'cpe:/a:foo:bar:1.0:::en-us',
        'cpe:/a:foo:bar%zz',
    ]
    report = convert_batch(names, source_version='2.2',
                           target_binding='2.3-fs')

    assert len(report) == 4
    assert report.output_names == [
        'cpe:2.3:a:ok:name:*:*:*:*:*:*:*:*',
        'cpe:2.3:a:foo:bar:1.0:*:*:en-us:*:*:*:*',
        'cpe:2.3:a:foo:bar\\%zz:*:*:*:*:*:*:*:*',
    ]
    failure = report.failures[0]
    assert isinstance(failure, ConversionResult)
    assert failure.index == 1
    assert failure.source == 'baduri'
    assert isinstance(failure.error, InvalidCPEError)


def test_batch_strict_mode_locates_unrepresentable_item():
    report = convert_batch(
        ['cpe:2.3:a:ok:name:*:*:*:*:*:*:*:*',
         'cpe:2.3:a:no:name:*:-:*:*:*:*:*:*'],
        source_version='fs', target_binding='2.2', strict=True)

    assert len(report.successes) == 1
    failure = report.failures[0]
    assert failure.index == 1
    assert isinstance(failure.error, UnrepresentableValueError)
