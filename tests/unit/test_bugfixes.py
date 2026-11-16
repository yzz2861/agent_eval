from cpe import CPE
from cpe.cpe2_3_fs import CPE2_3_FS
from cpe.cpe2_3_uri import CPE2_3_URI

import pytest


def test_issue_8():
    """TEST multiple %01 wildcards."""
    current = CPE2_3_URI('cpe:/a:microsoft:internet_explorer:%01%018.%02:%02s%01%01%01').as_wfn()
    expected = 'wfn:[part="a", vendor="microsoft", product="internet_explorer", version="??8\\.*", update="*s???"]'
    assert current == expected


def test_issue_11():
    """TEST: correctly transform not applicable values for edition."""
    current = CPE('wfn:[part="a", vendor="TauPan", product="cpelib", version="1\\.0\\.5", update=NA, edition=NA]').as_uri_2_3()
    expected = 'cpe:/a:taupan:cpelib:1.0.5:-:-'
    assert current == expected


def test_oversized_input_rejected_before_parsing():
    """TEST: an 8 MB CPE string is rejected before parsing or copying it."""
    big = 'cpe:2.3:a:' + 'x' * (8 * 1024 * 1024) + ':p:v:u:e:es-es:se:ts:th:o'

    with pytest.raises(ValueError) as excinfo:
        CPE2_3_FS(big)
    assert 'too long' in str(excinfo.value)
    # The error must not embed the input itself
    assert len(str(excinfo.value)) < 200

    # The factory converts the failure into NotImplementedError
    with pytest.raises(NotImplementedError):
        CPE(big)


def test_overlong_field_rejected_with_position():
    """TEST: a component value over the field budget fails with its position."""
    field = 'v' * (CPE2_3_FS.MAX_FIELD_LENGTH + 1)
    cpe_str = 'cpe:2.3:a:' + field + ':product:1.0:*:*:*:*:*'

    with pytest.raises(ValueError) as excinfo:
        CPE2_3_FS(cpe_str)

    # The vendor field starts right after 'cpe:2.3:a:'
    expected_pos = len('cpe:2.3:a:')
    assert 'position {0}'.format(expected_pos) in str(excinfo.value)
    assert field not in str(excinfo.value)


def test_too_many_components_rejected_with_position():
    """TEST: repeated separators beyond 11 components fail with position."""
    cpe_str = 'cpe:2.3:a:b:c:d:e:f:g:h:i:j:k:l'

    with pytest.raises(ValueError) as excinfo:
        CPE2_3_FS(cpe_str)

    # The eleventh separator is the one over the budget
    expected_pos = cpe_str.rindex(':')
    assert 'too many components' in str(excinfo.value)
    assert 'position {0}'.format(expected_pos) in str(excinfo.value)

    # A run of bare separators hits the same budget
    with pytest.raises(ValueError) as excinfo:
        CPE2_3_FS('cpe:2.3:a' + ':' * 100)
    assert 'too many components' in str(excinfo.value)


def test_unterminated_escape_rejected_with_position():
    """TEST: a dangling escape at the end of input fails with its position."""
    cpe_str = 'cpe:2.3:a:mozilla:firefox:2.0:*:*:*:*:*' + '\\'

    with pytest.raises(ValueError) as excinfo:
        CPE2_3_FS(cpe_str)

    assert 'unterminated escape' in str(excinfo.value)
    assert 'position {0}'.format(len(cpe_str) - 1) in str(excinfo.value)


def test_escape_depth_rejected_with_position():
    """TEST: escape runs deeper than the budget fail with their position."""
    cpe_str = 'cpe:2.3:a:' + '\\' * (CPE2_3_FS.MAX_ESCAPE_DEPTH + 1) + \
        ':p:v:u:e:es-es:se:ts:th:o'

    with pytest.raises(ValueError) as excinfo:
        CPE2_3_FS(cpe_str)

    assert 'escape depth' in str(excinfo.value)
    assert 'position {0}'.format(len('cpe:2.3:a:')) in str(excinfo.value)


def test_truncated_input_reports_end_position():
    """TEST: truncated CPE names report the missing components."""
    cpe_str = 'cpe:2.3:a:mozilla:firefox'

    with pytest.raises(ValueError) as excinfo:
        CPE2_3_FS(cpe_str)

    assert 'found 3' in str(excinfo.value)
    assert 'position {0}'.format(len(cpe_str)) in str(excinfo.value)


def test_valid_formatted_strings_still_parse():
    """TEST: normal values and factory return types are unchanged."""
    cpe_str = 'cpe:2.3:a:mozilla:firefox:2.0.0.6:*:osx:es-es:*:*:*:*'
    c = CPE(cpe_str)
    assert isinstance(c, CPE2_3_FS)
    assert c.as_fs() == cpe_str
    assert c.get_vendor() == ['mozilla']

    # Escaped separators stay inside their component
    c = CPE2_3_FS('cpe:2.3:a:vendor\\:name:product:1.0:*:*:*:*:*:*:*')
    assert c.get_vendor() == ['vendor\\:name']

    # A long but in-budget field parses fine
    vendor = 'v' * 512
    c = CPE2_3_FS('cpe:2.3:a:' + vendor + ':product:1.0:*:*:*:*:*:*:*')
    assert c.get_vendor() == [vendor]
