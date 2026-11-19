import pytest

from detect_secrets.exception_policy import RuleVersion


def test_parse_and_render():
    version = RuleVersion.parse("AWS", "2.5.9")
    assert version.to_string() == "2.5.9"
    assert version.to_dict() == {"name": "AWS", "version": "2.5.9"}


@pytest.mark.parametrize(
    "approved, current, expected",
    [
        ("1.4.0", "1.4.0", True),
        ("1.4.0", "1.9.7", True),
        ("1.4.0", "2.0.0", False),
        ("2.0.0", "1.9.0", False),
    ],
)
def test_compatibility(approved, current, expected):
    base = RuleVersion.parse("AWS", approved)
    assert base.is_compatible_with(RuleVersion.parse("AWS", current)) is expected


def test_different_rule_name_is_incompatible():
    base = RuleVersion.parse("AWS", "1.0.0")
    assert base.is_compatible_with(RuleVersion.parse("GCP", "1.0.0")) is False


def test_invalid_version_raises():
    with pytest.raises(ValueError):
        RuleVersion.parse("AWS", "v1.0")
