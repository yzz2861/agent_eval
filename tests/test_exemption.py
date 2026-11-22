import pytest
from packaging.version import Version

from pip_audit._deployment import (
    ExemptionCatalogError,
    ExemptionDecision,
    read_exemption_catalog,
)


@pytest.fixture
def catalog(exemption_file):
    return read_exemption_catalog(exemption_file)


def test_registered_roles_parsed(catalog):
    assert catalog.is_role_registered("build-host") is True
    assert catalog.is_role_registered("runtime-image") is True
    assert catalog.is_role_registered("legacy-ci") is False


def test_exemption_only_matches_explicit_role(catalog):
    evaluation = catalog.evaluate(
        role="runtime-image",
        name="requests",
        version=Version("2.32.2"),
        advisory_id="PYSEC-2024-REQUESTS",
        aliases=set(),
    )
    assert evaluation.decision is ExemptionDecision.RoleMismatch
    assert evaluation.exemption.role == "build-host"
    assert evaluation.is_applied is False

    applied = catalog.evaluate(
        role="build-host",
        name="requests",
        version=Version("2.32.2"),
        advisory_id="PYSEC-2024-REQUESTS",
        aliases=set(),
    )
    assert applied.decision is ExemptionDecision.Applied
    assert applied.is_applied is True


def test_alias_advisory_matches(catalog):
    evaluation = catalog.evaluate(
        role="runtime-image",
        name="urllib3",
        version=Version("2.2.1"),
        advisory_id="PYSEC-2024-URLLIB3",
        aliases={"GHSA-urllib3-cookie", "CVE-2024-37891"},
    )
    assert evaluation.decision is ExemptionDecision.Applied


def test_unregistered_role_entry_is_retained(catalog):
    evaluation = catalog.evaluate(
        role="runtime-image",
        name="jinja2",
        version=Version("3.1.4"),
        advisory_id="PYSEC-2025-JINJA2",
        aliases=set(),
    )
    assert evaluation.decision is ExemptionDecision.RoleNotRegistered
    assert evaluation.exemption.role == "legacy-ci"
    assert evaluation.is_applied is False


def test_unknown_package_is_package_mismatch(catalog):
    evaluation = catalog.evaluate(
        role="runtime-image",
        name="totally-unknown",
        version=Version("1.0.0"),
        advisory_id="PYSEC-9999",
        aliases=set(),
    )
    assert evaluation.decision is ExemptionDecision.PackageMismatch
    assert evaluation.exemption is None


def test_version_mismatch_is_package_mismatch(catalog):
    evaluation = catalog.evaluate(
        role="build-host",
        name="wheel",
        version=Version("9.9.9"),
        advisory_id="PYSEC-2024-WHEEL",
        aliases=set(),
    )
    assert evaluation.decision is ExemptionDecision.PackageMismatch


def test_missing_exemption_file_raises(tmp_path):
    with pytest.raises(ExemptionCatalogError, match="not found"):
        read_exemption_catalog(tmp_path / "missing.toml")


def test_bad_registered_roles_raises(tmp_path):
    bad = tmp_path / "bad.toml"
    bad.write_text("registered_roles = []\n", encoding="utf-8")
    with pytest.raises(ExemptionCatalogError, match="registered_roles"):
        read_exemption_catalog(bad)
