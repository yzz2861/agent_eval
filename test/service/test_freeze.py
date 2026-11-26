import pytest
from packaging.version import Version

from pip_audit._service import (
    FreezeFixtureError,
    FreezeService,
    FrozenService,
    ResolvedDependency,
    snapshot_from_dict,
)


def test_freeze_service_judged_and_clean(asset):
    service = FreezeService(asset("diff/advisories-old.json"))

    dependency = ResolvedDependency("alpha", Version("1.0"))
    result = service.query_with_status(dependency)
    assert result.status == "audited"
    assert [vuln.id for vuln in result.vulnerabilities] == ["PYSEC-2025-1"]
    assert result.vulnerabilities[0].aliases == {"CVE-2025-0001"}
    assert [str(version) for version in result.vulnerabilities[0].fix_versions] == ["1.1"]

    clean = service.query_with_status(ResolvedDependency("gamma", Version("3.0")))
    assert clean.status == "audited"
    assert clean.vulnerabilities == ()


def test_freeze_service_keeps_unknown(asset):
    service = FreezeService(asset("diff/advisories-old.json"))

    # zeta is intentionally absent from the snapshot's coverage section.
    unknown = service.query_with_status(ResolvedDependency("zeta", Version("6.0")))
    assert unknown.status == "unknown"
    assert "no judgment" in (unknown.reason or "")
    assert service.query(ResolvedDependency("zeta", Version("6.0"))) == (
        ResolvedDependency("zeta", Version("6.0")),
        [],
    )

    # Coverage can be version-specific too.
    unknown_version = service.query_with_status(
        ResolvedDependency("alpha", Version("9.9"))
    )
    assert unknown_version.status == "unknown"


def test_freeze_service_is_frozen_alias(asset):
    service = FrozenService(asset("diff/advisories-new.json"))
    assert service.snapshot_name == "advisories-2025-02"


def test_snapshot_from_osv_style_mapping():
    snapshot = snapshot_from_dict(
        {
            "snapshot": "osv-test",
            "coverage": {"foo": ["0.9", "1.0"]},
            "advisories": [
                {
                    "id": "GHSA-test",
                    "aliases": ["CVE-2026-0001"],
                    "affected": [
                        {
                            "package": {"name": "foo", "ecosystem": "PyPI"},
                            "ranges": [
                                {
                                    "type": "ECOSYSTEM",
                                    "events": [{"introduced": "0.9"}, {"fixed": "1.0"}],
                                }
                            ],
                        }
                    ],
                }
            ],
        }
    )

    assert snapshot.name == "osv-test"
    assert len(snapshot.advisories_for("foo", Version("0.9"))) == 1
    assert snapshot.advisories_for("foo", Version("1.0")) == ()
    assert not snapshot.covers("bar", "1.0")


def test_invalid_freeze_fixture():
    with pytest.raises(FreezeFixtureError):
        snapshot_from_dict({"advisories": [{"package": "foo"}]})

    with pytest.raises(FreezeFixtureError):
        snapshot_from_dict({"advisories": [{"id": "X", "package": "foo", "ranges": "bad"}]})
