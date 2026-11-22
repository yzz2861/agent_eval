import pytest
from packaging.version import Version

from pip_audit._deployment import OfflineAdvisoryServiceError
from pip_audit._deployment.offline import OfflineAdvisoryService
from pip_audit._service.interface import ResolvedDependency, SkippedDependency


@pytest.fixture
def service(advisory_snapshot):
    return OfflineAdvisoryService(advisory_snapshot)


def test_offline_query_returns_pinned_advisory(service):
    dep = ResolvedDependency(name="requests", version=Version("2.32.2"))
    returned, results = service.query(dep)

    assert returned.canonical_name == "requests"
    assert len(results) == 1
    result = results[0]
    assert result.id == "PYSEC-2024-REQUESTS"
    assert result.fix_versions == [Version("2.32.4")]
    assert "CVE-2024-35195" in result.aliases


def test_offline_query_clean_package_returns_empty(service):
    dep = ResolvedDependency(name="certifi", version=Version("2025.1.31"))
    _returned, results = service.query(dep)
    assert results == []


def test_offline_query_skipped_dependency_passthrough(service):
    skipped = SkippedDependency(name="internal-utils", skip_reason="no version specified")
    returned, results = service.query(skipped)
    assert returned is skipped
    assert results == []


def test_advisory_for_helper(service):
    advisories = service.advisory_for("Requests", Version("2.32.2"))
    assert len(advisories) == 1
    assert advisories[0].id == "PYSEC-2024-REQUESTS"


def test_missing_snapshot_raises(tmp_path):
    with pytest.raises(OfflineAdvisoryServiceError, match="not found"):
        OfflineAdvisoryService(tmp_path / "missing.json")


def test_bad_schema_raises(tmp_path):
    bad = tmp_path / "bad.json"
    bad.write_text("{\"schema\": \"other/v0\", \"advisories\": []}", encoding="utf-8")
    with pytest.raises(OfflineAdvisoryServiceError, match="unsupported schema"):
        OfflineAdvisoryService(bad)
