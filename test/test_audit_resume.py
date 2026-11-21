from __future__ import annotations

import json
from pathlib import Path

from packaging.version import Version

from pip_audit._audit import AuditOptions, Auditor, AuditResult
from pip_audit._audit_cache import AuditCache, CacheStatus
from pip_audit._dependency_source.interface import DependencySource
from pip_audit._format import JsonFormat
from pip_audit._service import (
    Dependency,
    ResolvedDependency,
    ServiceError,
    VulnerabilityResult,
    VulnerabilityService,
)

ALPHA = ResolvedDependency(name="alpha-demo", version=Version("1.0.0"))
BETA = ResolvedDependency(name="beta-demo", version=Version("2.0.0"))
GAMMA = ResolvedDependency(name="gamma-demo", version=Version("3.0.0"))
DELTA = ResolvedDependency(name="delta-demo", version=Version("4.0.0"))


def fake_vuln(identifier: str = "FAKE-0001") -> VulnerabilityResult:
    return VulnerabilityResult(
        id=identifier,
        description="fictional advisory for a fictional package",
        fix_versions=[Version("9.9.9")],
        aliases={identifier + "-ALIAS"},
    )


class MemoryAdvisorySource(VulnerabilityService):
    def __init__(
        self,
        source_id: str = "memory-advisory",
        responses: dict[str, list[VulnerabilityResult]] | None = None,
        abort_after: int | None = None,
    ) -> None:
        self._source_id = source_id
        self.responses = responses or {}
        self.abort_after = abort_after
        self.queries: list[str] = []

    @property
    def source_id(self) -> str:
        return self._source_id

    def query(self, spec: Dependency) -> tuple[Dependency, list[VulnerabilityResult]]:
        self.queries.append(spec.canonical_name)
        if self.abort_after is not None and len(self.queries) > self.abort_after:
            raise ServiceError("quota exhausted")
        return spec, list(self.responses.get(spec.canonical_name, []))


class MemoryDependencySource(DependencySource):
    def __init__(self, dependencies: list[Dependency]) -> None:
        self.dependencies = list(dependencies)

    def collect(self):
        yield from self.dependencies

    def fix(self, _fix) -> None:
        raise NotImplementedError


def run_audit(
    dependencies: list[Dependency],
    service: VulnerabilityService,
    cache_path: Path | None = None,
    cache: AuditCache | None = None,
) -> tuple[AuditResult, dict, AuditCache, list[tuple[Dependency, list[VulnerabilityResult]]]]:
    if cache is None:
        cache = AuditCache(cache_path)
    auditor = Auditor(service, AuditOptions(cache=cache))
    audit_result = auditor.audit(MemoryDependencySource(dependencies))
    rows = list(audit_result)
    output = json.loads(JsonFormat(True, True).format(dict(rows), [], audit_result.incomplete))
    return audit_result, output, cache, rows


def test_quota_abort_returns_partial_json_and_separates_outcomes() -> None:
    service = MemoryAdvisorySource(
        responses={ALPHA.canonical_name: [fake_vuln()]},
        abort_after=2,
    )

    audit_result, output, cache, rows = run_audit([ALPHA, BETA, GAMMA, DELTA], service)

    assert [dep.canonical_name for dep, _ in rows] == ["alpha-demo", "beta-demo"]
    assert output["dependencies"][0]["name"] == "alpha-demo"
    assert output["dependencies"][0]["vulns"][0]["id"] == "FAKE-0001"
    assert output["dependencies"][1]["name"] == "beta-demo"
    assert output["dependencies"][1]["vulns"] == []
    assert output["incomplete"] == [
        {
            "name": "gamma-demo",
            "status": "failed",
            "version": "3.0.0",
            "reason": "quota exhausted",
        },
        {
            "name": "delta-demo",
            "status": "unqueried",
            "version": "4.0.0",
            "reason": "delta-demo (4.0.0) was not queried after the audit stopped",
        },
    ]
    assert service.queries == ["alpha-demo", "beta-demo", "gamma-demo"]

    assert [key.name for key in cache.completed] == ["alpha-demo"]
    assert [key.name for key in cache.empty] == ["beta-demo"]
    assert [key.name for key in cache.failed] == ["gamma-demo"]
    assert [key.name for key in cache.unqueried] == ["delta-demo"]
    assert audit_result.is_complete is False


def test_interrupted_audit_resumes_without_requerying_or_losing_hit(tmp_path: Path) -> None:
    cache_path = tmp_path / "audit-cache.json"
    responses = {
        ALPHA.canonical_name: [fake_vuln("FAKE-ALPHA")],
        BETA.canonical_name: [fake_vuln("FAKE-BETA")],
    }
    first_service = MemoryAdvisorySource(responses=responses)
    cache = AuditCache(cache_path)
    first_result = Auditor(first_service, AuditOptions(cache=cache)).audit(
        MemoryDependencySource([ALPHA, BETA, GAMMA, DELTA])
    )

    first_dep, first_vulns = next(first_result)
    first_result.close()

    assert first_dep == ALPHA
    assert first_vulns[0].id == "FAKE-ALPHA"
    assert [key.name for key in cache.completed] == ["alpha-demo"]
    assert [key.name for key in cache.empty] == []
    assert [key.name for key in cache.failed] == []
    assert [key.name for key in cache.unqueried] == ["beta-demo", "gamma-demo", "delta-demo"]
    before = json.loads(
        JsonFormat(True, True).format({first_dep: first_vulns}, [], first_result.incomplete)
    )
    assert before["incomplete"][0]["status"] == "unqueried"

    second_service = MemoryAdvisorySource(responses=responses)
    second_result, after, second_cache, rows = run_audit(
        [ALPHA, BETA, GAMMA, DELTA], second_service, cache_path=cache_path
    )

    assert second_service.queries == ["beta-demo", "gamma-demo", "delta-demo"]
    assert [dep.canonical_name for dep, _ in rows] == [
        "alpha-demo",
        "beta-demo",
        "gamma-demo",
        "delta-demo",
    ]
    assert after["dependencies"][0] == before["dependencies"][0]
    assert after["dependencies"][1]["vulns"][0]["id"] == "FAKE-BETA"
    assert "incomplete" not in after
    assert second_result.is_complete is True
    assert [key.name for key in second_cache.completed] == ["alpha-demo", "beta-demo"]


def test_resume_after_quota_failure_preserves_prior_json_hits(tmp_path: Path) -> None:
    cache_path = tmp_path / "audit-cache.json"
    first_service = MemoryAdvisorySource(
        responses={ALPHA.canonical_name: [fake_vuln("FAKE-ALPHA")]},
        abort_after=2,
    )
    _, before, _, _ = run_audit([ALPHA, BETA, GAMMA, DELTA], first_service, cache_path=cache_path)
    assert before["dependencies"][0]["vulns"][0]["id"] == "FAKE-ALPHA"
    assert [item["name"] for item in before["incomplete"]] == ["gamma-demo", "delta-demo"]

    second_service = MemoryAdvisorySource(
        responses={GAMMA.canonical_name: [fake_vuln("FAKE-GAMMA")]},
        abort_after=1,
    )
    _, after, cache, rows = run_audit(
        [ALPHA, BETA, GAMMA, DELTA], second_service, cache_path=cache_path
    )

    assert second_service.queries == ["gamma-demo", "delta-demo"]
    assert [dep.canonical_name for dep, _ in rows] == ["alpha-demo", "beta-demo", "gamma-demo"]
    assert after["dependencies"][0] == before["dependencies"][0]
    assert after["dependencies"][2]["vulns"][0]["id"] == "FAKE-GAMMA"
    assert after["incomplete"] == [
        {
            "name": "delta-demo",
            "status": "failed",
            "version": "4.0.0",
            "reason": "quota exhausted",
        }
    ]
    assert [key.name for key in cache.completed] == ["alpha-demo", "gamma-demo"]
    assert [key.name for key in cache.empty] == ["beta-demo"]


def test_cache_reuses_only_matching_source_and_query() -> None:
    cache = AuditCache()
    cache.record_response("advisor-a", ALPHA, [fake_vuln()])

    assert cache.lookup("advisor-a", ALPHA) is not None
    assert cache.lookup("advisor-b", ALPHA) is None

    other_version = ResolvedDependency(name=ALPHA.name, version=Version("1.0.1"))
    assert cache.lookup("advisor-a", other_version) is None

    cache.record_response("advisor-a", BETA, [], query={"ecosystem": "PyPI"})
    assert cache.lookup("advisor-a", BETA, query={"ecosystem": "PyPI"}) is not None
    assert cache.lookup("advisor-a", BETA, query={"ecosystem": "npm"}) is None
    assert cache.lookup("advisor-a", BETA) is None


def test_empty_failed_and_unqueried_are_persisted_separately(tmp_path: Path) -> None:
    cache = AuditCache()
    cache.record_response("advisor-a", ALPHA, [fake_vuln()])
    cache.record_response("advisor-a", BETA, [])
    cache.record_failure("advisor-a", GAMMA, "network timed out")
    cache.record_unqueried("advisor-a", [DELTA])

    # A later failure for a package that already has a trusted response must
    # not replace that response.
    cache.record_failure("advisor-a", ALPHA, "later outage")

    data = cache.to_dict()
    assert [entry["query"]["name"] for entry in data["completed"]] == ["alpha-demo"]
    assert [entry["query"]["name"] for entry in data["empty"]] == ["beta-demo"]
    assert [entry["query"]["name"] for entry in data["failed"]] == ["gamma-demo"]
    assert [entry["query"]["name"] for entry in data["unqueried"]] == ["delta-demo"]

    cache_path = tmp_path / "audit-cache.json"
    cache.save(cache_path)
    loaded = AuditCache.load(cache_path)

    assert loaded.lookup("advisor-a", ALPHA) is not None
    assert loaded.lookup("advisor-a", BETA) is not None
    assert loaded.lookup("advisor-a", GAMMA) is None
    assert loaded.lookup("advisor-a", DELTA) is None
    assert [key.name for key in loaded.completed] == ["alpha-demo"]
    assert [key.name for key in loaded.empty] == ["beta-demo"]
    assert [key.name for key in loaded.failed] == ["gamma-demo"]
    assert [key.name for key in loaded.unqueried] == ["delta-demo"]
    gamma_key = next(iter(loaded.failed))
    assert loaded.failed[gamma_key].status is CacheStatus.FAILED
    assert loaded.failed[gamma_key].reason == "network timed out"


def test_failure_before_a_cached_hit_still_reports_the_cached_hit() -> None:
    cache = AuditCache()
    cache.record_response("memory-advisory", GAMMA, [fake_vuln("FAKE-GAMMA")])
    service = MemoryAdvisorySource(abort_after=0)

    _, output, _, rows = run_audit([ALPHA, GAMMA, BETA], service, cache=cache)

    assert service.queries == ["alpha-demo"]
    assert [dep.canonical_name for dep, _ in rows] == ["gamma-demo"]
    assert output["dependencies"][0]["name"] == "gamma-demo"
    assert output["dependencies"][0]["vulns"][0]["id"] == "FAKE-GAMMA"
    assert output["incomplete"] == [
        {
            "name": "alpha-demo",
            "status": "failed",
            "version": "1.0.0",
            "reason": "quota exhausted",
        },
        {
            "name": "beta-demo",
            "status": "unqueried",
            "version": "2.0.0",
            "reason": "beta-demo (2.0.0) was not queried after the audit stopped",
        },
    ]
