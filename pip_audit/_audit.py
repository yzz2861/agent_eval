"""
Core auditing APIs.
"""

from __future__ import annotations

import logging
from collections.abc import Iterator
from dataclasses import dataclass, field
from typing import cast

from pip_audit._audit_cache import AuditCache, CacheEntry, CacheStatus, IncompleteDependency
from pip_audit._dependency_source import DependencySource
from pip_audit._service import (
    Dependency,
    ResolvedDependency,
    ServiceError,
    VulnerabilityResult,
    VulnerabilityService,
)

logger = logging.getLogger(__name__)


def _add_unique_vulnerability(
    unique_vulns: list[VulnerabilityResult],
    seen_aliases: set[str],
    vuln: VulnerabilityResult,
) -> None:
    """
    Add a vulnerability result, merging it with an existing alias match.
    """

    if seen_aliases.intersection(vuln.aliases | {vuln.id}):
        idx, previous = next((i, p) for (i, p) in enumerate(unique_vulns) if p.alias_of(vuln))
        unique_vulns[idx] = previous.merge_aliases(vuln)
        return

    seen_aliases.update(vuln.aliases | {vuln.id})
    unique_vulns.append(vuln)


def _unique_vulnerabilities(
    vulns: list[VulnerabilityResult],
) -> list[VulnerabilityResult]:
    """
    Unique vulnerability results based on their alias sets.
    """

    unique_vulns: list[VulnerabilityResult] = []
    seen_aliases: set[str] = set()

    # First pass, add all PYSEC vulnerabilities and track their alias sets.
    for vuln in vulns:
        if not vuln.id.startswith("PYSEC"):
            continue
        _add_unique_vulnerability(unique_vulns, seen_aliases, vuln)

    # Second pass: add any non-PYSEC vulnerabilities.
    for vuln in vulns:
        _add_unique_vulnerability(unique_vulns, seen_aliases, vuln)

    return unique_vulns


@dataclass
class _AuditResultState:
    incomplete: list[IncompleteDependency] = field(default_factory=list)

    def add(self, dep: Dependency, status: CacheStatus, reason: str | None = None) -> None:
        for index, existing in enumerate(self.incomplete):
            if existing.dependency != dep:
                continue
            if existing.status is CacheStatus.FAILED:
                return
            if status is CacheStatus.FAILED:
                self.incomplete[index] = IncompleteDependency(dep, status, reason)
            return
        self.incomplete.append(IncompleteDependency(dep, status, reason))


class AuditResult(Iterator[tuple[Dependency, list[VulnerabilityResult]]]):
    """
    The result of one audit pass.

    This is an iterator of `(dependency, vulnerabilities)` pairs, matching the
    historical `Auditor.audit` contract. After the iterator has been exhausted
    (or interrupted), `incomplete` lists packages that do not have a reusable
    response.
    """

    def __init__(
        self,
        results: Iterator[tuple[Dependency, list[VulnerabilityResult]]],
        state: _AuditResultState,
    ):
        self._results = results
        self._state = state

    def __iter__(self) -> AuditResult:
        return self

    def __next__(self) -> tuple[Dependency, list[VulnerabilityResult]]:
        return next(self._results)

    def close(self) -> None:
        """
        Stop the audit early.

        Closing the result is treated like an interruption: completed responses
        are already in the cache, and the remaining packages are recorded as
        unqueried.
        """

        close = getattr(self._results, "close", None)
        if close is not None:
            close()

    @property
    def incomplete(self) -> list[IncompleteDependency]:
        """
        Dependencies that failed or were not queried during this audit.
        """

        return list(self._state.incomplete)

    @property
    def failed(self) -> list[IncompleteDependency]:
        """
        Dependencies whose query was attempted and failed.
        """

        return [item for item in self._state.incomplete if item.status is CacheStatus.FAILED]

    @property
    def unqueried(self) -> list[IncompleteDependency]:
        """
        Dependencies that were never queried because the audit stopped.
        """

        return [item for item in self._state.incomplete if item.status is CacheStatus.UNQUERIED]

    @property
    def is_complete(self) -> bool:
        """
        Whether every dependency has a completed response.
        """

        return not self._state.incomplete


@dataclass(frozen=True)
class AuditOptions:
    """
    Settings the control the behavior of an `Auditor` instance.
    """

    dry_run: bool = False
    cache: AuditCache | None = None


class Auditor:
    """
    The core class of the `pip-audit` API.

    For a given dependency source and vulnerability service, supply a mapping of dependencies to
    known vulnerabilities.
    """

    def __init__(
        self,
        service: VulnerabilityService,
        options: AuditOptions = AuditOptions(),
    ):
        """
        Create a new auditor. Auditors start with no dependencies to audit;
        each `audit` step is fed a `DependencySource`.

        The behavior of the auditor can be optionally tweaked with the `options`
        parameter.
        """
        self._service = service
        self._options = options
        self._last_result: AuditResult | None = None

    def audit(self, source: DependencySource) -> AuditResult:
        """
        Perform the auditing step, collecting dependencies from `source`.

        Individual vulnerability results are uniqued based on their `aliases` sets:
        any two results for the same dependency that share an alias are collapsed
        into a single result with a union of all aliases.

        `PYSEC`-identified results are given priority over other results.

        If the vulnerability service fails partway through, completed results
        are still yielded and the remaining dependencies are recorded in
        `AuditResult.incomplete`. When an `AuditCache` is configured, completed
        responses are persisted as they arrive, making a later audit resumable.
        """
        specs = list(source.collect())
        state = _AuditResultState()

        if self._options.dry_run:
            logger.info(f"Dry run: would have audited {len(specs)} packages")
            result = AuditResult(iter(()), state)
        else:
            result = AuditResult(self._audit(specs, state), state)

        self._last_result = result
        return result

    @property
    def incomplete(self) -> list[IncompleteDependency]:
        """
        Incomplete dependencies from the most recent audit.
        """

        if self._last_result is None:
            return []
        return self._last_result.incomplete

    def _service_source_id(self) -> str:
        source_id = getattr(self._service, "source_id", None)
        if source_id is None:
            source_id = getattr(self._service, "source", None)
        if source_id is not None:
            if callable(source_id):
                source_id = source_id()
            return str(source_id)

        service_type = type(self._service)
        return f"{service_type.__module__}.{service_type.__qualname__}"

    def _audit(
        self,
        specs: list[Dependency],
        state: _AuditResultState,
    ) -> Iterator[tuple[Dependency, list[VulnerabilityResult]]]:
        cache = self._options.cache
        source_id = self._service_source_id()

        plan: list[tuple[Dependency, CacheEntry | None]] = []
        pending: list[Dependency] = []
        for spec in specs:
            entry = cache.lookup(source_id, spec) if cache is not None else None
            plan.append((spec, entry))
            if entry is None:
                pending.append(spec)

        if not pending:
            for spec, entry in plan:
                assert entry is not None
                yield spec, _unique_vulnerabilities(list(entry.results))
            return

        completed = False
        current: Dependency | None = None
        pending_index = 0
        plan_index = -1

        def cached_after(index: int) -> Iterator[tuple[Dependency, list[VulnerabilityResult]]]:
            for later_spec, later_entry in plan[index + 1 :]:
                if later_entry is not None:
                    yield later_spec, _unique_vulnerabilities(list(later_entry.results))

        try:
            responses = iter(self._service.query_all(iter(pending)))
            for plan_index, (spec, entry) in enumerate(plan):
                if entry is not None:
                    yield spec, _unique_vulnerabilities(list(entry.results))
                    continue

                current = pending[pending_index]
                try:
                    dep, vulns = next(responses)
                except StopIteration:
                    reason = _missing_response_reason(current)
                    if cache is not None:
                        cache.record_failure(source_id, current, reason)
                    state.add(current, CacheStatus.FAILED, reason)
                    logger.error(reason)
                    yield from cached_after(plan_index)
                    return

                pending_index += 1
                current = None

                if cache is not None:
                    cache.record_response(source_id, dep, vulns)

                yield dep, _unique_vulnerabilities(vulns)

            completed = True
        except ServiceError as exc:
            reason = _service_error_reason(exc)
            if current is None and pending_index < len(pending):
                current = pending[pending_index]
            if current is not None:
                if cache is not None:
                    cache.record_failure(source_id, current, reason)
                state.add(current, CacheStatus.FAILED, reason)
            logger.error(
                f"Vulnerability service stopped after {pending_index} of "
                f"{len(pending)} pending queries: {reason}"
            )
            yield from cached_after(plan_index)
            return
        finally:
            if not completed:
                remaining = pending[pending_index:]
                if cache is not None and remaining:
                    cache.record_unqueried(source_id, remaining)
                for dep in remaining:
                    state.add(dep, CacheStatus.UNQUERIED, _unqueried_reason(dep))


def _missing_response_reason(dep: Dependency) -> str:
    if dep.is_skipped():
        return f"vulnerability service returned no response for {dep.name}"
    resolved = cast(ResolvedDependency, dep)
    return (
        "vulnerability service returned no response for "
        f"{resolved.canonical_name} ({resolved.version})"
    )


def _service_error_reason(exc: ServiceError) -> str:
    message = str(exc).strip()
    return message or type(exc).__name__


def _unqueried_reason(dep: Dependency) -> str:
    if dep.is_skipped():
        return "not queried after the audit stopped"
    resolved = cast(ResolvedDependency, dep)
    return f"{resolved.canonical_name} ({resolved.version}) was not queried after the audit stopped"
