"""
Resumable, per-query caching for vulnerability audits.

The HTTP cache used by the individual vulnerability services is deliberately
separate from this cache: an HTTP cache entry only means that a response was
seen, not that the response belonged to this audit's source and query. This
module records query outcomes so that an interrupted audit can be resumed
without re-querying completed work, while still keeping empty responses,
unqueried packages, and failed queries distinct.
"""

from __future__ import annotations

import json
import logging
import os
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from pathlib import Path
from tempfile import NamedTemporaryFile
from typing import Any, cast

from packaging.version import Version

from pip_audit._service.interface import (
    Dependency,
    ResolvedDependency,
    SkippedDependency,
    VulnerabilityID,
    VulnerabilityResult,
)

logger = logging.getLogger(__name__)

_CACHE_FORMAT_VERSION = 1


class CacheStatus(str, Enum):
    """
    The state of a single source/query pair in an `AuditCache`.
    """

    COMPLETE = "complete"
    EMPTY = "empty"
    FAILED = "failed"
    UNQUERIED = "unqueried"

    @property
    def reusable(self) -> bool:
        """
        Whether this record is a completed response that can be reused.

        Both non-empty and empty responses are completed responses. Failed and
        never-queried records are deliberately not reusable.
        """

        return self in (CacheStatus.COMPLETE, CacheStatus.EMPTY)


def _stringify_query_value(value: Any) -> str:
    if isinstance(value, (str, int, float, bool)):
        return str(value)
    return json.dumps(value, sort_keys=True, separators=(",", ":"))


@dataclass(frozen=True)
class QueryKey:
    """
    An identity for one vulnerability query.

    The source is part of the key to prevent responses from one advisory
    source being reused for another source. The remaining fields capture the
    query conditions. `query` contains any additional, source-specific query
    parameters, normalized into sorted string pairs.
    """

    source: str
    name: str
    version: str | None = None
    skip_reason: str | None = None
    query: tuple[tuple[str, str], ...] = ()

    @classmethod
    def from_dependency(
        cls,
        source: str,
        spec: Dependency,
        query: Mapping[str, Any] | None = None,
    ) -> QueryKey:
        """
        Build a key from a dependency and optional extra query parameters.
        """

        conditions: dict[str, str] = {}
        if query is not None:
            conditions.update(
                (str(key), _stringify_query_value(value))
                for key, value in sorted(query.items(), key=lambda item: str(item[0]))
            )

        name = conditions.pop("name", spec.canonical_name)
        version = conditions.pop("version", None)
        skip_reason = conditions.pop("skip_reason", None)

        if spec.is_skipped():
            skip_reason = skip_reason or spec.skip_reason
        elif version is None:
            version = str(spec.version)

        return cls(
            source=source,
            name=name,
            version=version,
            skip_reason=skip_reason,
            query=tuple(sorted(conditions.items())),
        )

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> QueryKey:
        """
        Deserialize a key from its JSON representation.
        """

        source = str(data["source"])
        raw_query = data.get("query", {})
        if not isinstance(raw_query, Mapping):
            raise ValueError("query must be an object")

        conditions = {str(key): _stringify_query_value(value) for key, value in raw_query.items()}
        name = conditions.pop("name")
        version = conditions.pop("version", None)
        skip_reason = conditions.pop("skip_reason", None)
        return cls(
            source=source,
            name=name,
            version=version,
            skip_reason=skip_reason,
            query=tuple(sorted(conditions.items())),
        )

    def to_dict(self) -> dict[str, Any]:
        """
        Serialize the key to a JSON-compatible object.
        """

        query: dict[str, Any] = {"name": self.name}
        if self.version is not None:
            query["version"] = self.version
        if self.skip_reason is not None:
            query["skip_reason"] = self.skip_reason
        query.update(dict(self.query))
        return {"source": self.source, "query": query}


@dataclass(frozen=True)
class CacheEntry:
    """
    The recorded outcome of a single source/query pair.
    """

    key: QueryKey
    status: CacheStatus
    results: tuple[VulnerabilityResult, ...] = ()
    reason: str | None = None

    @property
    def reusable(self) -> bool:
        """
        Whether this entry can satisfy a query without contacting the source.
        """

        return self.status.reusable

    def to_dict(self) -> dict[str, Any]:
        """
        Serialize the entry, including its status.
        """

        data = self.key.to_dict()
        data["status"] = self.status.value
        data["results"] = [_vuln_to_dict(vuln) for vuln in self.results]
        if self.reason is not None:
            data["reason"] = self.reason
        return data


@dataclass(frozen=True)
class IncompleteDependency:
    """
    A dependency whose query did not produce a reusable response.
    """

    dependency: Dependency
    status: CacheStatus
    reason: str | None = None

    def __post_init__(self) -> None:
        if self.status not in (CacheStatus.FAILED, CacheStatus.UNQUERIED):
            raise ValueError(f"{self.status.value!r} is not an incomplete status")

    @property
    def name(self) -> str:
        """
        The dependency's canonical name.
        """

        return self.dependency.canonical_name

    @property
    def version(self) -> str | None:
        """
        The dependency's version, if it is a resolved dependency.
        """

        if self.dependency.is_skipped():
            return None
        return str(cast(ResolvedDependency, self.dependency).version)

    def to_dict(self) -> dict[str, Any]:
        """
        Serialize the incomplete dependency for reports.
        """

        data: dict[str, Any] = {"name": self.name, "status": self.status.value}
        if self.version is not None:
            data["version"] = self.version
        if self.dependency.is_skipped():
            skipped = self.dependency
            assert isinstance(skipped, SkippedDependency)
            data["skip_reason"] = skipped.skip_reason
        if self.reason is not None:
            data["reason"] = self.reason
        return data


def _vuln_to_dict(vuln: VulnerabilityResult) -> dict[str, Any]:
    data: dict[str, Any] = {
        "id": vuln.id,
        "description": vuln.description,
        "fix_versions": [str(version) for version in vuln.fix_versions],
        "aliases": sorted(vuln.aliases),
    }
    if vuln.published is not None:
        data["published"] = vuln.published.isoformat()
    return data


def _vuln_from_dict(data: Mapping[str, Any]) -> VulnerabilityResult:
    published: datetime | None = None
    if data.get("published") is not None:
        published = datetime.fromisoformat(str(data["published"]))

    return VulnerabilityResult(
        id=VulnerabilityID(str(data["id"])),
        description=str(data.get("description", "")),
        fix_versions=[Version(str(version)) for version in data.get("fix_versions", [])],
        aliases={VulnerabilityID(str(alias)) for alias in data.get("aliases", [])},
        published=published,
    )


class AuditCache:
    """
    A resumable cache of per-query audit responses.

    Entries are separated by outcome:

    * `completed`: non-empty vulnerability response
    * `empty`: completed response with no vulnerabilities
    * `failed`: query was attempted but failed
    * `unqueried`: package was known but never queried

    Only `completed` and `empty` entries are reused. A failure or an
    interrupted run can therefore never erase an earlier trusted response.
    """

    def __init__(self, path: str | Path | None = None):
        """
        Create a cache.

        When `path` is supplied and exists, it is loaded immediately. Mutations
        are persisted to `path` atomically, so a process interruption leaves all
        responses completed before the interruption available to a later run.
        """

        self._path = Path(path).expanduser() if path is not None else None
        self._entries: dict[QueryKey, CacheEntry] = {}
        self._dependencies: dict[QueryKey, Dependency] = {}
        if self._path is not None and self._path.exists():
            self._load_file(self._path)

    @property
    def path(self) -> Path | None:
        """
        The cache file path, if this cache is persistent.
        """

        return self._path

    @property
    def entries(self) -> dict[QueryKey, CacheEntry]:
        """
        All cache entries, keyed by source and normalized query conditions.
        """

        return dict(self._entries)

    @property
    def completed(self) -> dict[QueryKey, CacheEntry]:
        """
        Completed responses that contained at least one vulnerability.
        """

        return self._with_status(CacheStatus.COMPLETE)

    @property
    def empty(self) -> dict[QueryKey, CacheEntry]:
        """
        Completed responses that contained no vulnerabilities.
        """

        return self._with_status(CacheStatus.EMPTY)

    @property
    def failed(self) -> dict[QueryKey, CacheEntry]:
        """
        Queries that were attempted and failed.
        """

        return self._with_status(CacheStatus.FAILED)

    @property
    def unqueried(self) -> dict[QueryKey, CacheEntry]:
        """
        Packages that are known but were never queried.
        """

        return self._with_status(CacheStatus.UNQUERIED)

    @property
    def pending(self) -> dict[QueryKey, CacheEntry]:
        """
        Alias for `unqueried`.
        """

        return self.unqueried

    def _with_status(self, status: CacheStatus) -> dict[QueryKey, CacheEntry]:
        return {key: entry for key, entry in self._entries.items() if entry.status is status}

    def lookup(
        self,
        source: str,
        spec: Dependency,
        query: Mapping[str, Any] | None = None,
    ) -> CacheEntry | None:
        """
        Return a reusable completed response, or `None`.

        The lookup is strict: the source and every query condition must match.
        Failed and unqueried records are intentionally not returned.
        """

        return self.lookup_key(QueryKey.from_dependency(source, spec, query))

    def get(
        self,
        source: str,
        spec: Dependency,
        query: Mapping[str, Any] | None = None,
    ) -> CacheEntry | None:
        """
        Alias for `lookup`.
        """

        return self.lookup(source, spec, query)

    def lookup_key(self, key: QueryKey) -> CacheEntry | None:
        """
        Look up a key directly.
        """

        entry = self._entries.get(key)
        if entry is not None and entry.reusable:
            return entry
        return None

    def record_response(
        self,
        source: str,
        spec: Dependency,
        results: Sequence[VulnerabilityResult],
        query: Mapping[str, Any] | None = None,
    ) -> CacheEntry:
        """
        Record a completed response, classifying it as `completed` or `empty`.
        """

        key = QueryKey.from_dependency(source, spec, query)
        status = CacheStatus.COMPLETE if results else CacheStatus.EMPTY
        entry = self._put(key, spec, status, tuple(results))
        self._save_if_needed()
        return entry

    store = record_response
    record = record_response

    def record_failure(
        self,
        source: str,
        spec: Dependency,
        reason: str,
        query: Mapping[str, Any] | None = None,
    ) -> CacheEntry:
        """
        Record a failed query.

        If a completed response already exists for the same key, it is kept:
        a later failure must not erase a previously trusted result.
        """

        key = QueryKey.from_dependency(source, spec, query)
        entry = self._put(key, spec, CacheStatus.FAILED, reason=reason)
        self._save_if_needed()
        return entry

    fail = record_failure

    def record_unqueried(
        self,
        source: str,
        specs: Iterable[Dependency],
    ) -> list[CacheEntry]:
        """
        Record packages that were known but not queried.
        """

        entries = [
            self._put(
                QueryKey.from_dependency(source, spec),
                spec,
                CacheStatus.UNQUERIED,
            )
            for spec in specs
        ]
        if entries:
            self._save_if_needed()
        return entries

    mark_unqueried = record_unqueried

    def _put(
        self,
        key: QueryKey,
        spec: Dependency,
        status: CacheStatus,
        results: tuple[VulnerabilityResult, ...] = (),
        reason: str | None = None,
    ) -> CacheEntry:
        existing = self._entries.get(key)
        if existing is not None and existing.reusable:
            # Never downgrade a completed response. A later failure or
            # interruption cannot invalidate a trusted hit.
            if not status.reusable:
                return existing
            # Prefer the non-empty response if a later empty response arrives.
            if existing.status is CacheStatus.COMPLETE and status is CacheStatus.EMPTY:
                return existing
        if existing is not None and existing.status is CacheStatus.FAILED:
            # An interrupted cleanup pass marks outstanding work as unqueried.
            # That must not turn an actual query failure into "never queried".
            if status is CacheStatus.UNQUERIED:
                return existing

        entry = CacheEntry(key=key, status=status, results=results, reason=reason)
        self._entries[key] = entry
        self._dependencies[key] = spec
        return entry

    def to_dict(self) -> dict[str, Any]:
        """
        Serialize the cache with empty, failed, and unqueried records separated.
        """

        data: dict[str, Any] = {
            "version": _CACHE_FORMAT_VERSION,
            "completed": [],
            "empty": [],
            "failed": [],
            "unqueried": [],
        }
        groups = {
            CacheStatus.COMPLETE: "completed",
            CacheStatus.EMPTY: "empty",
            CacheStatus.FAILED: "failed",
            CacheStatus.UNQUERIED: "unqueried",
        }
        for entry in self._entries.values():
            data[groups[entry.status]].append(entry.to_dict())
        return data

    def to_json(self) -> str:
        """
        Serialize the cache to a JSON string.
        """

        return json.dumps(self.to_dict(), sort_keys=True)

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> AuditCache:
        """
        Deserialize a cache from its JSON-compatible representation.
        """

        cache = cls()
        version = data.get("version", _CACHE_FORMAT_VERSION)
        if version != _CACHE_FORMAT_VERSION:
            raise ValueError(f"unsupported audit cache version: {version!r}")

        if "entries" in data:
            raw_entries: Iterable[Mapping[str, Any]] = data["entries"]
        else:
            raw_entries = (
                entry
                for group in ("completed", "empty", "failed", "unqueried")
                for entry in data.get(group, [])
            )

        for raw_entry in raw_entries:
            try:
                key = QueryKey.from_dict(raw_entry)
                status = CacheStatus(str(raw_entry["status"]))
                results = tuple(_vuln_from_dict(vuln) for vuln in raw_entry.get("results", []))
                reason = raw_entry.get("reason")
                if status is CacheStatus.COMPLETE and not results:
                    status = CacheStatus.EMPTY
                if status is CacheStatus.EMPTY and results:
                    status = CacheStatus.COMPLETE
            except (KeyError, TypeError, ValueError) as exc:
                raise ValueError(f"invalid audit cache entry: {raw_entry!r}") from exc

            cache._entries[key] = CacheEntry(
                key=key,
                status=status,
                results=results,
                reason=str(reason) if reason is not None else None,
            )
            cache._dependencies[key] = _dependency_from_key(key)

        return cache

    @classmethod
    def load(cls, path: str | Path) -> AuditCache:
        """
        Load a cache from a JSON file.
        """

        return cls(path)

    def save(self, path: str | Path | None = None) -> None:
        """
        Atomically write the cache to `path` (or to its configured path).
        """

        target = Path(path).expanduser() if path is not None else self._path
        if target is None:
            return

        target.parent.mkdir(parents=True, exist_ok=True)
        with NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            dir=target.parent,
            delete=False,
        ) as io:
            json.dump(self.to_dict(), io, sort_keys=True)
            io.flush()
            os.fsync(io.fileno())

        os.replace(io.name, target)
        self._path = target

    def _load_file(self, path: Path) -> None:
        with path.open(encoding="utf-8") as io:
            data = json.load(io)
        loaded = self.from_dict(data)
        self._entries.update(loaded._entries)
        self._dependencies.update(loaded._dependencies)

    def _save_if_needed(self) -> None:
        if self._path is None:
            return
        try:
            self.save()
        except OSError as exc:
            logger.warning(f"Failed to persist the resumable audit cache at {self._path}: {exc}")


def _dependency_from_key(key: QueryKey) -> Dependency:
    if key.skip_reason is not None:
        return SkippedDependency(name=key.name, skip_reason=key.skip_reason)
    if key.version is None:
        # A non-skipped query always has a version. Falling back to 0 keeps
        # deserialization conservative for hand-written cache files.
        return ResolvedDependency(name=key.name, version=Version("0"))
    return ResolvedDependency(name=key.name, version=Version(key.version))
