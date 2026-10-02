from __future__ import annotations

import enum
import hashlib
import threading
from collections import OrderedDict
from dataclasses import dataclass
from typing import TYPE_CHECKING

from cross_web import HTTPException
from graphql import GraphQLError, parse

from strawberry.http import GraphQLRequestData
from strawberry.types.execution import ExecutionResult

if TYPE_CHECKING:
    from collections.abc import Mapping

PERSISTED_QUERY_EXTENSION = "persistedQuery"
PERSISTED_QUERY_NOT_FOUND = "PERSISTED_QUERY_NOT_FOUND"
PERSISTED_QUERY_MISMATCH = "PERSISTED_QUERY_MISMATCH"


class PersistedQueryMode(enum.Enum):
    AUTOMATIC = "automatic"
    MANIFEST_ONLY = "manifest_only"


@dataclass(frozen=True)
class PersistedQueriesConfig:
    mode: PersistedQueryMode = PersistedQueryMode.AUTOMATIC
    manifest: Mapping[str, str] | None = None
    max_entries: int = 1000
    max_query_size: int = 100_000
    schema_version: str | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.mode, PersistedQueryMode):
            raise TypeError("`mode` must be a PersistedQueryMode")

        if self.max_entries < 1:
            raise ValueError("`max_entries` must be greater than zero")

        if self.max_query_size < 1:
            raise ValueError("`max_query_size` must be greater than zero")

        if self.schema_version is not None and not self.schema_version:
            raise ValueError("`schema_version` must not be empty")

        manifest = self.manifest or {}
        if len(manifest) > self.max_entries:
            raise ValueError("Persisted query manifest exceeds `max_entries`")

        normalized_manifest = {}
        for expected_hash, query in manifest.items():
            if not isinstance(expected_hash, str) or not isinstance(query, str):
                raise TypeError("Persisted query manifest must map hashes to strings")

            persisted_hash = _parse_hash(expected_hash)
            _validate_manifest_query_size(query, self.max_query_size)
            _validate_manifest_query_syntax(query)
            actual_hash = hashlib.sha256(query.encode()).hexdigest()
            if persisted_hash != actual_hash:
                raise ValueError(
                    "Persisted query manifest contains a query with an invalid hash"
                )
            normalized_manifest[persisted_hash] = query

        object.__setattr__(self, "manifest", normalized_manifest)


class _LRUQueryCache:
    def __init__(self, max_entries: int) -> None:
        self.max_entries = max_entries
        self._entries: OrderedDict[tuple[str, str], str] = OrderedDict()
        self._lock = threading.Lock()

    def get(self, schema_version: str, query_hash: str) -> str | None:
        key = (schema_version, query_hash)
        with self._lock:
            query = self._entries.get(key)
            if query is not None:
                self._entries.move_to_end(key)
            return query

    def set(self, schema_version: str, query_hash: str, query: str) -> None:
        key = (schema_version, query_hash)
        with self._lock:
            self._entries[key] = query
            self._entries.move_to_end(key)
            while len(self._entries) > self.max_entries:
                self._entries.popitem(last=False)


@dataclass(frozen=True)
class PersistedQueryResolution:
    request_data: GraphQLRequestData | None = None
    error: ExecutionResult | None = None


class PersistedQueryResolver:
    def __init__(self, config: PersistedQueriesConfig, schema_version: str) -> None:
        manifest = config.manifest or {}
        cache_capacity = config.max_entries - len(manifest)
        self._config = config
        self._schema_version = schema_version
        self._manifest = dict(manifest)
        self._cache = _LRUQueryCache(cache_capacity)

    def resolve(self, request_data: GraphQLRequestData) -> PersistedQueryResolution:
        extensions = request_data.extensions
        if not extensions or PERSISTED_QUERY_EXTENSION not in extensions:
            if self._config.mode is PersistedQueryMode.MANIFEST_ONLY:
                raise HTTPException(
                    400,
                    "Only persisted queries from the configured manifest are accepted",
                )
            return PersistedQueryResolution(request_data=request_data)

        persisted_query = extensions[PERSISTED_QUERY_EXTENSION]
        if not isinstance(persisted_query, dict):
            raise HTTPException(400, "Invalid persisted query extension")
        if persisted_query.get("version") != 1:
            raise HTTPException(400, "Unsupported persisted query version")

        query_hash = _validate_hash(persisted_query.get("sha256Hash"))
        query = request_data.query
        extensions = {
            key: value
            for key, value in extensions.items()
            if key != PERSISTED_QUERY_EXTENSION
        }

        if query is not None:
            return self._resolve_with_query(
                request_data=request_data,
                query=query,
                query_hash=query_hash,
                extensions=extensions or None,
            )

        return self._resolve_without_query(
            request_data=request_data,
            query_hash=query_hash,
            extensions=extensions or None,
        )

    def _resolve_with_query(
        self,
        *,
        request_data: GraphQLRequestData,
        query: str,
        query_hash: str,
        extensions: dict[str, object] | None,
    ) -> PersistedQueryResolution:
        if self._config.mode is PersistedQueryMode.MANIFEST_ONLY:
            raise HTTPException(
                400, "Query documents are not accepted in persisted query manifest mode"
            )

        try:
            _validate_manifest_query_size(query, self._config.max_query_size)
        except ValueError as error:
            raise HTTPException(400, error.args[0]) from error

        actual_hash = hashlib.sha256(query.encode()).hexdigest()
        if query_hash != actual_hash:
            return PersistedQueryResolution(
                error=_persisted_query_error(PERSISTED_QUERY_MISMATCH)
            )

        if not _is_valid_query(query):
            return PersistedQueryResolution(
                request_data=_replace_request_data(
                    request_data, query=query, extensions=extensions
                )
            )

        if query_hash not in self._manifest:
            self._cache.set(self._schema_version, query_hash, query)

        return PersistedQueryResolution(
            request_data=_replace_request_data(
                request_data, query=query, extensions=extensions
            )
        )

    def _resolve_without_query(
        self,
        *,
        request_data: GraphQLRequestData,
        query_hash: str,
        extensions: dict[str, object] | None,
    ) -> PersistedQueryResolution:
        query = self._manifest.get(query_hash)
        if query is None and self._config.mode is PersistedQueryMode.AUTOMATIC:
            query = self._cache.get(self._schema_version, query_hash)

        if query is None:
            if self._config.mode is PersistedQueryMode.MANIFEST_ONLY:
                raise HTTPException(
                    400, "Persisted query was not found in the manifest"
                )
            return PersistedQueryResolution(
                error=_persisted_query_error(PERSISTED_QUERY_NOT_FOUND)
            )

        return PersistedQueryResolution(
            request_data=_replace_request_data(
                request_data, query=query, extensions=extensions
            )
        )


def _replace_request_data(
    request_data: GraphQLRequestData,
    *,
    query: str,
    extensions: dict[str, object] | None,
) -> GraphQLRequestData:
    return GraphQLRequestData(
        query=query,
        variables=request_data.variables,
        operation_name=request_data.operation_name,
        extensions=extensions,
        protocol=request_data.protocol,
    )


def _validate_hash(value: object) -> str:
    if not isinstance(value, str):
        raise HTTPException(400, "Persisted query hash must be a SHA-256 hex digest")

    try:
        return _parse_hash(value)
    except ValueError as error:
        raise HTTPException(400, error.args[0]) from error


def _parse_hash(value: str) -> str:
    query_hash = value.lower()
    try:
        hash_bytes = bytes.fromhex(query_hash)
    except ValueError as error:
        raise ValueError("Persisted query hash must be a SHA-256 hex digest") from error

    if len(hash_bytes) != 32:
        raise ValueError("Persisted query hash must be a SHA-256 hex digest")

    return query_hash


def _validate_manifest_query_size(query: str, max_query_size: int) -> None:
    if len(query.encode("utf-8")) > max_query_size:
        raise ValueError("Persisted query exceeds the maximum query size")


def _validate_manifest_query_syntax(query: str) -> None:
    try:
        parse(query)
    except GraphQLError as error:
        raise ValueError("Persisted query manifest contains invalid GraphQL") from error


def _is_valid_query(query: str) -> bool:
    try:
        parse(query)
    except GraphQLError:
        return False
    return True


def _persisted_query_error(code: str) -> ExecutionResult:
    return ExecutionResult(
        data=None,
        errors=[
            GraphQLError(
                "PersistedQueryNotFound"
                if code == PERSISTED_QUERY_NOT_FOUND
                else "PersistedQueryMismatch",
                extensions={"code": code},
            )
        ],
    )


__all__ = [
    "PERSISTED_QUERY_MISMATCH",
    "PERSISTED_QUERY_NOT_FOUND",
    "PersistedQueriesConfig",
    "PersistedQueryMode",
    "PersistedQueryResolver",
]
