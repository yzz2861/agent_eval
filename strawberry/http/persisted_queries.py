from __future__ import annotations

import hashlib
import re
from collections import OrderedDict
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from enum import Enum
from threading import RLock
from types import MappingProxyType
from typing import TYPE_CHECKING, Any

from cross_web import HTTPException
from graphql import GraphQLError, GraphQLSyntaxError, parse

from strawberry.http import GraphQLRequestData

if TYPE_CHECKING:
    from strawberry.schema.base import BaseSchema

_SHA256_RE = re.compile(r"[0-9a-f]{64}\Z")
_PERSISTED_QUERY_KEY = "persistedQuery"
DEFAULT_MAX_ENTRIES = 1000
DEFAULT_MAX_QUERY_BYTES = 1024 * 1024


class PersistedQueryMode(str, Enum):
    AUTO = "auto"
    MANIFEST_ONLY = "manifest_only"


@dataclass(frozen=True)
class PersistedQueriesConfig:
    """Configuration for automatic and manifest-only persisted queries."""

    mode: PersistedQueryMode = PersistedQueryMode.AUTO
    preloaded_queries: Mapping[str, str] | Sequence[str] = field(default_factory=dict)
    max_entries: int = DEFAULT_MAX_ENTRIES
    max_query_bytes: int = DEFAULT_MAX_QUERY_BYTES

    def __post_init__(self) -> None:
        if self.max_entries < 1:
            raise ValueError("`max_entries` must be greater than zero")
        if self.max_query_bytes < 1:
            raise ValueError("`max_query_bytes` must be greater than zero")

        normalized = self._normalize_preloaded_queries()
        if len(normalized) > self.max_entries:
            raise ValueError("Preloaded persisted queries exceed `max_entries`")

        for query_hash, query in normalized.items():
            self._validate_hash(query_hash, query)
            self._validate_query_size(query)
            try:
                parse(query)
            except GraphQLSyntaxError as error:
                raise ValueError(
                    f"Preloaded persisted query {query_hash} is not valid GraphQL: "
                    f"{error.message}"
                ) from error

        object.__setattr__(self, "preloaded_queries", normalized)

    def _normalize_preloaded_queries(self) -> dict[str, str]:
        if isinstance(self.preloaded_queries, Mapping):
            queries = dict(self.preloaded_queries)
        else:
            if isinstance(self.preloaded_queries, str):
                raise TypeError(
                    "Preloaded persisted queries must be a mapping or sequence of strings"
                )
            queries = {query_sha256(query): query for query in self.preloaded_queries}

        for query_hash, query in queries.items():
            if not isinstance(query_hash, str) or not isinstance(query, str):
                raise TypeError(
                    "Preloaded persisted queries must map SHA-256 hashes to strings"
                )

        return queries

    def _validate_hash(self, query_hash: str, query: str) -> None:
        if not _SHA256_RE.fullmatch(query_hash):
            raise ValueError(f"`{query_hash}` is not a lowercase SHA-256 hex digest")
        if query_sha256(query) != query_hash:
            raise ValueError(
                f"Preloaded persisted query hash {query_hash} does not match"
            )

    def _validate_query_size(self, query: str) -> None:
        if len(query.encode("utf-8")) > self.max_query_bytes:
            raise ValueError("Preloaded persisted query exceeds `max_query_bytes`")


class PersistedQueryStore:
    def __init__(
        self,
        *,
        schema_version: str,
        preloaded_queries: Mapping[str, str] = MappingProxyType({}),
        max_entries: int = DEFAULT_MAX_ENTRIES,
        max_query_bytes: int = DEFAULT_MAX_QUERY_BYTES,
    ) -> None:
        self.schema_version = schema_version
        self.max_entries = max_entries
        self.max_query_bytes = max_query_bytes
        self._entries: OrderedDict[tuple[str, str], str] = OrderedDict(
            ((schema_version, query_hash), query)
            for query_hash, query in preloaded_queries.items()
        )
        self._preloaded_hashes = {
            (schema_version, query_hash) for query_hash in preloaded_queries
        }
        self._lock = RLock()

    def get(self, query_hash: str) -> str | None:
        with self._lock:
            key = (self.schema_version, query_hash)
            query = self._entries.get(key)
            if query is not None:
                self._entries.move_to_end(key)
            return query

    def put(self, query_hash: str, query: str) -> bool:
        if len(query.encode("utf-8")) > self.max_query_bytes:
            return False

        with self._lock:
            key = (self.schema_version, query_hash)
            if key in self._entries:
                self._entries.move_to_end(key)
                return True

            if len(self._entries) >= self.max_entries:
                for existing_hash in list(self._entries):
                    if existing_hash not in self._preloaded_hashes:
                        self._entries.pop(existing_hash)
                        break
                else:
                    return False

            self._entries[key] = query
            return True


class PersistedQueryManager:
    def __init__(self, schema: BaseSchema, config: PersistedQueriesConfig) -> None:
        self.schema = schema
        schema_version = query_sha256(schema.as_str())
        preloaded_queries = config.preloaded_queries
        if not isinstance(preloaded_queries, Mapping):
            preloaded_queries = dict(preloaded_queries)
        self.config = config
        self.store = PersistedQueryStore(
            schema_version=schema_version,
            preloaded_queries=preloaded_queries,
            max_entries=config.max_entries,
            max_query_bytes=config.max_query_bytes,
        )
        for query in preloaded_queries.values():
            errors = schema.validate_document(query)
            if errors:
                raise ValueError(
                    "Preloaded persisted query is invalid for the current schema: "
                    f"{errors[0].message}"
                )

    def resolve_all(self, requests: Sequence[GraphQLRequestData]) -> None:
        pending_entries: list[tuple[str, str]] = []

        for request_data in requests:
            self.resolve(request_data, pending_entries=pending_entries)

        for query_hash, query in pending_entries:
            errors = self._validate_query(query)
            if errors:
                continue
            if not self.store.put(query_hash, query):
                raise _persisted_query_error("Persisted query cache is full")

    def resolve(
        self,
        request_data: GraphQLRequestData,
        pending_entries: list[tuple[str, str]] | None = None,
    ) -> None:
        extensions = request_data.extensions or {}
        persisted_query = extensions.get(_PERSISTED_QUERY_KEY)

        if persisted_query is None:
            if self.config.mode is PersistedQueryMode.MANIFEST_ONLY:
                raise _persisted_query_error("PersistedQueryNotSupported")
            return

        query_hash = self._extract_hash(persisted_query)

        if request_data.query is not None:
            if self.config.mode is PersistedQueryMode.MANIFEST_ONLY:
                raise _persisted_query_error("PersistedQueryNotSupported")

            query = request_data.query
            if query_sha256(query) != query_hash:
                raise _persisted_query_error("PersistedQueryMismatch")
            if len(query.encode("utf-8")) > self.config.max_query_bytes:
                raise _persisted_query_error(
                    "Persisted query exceeds the configured maximum size"
                )

            if pending_entries is not None:
                if not self._validate_query(query):
                    pending_entries.append((query_hash, query))
            else:
                if not self._validate_query(query) and not self.store.put(
                    query_hash, query
                ):
                    raise _persisted_query_error("Persisted query cache is full")
            return

        query = self.store.get(query_hash)
        if query is None:
            raise _persisted_query_error("PersistedQueryNotFound")
        request_data.query = query

    def _validate_query(self, query: str) -> list[GraphQLError]:
        try:
            parse(query)
        except GraphQLSyntaxError as error:
            return [GraphQLError(error.message, original_error=error)]
        return self.schema.validate_document(query)

    def _extract_hash(self, persisted_query: Any) -> str:
        if not isinstance(persisted_query, dict):
            raise _persisted_query_error(
                "The persisted query extension must be an object"
            )
        if persisted_query.get("version") != 1:
            raise _persisted_query_error(
                "Unsupported persisted query version"
            )

        query_hash = persisted_query.get("sha256Hash")
        if not isinstance(query_hash, str) or not _SHA256_RE.fullmatch(query_hash):
            raise _persisted_query_error(
                "A lowercase SHA-256 hex digest is required"
            )
        return query_hash


def query_sha256(query: str) -> str:
    return hashlib.sha256(query.encode("utf-8")).hexdigest()


def _persisted_query_error(message: str) -> HTTPException:
    return HTTPException(400, message)


__all__ = [
    "DEFAULT_MAX_ENTRIES",
    "DEFAULT_MAX_QUERY_BYTES",
    "PersistedQueryManager",
    "PersistedQueryMode",
    "PersistedQueryStore",
    "PersistedQueriesConfig",
    "query_sha256",
]
