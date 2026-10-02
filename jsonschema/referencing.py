"""Asynchronous preparation of fully offline reference registries."""

from __future__ import annotations

import asyncio
from collections import deque
from collections.abc import Awaitable, Callable, Collection
import json
from urllib.parse import urldefrag, urljoin, urlsplit

from attrs import frozen
from jsonschema_specifications import REGISTRY as SPECIFICATIONS
import referencing
import referencing.jsonschema

Schema = referencing.jsonschema.Schema
Resource = referencing.Resource[Schema]

DEFAULT_SPECIFICATION = referencing.jsonschema.DRAFT202012
_REFERENCE_KEYWORDS = ("$ref", "$dynamicRef", "$recursiveRef")
_SPECIFICATION_URIS = frozenset(SPECIFICATIONS.crawl())


class SchemaPreparationError(Exception):
    """Preparation of an offline schema registry failed."""

    def __init__(self, message: str, uri: str | None = None):
        super().__init__(message)
        self.uri = uri


class DisallowedURI(SchemaPreparationError, ValueError):
    """A schema reference points outside the configured target range."""


class ResourceLimitExceeded(SchemaPreparationError):
    """More remote resources than permitted were required."""


class ByteLimitExceeded(SchemaPreparationError):
    """The remote schemas exceeded the permitted response size."""


class ConflictingResourceID(SchemaPreparationError):
    """Two prepared resources claim the same canonical URI."""


class SchemaPreparationTimeout(SchemaPreparationError, TimeoutError):
    """Preparing an offline schema registry exceeded its deadline."""


@frozen
class LoadedSchema:
    """A loader result with an explicit network payload size.

    Arguments:

        schema:
            a parsed JSON Schema, or a `referencing.Resource` when the
            loader needs to choose a non-default specification

        num_bytes:
            the number of bytes received for the schema, or `None` to
            measure a compact JSON encoding of the parsed schema

    """

    schema: Schema | Resource
    num_bytes: int | None = None


AsyncSchemaLoader = Callable[[str], Awaitable[object]]
URIAllowlist = Collection[str] | Callable[[str], bool]


async def prepare_registry(
    root_schema: Schema,
    loader: AsyncSchemaLoader,
    *,
    base_uri: str = "",
    allowed_schemes: Collection[str] = ("http", "https"),
    allowed_targets: URIAllowlist = (),
    max_concurrency: int = 8,
    max_resources: int | None = 128,
    max_bytes: int | None = 1024 * 1024,
    timeout: float | None = 30,
) -> referencing.jsonschema.SchemaRegistry:
    """Prepare the transitive reference closure of ``root_schema``.

    The async ``loader`` is called once for each distinct remote URI.
    Successful preparation returns a crawled registry without a retrieval
    callback, so subsequent validation cannot perform additional network or
    configuration-service access.

    ``allowed_targets`` is either a predicate called for each non-local URI
    or a collection of permitted URI prefixes. Remote references are not
    permitted unless both their scheme and target match this policy.
    """

    schemes = _normalized_schemes(allowed_schemes)
    _validate_limits(max_concurrency, max_resources, max_bytes, timeout)
    _validate_allowed_targets(allowed_targets)

    try:
        return await asyncio.wait_for(
            _prepare_registry(
                root_schema=root_schema,
                loader=loader,
                base_uri=base_uri,
                schemes=schemes,
                allowed_targets=allowed_targets,
                max_concurrency=max_concurrency,
                max_resources=max_resources,
                max_bytes=max_bytes,
            ),
            timeout=timeout,
        )
    except asyncio.TimeoutError as error:
        raise SchemaPreparationTimeout(
            f"Schema preparation exceeded {timeout} seconds",
        ) from error


async def _prepare_registry(
    root_schema,
    loader,
    base_uri,
    schemes,
    allowed_targets,
    max_concurrency,
    max_resources,
    max_bytes,
):
    root_resource = referencing.Resource.from_contents(
        root_schema,
        default_specification=DEFAULT_SPECIFICATION,
    )
    root_base = _resource_base(base_uri, root_resource)

    queue: asyncio.Queue[str] = asyncio.Queue()
    requested: set[str] = set()
    published: dict[str, Resource] = {}
    known = set(_SPECIFICATION_URIS)
    total_bytes = 0

    def is_allowed(uri: str) -> bool:
        if not uri or urlsplit(uri).scheme.lower() not in schemes:
            return False
        if callable(allowed_targets):
            return bool(allowed_targets(uri))
        return any(
            uri == target or uri.startswith(target)
            for target in allowed_targets
        )

    def require_allowed(uri: str) -> None:
        if not is_allowed(uri):
            raise DisallowedURI(
                f"URI is not permitted by the preparation policy: {uri}",
                uri=uri,
            )

    def publish_resource(resource: Resource, alias: str, owner: str) -> None:
        if alias:
            _publish(published, alias, resource, owner)
            known.add(alias)

        for base_uri, has_id, subresource in _walk_resources(
            resource,
            alias,
        ):
            if has_id:
                require_allowed(base_uri)
                if base_uri != alias:
                    _publish(
                        published,
                        base_uri,
                        subresource,
                        owner,
                    )
                    known.add(base_uri)

            for reference in _references(subresource, base_uri):
                request(reference)

    def request(uri: str) -> None:
        if not uri or uri in known or uri in requested:
            return
        require_allowed(uri)
        if max_resources is not None and len(requested) >= max_resources:
            raise ResourceLimitExceeded(
                f"More than {max_resources} remote resources are required",
                uri=uri,
            )
        requested.add(uri)
        queue.put_nowait(uri)

    async def worker() -> None:
        nonlocal total_bytes

        while True:
            uri = await queue.get()
            try:
                if uri in known:
                    continue

                result = await loader(uri)

                resource, num_bytes = _as_loaded_resource(result)
                if (
                    max_bytes is not None
                    and total_bytes + num_bytes > max_bytes
                ):
                    total = total_bytes + num_bytes
                    raise ByteLimitExceeded(
                        f"Remote schemas require {total} bytes, exceeding the "
                        f"configured limit of {max_bytes} bytes",
                        uri=uri,
                    )

                total_bytes += num_bytes
                publish_resource(resource, alias=uri, owner=uri)
            finally:
                queue.task_done()

    if root_base:
        require_allowed(root_base)
        _publish(published, root_base, root_resource, owner="")
        known.add(root_base)
    publish_resource(root_resource, alias=root_base, owner="")

    workers = [
        asyncio.create_task(worker())
        for _ in range(max_concurrency)
    ]
    queue_task = asyncio.create_task(queue.join())

    try:
        while True:
            await asyncio.wait(
                {queue_task, *workers},
                return_when=asyncio.FIRST_COMPLETED,
            )
            for worker_task in workers:
                if worker_task.done() and not worker_task.cancelled():
                    error = worker_task.exception()
                    if error is not None:
                        raise error
            if queue_task.done():
                queue_task.result()
                break
    finally:
        for task in (*workers, queue_task):
            task.cancel()
        await asyncio.gather(*workers, return_exceptions=True)
        await asyncio.gather(queue_task, return_exceptions=True)

    registry = referencing.Registry().with_resources(
        published.items(),
    ).crawl()

    for uri in registry:
        require_allowed(uri)

    return SPECIFICATIONS.combine(registry).crawl()


def _normalized_schemes(schemes):
    if isinstance(schemes, str) or not schemes:
        raise ValueError("allowed_schemes must contain at least one scheme")
    if any(
        not isinstance(scheme, str) or not scheme for scheme in schemes
    ):
        raise ValueError("allowed_schemes must contain non-empty strings")
    return frozenset(scheme.lower() for scheme in schemes)


def _validate_allowed_targets(targets):
    if callable(targets):
        return
    if (
        isinstance(targets, (str, bytes))
        or not isinstance(targets, Collection)
    ):
        raise TypeError(
            "allowed_targets must be a predicate or collection of URIs",
        )
    if any(not isinstance(target, str) or not target for target in targets):
        raise ValueError("allowed target prefixes must be non-empty strings")


def _validate_limits(max_concurrency, max_resources, max_bytes, timeout):
    if (
        isinstance(max_concurrency, bool)
        or not isinstance(max_concurrency, int)
    ):
        raise TypeError("max_concurrency must be an integer")
    if max_concurrency < 1:
        raise ValueError("max_concurrency must be at least 1")

    for name, value in (
        ("max_resources", max_resources),
        ("max_bytes", max_bytes),
    ):
        if value is None:
            continue
        if isinstance(value, bool) or not isinstance(value, int):
            raise TypeError(f"{name} must be an integer or None")
        if value < 1:
            raise ValueError(f"{name} must be at least 1")

    if timeout is None:
        return
    if isinstance(timeout, bool) or not isinstance(timeout, (int, float)):
        raise TypeError("timeout must be a number or None")
    if timeout <= 0:
        raise ValueError("timeout must be greater than zero")


def _resource_base(base_uri: str, resource: Resource) -> str:
    resource_id = resource.id()
    if resource_id:
        return urldefrag(urljoin(base_uri, resource_id)).url
    return urldefrag(base_uri).url


def _walk_resources(resource: Resource, base_uri: str):
    queue = deque([(base_uri, resource)])
    while queue:
        base_uri, current = queue.popleft()
        resource_id = current.id()
        if resource_id:
            base_uri = urldefrag(urljoin(base_uri, resource_id)).url
        yield base_uri, resource_id is not None, current
        queue.extend(
            (base_uri, subresource)
            for subresource in current.subresources()
        )


def _references(resource: Resource, base_uri: str):
    contents = resource.contents
    if not isinstance(contents, dict):
        return

    for keyword in _REFERENCE_KEYWORDS:
        reference = contents.get(keyword)
        if not isinstance(reference, str) or reference.startswith("#"):
            continue
        resolved, _fragment = urldefrag(urljoin(base_uri, reference))
        if resolved:
            yield resolved


def _publish(published, uri, resource, owner):
    existing = published.get(uri)
    if existing is not None and existing != resource:
        raise ConflictingResourceID(
            f"URI {uri} is claimed by both {owner!r} and another resource",
            uri=uri,
        )
    published[uri] = resource


def _as_loaded_resource(result) -> tuple[Resource, int]:
    if isinstance(result, LoadedSchema):
        if result.num_bytes is not None:
            _validate_byte_count(result.num_bytes)
        if isinstance(result.schema, referencing.Resource):
            resource = result.schema
        else:
            resource = _resource_from_contents(result.schema)
        num_bytes = result.num_bytes
    elif isinstance(result, referencing.Resource):
        resource = result
        num_bytes = None
    elif isinstance(result, bytes):
        num_bytes = len(result)
        resource = _resource_from_contents(json.loads(result))
    elif isinstance(result, str):
        encoded = result.encode("utf-8")
        num_bytes = len(encoded)
        resource = _resource_from_contents(json.loads(encoded))
    elif isinstance(result, (bool, dict)):
        resource = _resource_from_contents(result)
        num_bytes = None
    else:
        raise TypeError(
            "Async schema loaders must return bytes, text, a schema, a "
            "referencing.Resource, or a LoadedSchema",
        )

    if num_bytes is None:
        num_bytes = _encoded_size(resource.contents)
    return resource, num_bytes


def _resource_from_contents(contents) -> Resource:
    if not isinstance(contents, (bool, dict)):
        raise TypeError("A JSON Schema root must be an object or boolean")
    return referencing.Resource.from_contents(
        contents,
        default_specification=DEFAULT_SPECIFICATION,
    )


def _validate_byte_count(value):
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise TypeError(
            "LoadedSchema.num_bytes must be a non-negative integer",
        )


def _encoded_size(schema) -> int:
    encoded = json.dumps(schema, ensure_ascii=False, separators=(",", ":"))
    return len(encoded.encode("utf-8"))
