"""
Asynchronous prefetching of remotely-referenced schemas.

Validation itself is synchronous, but schemas which refer to remote
resources need those resources to be available ahead of time. This
module implements an *asynchronous preparation phase*: given a schema
and an async loader callable, `prefetch` follows references (resolving
relative references against each resource's own ``$id``), retrieves
each distinct referenced document at most once, and returns an offline
`referencing.jsonschema.SchemaRegistry` which can be handed directly to
any `jsonschema.protocols.Validator`.
"""

from __future__ import annotations

from collections import deque
from collections.abc import Awaitable, Callable, Collection, Mapping
from urllib.parse import urldefrag, urljoin, urlsplit
import asyncio
import json

from jsonschema_specifications import REGISTRY as _SPECIFICATIONS
from referencing import Registry
import referencing.jsonschema

__all__ = [
    "DisallowedTarget",
    "PrefetchError",
    "PrefetchTimeout",
    "ResourceLimitExceeded",
    "SizeLimitExceeded",
    "prefetch",
]

#: Keywords whose values are references to other schema documents.
_REF_KEYS = ("$ref", "$dynamicRef", "$recursiveRef")

#: An async callable retrieving the raw contents of the given URI.
Loader = Callable[[str], Awaitable[bytes | str]]


class PrefetchError(Exception):
    """
    A remote schema could not be prefetched, so no registry was produced.
    """


class DisallowedTarget(PrefetchError):
    """
    A reference pointed at a URI whose scheme or host is not allowed.
    """


class ResourceLimitExceeded(PrefetchError):
    """
    Prefetching would have required retrieving too many resources.
    """


class SizeLimitExceeded(PrefetchError):
    """
    Prefetching would have retrieved too many bytes in total.
    """


class PrefetchTimeout(PrefetchError):
    """
    Prefetching did not complete within the configured timeout.
    """


def _offline_retrieve(uri: str) -> referencing.jsonschema.SchemaResource:
    raise PrefetchError(
        f"{uri!r} is not present in this registry. The registry is "
        "offline; if validation requires retrieving it, prefetching "
        "did not cover every reference.",
    )


def _scan(resource, base_uri, known):
    """
    Find the absolute URIs of documents referenced by the resource.

    Relative references are resolved against ``base_uri``, updated by
    the ``$id`` of each (sub)resource encountered along the way. The
    canonical URI of every (sub)resource is added to ``known``, as
    those are available without further retrieval.
    """
    refs = []
    stack = [(resource, base_uri)]
    while stack:
        current, base = stack.pop()
        contents = current.contents
        if isinstance(contents, Mapping):
            for key in _REF_KEYS:
                ref = contents.get(key)
                if isinstance(ref, str):
                    uri, _ = urldefrag(urljoin(base, ref))
                    if uri:
                        refs.append(uri)
            subresources = current.subresources()
        elif isinstance(contents, bool):
            subresources = ()
        else:  # not a schema at all, ignore it
            continue
        for sub in subresources:
            sub_base = base
            if isinstance(sub.contents, Mapping):
                sub_id = sub.id()
                if sub_id is not None:
                    sub_base = urldefrag(urljoin(base, sub_id))[0]
                    known.add(sub_base)
            stack.append((sub, sub_base))
    return refs


def _check_allowed(uri, schemes, hosts):
    parts = urlsplit(uri)
    if parts.scheme.lower() not in schemes:
        raise DisallowedTarget(
            f"{uri!r} uses scheme {parts.scheme!r} which is not allowed.",
        )
    if hosts is not None and (parts.hostname or "").lower() not in hosts:
        raise DisallowedTarget(
            f"{uri!r} points at host {parts.hostname!r} which is not allowed.",
        )


async def _retrieve_one(loader, uri):
    """
    Retrieve and parse a single document, returning contents and size.
    """
    try:
        payload = await loader(uri)
    except Exception as error:
        raise PrefetchError(f"{uri!r} could not be retrieved.") from error
    if isinstance(payload, str):
        data = payload.encode("utf-8")
    elif isinstance(payload, (bytes, bytearray)):
        data = bytes(payload)
    else:
        raise PrefetchError(
            f"The loader for {uri!r} returned "
            f"{type(payload).__name__}, expected bytes or str.",
        )
    try:
        return json.loads(data), len(data)
    except json.JSONDecodeError as error:
        raise PrefetchError(
            f"{uri!r} did not contain valid JSON.",
        ) from error


async def _crawl(
    schema,
    loader,
    *,
    schemes,
    hosts,
    max_resources,
    max_bytes,
    max_concurrency,
    default_specification,
):
    """
    Retrieve every transitively referenced document.

    Returns a list of ``(uri, resource)`` pairs. Any failure cancels
    in-flight retrievals and propagates, so no partial result escapes.
    """
    root = referencing.jsonschema.SchemaResource.from_contents(
        schema,
        default_specification=default_specification,
    )
    known = set()
    root_id = root.id()
    if root_id is not None:
        known.add(root_id)

    queue = deque()
    enqueued = set()

    def discover(resource, base):
        for uri in _scan(resource, base, known):
            if uri in known or uri in enqueued or uri in _SPECIFICATIONS:
                continue
            enqueued.add(uri)
            queue.append(uri)

    discover(root, root_id or "")

    in_flight = {}
    fetched = []
    total_bytes = 0
    try:
        while queue or in_flight:
            while queue and len(in_flight) < max_concurrency:
                uri = queue.popleft()
                if uri in known:
                    continue
                _check_allowed(uri, schemes, hosts)
                if len(fetched) + len(in_flight) >= max_resources:
                    raise ResourceLimitExceeded(
                        "Prefetching would exceed the limit of "
                        f"{max_resources} resources.",
                    )
                task = asyncio.ensure_future(_retrieve_one(loader, uri))
                in_flight[task] = uri
            if not in_flight:
                break  # everything left was already known
            done, _ = await asyncio.wait(
                in_flight,
                return_when=asyncio.FIRST_COMPLETED,
            )
            for task in done:
                uri = in_flight.pop(task)
                contents, size = task.result()
                total_bytes += size
                if total_bytes > max_bytes:
                    raise SizeLimitExceeded(
                        "Prefetching would exceed the limit of "
                        f"{max_bytes} bytes.",
                    )
                resource = referencing.jsonschema.SchemaResource.from_contents(
                    contents,
                    default_specification=default_specification,
                )
                fetched.append((uri, resource))
                known.add(uri)
                resource_id = resource.id()
                if resource_id is not None:
                    known.add(resource_id)
                discover(resource, resource_id or uri)
    finally:
        for task in in_flight:
            task.cancel()
        if in_flight:
            await asyncio.gather(*in_flight, return_exceptions=True)

    return fetched


async def prefetch(
    schema: referencing.jsonschema.Schema,
    *,
    loader: Loader,
    allowed_schemes: Collection[str] = ("https",),
    allowed_hosts: Collection[str] | None = None,
    max_resources: int = 64,
    max_bytes: int = 8 * 1024 * 1024,
    max_concurrency: int = 8,
    timeout: float | None = None,
    default_specification=referencing.jsonschema.DRAFT202012,
) -> referencing.jsonschema.SchemaRegistry:
    """
    Asynchronously retrieve every remote document referenced by a schema.

    Arguments:

        schema:

            the schema whose remote references should be prefetched

        loader:

            an async callable which is passed a single absolute URI and
            returns the referenced document as ``bytes`` or ``str``
            (JSON text). It is called at most once per distinct URI,
            with at most ``max_concurrency`` calls in flight

        allowed_schemes:

            URI schemes which references are allowed to use. Any
            reference to another scheme fails the whole preparation

        allowed_hosts:

            hosts which references are allowed to point at, or `None`
            to allow any host (within ``allowed_schemes``)

        max_resources:

            the maximum number of remote documents to retrieve

        max_bytes:

            the maximum total size of retrieved documents, in bytes

        max_concurrency:

            the maximum number of simultaneous loader calls

        timeout:

            seconds after which the whole preparation is aborted, or
            `None` to wait indefinitely. Cancelling the surrounding
            task aborts the preparation as well, cancelling any
            in-flight loader calls

        default_specification:

            the `referencing.Specification` used for documents which do
            not declare their dialect via :kw:`$schema`

    Returns:

        a `referencing.jsonschema.SchemaRegistry` containing every
        prefetched resource, suitable for passing directly to a
        validator via its ``registry`` argument. The registry is fully
        offline: looking up anything which was not prefetched raises an
        error rather than attempting further retrieval

    Raises:

        PrefetchError: (or a subclass) if any document could not be
            retrieved, parsed, or was not allowed, or if any limit was
            exceeded. No registry is produced in any of these cases.

    """
    if max_concurrency < 1:
        raise ValueError("max_concurrency must be at least 1.")
    if max_resources < 0:
        raise ValueError("max_resources cannot be negative.")
    if max_bytes < 0:
        raise ValueError("max_bytes cannot be negative.")

    schemes = frozenset(each.lower() for each in allowed_schemes)
    hosts = (
        None
        if allowed_hosts is None
        else frozenset(each.lower() for each in allowed_hosts)
    )
    crawl = _crawl(
        schema,
        loader,
        schemes=schemes,
        hosts=hosts,
        max_resources=max_resources,
        max_bytes=max_bytes,
        max_concurrency=max_concurrency,
        default_specification=default_specification,
    )
    try:
        if timeout is None:
            fetched = await crawl
        else:
            fetched = await asyncio.wait_for(crawl, timeout)
    except (asyncio.TimeoutError, TimeoutError):
        raise PrefetchTimeout(
            f"Prefetching did not complete within {timeout} seconds.",
        )

    registry: referencing.jsonschema.SchemaRegistry = Registry(
        retrieve=_offline_retrieve,
    )
    return registry.with_resources(fetched)
