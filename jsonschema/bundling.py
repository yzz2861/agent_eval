"""
Create and load offline-verifiable bundles of schemas and their resources.

Deployment environments without network access cannot retrieve schemas
referenced by an entry schema at validation time. This module packages an
entry schema together with every resource it (transitively) references --
drawn exclusively from a caller-provided "referencing" registry, never from
the network -- into a single JSON-serializable bundle. Loading the bundle
rebuilds an equivalent offline registry after verifying the bundle's
integrity.

Resources are stored as-is (keyed by content digest), so ``$id``,
``$anchor``, relative references and ``$dynamicRef`` keep their original
meaning -- references are *not* rewritten or inlined.

Typical usage::

    from referencing import Registry, Resource

    import jsonschema.bundling

    registry = Registry().with_resources([
        ("https://example.com/common.json", Resource.from_contents({...})),
    ])
    bundle = jsonschema.bundling.bundle(schema, registry=registry)

    # ... ship bundle.to_json() to the offline environment, then ...

    loaded = jsonschema.bundling.load(bundle.to_json())
    loaded.validate(instance)
"""
from __future__ import annotations

from collections.abc import Mapping
from typing import Any
from urllib.parse import urldefrag, urljoin
import hashlib
import json

from attrs import field, frozen
from referencing import Registry, Resource
from referencing.jsonschema import (
    DRAFT3,
    DRAFT4,
    DRAFT6,
    DRAFT7,
    DRAFT201909,
    DRAFT202012,
    EMPTY_REGISTRY,
    Schema,
    SchemaRegistry,
    SchemaResource,
)

from jsonschema.exceptions import (
    BundleError,
    BundleIntegrityError,
    ConflictingResourceError,
    MissingResourceError,
)
from jsonschema.validators import validator_for

__all__ = ["Bundle", "LoadedBundle", "bundle", "load"]

_BUNDLE_FORMAT_VERSION = 1

#: Keywords whose values are references to other resources.
_REFERENCING_KEYS = frozenset({"$ref", "$dynamicRef", "$recursiveRef"})

_SPECIFICATIONS_BY_NAME = {
    spec.name: spec
    for spec in (
        DRAFT202012,
        DRAFT201909,
        DRAFT7,
        DRAFT6,
        DRAFT4,
        DRAFT3,
    )
}


def _canonical(contents: Any, uri: str) -> str:
    try:
        return json.dumps(
            contents,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        )
    except (TypeError, ValueError) as error:
        raise BundleError(
            f"The contents of {uri!r} are not JSON serializable and so "
            f"cannot be bundled: {error}",
        ) from error


def _digest_of(contents: Any, uri: str) -> str:
    canonical = _canonical(contents, uri)
    return "sha256:" + hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _specification_of(resource: SchemaResource):
    # referencing does not expose a resource's specification publicly,
    # but it is needed to faithfully round-trip resources through a bundle.
    return resource._specification


def _collect_resources(
    entry_uri: str,
    entry_resource: SchemaResource,
    registry: SchemaRegistry,
) -> dict[str, SchemaResource]:
    """
    Collect the entry resource and everything it transitively references.

    Resources are keyed by their (absolute, fragment-less) retrieval URI.
    Only the caller-provided registry is consulted; nothing is retrieved
    from the network.
    """
    crawled = registry.crawl()
    collected: dict[str, SchemaResource] = {}
    references: list[tuple[str, str]] = []

    def consider(uri: str, resource: SchemaResource):
        existing = collected.get(uri)
        if existing is not None:
            if existing != resource:
                raise ConflictingResourceError(uri)
            return
        known = crawled.get(uri)
        if known is not None and known != resource:
            raise ConflictingResourceError(uri)
        collected[uri] = resource
        walk(resource.contents, uri, _specification_of(resource))

    def walk(contents: Schema, base_uri: str, specification):
        if isinstance(contents, bool):
            return
        for key in _REFERENCING_KEYS:
            ref = contents.get(key)
            if isinstance(ref, str):
                references.append((ref, base_uri))
        for subschema in specification.subresources_of(contents):
            subresource = Resource.from_contents(
                subschema,
                default_specification=specification,
            )
            id = subresource.id()
            if id is None:
                walk(subschema, base_uri, _specification_of(subresource))
            else:
                consider(urljoin(base_uri, id), subresource)

    consider(entry_uri, entry_resource)

    index = 0
    while index < len(references):
        ref, base_uri = references[index]
        index += 1
        uri = urldefrag(urljoin(base_uri, ref))[0].rstrip("#")
        if uri in collected:
            continue
        resource = crawled.get(uri)
        if resource is None:
            raise MissingResourceError(uri, referenced_from=base_uri)
        consider(uri, resource)

    return collected


@frozen
class Bundle:
    """
    A schema and its referenced resources, packaged for offline use.

    The bundle is plain JSON-serializable data; use `Bundle.to_json` (or
    `Bundle.to_dict`) to serialize it, and `jsonschema.bundling.load` to
    verify and load it later.
    """

    _data: Mapping[str, Any] = field(repr=False, alias="data")

    @property
    def digest(self) -> str:
        """
        A content digest of the bundle's entry point and manifest.
        """
        return self._data["digest"]

    @property
    def entry(self) -> str:
        """
        The retrieval URI of the entry schema within the bundle.
        """
        return self._data["entry"]

    @property
    def manifest(self) -> Mapping[str, Any]:
        """
        A mapping of each bundled resource URI to its digest and dialect.
        """
        return self._data["manifest"]

    def to_dict(self) -> dict[str, Any]:
        """
        Return the bundle as a plain JSON-serializable dict.
        """
        return json.loads(self.to_json())

    def to_json(self, **kwargs: Any) -> str:
        """
        Serialize the bundle to a JSON string.

        Additional keyword arguments are passed to `json.dumps`.
        """
        return json.dumps(self._data, **kwargs)

    def load(self) -> LoadedBundle:
        """
        Verify and load this bundle, as `jsonschema.bundling.load` does.
        """
        return load(self)


@frozen
class LoadedBundle:
    """
    The result of loading a `Bundle`: an entry schema and its registry.

    The registry contains exactly the resources recorded in the bundle's
    manifest and never retrieves anything from the network.
    """

    #: The contents of the entry schema.
    schema: Schema

    #: An offline registry containing every resource the schema references.
    registry: SchemaRegistry

    #: The content digest of the bundle this was loaded from.
    digest: str

    #: The retrieval URI of the entry schema.
    entry: str

    def validator(self, **kwargs: Any):
        """
        Create a validator for the entry schema using the offline registry.

        Additional keyword arguments (e.g. ``format_checker``) are passed
        to the validator class.
        """
        cls = validator_for(self.schema)
        return cls(self.schema, registry=self.registry, **kwargs)

    def validate(self, instance: Any, **kwargs: Any) -> None:
        """
        Validate an instance against the entry schema, fully offline.
        """
        self.validator(**kwargs).validate(instance)

    def is_valid(self, instance: Any, **kwargs: Any) -> bool:
        """
        Check whether an instance is valid under the entry schema.
        """
        return self.validator(**kwargs).is_valid(instance)


def bundle(
    schema: Schema | SchemaResource,
    registry: SchemaRegistry = EMPTY_REGISTRY,
    *,
    base_uri: str = "",
) -> Bundle:
    """
    Package a schema and its referenced resources into an offline bundle.

    Arguments:

        schema:

            the entry schema (or a `referencing.Resource`). Its ``$id``,
            if any, is used as its retrieval URI, resolved against
            ``base_uri``.

        registry:

            the registry to draw referenced resources from. It is the
            *only* source of resources; nothing is ever retrieved from
            the network.

        base_uri:

            an absolute URI to resolve the entry schema's ``$id``
            against, if the schema itself does not provide an absolute
            one.

    Returns:

        a `Bundle` containing the entry schema, every transitively
        referenced resource (each stored once, keyed by content digest),
        and a manifest mapping each resource's URI to its digest and
        dialect.

    Raises:

        `jsonschema.exceptions.MissingResourceError`:

            if a referenced resource is not present in the registry

        `jsonschema.exceptions.ConflictingResourceError`:

            if two different resources are found for the same URI

        `jsonschema.exceptions.BundleError`:

            if a resource cannot be represented in a bundle (e.g. it is
            not JSON serializable or uses an unknown dialect)

    """
    if isinstance(schema, Resource):
        resource = schema
    else:
        resource = Resource.from_contents(
            schema,
            default_specification=DRAFT202012,
        )
    entry_uri = urljoin(base_uri, resource.id() or "")

    collected = _collect_resources(entry_uri, resource, registry)

    resources: dict[str, Schema] = {}
    manifest: dict[str, Any] = {}
    for uri, each in sorted(collected.items()):
        name = _specification_of(each).name
        if name not in _SPECIFICATIONS_BY_NAME:
            raise BundleError(
                f"The resource at {uri!r} uses the unknown specification "
                f"{name!r} and so cannot be bundled.",
            )
        digest = _digest_of(each.contents, uri)
        resources[digest] = each.contents
        manifest[uri] = {"digest": digest, "specification": name}

    payload = {
        "version": _BUNDLE_FORMAT_VERSION,
        "entry": entry_uri,
        "manifest": manifest,
    }
    data = {
        **payload,
        "resources": resources,
        "digest": _digest_of(payload, "<bundle>"),
    }
    return Bundle(data=data)


def load(data: Bundle | Mapping[str, Any] | str | bytes) -> LoadedBundle:
    """
    Verify and load a bundle created by `bundle`, without any network use.

    Arguments:

        data:

            a `Bundle`, its dict form (see `Bundle.to_dict`), or its JSON
            serialization (see `Bundle.to_json`).

    Returns:

        a `LoadedBundle` pairing the entry schema with an offline
        registry containing every bundled resource.

    Raises:

        `jsonschema.exceptions.BundleIntegrityError`:

            if the bundle is malformed, is missing resources, or fails
            digest verification (e.g. its contents were tampered with)

    """
    if isinstance(data, Bundle):
        mapping = data._data
    elif isinstance(data, (str, bytes, bytearray)):
        try:
            mapping = json.loads(data)
        except json.JSONDecodeError as error:
            raise BundleIntegrityError(
                f"The bundle is not valid JSON: {error}",
            ) from error
    elif isinstance(data, Mapping):
        mapping = data
    else:
        raise TypeError(f"Cannot load a bundle from {type(data)!r}.")

    def fail(message: str) -> BundleIntegrityError:
        return BundleIntegrityError(message)

    if not isinstance(mapping, Mapping):
        raise fail("The bundle is not a JSON object.")
    if mapping.get("version") != _BUNDLE_FORMAT_VERSION:
        raise fail(
            f"Unsupported bundle version: {mapping.get('version')!r}.",
        )

    entry = mapping.get("entry")
    manifest = mapping.get("manifest")
    resources = mapping.get("resources")
    digest = mapping.get("digest")
    if not isinstance(entry, str):
        raise fail("The bundle's 'entry' is missing or not a string.")
    if not isinstance(manifest, Mapping):
        raise fail("The bundle's 'manifest' is missing or not an object.")
    if not isinstance(resources, Mapping):
        raise fail("The bundle's 'resources' is missing or not an object.")
    if not isinstance(digest, str):
        raise fail("The bundle's 'digest' is missing or not a string.")

    payload = {
        "version": _BUNDLE_FORMAT_VERSION,
        "entry": entry,
        "manifest": manifest,
    }
    if _digest_of(payload, "<bundle>") != digest:
        raise fail(
            "The bundle's manifest does not match its digest; "
            "the bundle may have been tampered with.",
        )

    pairs = []
    for uri, info in manifest.items():
        if not isinstance(uri, str) or not isinstance(info, Mapping):
            raise fail("The bundle's manifest is malformed.")
        resource_digest = info.get("digest")
        name = info.get("specification")
        if not isinstance(resource_digest, str):
            raise fail(f"The manifest entry for {uri!r} has no digest.")
        specification = _SPECIFICATIONS_BY_NAME.get(name)
        if specification is None:
            raise fail(
                f"The manifest entry for {uri!r} names the unknown "
                f"specification {name!r}.",
            )
        contents = resources.get(resource_digest)
        if contents is None:
            raise fail(
                f"The resource for {uri!r} is missing from the bundle.",
            )
        if _digest_of(contents, uri) != resource_digest:
            raise fail(
                f"The resource for {uri!r} does not match its digest; "
                f"the bundle may have been tampered with.",
            )
        pairs.append((uri, Resource(contents, specification)))

    if entry not in manifest:
        raise fail(f"The entry schema {entry!r} is missing from the bundle.")

    registry: SchemaRegistry = Registry().with_resources(pairs)
    return LoadedBundle(
        schema=registry[entry].contents,
        registry=registry,
        digest=digest,
        entry=entry,
    )
