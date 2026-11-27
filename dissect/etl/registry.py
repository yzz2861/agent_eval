from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from typing import TYPE_CHECKING
from uuid import UUID

from dissect.etl.exceptions import (
    ManifestDigestNotAllowedError,
    ManifestNotFoundError,
    ManifestVersionNotFoundError,
)

if TYPE_CHECKING:
    from collections.abc import Iterable, Iterator
    from types import ModuleType

DIGEST_ALGORITHM = "sha256"


def manifest_digest(content: bytes | str) -> str:
    """Calculate the canonical digest of an offline manifest definition.

    The digest is taken over the raw manifest text so that two provider lists shipped with
    different field widths or field names still produce a different digest even when they
    decode the same provider GUID and event version.
    """
    if isinstance(content, str):
        content = content.encode("utf-8")
    return f"{DIGEST_ALGORITHM}:{hashlib.sha256(content).hexdigest()}"


@dataclass(frozen=True, slots=True)
class ManifestDefinition:
    """A single offline manifest definition for one provider."""

    provider_id: UUID
    descriptor_version: int
    digest: str
    module: ModuleType
    source: str | None = None

    def describe(self) -> dict[str, object]:
        """Return the provenance information stored on a decoded event."""
        return {
            "provider_id": str(self.provider_id),
            "provider_name": getattr(self.module, "PROVIDER_NAME", None),
            "descriptor_version": self.descriptor_version,
            "digest": self.digest,
            "source": self.source,
        }


@dataclass(frozen=True, slots=True)
class ManifestArchivePolicy:
    """The manifest digests that are allowed for the current archive.

    An empty allowlist permits every registered definition. When the allowlist is set, only
    definitions whose digest is part of the allowlist can be selected.
    """

    allowed_digests: frozenset[str] = frozenset()

    @classmethod
    def from_digests(cls, digests: Iterable[str] | None = None) -> ManifestArchivePolicy:
        return cls(frozenset(digests) if digests else frozenset())

    def allows(self, digest: str) -> bool:
        return not self.allowed_digests or digest in self.allowed_digests


@dataclass(slots=True)
class ManifestRegistry:
    """Holds every known offline manifest definition.

    Definitions are keyed by provider GUID, descriptor version and manifest digest. Keeping
    the digest in the key allows multiple provider lists that target the same event number
    and version (but use different field widths or names) to coexist. All lookups are based
    on the key, never on insertion order.
    """

    _definitions: dict[UUID, dict[tuple[int, str], ManifestDefinition]] = field(default_factory=dict)

    def register(
        self,
        module: ModuleType,
        descriptor_version: int | None = None,
        digest: str | None = None,
        source: str | None = None,
    ) -> list[ManifestDefinition]:
        """Register a compiled manifest module.

        A module may describe multiple event versions. When ``descriptor_version`` is not
        given, every event version inside the module is registered separately.
        """
        provider_id = UUID(str(module.PROVIDER_GUID))
        versions = self._module_versions(module) if descriptor_version is None else {descriptor_version}
        digest = digest or self._module_digest(module)

        registered = []
        provider_definitions = self._definitions.setdefault(provider_id, {})
        for version in sorted(versions):
            definition = ManifestDefinition(
                provider_id=provider_id,
                descriptor_version=version,
                digest=digest,
                module=module,
                source=source,
            )
            provider_definitions[(version, digest)] = definition
            registered.append(definition)
        return registered

    def definitions(self, provider_id: UUID) -> tuple[ManifestDefinition, ...]:
        """Return every registered definition of a provider, ordered by version and digest."""
        provider_definitions = self._definitions.get(provider_id, {})
        return tuple(provider_definitions[key] for key in sorted(provider_definitions))

    def versions(self, provider_id: UUID) -> tuple[int, ...]:
        return tuple(sorted({definition.descriptor_version for definition in self.definitions(provider_id)}))

    def digests(self, provider_id: UUID) -> tuple[str, ...]:
        return tuple(sorted({definition.digest for definition in self.definitions(provider_id)}))

    def select(
        self,
        provider_id: UUID,
        descriptor_version: int,
        policy: ManifestArchivePolicy | None = None,
    ) -> ManifestDefinition:
        """Select a definition by provider, descriptor version and archive digest policy.

        The digest makes the result deterministic: it is part of the registry key, so swapping
        the load order of the provider lists cannot change which definition is returned.
        """
        policy = policy or ManifestArchivePolicy()
        candidates = [
            definition
            for definition in self.definitions(provider_id)
            if definition.descriptor_version == descriptor_version and policy.allows(definition.digest)
        ]

        if not candidates:
            if not self._definitions.get(provider_id):
                raise ManifestNotFoundError(provider_id)
            if not any(
                definition.descriptor_version == descriptor_version for definition in self.definitions(provider_id)
            ):
                raise ManifestVersionNotFoundError(
                    f"No manifest definition for provider {provider_id} descriptor version {descriptor_version}"
                )
            raise ManifestDigestNotAllowedError(
                f"No archive-allowed manifest digest for provider {provider_id} descriptor version {descriptor_version}"
            )

        if len(candidates) > 1:
            raise ManifestDigestNotAllowedError(
                f"Multiple manifest definitions match provider {provider_id} descriptor version "
                f"{descriptor_version}; restrict the archive policy to one digest: {self.digests(provider_id)}"
            )

        return candidates[0]

    def __len__(self) -> int:
        return sum(len(definitions) for definitions in self._definitions.values())

    def __iter__(self) -> Iterator[ManifestDefinition]:
        for provider_id in sorted(self._definitions):
            yield from self.definitions(provider_id)

    @staticmethod
    def _module_versions(module: ModuleType) -> set[int]:
        return {event.version for event in module.EVENTS.values()}

    @staticmethod
    def _module_digest(module: ModuleType) -> str:
        raw = getattr(module, "MANIFEST_DIGEST", None)
        if raw:
            return str(raw)
        return manifest_digest(str(module.PROVIDER_GUID))
