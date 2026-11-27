from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import TYPE_CHECKING, Any
from uuid import UUID

if TYPE_CHECKING:
    from collections.abc import Iterable, Iterator, Mapping


class ResourceKind(str, Enum):
    """Kinds of resources that can be signed into an offline acquisition."""

    WEVT = "wevt"
    MESSAGES = "messages"


class FallbackReason(str, Enum):
    """Reason why a candidate was selected, skipped, or not found."""

    EXACT = "exact"
    VERSION_FALLBACK = "version_fallback"
    LOCALE_FALLBACK = "locale_fallback"
    VERSION_AND_LOCALE_FALLBACK = "version_and_locale_fallback"
    UNSIGNED_SOURCE = "unsigned_source"
    DIGEST_MISMATCH = "digest_mismatch"
    MISSING_RESOURCE = "missing_resource"
    UNREADABLE_RESOURCE = "unreadable_resource"
    FIELD_NOT_FOUND = "field_not_found"
    DEFINITION_MISMATCH = "definition_mismatch"
    UNTRANSLATED = "untranslated"


def normalize_provider_id(provider_id: str | UUID | None) -> str | None:
    """Return a stable, case-insensitive representation of a provider id."""
    if provider_id is None:
        return None

    value = str(provider_id).strip().strip("{}").lower()
    try:
        return str(UUID(value))
    except ValueError:
        return value


def _normalize_locale(locale: str | None) -> str | None:
    if locale is None:
        return None
    return locale.replace("_", "-").casefold()


def _version_key(version: str | int | None) -> str | None:
    return None if version is None else str(version).strip().casefold()


@dataclass(frozen=True, slots=True)
class ResourceRecord:
    """A resource declared by the acquisition manifest.

    A resource outside the manifest is never considered. ``signed`` identifies the copy that was
    accepted with the image and ``sha256`` pins its content. If a digest is supplied it must match.
    """

    path: Path
    kind: ResourceKind
    provider_id: str | None = None
    version: str | None = None
    locale: str | None = None
    sha256: str | None = None
    signed: bool = True

    def __post_init__(self) -> None:
        object.__setattr__(self, "path", Path(self.path))
        object.__setattr__(self, "kind", ResourceKind(self.kind))
        object.__setattr__(self, "provider_id", normalize_provider_id(self.provider_id))
        object.__setattr__(self, "version", _version_key(self.version))
        object.__setattr__(self, "sha256", self.sha256.casefold() if self.sha256 else None)

    @property
    def name(self) -> str:
        """Return the file name for diagnostics."""
        return self.path.name


@dataclass(frozen=True, slots=True)
class ResourceManifest:
    """The set of resources signed into the offline image."""

    resources: tuple[ResourceRecord, ...]
    path: Path | None = None

    @classmethod
    def load(cls, path: str | Path) -> ResourceManifest:
        """Load a local JSON manifest. No directory scan or network lookup is performed."""
        manifest_path = Path(path)
        payload = json.loads(manifest_path.read_text(encoding="utf-8"))
        return cls.from_dict(payload, base_path=manifest_path.parent, path=manifest_path)

    @classmethod
    def from_dict(
        cls,
        payload: Mapping[str, Any] | list[Mapping[str, Any]],
        *,
        base_path: str | Path = ".",
        path: str | Path | None = None,
    ) -> ResourceManifest:
        """Build a manifest from decoded JSON data."""
        entries = payload.get("resources", []) if isinstance(payload, dict) else payload
        base = Path(base_path)
        resources = []
        for entry in entries:
            resource_path = Path(entry["path"])
            if not resource_path.is_absolute():
                resource_path = base / resource_path
            resources.append(
                ResourceRecord(
                    path=resource_path,
                    kind=ResourceKind(entry["kind"]),
                    provider_id=entry.get("provider_id"),
                    version=entry.get("version"),
                    locale=entry.get("locale"),
                    sha256=entry.get("sha256"),
                    signed=bool(entry.get("signed", True)),
                )
            )

        return cls(tuple(resources), Path(path) if path is not None else None)

    @property
    def catalog(self) -> OfflineResourceCatalog:
        """Return a catalog restricted to this manifest."""
        return OfflineResourceCatalog(self)


@dataclass(frozen=True, slots=True)
class ResourceSource:
    """Concrete provenance of a selected resource."""

    record: ResourceRecord
    digest: str | None
    selection_reason: FallbackReason = FallbackReason.EXACT

    @property
    def path(self) -> Path:
        """Return the concrete local path."""
        return self.record.path

    @property
    def kind(self) -> ResourceKind:
        """Return the resource kind."""
        return self.record.kind

    @property
    def provider_id(self) -> str | None:
        """Return the provider id."""
        return self.record.provider_id

    @property
    def version(self) -> str | None:
        """Return the package version."""
        return self.record.version

    @property
    def locale(self) -> str | None:
        """Return the locale."""
        return self.record.locale

    @property
    def signed(self) -> bool:
        """Return whether the source was signed with the image."""
        return self.record.signed

    def as_dict(self) -> dict[str, Any]:
        """Return a serialisable provenance record."""
        return {
            "path": str(self.path),
            "kind": self.kind.value,
            "provider_id": self.provider_id,
            "version": self.version,
            "locale": self.locale,
            "sha256": self.digest,
            "signed": self.signed,
            "selection_reason": self.selection_reason.value,
        }


@dataclass(frozen=True, slots=True)
class ResourceAttempt:
    """One candidate considered during a resource lookup."""

    reason: FallbackReason
    accepted: bool
    path: Path | None = None
    record: ResourceRecord | None = None
    detail: str = ""
    requested_version: str | None = None
    requested_locale: str | None = None

    @property
    def version(self) -> str | None:
        """Return the candidate version, if any."""
        return self.record.version if self.record else self.requested_version

    @property
    def locale(self) -> str | None:
        """Return the candidate locale, if any."""
        return self.record.locale if self.record else self.requested_locale

    def as_dict(self) -> dict[str, Any]:
        """Return a serialisable attempt record."""
        return {
            "path": str(self.path) if self.path is not None else None,
            "version": self.version,
            "locale": self.locale,
            "reason": self.reason.value,
            "accepted": self.accepted,
            "detail": self.detail,
        }


@dataclass(frozen=True, slots=True)
class LookupPolicy:
    """Ordered language and version fallback policy.

    The requested locale and version are always tried first. ``order`` can be set to
    ``("version", "locale")`` when an older resource in the requested language should be preferred
    over a newer resource in a secondary language.
    """

    version_fallbacks: tuple[str, ...] = ()
    locale_fallbacks: tuple[str, ...] = ()
    order: tuple[str, ...] = ("locale", "version")

    def __init__(
        self,
        version_fallbacks: Iterable[str | int] = (),
        locale_fallbacks: Iterable[str] = (),
        order: Iterable[str] = ("locale", "version"),
    ) -> None:
        object.__setattr__(self, "version_fallbacks", tuple(_version_key(version) for version in version_fallbacks))
        object.__setattr__(self, "locale_fallbacks", tuple(_normalize_locale(locale) for locale in locale_fallbacks))
        object.__setattr__(self, "order", tuple(order))

    def steps(self, requested_version: str | int | None, requested_locale: str | None) -> tuple[LookupStep, ...]:
        """Return the configured candidate chain without duplicates."""
        requested_version = _version_key(requested_version)
        requested_locale = _normalize_locale(requested_locale)
        versions = (requested_version, *self.version_fallbacks)
        locales = (requested_locale, *self.locale_fallbacks)
        pairs = [(requested_version, requested_locale)]

        for group in self.order:
            if group == "locale":
                pairs.extend((requested_version, locale) for locale in locales[1:])
            elif group == "version":
                pairs.extend((version, requested_locale) for version in versions[1:])

        pairs.extend((version, locale) for version in versions[1:] for locale in locales[1:])

        steps = []
        seen = set()
        for version, locale in pairs:
            if (version, locale) in seen:
                continue
            seen.add((version, locale))
            steps.append(
                LookupStep(
                    version=version,
                    locale=locale,
                    reason=self._reason(version, locale, requested_version, requested_locale),
                )
            )
        return tuple(steps)

    @staticmethod
    def _reason(
        version: str | None,
        locale: str | None,
        requested_version: str | None,
        requested_locale: str | None,
    ) -> FallbackReason:
        version_changed = requested_version is not None and version != requested_version
        locale_changed = requested_locale is not None and locale != requested_locale
        if version_changed and locale_changed:
            return FallbackReason.VERSION_AND_LOCALE_FALLBACK
        if version_changed:
            return FallbackReason.VERSION_FALLBACK
        if locale_changed:
            return FallbackReason.LOCALE_FALLBACK
        return FallbackReason.EXACT


@dataclass(frozen=True, slots=True)
class LookupStep:
    """A single version/locale combination in a fallback policy."""

    version: str | None
    locale: str | None
    reason: FallbackReason


@dataclass(frozen=True)
class ResourceLookup:
    """Result of a constrained offline resource lookup."""

    kind: ResourceKind
    provider_id: str | None
    requested_version: str | None
    requested_locale: str | None
    source: ResourceSource | None
    attempts: tuple[ResourceAttempt, ...]
    fallback_reasons: tuple[FallbackReason, ...] = ()

    @property
    def found(self) -> bool:
        """Return whether an accepted resource was selected."""
        return self.source is not None

    @property
    def resource(self) -> ResourceRecord | None:
        """Return the selected manifest record."""
        return self.source.record if self.source else None

    def as_dict(self) -> dict[str, Any]:
        """Return a serialisable lookup result, including all intermediate reasons."""
        return {
            "kind": self.kind.value,
            "provider_id": self.provider_id,
            "requested_version": self.requested_version,
            "requested_locale": self.requested_locale,
            "source": self.source.as_dict() if self.source else None,
            "fallback_reasons": [reason.value for reason in self.fallback_reasons],
            "attempts": [attempt.as_dict() for attempt in self.attempts],
        }


class OfflineResourceCatalog:
    """Look up resources that were explicitly signed into the offline acquisition."""

    def __init__(self, resources: ResourceManifest | Iterable[ResourceRecord]):
        if isinstance(resources, ResourceManifest):
            self.manifest = resources
            resources = resources.resources
        else:
            self.manifest = ResourceManifest(tuple(resources))
        self.resources = tuple(resources)

    @classmethod
    def from_manifest(cls, path: str | Path) -> OfflineResourceCatalog:
        """Create a catalog from a local acquisition manifest."""
        return cls(ResourceManifest.load(path))

    def lookup_wevt(
        self,
        provider_id: str | UUID,
        version: str | int | None = None,
        locale: str | None = None,
        policy: LookupPolicy | None = None,
    ) -> ResourceLookup:
        """Resolve a provider manifest only from signed WEVT resources."""
        return self.lookup(ResourceKind.WEVT, provider_id, version, locale, policy)

    def lookup_messages(
        self,
        provider_id: str | UUID,
        version: str | int | None = None,
        locale: str | None = None,
        policy: LookupPolicy | None = None,
    ) -> ResourceLookup:
        """Resolve a language/message resource only from manifest-declared files."""
        return self.lookup(ResourceKind.MESSAGES, provider_id, version, locale, policy)

    def lookup(
        self,
        kind: ResourceKind,
        provider_id: str | UUID | None = None,
        version: str | int | None = None,
        locale: str | None = None,
        policy: LookupPolicy | None = None,
    ) -> ResourceLookup:
        """Resolve one resource and retain the complete candidate history."""
        kind = ResourceKind(kind)
        provider_id = normalize_provider_id(provider_id)
        requested_version = _version_key(version)
        requested_locale = locale
        policy = policy or LookupPolicy()
        attempts = []
        source = None
        fallback_reasons = ()

        for step in policy.steps(requested_version, requested_locale):
            records = self._matching(kind, provider_id, step.version, step.locale)
            if not records:
                attempts.append(
                    ResourceAttempt(
                        reason=FallbackReason.MISSING_RESOURCE,
                        accepted=False,
                        detail=f"no manifest resource for {kind.value} version={step.version!r} locale={step.locale!r}",
                        requested_version=step.version,
                        requested_locale=step.locale,
                    )
                )
                continue

            for record in records:
                accepted, digest, reason, detail = self._validate(record)
                attempts.append(
                    ResourceAttempt(
                        reason=step.reason if accepted else reason,
                        accepted=accepted,
                        path=record.path,
                        record=record,
                        detail=detail,
                    )
                )
                if accepted:
                    source = ResourceSource(record, digest, step.reason)
                    fallback_reasons = () if step.reason == FallbackReason.EXACT else (step.reason,)
                    break

            if source is not None:
                break

        return ResourceLookup(
            kind=kind,
            provider_id=provider_id,
            requested_version=requested_version,
            requested_locale=requested_locale,
            source=source,
            attempts=tuple(attempts),
            fallback_reasons=fallback_reasons,
        )

    def candidates(
        self,
        kind: ResourceKind,
        provider_id: str | UUID,
        version: str | int | None,
        locale: str | None,
        policy: LookupPolicy | None = None,
    ) -> Iterator[tuple[LookupStep, ResourceRecord | None]]:
        """Yield every configured candidate in order, including missing combinations."""
        policy = policy or LookupPolicy()
        provider_id = normalize_provider_id(provider_id)
        for step in policy.steps(version, locale):
            records = self._matching(ResourceKind(kind), provider_id, step.version, step.locale)
            if not records:
                yield step, None
            else:
                yield from ((step, record) for record in records)

    def validate(self, record: ResourceRecord) -> tuple[bool, str | None, FallbackReason, str]:
        """Return acceptance, digest, reason, and diagnostic detail for one record."""
        return self._validate(record)

    def _matching(
        self,
        kind: ResourceKind,
        provider_id: str | None,
        version: str | None,
        locale: str | None,
    ) -> tuple[ResourceRecord, ...]:
        return tuple(
            sorted(
                (
                    record
                    for record in self.resources
                    if record.kind == kind
                    and record.provider_id == provider_id
                    and record.version == version
                    and _normalize_locale(record.locale) == locale
                ),
                key=lambda record: str(record.path),
            )
        )

    @staticmethod
    def _validate(record: ResourceRecord) -> tuple[bool, str | None, FallbackReason, str]:
        if not record.signed:
            return False, None, FallbackReason.UNSIGNED_SOURCE, "resource was not signed with the image"
        if not record.path.is_file():
            return False, None, FallbackReason.MISSING_RESOURCE, "resource is absent from the offline image"

        try:
            digest = hashlib.sha256(record.path.read_bytes()).hexdigest()
        except OSError as exc:
            return False, None, FallbackReason.UNREADABLE_RESOURCE, str(exc)

        if record.sha256 is not None and digest != record.sha256:
            return (
                False,
                digest,
                FallbackReason.DIGEST_MISMATCH,
                f"expected sha256={record.sha256}, got sha256={digest}",
            )
        return True, digest, FallbackReason.EXACT, "resource digest matches the manifest"
