"""Experimental versioned `TypeAdapter` functionality. Be careful with this API, it's subject to change."""

from __future__ import annotations

import copy
import json
from collections.abc import Callable, Hashable, Mapping
from typing import Any, Generic, TypeVar

from typing_extensions import Self, TypeForm

from pydantic import TypeAdapter, ValidationError

__all__ = [
    'AmbiguousMigrationError',
    'DuplicateMigrationError',
    'DuplicateVersionError',
    'MigrationCycleError',
    'MigrationValidationError',
    'MissingVersionError',
    'NoMigrationPathError',
    'UnknownVersionError',
    'VersionedAdapterError',
    'VersionedTypeAdapter',
]

TargetT = TypeVar('TargetT')

MigrationFn = Callable[[Any], Any]
"""A migration function. Receives payload data of one version and returns data for the next version."""


class VersionedAdapterError(Exception):
    """Base class for all errors raised by `VersionedTypeAdapter`."""


class DuplicateVersionError(VersionedAdapterError, ValueError):
    """Raised when a type is registered twice for the same version."""


class DuplicateMigrationError(VersionedAdapterError, ValueError):
    """Raised when the same migration edge is registered twice."""


class AmbiguousMigrationError(VersionedAdapterError, ValueError):
    """Raised when a version would get a second outgoing migration, making the migration path ambiguous."""


class MigrationCycleError(VersionedAdapterError, ValueError):
    """Raised when a migration would introduce a cycle in the migration graph."""


class UnknownVersionError(VersionedAdapterError):
    """Raised when a payload carries a version that was never registered."""

    def __init__(self, version: Any) -> None:
        self.version = version
        super().__init__(f'unknown version: {version!r}')


class MissingVersionError(VersionedAdapterError):
    """Raised when a payload does not carry the version field."""


class NoMigrationPathError(VersionedAdapterError):
    """Raised when no chain of migrations leads from the payload version to the target version."""

    def __init__(self, from_version: Any, to_version: Any) -> None:
        self.from_version = from_version
        self.to_version = to_version
        super().__init__(f'no migration path from version {from_version!r} to version {to_version!r}')


class MigrationValidationError(VersionedAdapterError):
    """Raised when the output of a migration step fails validation against the next version's type.

    The failing step and the original field error locations are preserved.
    """

    def __init__(self, from_version: Any, to_version: Any, validation_error: ValidationError) -> None:
        self.from_version = from_version
        self.to_version = to_version
        self.validation_error = validation_error
        super().__init__(f'migration step {from_version!r} -> {to_version!r} produced invalid data: {validation_error}')

    def errors(self) -> list[dict[str, Any]]:
        """Return the validation errors of the failed step, with their original field locations."""
        return self.validation_error.errors()


class VersionedTypeAdapter(Generic[TargetT]):
    """A `TypeAdapter` that migrates versioned payloads to a target version before validating them.

    Each known version is registered together with its input type, and adjacent versions are
    connected by migration functions. When a payload arrives, its version is read from the
    version field and the payload is walked along the migration chain towards the target
    version; the output of every step is validated against the next version's type.

    Payloads that already carry the target version are validated directly, without running
    any migration function.
    """

    def __init__(
        self, target_type: TypeForm[TargetT], target_version: Hashable, *, version_field: str = 'version'
    ) -> None:
        self._version_field = version_field
        self._target_version = target_version
        self._adapters: dict[Hashable, TypeAdapter[Any]] = {target_version: TypeAdapter(target_type)}
        self._migrations: dict[Hashable, tuple[Hashable, MigrationFn]] = {}

    @property
    def target_version(self) -> Hashable:
        """The version payloads are migrated towards."""
        return self._target_version

    @property
    def version_field(self) -> str:
        """The payload field the version is read from."""
        return self._version_field

    def register_version(self, version: Hashable, type_: TypeForm[Any]) -> Self:
        """Register the input type for a version."""
        if version in self._adapters:
            raise DuplicateVersionError(f'a type is already registered for version {version!r}')
        self._adapters[version] = TypeAdapter(type_)
        return self

    def register_migration(self, from_version: Hashable, to_version: Hashable, migrate: MigrationFn) -> Self:
        """Register a migration function between two adjacent, already registered versions."""
        for version in (from_version, to_version):
            if version not in self._adapters:
                raise UnknownVersionError(version)
        existing = self._migrations.get(from_version)
        if existing is not None:
            if existing[0] == to_version:
                raise DuplicateMigrationError(f'migration {from_version!r} -> {to_version!r} is already registered')
            raise AmbiguousMigrationError(
                f'version {from_version!r} already migrates to {existing[0]!r}, cannot also migrate to {to_version!r}'
            )
        if from_version == to_version or self._reaches(to_version, from_version):
            raise MigrationCycleError(f'migration {from_version!r} -> {to_version!r} would create a cycle')
        self._migrations[from_version] = (to_version, migrate)
        return self

    def validate_python(self, data: Any) -> TargetT:
        """Validate data, migrating it through the registered versions first if needed."""
        version = self._extract_version(data)
        try:
            known = version in self._adapters
        except TypeError:  # unhashable version value
            known = False
        if not known:
            raise UnknownVersionError(version)
        if version == self._target_version:
            return self._adapters[self._target_version].validate_python(data)

        # Work on a private copy so migration functions can never mutate the caller's input.
        current = copy.deepcopy(data)
        for from_version, to_version, migrate in self._path_to_target(version):
            migrated = migrate(current)
            adapter = self._adapters[to_version]
            try:
                validated = adapter.validate_python(migrated)
            except ValidationError as exc:
                raise MigrationValidationError(from_version, to_version, exc) from exc
            if to_version == self._target_version:
                return validated
            # Hand fresh plain data to the next step, so nothing is shared across steps or requests.
            current = adapter.dump_python(validated, mode='python', round_trip=True)
        raise VersionedAdapterError('migration path did not reach the target version')  # pragma: no cover

    def validate_json(self, data: str | bytes | bytearray) -> TargetT:
        """Parse JSON data and validate it, migrating older versions first if needed."""
        return self.validate_python(json.loads(data))

    def _extract_version(self, data: Any) -> Any:
        if isinstance(data, Mapping):
            if self._version_field in data:
                return data[self._version_field]
        elif hasattr(data, self._version_field):
            return getattr(data, self._version_field)
        raise MissingVersionError(f'payload does not contain the version field {self._version_field!r}')

    def _path_to_target(self, version: Hashable) -> list[tuple[Hashable, Hashable, MigrationFn]]:
        steps: list[tuple[Hashable, Hashable, MigrationFn]] = []
        current = version
        while current != self._target_version:
            edge = self._migrations.get(current)
            if edge is None:
                raise NoMigrationPathError(version, self._target_version)
            steps.append((current, edge[0], edge[1]))
            current = edge[0]
        return steps

    def _reaches(self, start: Hashable, target: Hashable) -> bool:
        current = start
        while current in self._migrations:
            current = self._migrations[current][0]
            if current == target:
                return True
        return False
